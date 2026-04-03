package storage

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

var (
	ErrBucketNotFound   = errors.New("bucket not found")
	ErrBucketNotEmpty   = errors.New("bucket not empty")
	ErrBucketExists     = errors.New("bucket already exists")
	ErrObjectNotFound   = errors.New("object not found")
	ErrInvalidBucket    = errors.New("invalid bucket name")
	ErrPathTraversal    = errors.New("path traversal detected")
	ErrNoSuchUpload     = errors.New("no such upload")
	ErrInvalidPartOrder = errors.New("invalid part order")
	ErrInvalidPart      = errors.New("invalid part")
)

const (
	metaSuffix   = ".s3meta"
	multipartDir = ".multipart"
	bufferSize   = 256 * 1024 // 256KB
)

type Filesystem struct {
	rootDir string
}

func NewFilesystem(rootDir string) *Filesystem {
	return &Filesystem{rootDir: rootDir}
}

func (f *Filesystem) RootDir() string {
	return f.rootDir
}

// Bucket operations

func (f *Filesystem) CreateBucket(name string) error {
	if err := ValidateBucketName(name); err != nil {
		return err
	}
	path := filepath.Join(f.rootDir, name)
	if err := os.Mkdir(path, 0755); err != nil {
		if os.IsExist(err) {
			return ErrBucketExists
		}
		return fmt.Errorf("create bucket: %w", err)
	}
	return nil
}

func (f *Filesystem) HeadBucket(name string) error {
	path := filepath.Join(f.rootDir, name)
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrBucketNotFound
		}
		return err
	}
	if !info.IsDir() {
		return ErrBucketNotFound
	}
	return nil
}

func (f *Filesystem) DeleteBucket(name string) error {
	path := filepath.Join(f.rootDir, name)
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrBucketNotFound
		}
		return err
	}
	if !info.IsDir() {
		return ErrBucketNotFound
	}

	// Check if empty (only allow .multipart dir)
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() != multipartDir {
			return ErrBucketNotEmpty
		}
	}

	// Remove .multipart dir if it exists
	os.RemoveAll(filepath.Join(path, multipartDir))
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("delete bucket: %w", err)
	}
	return nil
}

type BucketInfo struct {
	Name         string
	CreationDate time.Time
}

func (f *Filesystem) ListBuckets() ([]BucketInfo, error) {
	entries, err := os.ReadDir(f.rootDir)
	if err != nil {
		return nil, err
	}
	var buckets []BucketInfo
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		buckets = append(buckets, BucketInfo{
			Name:         e.Name(),
			CreationDate: info.ModTime(),
		})
	}
	return buckets, nil
}

// Object operations

func (f *Filesystem) PutObject(bucket, key string, body io.Reader, contentType string, userMeta map[string]string) (string, error) {
	if err := f.validateObjectPath(bucket, key); err != nil {
		return "", err
	}
	if err := f.HeadBucket(bucket); err != nil {
		return "", err
	}

	objPath := filepath.Join(f.rootDir, bucket, key)

	// Ensure parent dir exists
	if err := os.MkdirAll(filepath.Dir(objPath), 0755); err != nil {
		return "", fmt.Errorf("create object dir: %w", err)
	}

	// Write to temp file
	tmpPath := objPath + ".tmp." + uuid.New().String()
	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	defer func() {
		tmpFile.Close()
		os.Remove(tmpPath) // cleanup on error
	}()

	// Stream and compute MD5
	hasher := md5.New()
	buf := make([]byte, bufferSize)
	tee := io.TeeReader(body, hasher)
	n, err := io.CopyBuffer(tmpFile, tee, buf)
	if err != nil {
		return "", fmt.Errorf("write object: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return "", fmt.Errorf("close temp file: %w", err)
	}

	etag := fmt.Sprintf("\"%s\"", hex.EncodeToString(hasher.Sum(nil)))

	// Atomic rename
	if err := os.Rename(tmpPath, objPath); err != nil {
		return "", fmt.Errorf("rename object: %w", err)
	}

	// Write metadata sidecar
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	meta := ObjectMetadata{
		ContentType:   contentType,
		ContentLength: n,
		ETag:          etag,
		LastModified:  time.Now().UTC(),
		UserMetadata:  userMeta,
	}
	metaPath := objPath + metaSuffix
	if err := WriteMetadata(metaPath, meta); err != nil {
		return "", err
	}

	return etag, nil
}

type GetObjectResult struct {
	Body     io.ReadCloser
	Metadata ObjectMetadata
}

func (f *Filesystem) GetObject(bucket, key string) (*GetObjectResult, error) {
	if err := f.validateObjectPath(bucket, key); err != nil {
		return nil, err
	}

	objPath := filepath.Join(f.rootDir, bucket, key)
	file, err := os.Open(objPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Check if bucket exists
			if berr := f.HeadBucket(bucket); berr != nil {
				return nil, ErrBucketNotFound
			}
			return nil, ErrObjectNotFound
		}
		return nil, err
	}

	metaPath := objPath + metaSuffix
	meta, err := ReadMetadata(metaPath)
	if err != nil {
		// If metadata is missing, build from file info
		info, statErr := file.Stat()
		if statErr != nil {
			file.Close()
			return nil, statErr
		}
		h := md5.New()
		if _, err := io.Copy(h, file); err != nil {
			file.Close()
			return nil, err
		}
		file.Seek(0, io.SeekStart)
		meta = ObjectMetadata{
			ContentType:   "application/octet-stream",
			ContentLength: info.Size(),
			ETag:          fmt.Sprintf("\"%s\"", hex.EncodeToString(h.Sum(nil))),
			LastModified:  info.ModTime(),
		}
	}

	return &GetObjectResult{
		Body:     file,
		Metadata: meta,
	}, nil
}

func (f *Filesystem) HeadObject(bucket, key string) (ObjectMetadata, error) {
	if err := f.validateObjectPath(bucket, key); err != nil {
		return ObjectMetadata{}, err
	}

	objPath := filepath.Join(f.rootDir, bucket, key)
	if _, err := os.Stat(objPath); err != nil {
		if os.IsNotExist(err) {
			if berr := f.HeadBucket(bucket); berr != nil {
				return ObjectMetadata{}, ErrBucketNotFound
			}
			return ObjectMetadata{}, ErrObjectNotFound
		}
		return ObjectMetadata{}, err
	}

	metaPath := objPath + metaSuffix
	return ReadMetadata(metaPath)
}

func (f *Filesystem) DeleteObject(bucket, key string) error {
	if err := f.validateObjectPath(bucket, key); err != nil {
		return err
	}

	objPath := filepath.Join(f.rootDir, bucket, key)
	os.Remove(objPath)
	os.Remove(objPath + metaSuffix)

	// Clean up empty parent directories up to bucket level
	bucketPath := filepath.Join(f.rootDir, bucket)
	dir := filepath.Dir(objPath)
	for dir != bucketPath {
		if err := os.Remove(dir); err != nil {
			break // not empty or other error
		}
		dir = filepath.Dir(dir)
	}
	return nil
}

// Listing

type ListObjectsInput struct {
	Bucket            string
	Prefix            string
	Delimiter         string
	MaxKeys           int
	StartAfter        string
	ContinuationToken string
}

type ObjectInfo struct {
	Key          string
	Size         int64
	ETag         string
	LastModified time.Time
}

type ListObjectsOutput struct {
	Objects               []ObjectInfo
	CommonPrefixes        []string
	IsTruncated           bool
	NextContinuationToken string
}

func (f *Filesystem) ListObjects(input ListObjectsInput) (*ListObjectsOutput, error) {
	if err := f.HeadBucket(input.Bucket); err != nil {
		return nil, err
	}

	bucketPath := filepath.Join(f.rootDir, input.Bucket)
	if input.MaxKeys <= 0 {
		input.MaxKeys = 1000
	}

	// Collect all keys
	var allKeys []ObjectInfo
	prefixSet := make(map[string]bool)

	err := filepath.WalkDir(bucketPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == multipartDir {
				return filepath.SkipDir
			}
			return nil
		}
		// Skip metadata sidecars and temp files
		if strings.HasSuffix(d.Name(), metaSuffix) || strings.Contains(d.Name(), ".tmp.") {
			return nil
		}

		relPath, err := filepath.Rel(bucketPath, path)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(relPath)

		// Apply prefix filter
		if input.Prefix != "" && !strings.HasPrefix(key, input.Prefix) {
			return nil
		}

		// Apply delimiter
		if input.Delimiter != "" {
			afterPrefix := key[len(input.Prefix):]
			idx := strings.Index(afterPrefix, input.Delimiter)
			if idx >= 0 {
				commonPrefix := input.Prefix + afterPrefix[:idx+len(input.Delimiter)]
				prefixSet[commonPrefix] = true
				return nil
			}
		}

		info, err := d.Info()
		if err != nil {
			return nil // skip files we can't stat
		}

		etag := ""
		metaPath := path + metaSuffix
		if meta, err := ReadMetadata(metaPath); err == nil {
			etag = meta.ETag
		}

		allKeys = append(allKeys, ObjectInfo{
			Key:          key,
			Size:         info.Size(),
			ETag:         etag,
			LastModified: info.ModTime(),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Sort keys
	sort.Slice(allKeys, func(i, j int) bool {
		return allKeys[i].Key < allKeys[j].Key
	})

	// Sort common prefixes
	var commonPrefixes []string
	for p := range prefixSet {
		commonPrefixes = append(commonPrefixes, p)
	}
	sort.Strings(commonPrefixes)

	// Apply start-after / continuation-token
	startAfter := input.StartAfter
	if input.ContinuationToken != "" {
		startAfter = input.ContinuationToken
	}

	if startAfter != "" {
		idx := sort.Search(len(allKeys), func(i int) bool {
			return allKeys[i].Key > startAfter
		})
		allKeys = allKeys[idx:]

		// Also filter common prefixes
		filtered := commonPrefixes[:0]
		for _, p := range commonPrefixes {
			if p > startAfter {
				filtered = append(filtered, p)
			}
		}
		commonPrefixes = filtered
	}

	// Merge objects and prefixes for pagination
	// Both count against maxKeys
	result := &ListObjectsOutput{}
	count := 0
	oi := 0
	pi := 0

	for count < input.MaxKeys && (oi < len(allKeys) || pi < len(commonPrefixes)) {
		useObj := false
		if oi < len(allKeys) && pi < len(commonPrefixes) {
			if allKeys[oi].Key <= commonPrefixes[pi] {
				useObj = true
			}
		} else if oi < len(allKeys) {
			useObj = true
		}

		if useObj {
			result.Objects = append(result.Objects, allKeys[oi])
			oi++
		} else {
			result.CommonPrefixes = append(result.CommonPrefixes, commonPrefixes[pi])
			pi++
		}
		count++
	}

	if oi < len(allKeys) || pi < len(commonPrefixes) {
		result.IsTruncated = true
		if len(result.Objects) > 0 {
			result.NextContinuationToken = result.Objects[len(result.Objects)-1].Key
		} else if len(result.CommonPrefixes) > 0 {
			result.NextContinuationToken = result.CommonPrefixes[len(result.CommonPrefixes)-1]
		}
	}

	return result, nil
}

// Multipart operations

type MultipartUpload struct {
	UploadID    string    `json:"upload_id"`
	Bucket      string    `json:"bucket"`
	Key         string    `json:"key"`
	Initiated   time.Time `json:"initiated"`
	ContentType string    `json:"content_type,omitempty"`
}

type PartInfo struct {
	PartNumber int
	Size       int64
	ETag       string
}

func (f *Filesystem) CreateMultipartUpload(bucket, key, contentType string) (string, error) {
	if err := f.validateObjectPath(bucket, key); err != nil {
		return "", err
	}
	if err := f.HeadBucket(bucket); err != nil {
		return "", err
	}

	uploadID := uuid.New().String()
	uploadDir := filepath.Join(f.rootDir, multipartDir, uploadID)
	if err := os.MkdirAll(filepath.Join(uploadDir, "parts"), 0755); err != nil {
		return "", fmt.Errorf("create multipart dir: %w", err)
	}

	meta := MultipartUpload{
		UploadID:    uploadID,
		Bucket:      bucket,
		Key:         key,
		Initiated:   time.Now().UTC(),
		ContentType: contentType,
	}
	data, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(filepath.Join(uploadDir, "meta.json"), data, 0644); err != nil {
		return "", err
	}

	return uploadID, nil
}

func (f *Filesystem) UploadPart(uploadID string, partNumber int, body io.Reader) (string, error) {
	uploadDir := filepath.Join(f.rootDir, multipartDir, uploadID)
	if _, err := os.Stat(filepath.Join(uploadDir, "meta.json")); err != nil {
		return "", ErrNoSuchUpload
	}

	partPath := filepath.Join(uploadDir, "parts", fmt.Sprintf("%05d", partNumber))
	tmpPath := partPath + ".tmp." + uuid.New().String()

	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		return "", err
	}
	defer func() {
		tmpFile.Close()
		os.Remove(tmpPath)
	}()

	hasher := md5.New()
	buf := make([]byte, bufferSize)
	tee := io.TeeReader(body, hasher)
	if _, err := io.CopyBuffer(tmpFile, tee, buf); err != nil {
		return "", err
	}
	if err := tmpFile.Close(); err != nil {
		return "", err
	}

	etag := fmt.Sprintf("\"%s\"", hex.EncodeToString(hasher.Sum(nil)))

	if err := os.Rename(tmpPath, partPath); err != nil {
		return "", err
	}

	return etag, nil
}

type CompletePart struct {
	PartNumber int
	ETag       string
}

func (f *Filesystem) CompleteMultipartUpload(uploadID string, parts []CompletePart) (string, error) {
	uploadDir := filepath.Join(f.rootDir, multipartDir, uploadID)
	metaData, err := os.ReadFile(filepath.Join(uploadDir, "meta.json"))
	if err != nil {
		return "", ErrNoSuchUpload
	}

	var upload MultipartUpload
	if err := json.Unmarshal(metaData, &upload); err != nil {
		return "", fmt.Errorf("parse upload metadata: %w", err)
	}

	// Validate part order
	for i := 1; i < len(parts); i++ {
		if parts[i].PartNumber <= parts[i-1].PartNumber {
			return "", ErrInvalidPartOrder
		}
	}

	// Verify all parts exist and ETags match
	for _, p := range parts {
		partPath := filepath.Join(uploadDir, "parts", fmt.Sprintf("%05d", p.PartNumber))
		if _, err := os.Stat(partPath); err != nil {
			return "", ErrInvalidPart
		}
		// Verify ETag if provided
		if p.ETag != "" {
			h := md5.New()
			pf, err := os.Open(partPath)
			if err != nil {
				return "", err
			}
			io.Copy(h, pf)
			pf.Close()
			partETag := fmt.Sprintf("\"%s\"", hex.EncodeToString(h.Sum(nil)))
			cleanProvided := strings.Trim(p.ETag, "\"")
			cleanActual := strings.Trim(partETag, "\"")
			if cleanProvided != cleanActual {
				return "", ErrInvalidPart
			}
		}
	}

	// Validate that bucket still exists
	if err := f.HeadBucket(upload.Bucket); err != nil {
		return "", err
	}

	// Assemble the final object
	objPath := filepath.Join(f.rootDir, upload.Bucket, upload.Key)
	if err := os.MkdirAll(filepath.Dir(objPath), 0755); err != nil {
		return "", err
	}

	tmpPath := objPath + ".tmp." + uuid.New().String()
	outFile, err := os.Create(tmpPath)
	if err != nil {
		return "", err
	}
	defer func() {
		outFile.Close()
		os.Remove(tmpPath)
	}()

	// Compute composite ETag: md5(binary_md5_part1 + binary_md5_part2 + ...)-N
	var totalSize int64
	var md5Concat []byte
	buf := make([]byte, bufferSize)

	for _, p := range parts {
		partPath := filepath.Join(uploadDir, "parts", fmt.Sprintf("%05d", p.PartNumber))
		pf, err := os.Open(partPath)
		if err != nil {
			return "", err
		}
		h := md5.New()
		tee := io.TeeReader(pf, h)
		n, err := io.CopyBuffer(outFile, tee, buf)
		pf.Close()
		if err != nil {
			return "", err
		}
		totalSize += n
		md5Concat = append(md5Concat, h.Sum(nil)...)
	}

	if err := outFile.Close(); err != nil {
		return "", err
	}

	if err := os.Rename(tmpPath, objPath); err != nil {
		return "", err
	}

	compositeHash := md5.Sum(md5Concat)
	etag := fmt.Sprintf("\"%s-%d\"", hex.EncodeToString(compositeHash[:]), len(parts))

	// Write metadata
	ct := upload.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	meta := ObjectMetadata{
		ContentType:   ct,
		ContentLength: totalSize,
		ETag:          etag,
		LastModified:  time.Now().UTC(),
	}
	if err := WriteMetadata(objPath+metaSuffix, meta); err != nil {
		return "", err
	}

	// Cleanup
	os.RemoveAll(uploadDir)

	return etag, nil
}

func (f *Filesystem) AbortMultipartUpload(uploadID string) error {
	uploadDir := filepath.Join(f.rootDir, multipartDir, uploadID)
	if _, err := os.Stat(filepath.Join(uploadDir, "meta.json")); err != nil {
		return ErrNoSuchUpload
	}
	return os.RemoveAll(uploadDir)
}

func (f *Filesystem) ListMultipartUploads(bucket string) ([]MultipartUpload, error) {
	mpDir := filepath.Join(f.rootDir, multipartDir)
	entries, err := os.ReadDir(mpDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var uploads []MultipartUpload
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		metaPath := filepath.Join(mpDir, e.Name(), "meta.json")
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		var upload MultipartUpload
		if err := json.Unmarshal(data, &upload); err != nil {
			continue
		}
		if bucket == "" || upload.Bucket == bucket {
			uploads = append(uploads, upload)
		}
	}
	return uploads, nil
}

func (f *Filesystem) ListParts(uploadID string) ([]PartInfo, error) {
	uploadDir := filepath.Join(f.rootDir, multipartDir, uploadID)
	if _, err := os.Stat(filepath.Join(uploadDir, "meta.json")); err != nil {
		return nil, ErrNoSuchUpload
	}

	partsDir := filepath.Join(uploadDir, "parts")
	entries, err := os.ReadDir(partsDir)
	if err != nil {
		return nil, err
	}

	var parts []PartInfo
	for _, e := range entries {
		if e.IsDir() || strings.Contains(e.Name(), ".tmp.") {
			continue
		}
		var partNum int
		fmt.Sscanf(e.Name(), "%d", &partNum)

		info, err := e.Info()
		if err != nil {
			continue
		}

		// Compute ETag
		pf, err := os.Open(filepath.Join(partsDir, e.Name()))
		if err != nil {
			continue
		}
		h := md5.New()
		io.Copy(h, pf)
		pf.Close()
		etag := fmt.Sprintf("\"%s\"", hex.EncodeToString(h.Sum(nil)))

		parts = append(parts, PartInfo{
			PartNumber: partNum,
			Size:       info.Size(),
			ETag:       etag,
		})
	}

	sort.Slice(parts, func(i, j int) bool {
		return parts[i].PartNumber < parts[j].PartNumber
	})
	return parts, nil
}

// Validation helpers

func (f *Filesystem) validateObjectPath(bucket, key string) error {
	if strings.Contains(key, "..") {
		return ErrPathTraversal
	}
	if strings.ContainsRune(key, 0) {
		return ErrPathTraversal
	}

	// Check resolved path stays within bucket
	bucketPath := filepath.Join(f.rootDir, bucket)
	fullPath := filepath.Join(bucketPath, key)
	cleaned := filepath.Clean(fullPath)
	if !strings.HasPrefix(cleaned, filepath.Clean(bucketPath)+string(filepath.Separator)) && cleaned != filepath.Clean(bucketPath) {
		return ErrPathTraversal
	}
	return nil
}

func ValidateBucketName(name string) error {
	if len(name) < 3 || len(name) > 63 {
		return ErrInvalidBucket
	}
	for i, ch := range name {
		if !(unicode.IsLower(ch) || ch == '.' || ch == '-' || unicode.IsDigit(ch)) {
			return ErrInvalidBucket
		}
		if i > 0 && ch == '.' && rune(name[i-1]) == '.' {
			return ErrInvalidBucket
		}
	}
	if name[0] == '.' || name[0] == '-' {
		return ErrInvalidBucket
	}
	if name[len(name)-1] == '.' || name[len(name)-1] == '-' {
		return ErrInvalidBucket
	}
	if strings.HasPrefix(name, "xn--") {
		return ErrInvalidBucket
	}
	if strings.HasSuffix(name, "-s3alias") {
		return ErrInvalidBucket
	}
	if net.ParseIP(name) != nil {
		return ErrInvalidBucket
	}
	return nil
}

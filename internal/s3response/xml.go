package s3response

import (
	"encoding/xml"
	"time"
)

// ListAllMyBucketsResult is the response for ListBuckets (GET /)
type ListAllMyBucketsResult struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListAllMyBucketsResult"`
	Owner   Owner    `xml:"Owner"`
	Buckets Buckets  `xml:"Buckets"`
}

type Owner struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

type Buckets struct {
	Bucket []BucketEntry `xml:"Bucket"`
}

type BucketEntry struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate"`
}

// ListBucketResultV2 is the response for ListObjectsV2
type ListBucketResultV2 struct {
	XMLName               xml.Name        `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
	Name                  string          `xml:"Name"`
	Prefix                string          `xml:"Prefix"`
	Delimiter             string          `xml:"Delimiter,omitempty"`
	MaxKeys               int             `xml:"MaxKeys"`
	IsTruncated           bool            `xml:"IsTruncated"`
	KeyCount              int             `xml:"KeyCount"`
	StartAfter            string          `xml:"StartAfter,omitempty"`
	ContinuationToken     string          `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string          `xml:"NextContinuationToken,omitempty"`
	Contents              []ObjectEntry   `xml:"Contents"`
	CommonPrefixes        []CommonPrefix  `xml:"CommonPrefixes"`
}

type ObjectEntry struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

type CommonPrefix struct {
	Prefix string `xml:"Prefix"`
}

// CreateBucketConfiguration for PUT /{bucket} request body
type CreateBucketConfiguration struct {
	XMLName            xml.Name `xml:"CreateBucketConfiguration"`
	LocationConstraint string   `xml:"LocationConstraint"`
}

// InitiateMultipartUploadResult
type InitiateMultipartUploadResult struct {
	XMLName  xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ InitiateMultipartUploadResult"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadId string   `xml:"UploadId"`
}

// CompleteMultipartUploadResult
type CompleteMultipartUploadResult struct {
	XMLName  xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CompleteMultipartUploadResult"`
	Location string   `xml:"Location"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	ETag     string   `xml:"ETag"`
}

// CompleteMultipartUpload request body
type CompleteMultipartUpload struct {
	XMLName xml.Name             `xml:"CompleteMultipartUpload"`
	Parts   []CompleteUploadPart `xml:"Part"`
}

type CompleteUploadPart struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
}

// ListMultipartUploadsResult
type ListMultipartUploadsResult struct {
	XMLName    xml.Name       `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListMultipartUploadsResult"`
	Bucket     string         `xml:"Bucket"`
	KeyMarker  string         `xml:"KeyMarker"`
	MaxUploads int            `xml:"MaxUploads"`
	IsTruncated bool          `xml:"IsTruncated"`
	Uploads    []UploadEntry  `xml:"Upload"`
}

type UploadEntry struct {
	Key       string `xml:"Key"`
	UploadId  string `xml:"UploadId"`
	Initiated string `xml:"Initiated"`
}

// ListPartsResult
type ListPartsResult struct {
	XMLName  xml.Name    `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListPartsResult"`
	Bucket   string      `xml:"Bucket"`
	Key      string      `xml:"Key"`
	UploadId string      `xml:"UploadId"`
	Parts    []PartEntry `xml:"Part"`
}

type PartEntry struct {
	PartNumber   int    `xml:"PartNumber"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
}

// CopyObjectResult
type CopyObjectResult struct {
	XMLName      xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CopyObjectResult"`
	LastModified string   `xml:"LastModified"`
	ETag         string   `xml:"ETag"`
}

// FormatTime formats a time in S3 ISO 8601 format
func FormatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

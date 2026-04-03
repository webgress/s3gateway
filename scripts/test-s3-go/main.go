package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	endpoint  = "http://localhost:8333"
	bucket    = "test-go-sdk-bucket"
	accessKey = "test-access-key"
	secretKey = "test-secret-key"
	region    = "us-east-1"
)

var (
	passed int32
	failed int32
)

func check(desc string, fn func() error) {
	if err := fn(); err != nil {
		fmt.Printf("FAIL: %s (%v)\n", desc, err)
		atomic.AddInt32(&failed, 1)
	} else {
		fmt.Printf("PASS: %s\n", desc)
		atomic.AddInt32(&passed, 1)
	}
}

func main() {
	ctx := context.Background()

	resolver := aws.EndpointResolverWithOptionsFunc(
		func(service, r string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				URL:               endpoint,
				HostnameImmutable: true,
			}, nil
		},
	)

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
		config.WithEndpointResolverWithOptions(resolver),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})

	fmt.Println("=== S3 Gateway Go SDK Integration Tests ===")

	// Create bucket
	check("Create bucket", func() error {
		_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)})
		return err
	})

	// Put object
	content := []byte("hello from go sdk")
	check("Put object", func() error {
		_, err := client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:      aws.String(bucket),
			Key:         aws.String("hello.txt"),
			Body:        bytes.NewReader(content),
			ContentType: aws.String("text/plain"),
		})
		return err
	})

	// Get object
	check("Get object", func() error {
		resp, err := client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String("hello.txt"),
		})
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if !bytes.Equal(body, content) {
			return fmt.Errorf("content mismatch: %q vs %q", body, content)
		}
		return nil
	})

	// Head object
	check("Head object", func() error {
		resp, err := client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String("hello.txt"),
		})
		if err != nil {
			return err
		}
		if resp.ContentLength == nil || *resp.ContentLength != int64(len(content)) {
			return fmt.Errorf("wrong content length")
		}
		return nil
	})

	// List objects
	check("List objects", func() error {
		resp, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: aws.String(bucket),
		})
		if err != nil {
			return err
		}
		if len(resp.Contents) < 1 {
			return fmt.Errorf("expected at least 1 object")
		}
		return nil
	})

	// Delete object
	check("Delete object", func() error {
		_, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String("hello.txt"),
		})
		return err
	})

	// Concurrent operations
	check("Concurrent put objects", func() error {
		var wg sync.WaitGroup
		var errCount int32
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				_, err := client.PutObject(ctx, &s3.PutObjectInput{
					Bucket: aws.String(bucket),
					Key:    aws.String(fmt.Sprintf("concurrent/%d", n)),
					Body:   bytes.NewReader([]byte(fmt.Sprintf("data-%d", n))),
				})
				if err != nil {
					atomic.AddInt32(&errCount, 1)
				}
			}(i)
		}
		wg.Wait()
		if errCount > 0 {
			return fmt.Errorf("%d concurrent puts failed", errCount)
		}
		return nil
	})

	// Large file upload/download
	check("Large file (5MB) upload+download", func() error {
		size := 5 * 1024 * 1024
		data := make([]byte, size)
		rand.Read(data)
		origHash := md5.Sum(data)

		_, err := client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String("large.bin"),
			Body:   bytes.NewReader(data),
		})
		if err != nil {
			return fmt.Errorf("upload: %w", err)
		}

		resp, err := client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String("large.bin"),
		})
		if err != nil {
			return fmt.Errorf("download: %w", err)
		}
		defer resp.Body.Close()
		dlData, _ := io.ReadAll(resp.Body)
		dlHash := md5.Sum(dlData)

		if origHash != dlHash {
			return fmt.Errorf("MD5 mismatch: %s vs %s",
				hex.EncodeToString(origHash[:]),
				hex.EncodeToString(dlHash[:]))
		}
		return nil
	})

	// Cleanup
	listResp, _ := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(bucket)})
	if listResp != nil {
		for _, obj := range listResp.Contents {
			client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: obj.Key})
		}
	}
	client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)})

	fmt.Printf("\n=== Results: %d passed, %d failed ===\n", passed, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

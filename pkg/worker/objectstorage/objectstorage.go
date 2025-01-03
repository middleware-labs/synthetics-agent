package objectstorage

import (
	"io"
	"time"
)

type CompressionType int

const (
	NoCompression CompressionType = iota
	Gzip
	Brotli
	Zstd
)

type StorageConfig struct {
	CLOUD_STORAGE_TYPE          string
	CLOUD_STORAGE_BUCKET_URL    string
	CLOUD_STORAGE_BUCKET        string
	CLOUD_STORAGE_CLIENT_ID     string
	CLOUD_STORAGE_CLIENT_SECRET string
}

type ObjectStorage interface {
	Upload(reader io.Reader, key string, contentType string, compression CompressionType) error
	Get(key string) (io.ReadCloser, error)
	Exists(key string) bool
	GetCreationTime(key string) *time.Time
	GetPreSignedUploadUrl(key string, expiry time.Duration) (string, error)
}

package worker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/sas"
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
	UploadPreSignedURL(preSignedURL string, reader io.Reader, contentType string) error
}

const MAX_RETURNING_COUNT = 40

type storageImpl struct {
	serviceClient azblob.Client
	containerName string
	fileTag       string
}

func NewAzure(cfg *StorageConfig) (ObjectStorage, error) {
	if cfg == nil {
		return nil, fmt.Errorf("azure config is nil")
	}

	cred, err := azblob.NewSharedKeyCredential(cfg.CLOUD_STORAGE_CLIENT_ID, cfg.CLOUD_STORAGE_CLIENT_SECRET)
	if err != nil {
		return nil, fmt.Errorf("failed to create credentials: %v", err)
	}

	serviceClient, err := azblob.NewClientWithSharedKeyCredential(cfg.CLOUD_STORAGE_BUCKET_URL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create service client: %v", err)
	}

	return &storageImpl{
		serviceClient: *serviceClient,
		containerName: cfg.CLOUD_STORAGE_BUCKET,
		fileTag:       loadFileTag(),
	}, nil
}

func (s *storageImpl) tagging() map[string]*string {
	return map[string]*string{"fileTag": &s.fileTag}
}

func (s *storageImpl) Upload(reader io.Reader, key string, contentType string, compression CompressionType) error {
	containerClient := s.serviceClient.ServiceClient().NewContainerClient(s.containerName)
	blobClient := containerClient.NewBlockBlobClient(key)

	_, err := blobClient.UploadStream(context.TODO(),
		reader,
		&azblob.UploadStreamOptions{
			Metadata: s.tagging(),
		})
	return err
}

func (s *storageImpl) UploadPreSignedURL(preSignedURL string, reader io.Reader, contentType string) error {
	buf := new(bytes.Buffer)
	_, err := io.Copy(buf, reader)
	if err != nil {
		return fmt.Errorf("failed to read content into buffer: %v", err)
	}

	req, err := http.NewRequest("PUT", preSignedURL, buf)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %v", err)
	}

	req.Header.Set("Content-Type", contentType)
	req.Header.Set("x-ms-blob-type", "BlockBlob")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upload to pre-signed URL: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (s *storageImpl) Get(key string) (io.ReadCloser, error) {
	containerClient := s.serviceClient.ServiceClient().NewContainerClient(s.containerName)
	blobClient := containerClient.NewBlobClient(key)

	get, err := blobClient.DownloadStream(context.TODO(), nil)
	if err != nil {
		return nil, err
	}
	return get.Body, nil
}

func (s *storageImpl) GetAll(key string) ([]io.ReadCloser, error) {
	reader, err := s.Get(key)
	if err != nil {
		return nil, err
	}
	return []io.ReadCloser{reader}, nil
}

func (s *storageImpl) Exists(key string) bool {
	containerClient := s.serviceClient.ServiceClient().NewContainerClient(s.containerName)
	blobClient := containerClient.NewBlobClient(key)

	_, err := blobClient.GetProperties(context.TODO(), nil)
	return err == nil
}

func (s *storageImpl) GetCreationTime(key string) *time.Time {
	containerClient := s.serviceClient.ServiceClient().NewContainerClient(s.containerName)
	blobClient := containerClient.NewBlobClient(key)

	props, err := blobClient.GetProperties(context.TODO(), nil)
	if err != nil {
		return nil
	}
	return props.LastModified
}

func (s *storageImpl) GetPreSignedUploadUrl(key string, expiry time.Duration) (string, error) {
	containerClient := s.serviceClient.ServiceClient().NewContainerClient(s.containerName)
	blobClient := containerClient.NewBlobClient(key)

	if expiry == 0*time.Second {
		expiry = 30 * 24 * time.Hour
	}

	sasUrl, err := blobClient.GetSASURL(
		sas.BlobPermissions{Read: true, Write: true},
		time.Now().Add(expiry),
		nil,
	)
	if err != nil {
		return "", err
	}
	return sasUrl, nil
}

func loadFileTag() string {
	key := "retention"
	value := os.Getenv("RETENTION")
	if value == "" {
		value = "default"
	}
	params := url.Values{}
	params.Add(key, value)
	return params.Encode()
}

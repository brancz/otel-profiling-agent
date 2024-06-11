package symuploader

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/elastic/otel-profiling-agent/config"
	"github.com/elastic/otel-profiling-agent/debug/log"
	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/symuploader/elfwriter"

	lru "github.com/elastic/go-freelru"
	v1alpha1 "github.com/elastic/otel-profiling-agent/proto/experiments/parca/debuginfo/v1alpha1"
)

type ParcaSymbolUploader struct {
	client     v1alpha1.DebuginfoServiceClient
	httpClient *http.Client

	retry        *lru.SyncedLRU[libpf.FileID, bool]
	singleflight *lru.SyncedLRU[libpf.FileID, bool]

	keepTextSection bool
	tmp             string
}

func NewParcaSymbolUploader(
	client v1alpha1.DebuginfoServiceClient,
	cacheSize int,
	keepTextSection bool,
) (*ParcaSymbolUploader, error) {
	retryCache, err := lru.NewSynced[libpf.FileID, bool](uint32(cacheSize), libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}

	singleflightCache, err := lru.NewSynced[libpf.FileID, bool](uint32(cacheSize), libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}

	cacheDirectory := filepath.Join(config.CacheDirectory(), "symuploader")
	if _, err := os.Stat(cacheDirectory); os.IsNotExist(err) {
		log.Debugf("Creating cache directory '%s'", cacheDirectory)
		if err := os.MkdirAll(cacheDirectory, os.ModePerm); err != nil {
			return nil, fmt.Errorf("failed to create cache directory (%s): %s", cacheDirectory, err)
		}
	}

	if err := filepath.Walk(cacheDirectory, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}

		if os.Remove(path) != nil {
			log.Warnf("Failed to remove cached file: %s", path)
		}

		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to clean cache directory (%s): %s", cacheDirectory, err)
	}

	return &ParcaSymbolUploader{
		httpClient:      http.DefaultClient,
		client:          client,
		retry:           retryCache,
		singleflight:    singleflightCache,
		keepTextSection: keepTextSection,
		tmp:             cacheDirectory,
	}, nil
}

const (
	ReasonUploadInProgress = "A previous upload is still in-progress and not stale yet (only stale uploads can be retried)."
)

func (u *ParcaSymbolUploader) Upload(ctx context.Context, fileID libpf.FileID, path, buildID string) {
	if buildID == "" {
		return
	}

	retry, ok := u.retry.Get(fileID)
	if ok && !retry {
		return
	}

	// Check if the file is already uploading.
	singleflight, ok := u.singleflight.Get(fileID)
	if ok || singleflight {
		return
	}
	u.singleflight.Add(fileID, true)

	go func() {
		defer u.singleflight.Add(fileID, false)

		if err := u.attemptUpload(ctx, fileID, path, buildID); err != nil {
			log.Warnf("Failed to upload %q with file ID %q and build ID %q: %v", path, fileID.StringNoQuotes(), buildID, err)
		}
	}()
}

func (u *ParcaSymbolUploader) attemptUpload(ctx context.Context, fileID libpf.FileID, path, buildID string) error {
	defer u.singleflight.Add(fileID, false)

	shouldInitiateUploadResp, err := u.client.ShouldInitiateUpload(ctx, &v1alpha1.ShouldInitiateUploadRequest{
		BuildId: buildID,
		Type:    v1alpha1.DebuginfoType_DEBUGINFO_TYPE_DEBUGINFO_UNSPECIFIED,
	})
	if err != nil {
		return err
	}

	if !shouldInitiateUploadResp.ShouldInitiateUpload {
		if shouldInitiateUploadResp.Reason == ReasonUploadInProgress {
			u.retry.AddWithLifetime(fileID, false, 5*time.Minute)
			return nil
		}
		u.retry.Add(fileID, false)
		return nil
	}

	var (
		f    *os.File
		size int64
	)
	if u.keepTextSection {
		f, err = os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				// File doesn't exist, likely because the process is already
				// gone.
				return nil
			}
			return fmt.Errorf("open file: %w", err)
		}
		defer f.Close()

		stat, err := f.Stat()
		if err != nil {
			return fmt.Errorf("stat file to upload: %w", err)
		}

		size = stat.Size()
		if size == 0 {
			// The original file is empty no need to ever upload it.
			u.retry.Add(fileID, false)
			return nil
		}
	} else {
		cachedFile := filepath.Join(u.tmp, fileID.StringNoQuotes())

		_, err := os.Stat(cachedFile)
		if err == nil {
			// File already exists, no need to extract it again.
			f, err = os.Open(cachedFile)
			if err != nil {
				return fmt.Errorf("open cached file: %w", err)
			}
			defer f.Close()

			stat, err := f.Stat()
			if err != nil {
				return fmt.Errorf("stat file to upload: %w", err)
			}
			size = stat.Size()

			if size == 0 {
				// Something went wrong, an empty file should have never been left behind.
				os.Remove(f.Name())
				return nil
			}
		} else if os.IsNotExist(err) {
			// Doesn't exist yet so we need to extract it.
			f, err = os.Create(filepath.Join(u.tmp, fileID.StringNoQuotes()))
			if err != nil {
				os.Remove(f.Name())
				return fmt.Errorf("create file: %w", err)
			}
			defer f.Close()

			original, err := os.Open(path)
			if err != nil {
				os.Remove(f.Name())
				if os.IsNotExist(err) {
					// Original file doesn't exist the process is likely
					// already gone.
					return nil
				}
				return fmt.Errorf("open original file: %w", err)
			}
			defer original.Close()

			if err := elfwriter.OnlyKeepDebug(f, original); err != nil {
				os.Remove(f.Name())
				return fmt.Errorf("extract debuginfo: %w", err)
			}

			if _, err := f.Seek(0, io.SeekStart); err != nil {
				os.Remove(f.Name())
				return fmt.Errorf("seek extracted debuginfo to start: %w", err)
			}

			stat, err := f.Stat()
			if err != nil {
				os.Remove(f.Name())
				return fmt.Errorf("stat file to upload: %w", err)
			}
			size = stat.Size()

			if size == 0 {
				os.Remove(f.Name())
				u.retry.AddWithLifetime(fileID, false, 5*time.Minute)
				return nil
			}
		} else {
			return fmt.Errorf("stat cached file file: %w", err)
		}
	}

	initiateUploadResp, err := u.client.InitiateUpload(ctx, &v1alpha1.InitiateUploadRequest{
		BuildId: buildID,
		Type:    v1alpha1.DebuginfoType_DEBUGINFO_TYPE_DEBUGINFO_UNSPECIFIED,
		Hash:    fileID.StringNoQuotes(),
		Size:    size,
	})
	if err != nil {
		return err
	}

	if initiateUploadResp.UploadInstructions == nil {
		u.retry.Add(fileID, false)
		return nil
	}

	instructions := initiateUploadResp.UploadInstructions
	// For now we only support signed URL uploads.
	if instructions.UploadStrategy != v1alpha1.UploadInstructions_UPLOAD_STRATEGY_SIGNED_URL {
		u.retry.Add(fileID, false)
		return nil
	}

	if err := u.uploadViaSignedURL(ctx, instructions.SignedUrl, f, size); err != nil {
		return err
	}

	_, err = u.client.MarkUploadFinished(ctx, &v1alpha1.MarkUploadFinishedRequest{
		BuildId:  buildID,
		UploadId: initiateUploadResp.UploadInstructions.UploadId,
	})
	if err != nil {
		return err
	}

	u.retry.Add(fileID, false)

	// We've successfully uploaded the file, no need to keep it around.
	if err := os.Remove(f.Name()); err != nil {
		log.Warnf("Failed to remove cached file: %s", f.Name())
	}

	return nil
}

func (u *ParcaSymbolUploader) uploadViaSignedURL(ctx context.Context, url string, r io.Reader, size int64) error {
	// Client is closing the reader if the reader is also closer.
	// We need to wrap the reader to avoid this.
	// We want to have total control over the reader.
	r = bufio.NewReader(r)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, r)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.ContentLength = size
	resp, err := u.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("do upload request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode/100 != 2 {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status code: %d, msg: %s", resp.StatusCode, string(data))
	}

	return nil
}

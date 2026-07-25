package geolocation

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

const maxGeolocationDownloadBytes int64 = 512 << 20

var geolocationHTTPClient = &http.Client{Timeout: 2 * time.Minute}

// decompressTarGzFile decompresses a .tar.gz file.
func decompressTarGzFile(filepath, destDir string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)

	for {
		header, err := tarReader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}

		if header.Typeflag == tar.TypeReg {
			outFile, err := os.Create(path.Join(destDir, path.Base(header.Name)))
			if err != nil {
				return err
			}

			_, err = io.Copy(outFile, tarReader) // #nosec G110
			outFile.Close()
			if err != nil {
				return err
			}
		}

	}

	return nil
}

// decompressZipFile decompresses a .zip file.
func decompressZipFile(filepath, destDir string) error {
	r, err := zip.OpenReader(filepath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}

		outFile, err := os.Create(path.Join(destDir, path.Base(f.Name)))
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc) // #nosec G110
		outFile.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

// calculateFileSHA256 calculates the SHA256 checksum of a file.
func calculateFileSHA256(filepath string) ([]byte, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// loadChecksumFromFile loads the first checksum from a file.
func loadChecksumFromFile(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) > 0 {
			return parts[0], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", nil
}

// verifyChecksum compares the calculated SHA256 checksum of a file against the expected checksum.
func verifyChecksum(filepath, expectedChecksum string) error {
	calculatedChecksum, err := calculateFileSHA256(filepath)

	fileCheckSum := fmt.Sprintf("%x", calculatedChecksum)
	if err != nil {
		return err
	}

	if fileCheckSum != expectedChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, fileCheckSum)
	}

	return nil
}

// downloadFile downloads a file from a URL and saves it to a local file path.
func downloadFile(url, filepath string) error {
	parsedURL, err := validateGeolocationURL(url)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return err
	}
	resp, err := geolocationHTTPClient.Do(req) // #nosec G107 -- URL is explicitly validated and is the configured GeoIP source
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("unexpected status downloading geolocation file: %s: %s", resp.Status, strings.TrimSpace(string(bodyBytes)))
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	written, err := io.Copy(out, io.LimitReader(resp.Body, maxGeolocationDownloadBytes+1))
	if err != nil {
		return err
	}
	if written > maxGeolocationDownloadBytes {
		return fmt.Errorf("geolocation download exceeds %d bytes", maxGeolocationDownloadBytes)
	}
	return nil
}

func getFilenameFromURL(url string) (string, error) {
	parsedURL, err := validateGeolocationURL(url)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodHead, parsedURL.String(), nil)
	if err != nil {
		return "", err
	}
	resp, err := geolocationHTTPClient.Do(req) // #nosec G107 -- URL is explicitly validated and is the configured GeoIP source
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("unexpected status resolving geolocation filename: %s", resp.Status)
	}

	if disposition := resp.Header.Get("Content-Disposition"); disposition != "" {
		_, params, parseErr := mime.ParseMediaType(disposition)
		if parseErr == nil && path.Base(params["filename"]) != "." {
			return path.Base(params["filename"]), nil
		}
	}

	filename := path.Base(parsedURL.Path)
	if filename == "." || filename == "/" || filename == "" {
		return "", errors.New("geolocation URL does not contain a filename")
	}
	return filename, nil
}

func validateGeolocationURL(rawURL string) (*url.URL, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse geolocation URL: %w", err)
	}
	if (parsedURL.Scheme != "https" && parsedURL.Scheme != "http") || parsedURL.Host == "" {
		return nil, errors.New("geolocation URL must be an absolute HTTP or HTTPS URL")
	}
	if parsedURL.User != nil {
		return nil, errors.New("geolocation URL must not contain user information")
	}
	return parsedURL, nil
}

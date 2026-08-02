package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type SecretMount struct {
	Path  string `json:"path"`
	Mount string `json:"mount"`
}

type SecretMounter struct {
	tm      *TokenManager
	baseURL string
	vaultID string
	mounts  []SecretMount
	client  *http.Client
	hashes  map[string]string // mount path → last content hash
}

func NewSecretMounter(tm *TokenManager, baseURL, vaultID string, mounts []SecretMount) *SecretMounter {
	return &SecretMounter{
		tm:      tm,
		baseURL: baseURL,
		vaultID: vaultID,
		mounts:  mounts,
		client:  &http.Client{Timeout: 15 * time.Second},
		hashes:  make(map[string]string),
	}
}

func ParseSecretMounts(raw string) ([]SecretMount, error) {
	if raw == "" {
		return nil, nil
	}
	var mounts []SecretMount
	if err := json.Unmarshal([]byte(raw), &mounts); err != nil {
		return nil, fmt.Errorf("invalid SECRET_MOUNTS JSON: %w", err)
	}
	for _, m := range mounts {
		if m.Path == "" || m.Mount == "" {
			return nil, fmt.Errorf("SECRET_MOUNTS: each entry needs 'path' and 'mount'")
		}
	}
	return mounts, nil
}

func (sm *SecretMounter) MountAll(ctx context.Context) error {
	for _, m := range sm.mounts {
		if err := sm.fetchAndWrite(ctx, m); err != nil {
			return fmt.Errorf("mount %s → %s: %w", m.Path, m.Mount, err)
		}
	}
	log.Printf("[secret-mounts] mounted %d secrets", len(sm.mounts))
	return nil
}

func (sm *SecretMounter) RefreshLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, m := range sm.mounts {
				if err := sm.fetchAndWrite(ctx, m); err != nil {
					log.Printf("[secret-mounts] refresh %s: %v", m.Path, err)
				}
			}
		}
	}
}

func (sm *SecretMounter) fetchAndWrite(ctx context.Context, m SecretMount) error {
	url := fmt.Sprintf("%s/v1/vaults/%s/secrets/%s", sm.baseURL, sm.vaultID, m.Path)
	req, err := sm.tm.AuthedRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req = req.WithContext(ctx)

	resp, err := sm.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var secret struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &secret); err != nil {
		return fmt.Errorf("parse secret: %w", err)
	}

	contentHash := fmt.Sprintf("%x", len(secret.Value))
	if prev, ok := sm.hashes[m.Mount]; ok && prev == contentHash {
		return nil // unchanged
	}

	dir := filepath.Dir(m.Mount)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	tmpFile := m.Mount + ".tmp"
	if err := os.WriteFile(tmpFile, []byte(secret.Value), 0400); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	if err := os.Rename(tmpFile, m.Mount); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("rename: %w", err)
	}

	sm.hashes[m.Mount] = contentHash
	log.Printf("[secret-mounts] wrote %s (%d bytes)", m.Mount, len(secret.Value))
	return nil
}

// CleanupMounts removes tmpfs files on shutdown (best-effort).
func (sm *SecretMounter) CleanupMounts() {
	for _, m := range sm.mounts {
		os.Remove(m.Mount)
	}
}

// ParseSecretMountsFromEnv reads and parses the SECRET_MOUNTS env var.
func ParseSecretMountsFromEnv() ([]SecretMount, error) {
	raw := os.Getenv("SECRET_MOUNTS")
	return ParseSecretMounts(raw)
}

// FetchSecretValue fetches a secret value from Vault. Exported for testing.
func FetchSecretValue(tm *TokenManager, baseURL, vaultID, path string) (string, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	url := fmt.Sprintf("%s/v1/vaults/%s/secrets/%s", baseURL, vaultID, path)
	req, err := tm.AuthedRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var secret struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &secret); err != nil {
		return "", err
	}
	return secret.Value, nil
}

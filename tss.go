package main

// Runtime share holder (non-custodial signing plan, Phase 3 / Model 3).
//
// The sidecar holds the customer's half of a 2-of-2 FROST key on the
// agent's behalf, so a below-cap transaction can be signed unattended. At
// boot it generates a P-256 key and registers the public half with the vault
// (`POST /v1/runtimes/{id}/tss/holder`); the owner's browser re-wraps the
// share to that key (ECIES: ephemeral P-256 ‖ iv ‖ AES-GCM) and stores it
// with the vault. The private half never leaves this process; the wrapped
// share is fetched, decrypted in memory for one signing, and dropped.
//
// Local endpoints (loopback, for the agent):
//   POST /tss/send {key_id, to, value, memo?}   prepare → sign → broadcast
//   POST /tss/sign {key_id, message}            co-sign a prepared message

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

const shareWrapInfo = "1claw sidecar share wrap v1"

type ShareHolder struct {
	tm        *TokenManager
	baseURL   string
	agentID   string
	runtimeID string
	engine    *TssEngine
	client    *http.Client
	activity  *ActivityTracker

	mu       sync.Mutex
	priv     *ecdh.PrivateKey
	holderID string
}

func NewShareHolder(tm *TokenManager, baseURL, agentID, runtimeID string, engine *TssEngine, activity *ActivityTracker) (*ShareHolder, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ShareHolder{
		tm:        tm,
		baseURL:   baseURL,
		agentID:   agentID,
		runtimeID: runtimeID,
		engine:    engine,
		client:    &http.Client{Timeout: 60 * time.Second},
		activity:  activity,
		priv:      priv,
	}, nil
}

// Register tells the vault this runtime can hold a share. Retried in the
// background; signing before registration simply finds no share.
func (h *ShareHolder) Register(ctx context.Context) {
	if h.runtimeID == "" {
		log.Printf("tss: no ONECLAW_RUNTIME_ID; share holder not registered")
		return
	}
	body, _ := json.Marshal(map[string]string{
		"public_key": base64.StdEncoding.EncodeToString(h.priv.PublicKey().Bytes()),
	})
	for attempt := 0; attempt < 10; attempt++ {
		req, err := h.tm.AuthedRequest(http.MethodPost, fmt.Sprintf("%s/v1/runtimes/%s/tss/holder", h.baseURL, h.runtimeID), bytes.NewReader(body))
		if err == nil {
			resp, err := h.client.Do(req.WithContext(ctx))
			if err == nil {
				var out struct {
					HolderID string `json:"holder_id"`
				}
				_ = json.NewDecoder(resp.Body).Decode(&out)
				resp.Body.Close()
				if resp.StatusCode < 300 && out.HolderID != "" {
					h.mu.Lock()
					h.holderID = out.HolderID
					h.mu.Unlock()
					log.Printf("tss: share holder registered (holder %s)", out.HolderID)
					return
				}
				log.Printf("tss: holder registration → %d", resp.StatusCode)
			} else {
				log.Printf("tss: holder registration: %v", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(5*(attempt+1)) * time.Second):
		}
	}
}

func (h *ShareHolder) api(ctx context.Context, method, path string, in any, out any) (int, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(b)
	}
	req, err := h.tm.AuthedRequest(method, h.baseURL+path, body)
	if err != nil {
		return 0, err
	}
	resp, err := h.client.Do(req.WithContext(ctx))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := e.Error
		if msg == "" {
			msg = e.Message
		}
		if msg == "" {
			msg = string(raw)
		}
		return resp.StatusCode, fmt.Errorf("%s %s → %d: %s", method, path, resp.StatusCode, msg)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode %s: %w", path, err)
		}
	}
	return resp.StatusCode, nil
}

// unwrap decrypts an ECIES blob made for this holder's key.
func (h *ShareHolder) unwrap(blob []byte) ([]byte, error) {
	if len(blob) < 65+12+16 || blob[0] != 0x04 {
		return nil, errors.New("tss: wrapped share is not an ECIES blob")
	}
	eph, err := ecdh.P256().NewPublicKey(blob[:65])
	if err != nil {
		return nil, fmt.Errorf("tss: ephemeral key: %w", err)
	}
	shared, err := h.priv.ECDH(eph)
	if err != nil {
		return nil, fmt.Errorf("tss: ecdh: %w", err)
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, nil, []byte(shareWrapInfo)), key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	share, err := gcm.Open(nil, blob[65:77], blob[77:], nil)
	if err != nil {
		return nil, errors.New("tss: share does not decrypt for this holder (re-provision after a restart)")
	}
	return share, nil
}

// fetchShare pulls this holder's wrap for a key and decrypts it.
func (h *ShareHolder) fetchShare(ctx context.Context, keyID string) ([]byte, error) {
	var out struct {
		WrappedShare string `json:"wrapped_share"`
	}
	if _, err := h.api(ctx, http.MethodGet, fmt.Sprintf("/v1/keys/%s/client-share/holder", keyID), nil, &out); err != nil {
		return nil, err
	}
	blob, err := base64.StdEncoding.DecodeString(out.WrappedShare)
	if err != nil {
		return nil, errors.New("tss: wrapped share is not base64")
	}
	return h.unwrap(blob)
}

// coSign runs the FROST rounds with the vault over a prepared message.
func (h *ShareHolder) coSign(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	share, err := h.fetchShare(ctx, keyID)
	if err != nil {
		return nil, err
	}
	defer zero(share)

	var begin struct {
		SessionID         string `json:"session_id"`
		ServerCommitments string `json:"server_commitments"`
	}
	if _, err := h.api(ctx, http.MethodPost, fmt.Sprintf("/v1/agents/%s/tss/sign/begin", h.agentID), map[string]string{
		"key_id":  keyID,
		"message": base64.StdEncoding.EncodeToString(message),
	}, &begin); err != nil {
		return nil, err
	}
	serverCommit, err := base64.StdEncoding.DecodeString(begin.ServerCommitments)
	if err != nil {
		return nil, errors.New("tss: server commitments are not base64")
	}
	nonces, commit, err := h.engine.SignRound1(ctx, share)
	if err != nil {
		return nil, err
	}
	defer zero(nonces)
	sigShare, err := h.engine.SignRound2(ctx, tssClientID, share, nonces, commit, tssServerID, serverCommit, message)
	if err != nil {
		return nil, err
	}
	var done struct {
		Signature string `json:"signature"`
	}
	if _, err := h.api(ctx, http.MethodPost, fmt.Sprintf("/v1/agents/%s/tss/sign/complete", h.agentID), map[string]string{
		"session_id":             begin.SessionID,
		"client_commitments":     base64.StdEncoding.EncodeToString(commit),
		"client_signature_share": base64.StdEncoding.EncodeToString(sigShare),
	}, &done); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(done.Signature)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (h *ShareHolder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.activity.Touch()
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	ctx := r.Context()
	switch r.URL.Path {
	case "/tss/send", "/tss/send/":
		var req struct {
			KeyID string `json:"key_id"`
			To    string `json:"to"`
			Value string `json:"value"`
			Memo  string `json:"memo,omitempty"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil || req.KeyID == "" || req.To == "" || req.Value == "" {
			writeError(w, http.StatusBadRequest, "key_id, to and value are required")
			return
		}
		var prepared struct {
			Message        string `json:"message"`
			To             string `json:"to"`
			ValueBaseUnits string `json:"value_base_units"`
		}
		if code, err := h.api(ctx, http.MethodPost, fmt.Sprintf("/v1/agents/%s/tss/prepare", h.agentID), map[string]any{
			"key_id": req.KeyID, "to": req.To, "value": req.Value, "memo": req.Memo,
		}, &prepared); err != nil {
			writeError(w, upstreamStatus(code), err.Error())
			return
		}
		message, err := base64.StdEncoding.DecodeString(prepared.Message)
		if err != nil {
			writeError(w, http.StatusBadGateway, "prepared message is not base64")
			return
		}
		sig, err := h.coSign(ctx, req.KeyID, message)
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		var out json.RawMessage
		if code, err := h.api(ctx, http.MethodPost, fmt.Sprintf("/v1/agents/%s/tss/broadcast", h.agentID), map[string]string{
			"key_id":    req.KeyID,
			"message":   prepared.Message,
			"signature": base64.StdEncoding.EncodeToString(sig),
		}, &out); err != nil {
			writeError(w, upstreamStatus(code), err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	case "/tss/sign", "/tss/sign/":
		var req struct {
			KeyID   string `json:"key_id"`
			Message string `json:"message"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 128<<10)).Decode(&req); err != nil || req.KeyID == "" || req.Message == "" {
			writeError(w, http.StatusBadRequest, "key_id and message (base64) are required")
			return
		}
		message, err := base64.StdEncoding.DecodeString(req.Message)
		if err != nil {
			writeError(w, http.StatusBadRequest, "message is not base64")
			return
		}
		sig, err := h.coSign(ctx, req.KeyID, message)
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"key_id":    req.KeyID,
			"signature": base64.StdEncoding.EncodeToString(sig),
		})
	default:
		writeError(w, http.StatusNotFound, "unknown tss endpoint")
	}
}

func upstreamStatus(code int) int {
	if code >= 400 && code < 500 {
		return code
	}
	return http.StatusBadGateway
}

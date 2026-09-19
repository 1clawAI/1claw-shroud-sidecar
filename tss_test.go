package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"
)

// Mirrors what dashboard/src/lib/tss.ts does with WebCrypto to wrap a share
// for a holder: ECDH(ephemeral, holder) → HKDF-SHA256(info) → AES-256-GCM.
func wrapForHolder(t *testing.T, holderPub *ecdh.PublicKey, share []byte) []byte {
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := eph.ECDH(holderPub)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, nil, []byte(shareWrapInfo)), key); err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	iv := make([]byte, 12)
	_, _ = rand.Read(iv)
	blob := append([]byte{}, eph.PublicKey().Bytes()...)
	blob = append(blob, iv...)
	return append(blob, gcm.Seal(nil, iv, share, nil)...)
}

func TestHolderUnwrapsAShareWrappedToItsKey(t *testing.T) {
	h := &ShareHolder{}
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h.priv = priv
	share := []byte("this stands in for a FROST key package")
	blob := wrapForHolder(t, priv.PublicKey(), share)
	got, err := h.unwrap(blob)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(share) {
		t.Fatal("unwrapped share differs")
	}

	// Wrapped to someone else → refused.
	other, _ := ecdh.P256().GenerateKey(rand.Reader)
	if _, err := h.unwrap(wrapForHolder(t, other.PublicKey(), share)); err == nil {
		t.Fatal("unwrapped a share meant for another holder")
	}
	// Tampered ciphertext → refused.
	blob[len(blob)-1] ^= 1
	if _, err := h.unwrap(blob); err == nil {
		t.Fatal("unwrapped tampered ciphertext")
	}
}

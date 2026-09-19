package main

import (
	"context"
	"crypto/ed25519"
	"testing"
)

// Both parties run through the embedded module; the result must be a plain
// Ed25519 signature Go's standard library accepts. That is the interop
// proof: the vault runs the same crate natively.
func TestFrostThroughWasmProducesAValidEd25519Signature(t *testing.T) {
	ctx := context.Background()
	e, err := NewTssEngine(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(ctx)

	s1, p1, err := e.KeygenPart1(ctx, tssServerID)
	if err != nil {
		t.Fatal(err)
	}
	s2, p2, err := e.KeygenPart1(ctx, tssClientID)
	if err != nil {
		t.Fatal(err)
	}
	s1b, p1for2, err := e.KeygenPart2(ctx, tssServerID, s1, tssClientID, p2)
	if err != nil {
		t.Fatal(err)
	}
	s2b, p2for1, err := e.KeygenPart2(ctx, tssClientID, s2, tssServerID, p1)
	if err != nil {
		t.Fatal(err)
	}
	kp1, pub1, vk1, err := e.KeygenPart3(ctx, s1b, tssClientID, p2, p2for1)
	if err != nil {
		t.Fatal(err)
	}
	kp2, pub2, vk2, err := e.KeygenPart3(ctx, s2b, tssServerID, p1, p1for2)
	if err != nil {
		t.Fatal(err)
	}
	if string(pub1) != string(pub2) || string(vk1) != string(vk2) {
		t.Fatal("parties disagree on the group key")
	}
	if len(vk1) != 32 {
		t.Fatalf("verifying key is %d bytes", len(vk1))
	}

	msg := []byte("solana message from the sidecar")
	n1, c1, err := e.SignRound1(ctx, kp1)
	if err != nil {
		t.Fatal(err)
	}
	n2, c2, err := e.SignRound1(ctx, kp2)
	if err != nil {
		t.Fatal(err)
	}
	sh1, err := e.SignRound2(ctx, tssServerID, kp1, n1, c1, tssClientID, c2, msg)
	if err != nil {
		t.Fatal(err)
	}
	sh2, err := e.SignRound2(ctx, tssClientID, kp2, n2, c2, tssServerID, c1, msg)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := e.Aggregate(ctx, pub1, tssServerID, c1, sh1, tssClientID, c2, sh2, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(ed25519.PublicKey(vk1), msg, sig) {
		t.Fatal("aggregate signature does not verify under Go ed25519")
	}

	// A share over a different message is refused at aggregation.
	bad, err := e.SignRound2(ctx, tssClientID, kp2, n2, c2, tssServerID, c1, []byte("other"))
	if err == nil {
		if _, err := e.Aggregate(ctx, pub1, tssServerID, c1, sh1, tssClientID, c2, bad, msg); err == nil {
			t.Fatal("bad share aggregated")
		}
	}
}

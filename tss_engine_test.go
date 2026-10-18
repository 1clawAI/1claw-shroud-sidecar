package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
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

// The sidecar derives XRPL signing data through the same restricted encoder
// as the browser and the vault (vectors pinned in all three), and refuses a
// transaction the vault's classifier would refuse.
func TestCheckTransactionDerivesThePayloadAndRefusesBadShapes(t *testing.T) {
	ctx := context.Background()
	e, err := NewTssEngine(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tx := `{"TransactionType":"Payment","Account":"r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ","Destination":"rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe","Amount":"1000000","Fee":"12","Flags":2147483648,"Sequence":5,"LastLedgerSequence":1000,"SourceTag":482684816,"SigningPubKey":"ED5F5AC8B98974A3CA843326D9B88CEBD0560177B973EE0B149F782CFAA06DC66A"}`
	payload, err := e.CheckTransaction(ctx, "xrp", "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ", []byte(tx))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.ToUpper(hex.EncodeToString(payload)); got != "535458001200002280000000231CC52F902400000005201B000003E86140000000000F424068400000000000000C7321ED5F5AC8B98974A3CA843326D9B88CEBD0560177B973EE0B149F782CFAA06DC66A81145B812C9D57731E27A2DA8B1830195F88EF32A3B68314F667B0CA50CC7709A220B0561B85E53A48461FA8" {
		t.Fatalf("payload mismatch: %s", got)
	}
	bad := strings.Replace(tx, "\"Payment\"", "\"SetRegularKey\"", 1)
	if _, err := e.CheckTransaction(ctx, "xrp", "r9LqNeG6qHxjeUocjvVki2XR35weJ9mZgQ", []byte(bad)); err == nil {
		t.Fatal("SetRegularKey was accepted")
	}
	if _, err := e.CheckTransaction(ctx, "xrp", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", []byte(tx)); err == nil {
		t.Fatal("a transaction from another wallet was accepted")
	}
	msg := []byte{1, 2, 3}
	if p, err := e.CheckTransaction(ctx, "solana", "x", msg); err != nil || string(p) != string(msg) {
		t.Fatalf("solana payload is the message: %v", err)
	}
}

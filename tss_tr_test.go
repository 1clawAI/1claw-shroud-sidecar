package main

import (
	"context"
	"testing"
)

// The Taproot exports, end to end through the embedded module: a two-party
// FROST-TR keygen, one co-signing round per payload with fresh nonces (as
// coSign runs for a multi-input Bitcoin send), aggregation, and BIP340
// verification by the module's own verifier. The vault runs the same crate
// natively, and the Bitcoin Core regtest proof covers consensus.
func TestTaprootRoundsThroughWasmProduceBip340Signatures(t *testing.T) {
	ctx := context.Background()
	e, err := NewTssEngine(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(ctx)
	tr := CurveSecp256k1Tr
	call := func(name string, want int, inputs [][]byte, args func(b []guestBuf) []uint64) [][]byte {
		t.Helper()
		out, err := e.withBufs(ctx, inputs, func(b []guestBuf) ([]byte, error) {
			return e.call(ctx, name, args(b)...)
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		p, err := splitParts(out, want)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return p
	}
	k1 := func(id uint32) [][]byte {
		return call(tr.export("keygen_part1"), 2, nil, func([]guestBuf) []uint64 { return []uint64{uint64(id)} })
	}
	k2 := func(id uint32, secret []byte, other uint32, otherR1 []byte) [][]byte {
		return call(tr.export("keygen_part2"), 2, [][]byte{secret, otherR1}, func(b []guestBuf) []uint64 {
			return []uint64{uint64(id), uint64(b[0].ptr), uint64(b[0].n), uint64(other), uint64(b[1].ptr), uint64(b[1].n)}
		})
	}
	k3 := func(secret2 []byte, other uint32, otherR1, otherR2 []byte) [][]byte {
		return call(tr.export("keygen_part3"), 3, [][]byte{secret2, otherR1, otherR2}, func(b []guestBuf) []uint64 {
			return []uint64{uint64(b[0].ptr), uint64(b[0].n), uint64(other), uint64(b[1].ptr), uint64(b[1].n), uint64(b[2].ptr), uint64(b[2].n)}
		})
	}
	a1, a2 := k1(tssServerID), k1(tssClientID)
	b1 := k2(tssServerID, a1[0], tssClientID, a2[1])
	b2 := k2(tssClientID, a2[0], tssServerID, a1[1])
	c1 := k3(b1[0], tssClientID, a2[1], b2[1])
	c2 := k3(b2[0], tssServerID, a1[1], b1[1])
	kp1, pub, vk := c1[0], c1[1], c1[2]
	kp2 := c2[0]
	if string(vk) != string(c2[2]) || len(vk) != 33 {
		t.Fatalf("group key: %d bytes / parties disagree", len(vk))
	}

	payloads := [][]byte{make([]byte, 32), make([]byte, 32)}
	payloads[0][0], payloads[1][0] = 1, 2
	for i, msg := range payloads {
		n1, cm1, err := e.SignRound1Curve(ctx, tr, kp1)
		if err != nil {
			t.Fatal(err)
		}
		n2, cm2, err := e.SignRound1Curve(ctx, tr, kp2)
		if err != nil {
			t.Fatal(err)
		}
		s1, err := e.SignRound2Curve(ctx, tr, tssServerID, kp1, n1, cm1, tssClientID, cm2, msg)
		if err != nil {
			t.Fatal(err)
		}
		s2, err := e.SignRound2Curve(ctx, tr, tssClientID, kp2, n2, cm2, tssServerID, cm1, msg)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := e.withBufs(ctx, [][]byte{pub, cm1, s1, cm2, s2, msg}, func(b []guestBuf) ([]byte, error) {
			return e.call(ctx, tr.export("aggregate"),
				uint64(b[0].ptr), uint64(b[0].n),
				uint64(tssServerID), uint64(b[1].ptr), uint64(b[1].n), uint64(b[2].ptr), uint64(b[2].n),
				uint64(tssClientID), uint64(b[3].ptr), uint64(b[3].n), uint64(b[4].ptr), uint64(b[4].n),
				uint64(b[5].ptr), uint64(b[5].n))
		})
		if err != nil || len(sig) != 64 {
			t.Fatalf("payload %d: aggregate: %v (%d bytes)", i, err, len(sig))
		}
		for _, tc := range []struct {
			m    []byte
			want uint64
		}{{msg, 1}, {payloads[1-i], 0}} {
			ptrs := []uint32{}
			for _, in := range [][]byte{vk, tc.m, sig} {
				p, err := e.put(ctx, in)
				if err != nil {
					t.Fatal(err)
				}
				ptrs = append(ptrs, p)
			}
			r, err := e.mod.ExportedFunction("tss_tr_verify").Call(ctx,
				uint64(ptrs[0]), 33, uint64(ptrs[1]), 32, uint64(ptrs[2]), 64)
			if err != nil || r[0] != tc.want {
				t.Fatalf("payload %d: verify want %d got %v (%v)", i, tc.want, r, err)
			}
			e.free(ctx, ptrs[0], 33)
			e.free(ctx, ptrs[1], 32)
			e.free(ctx, ptrs[2], 64)
		}
	}
	if CurveForChain("bitcoin-signet") != tr || CurveForChain("solana") != CurveEd25519 {
		t.Fatal("curve routing")
	}
}

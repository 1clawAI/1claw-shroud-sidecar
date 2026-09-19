package main

// The sidecar's half of a 2-of-2 FROST (Ed25519) key, run through the same
// Rust crate the browser uses (`packages/tss-wasm`, C-ABI build) via wazero.
// No Go reimplementation of the protocol: interop with the vault is by
// construction, not by matching two implementations of RFC 9591.

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

//go:embed tss/oneclaw_tss_cabi.wasm
var tssWasm []byte

// Party identifiers, fixed for the life of a key: the vault is 1, the
// share holder (browser or sidecar) is 2.
const (
	tssServerID = 1
	tssClientID = 2
)

// TssEngine wraps one instantiated module. Calls are serialised: the module
// has a single linear memory and its allocator is not reentrant.
type TssEngine struct {
	mu      sync.Mutex
	rt      wazero.Runtime
	mod     api.Module
	alloc   api.Function
	dealloc api.Function
	lastErr api.Function
}

func NewTssEngine(ctx context.Context) (*TssEngine, error) {
	rt := wazero.NewRuntime(ctx)
	// The module's only import: randomness, from Go's crypto/rand.
	_, err := rt.NewHostModuleBuilder("env").
		NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, ptr, n uint32) {
			buf := make([]byte, n)
			if _, err := rand.Read(buf); err != nil {
				panic("crypto/rand: " + err.Error())
			}
			if !m.Memory().Write(ptr, buf) {
				panic("tss wasm: random write out of range")
			}
		}).
		Export("oneclaw_random").
		Instantiate(ctx)
	if err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("tss wasm host module: %w", err)
	}
	mod, err := rt.Instantiate(ctx, tssWasm)
	if err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("tss wasm: %w", err)
	}
	e := &TssEngine{rt: rt, mod: mod}
	for name, dst := range map[string]*api.Function{
		"tss_alloc":      &e.alloc,
		"tss_dealloc":    &e.dealloc,
		"tss_last_error": &e.lastErr,
	} {
		f := mod.ExportedFunction(name)
		if f == nil {
			_ = rt.Close(ctx)
			return nil, fmt.Errorf("tss wasm: missing export %s", name)
		}
		*dst = f
	}
	return e, nil
}

func (e *TssEngine) Close(ctx context.Context) error { return e.rt.Close(ctx) }

// put copies b into guest memory; the caller frees with free.
func (e *TssEngine) put(ctx context.Context, b []byte) (uint32, error) {
	if len(b) == 0 {
		return 0, nil
	}
	r, err := e.alloc.Call(ctx, uint64(len(b)))
	if err != nil {
		return 0, err
	}
	ptr := uint32(r[0])
	if !e.mod.Memory().Write(ptr, b) {
		return 0, errors.New("tss wasm: write out of range")
	}
	return ptr, nil
}

func (e *TssEngine) free(ctx context.Context, ptr, n uint32) {
	if ptr != 0 {
		_, _ = e.dealloc.Call(ctx, uint64(ptr), uint64(n))
	}
}

// read copies a packed ptr<<32|len result out and frees it.
func (e *TssEngine) read(ctx context.Context, packed uint64) ([]byte, error) {
	if packed == 0 {
		msg := "unknown error"
		if r, err := e.lastErr.Call(ctx); err == nil && r[0] != 0 {
			p, n := uint32(r[0]>>32), uint32(r[0])
			if b, ok := e.mod.Memory().Read(p, n); ok {
				msg = string(b)
			}
			e.free(ctx, p, n)
		}
		return nil, fmt.Errorf("tss: %s", msg)
	}
	p, n := uint32(packed>>32), uint32(packed)
	b, ok := e.mod.Memory().Read(p, n)
	if !ok {
		return nil, errors.New("tss wasm: read out of range")
	}
	out := make([]byte, n)
	copy(out, b)
	e.free(ctx, p, n)
	return out, nil
}

// splitParts decodes `[u32 len][part]…`.
func splitParts(b []byte, want int) ([][]byte, error) {
	var out [][]byte
	for len(b) >= 4 && len(out) < want {
		n := binary.LittleEndian.Uint32(b[:4])
		b = b[4:]
		if uint32(len(b)) < n {
			return nil, errors.New("tss: truncated part")
		}
		out = append(out, b[:n])
		b = b[n:]
	}
	if len(out) != want {
		return nil, fmt.Errorf("tss: expected %d parts, got %d", want, len(out))
	}
	return out, nil
}

type guestBuf struct {
	ptr, n uint32
}

func (e *TssEngine) call(ctx context.Context, name string, args ...uint64) ([]byte, error) {
	f := e.mod.ExportedFunction(name)
	if f == nil {
		return nil, fmt.Errorf("tss wasm: missing export %s", name)
	}
	r, err := f.Call(ctx, args...)
	if err != nil {
		return nil, fmt.Errorf("tss %s: %w", name, err)
	}
	return e.read(ctx, r[0])
}

// withBufs copies inputs into the guest and frees them after fn returns.
func (e *TssEngine) withBufs(ctx context.Context, inputs [][]byte, fn func(bufs []guestBuf) ([]byte, error)) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	bufs := make([]guestBuf, 0, len(inputs))
	defer func() {
		for _, b := range bufs {
			e.free(ctx, b.ptr, b.n)
		}
	}()
	for _, in := range inputs {
		p, err := e.put(ctx, in)
		if err != nil {
			return nil, err
		}
		bufs = append(bufs, guestBuf{ptr: p, n: uint32(len(in))})
	}
	return fn(bufs)
}

// KeygenPart1 → secret, package.
func (e *TssEngine) KeygenPart1(ctx context.Context, id uint32) (secret, pkg []byte, err error) {
	out, err := e.withBufs(ctx, nil, func([]guestBuf) ([]byte, error) {
		return e.call(ctx, "tss_keygen_part1", uint64(id))
	})
	if err != nil {
		return nil, nil, err
	}
	p, err := splitParts(out, 2)
	if err != nil {
		return nil, nil, err
	}
	return p[0], p[1], nil
}

// KeygenPart2 → secret2, package for the other party.
func (e *TssEngine) KeygenPart2(ctx context.Context, id uint32, secret []byte, otherID uint32, otherR1 []byte) (secret2, forOther []byte, err error) {
	out, err := e.withBufs(ctx, [][]byte{secret, otherR1}, func(b []guestBuf) ([]byte, error) {
		return e.call(ctx, "tss_keygen_part2", uint64(id), uint64(b[0].ptr), uint64(b[0].n), uint64(otherID), uint64(b[1].ptr), uint64(b[1].n))
	})
	if err != nil {
		return nil, nil, err
	}
	p, err := splitParts(out, 2)
	if err != nil {
		return nil, nil, err
	}
	return p[0], p[1], nil
}

// KeygenPart3 → key package, public key package, verifying key.
func (e *TssEngine) KeygenPart3(ctx context.Context, secret2 []byte, otherID uint32, otherR1, otherR2 []byte) (keyPackage, pubPackage, verifyingKey []byte, err error) {
	out, err := e.withBufs(ctx, [][]byte{secret2, otherR1, otherR2}, func(b []guestBuf) ([]byte, error) {
		return e.call(ctx, "tss_keygen_part3", uint64(b[0].ptr), uint64(b[0].n), uint64(otherID), uint64(b[1].ptr), uint64(b[1].n), uint64(b[2].ptr), uint64(b[2].n))
	})
	if err != nil {
		return nil, nil, nil, err
	}
	p, err := splitParts(out, 3)
	if err != nil {
		return nil, nil, nil, err
	}
	return p[0], p[1], p[2], nil
}

// SignRound1 → nonces (keep, single use), commitments (send).
func (e *TssEngine) SignRound1(ctx context.Context, keyPackage []byte) (nonces, commitments []byte, err error) {
	out, err := e.withBufs(ctx, [][]byte{keyPackage}, func(b []guestBuf) ([]byte, error) {
		return e.call(ctx, "tss_sign_round1", uint64(b[0].ptr), uint64(b[0].n))
	})
	if err != nil {
		return nil, nil, err
	}
	p, err := splitParts(out, 2)
	if err != nil {
		return nil, nil, err
	}
	return p[0], p[1], nil
}

// SignRound2 → this party's signature share over message.
func (e *TssEngine) SignRound2(ctx context.Context, id uint32, keyPackage, nonces, ownCommitments []byte, otherID uint32, otherCommitments, message []byte) ([]byte, error) {
	return e.withBufs(ctx, [][]byte{keyPackage, nonces, ownCommitments, otherCommitments, message}, func(b []guestBuf) ([]byte, error) {
		return e.call(ctx, "tss_sign_round2",
			uint64(id), uint64(b[0].ptr), uint64(b[0].n),
			uint64(b[1].ptr), uint64(b[1].n),
			uint64(b[2].ptr), uint64(b[2].n),
			uint64(otherID), uint64(b[3].ptr), uint64(b[3].n),
			uint64(b[4].ptr), uint64(b[4].n))
	})
}

// Aggregate both shares into a 64-byte Ed25519 signature (tests; the vault
// aggregates in production).
func (e *TssEngine) Aggregate(ctx context.Context, pubPackage []byte, idA uint32, commitA, shareA []byte, idB uint32, commitB, shareB, message []byte) ([]byte, error) {
	return e.withBufs(ctx, [][]byte{pubPackage, commitA, shareA, commitB, shareB, message}, func(b []guestBuf) ([]byte, error) {
		return e.call(ctx, "tss_aggregate",
			uint64(b[0].ptr), uint64(b[0].n),
			uint64(idA), uint64(b[1].ptr), uint64(b[1].n), uint64(b[2].ptr), uint64(b[2].n),
			uint64(idB), uint64(b[3].ptr), uint64(b[3].n), uint64(b[4].ptr), uint64(b[4].n),
			uint64(b[5].ptr), uint64(b[5].n))
	})
}

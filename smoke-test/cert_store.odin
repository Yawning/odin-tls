package main

import "base:runtime"
import "core:crypto/x509"
import "core:encoding/pem"

@(private, rodata)
MKCERT_ORG_ROOTS := #load("mkcert-20261002.pem")

Trust_Store_Error :: union #shared_nil {
	runtime.Allocator_Error,
	pem.Error,
	x509.Error,
}

Trust_Store :: struct {
	roots: [dynamic]^x509.Certificate,
	ders:  [dynamic]^pem.Block,
}

@(require_results)
load_trust_store :: proc(
	allocator := context.allocator,
) -> (store: Trust_Store, err: Trust_Store_Error) {
	store.roots = make([dynamic]^x509.Certificate, allocator) or_return
	store.ders = make([dynamic]^pem.Block, allocator) or_return

	data := MKCERT_ORG_ROOTS
	for len(data) > 0 {
		blk: ^pem.Block
		blk, data = pem.decode(data, allocator) or_return
		if blk == nil && data == nil {
			break
		}

		cert := new(x509.Certificate, allocator) or_return
		cert^ = x509.parse(pem.block_bytes(blk), allocator) or_return

		append(&store.roots, cert)
		append(&store.ders, blk)
	}

	return store, nil
}

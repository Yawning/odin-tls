#+private
package tls

import "base:intrinsics"
import "base:runtime"
import "core:crypto"
import "core:encoding/endian"
import "core:io"
import "core:net"

// Everyone is doomed to re-implement `mbuf`/`sk_buf` in one form or
// another, and we are no different.

unchecked_get_u24be :: #force_inline proc "contextless" (b: []byte) -> int {
	i: u32

	#no_bounds_check {
		i = u32(b[0]) << 16
		i |= u32(b[1]) << 8
		i |= u32(b[2])
	}

	return int(i)
}

unchecked_put_u24be :: #force_inline proc "contextless" (b: []byte, v: int) {
	#no_bounds_check {
		b[0] = byte(v >> 16)
		b[1] = byte(v >> 8)
		b[2] = byte(v & 0xff)
	}
}

Buffer :: struct {
	b:   []byte,
	off: int,
	idx: int,
}

buffer_init :: proc(buf: ^Buffer, backing: []u8, pre_filled := false) {
	buf.b = backing
	buf.off = pre_filled ? len(backing) : 0
	buf.idx = 0
}

buffer_make :: proc(buf: ^Buffer, n: int, allocator: runtime.Allocator) -> Error {
	buffer_clear(buf)
	buf.b = make([]byte, n) or_return
	return nil
}

buffer_delete :: proc(buf: ^Buffer, allocator: runtime.Allocator) {
	delete(buf.b, allocator)
	buf.b = nil
	buffer_clear(buf)
}

buffer_clear :: proc(buf: ^Buffer) {
	buf.off = 0
	buf.idx = 0
}

buffer_sanitize :: proc(buf: ^Buffer) {
	crypto.zero_explicit(raw_data(buf.b), len(buf.b))
	buffer_clear(buf)
}

@(require_results)
buffer_len :: proc(buf: ^Buffer) -> int {
	return buf.off
}

@(require_results)
buffer_unread_len :: proc(buf: ^Buffer) -> int {
	return buf.off - buf.idx
}

@(require_results)
buffer_available :: proc(buf: ^Buffer) -> int {
	return len(buf.b) - buf.off
}

@(require_results)
buffer_bytes :: proc(buf: ^Buffer) -> []byte {
	return buf.b[:buf.off]
}

@(require_results)
buffer_unread_bytes :: proc(buf: ^Buffer) -> []byte {
	return buf.b[buf.idx:buf.off]
}

@(require_results)
buffer_bytes_at :: proc(buf: ^Buffer, idx: int) -> []byte {
	ensure(idx < buf.off, "tls: out-of-bounds read")
	return buf.b[idx:buf.off]
}

@(require_results)
buffer_trim :: proc(buf: ^Buffer, n: int) -> io.Error {
	if n < 0 || buf.off < n {
		return io.Error.Short_Buffer
	}
	buf.off -= n
	buf.idx = min(buf.off, buf.idx)

	return nil
}

buffer_trim_read :: proc(buf: ^Buffer) {
	if buf.off == buf.idx {
		buffer_clear(buf)
		return
	}

	unread := buffer_unread_bytes(buf)
	buf.off = len(unread)
	buf.idx = 0
	copy(buf.b, unread)
}

@(require_results, private="file")
buffer_check_write :: #force_inline proc(buf: ^Buffer, sz: int) -> io.Error {
	if sz < 0 || len(buf.b) < buf.off + sz {
		return io.Error.Short_Buffer
	}
	return nil
}

@(require_results)
buffer_write_u8 :: proc(buf: ^Buffer, i: u8) -> io.Error {
	buffer_check_write(buf, 1) or_return

	#no_bounds_check buf.b[buf.off] = i
	buf.off += 1

	return nil
}

@(require_results)
buffer_write_u16 :: proc(buf: ^Buffer, i: u16) -> io.Error {
	buffer_check_write(buf, 2) or_return

	endian.unchecked_put_u16be(buf.b[buf.off:], i)
	buf.off += 2

	return nil
}

@(require_results)
buffer_write_u24 :: proc(buf: ^Buffer, i: int) -> io.Error {
	buffer_check_write(buf, 3) or_return
	if i >= 1 << 24 || i < 0 {
		return io.Error.Unknown
	}

	unchecked_put_u24be(buf.b[buf.off:], i)
	buf.off += 3

	return nil
}

@(require_results)
buffer_write_u32 :: proc(buf: ^Buffer, i: u32) -> io.Error {
	buffer_check_write(buf, 4) or_return

	endian.unchecked_put_u32be(buf.b[buf.off:], i)
	buf.off += 4

	return nil
}

@(require_results)
buffer_write_zeroes :: proc(buf: ^Buffer, n: int) -> io.Error {
	buffer_check_write(buf, n) or_return

	intrinsics.mem_zero(raw_data(buf.b[buf.off:]), n)
	buf.off += n

	return nil
}

@(require_results)
buffer_write_bytes :: proc(buf: ^Buffer, b: []byte) -> io.Error {
	n := len(b)
	buffer_check_write(buf, n) or_return

	copy(buf.b[buf.off:], b)
	buf.off += n

	return nil
}

@(require_results)
buffer_write_opaque_bytes :: proc(buf: ^Buffer, b: []byte, $LEN_BYTES: int) -> io.Error {
	n := len(b)
	buffer_check_write(buf, LEN_BYTES + n) or_return

	switch LEN_BYTES {
	case 1:
		if n > int(max(u8)) {
			return io.Error.Buffer_Full
		}
		buffer_write_u8(buf, u8(n)) or_return
	case 2:
		if n > int(max(u16)) {
			return io.Error.Buffer_Full
		}
		buffer_write_u16(buf, u16(n)) or_return
	case:
		// No individual field exceeds 2^16 bytes.
		return io.Error.Unsupported
	}

	copy(buf.b[buf.off:], b)
	buf.off += n

	return nil
}

@(require_results)
buffer_write_opaque_u16s :: proc(buf: ^Buffer, d: []u16, $LEN_BYTES: int) -> io.Error {
	n := len(d) * 2
	buffer_check_write(buf, LEN_BYTES + n) or_return

	switch LEN_BYTES {
	case 1:
		if n > int(max(u8)) {
			return io.Error.Buffer_Full
		}
		buffer_write_u8(buf, u8(n)) or_return
	case 2:
		if n > int(max(u16)) {
			return io.Error.Buffer_Full
		}
		buffer_write_u16(buf, u16(n)) or_return
	case:
		// No individual field exceeds 2^16 bytes.
		return io.Error.Unsupported
	}

	for v in d {
		endian.unchecked_put_u16be(buf.b[buf.off:], v)
		buf.off += 2
	}

	return nil
}

@(require_results)
buffer_write_recv :: proc(buf: ^Buffer, sock: net.TCP_Socket, n: int) -> (err: Error) {
	if n == 0 {
		return
	}
	buffer_check_write(buf, n) or_return

	for i := 0; i < n; {
		i += net.recv_tcp(sock, buf.b[buf.off+i:buf.off+n]) or_return
	}
	buf.off += n

	return
}

@(require_results)
buffer_pullup :: proc(buf, src: ^Buffer) -> Error {
	return buffer_write_bytes(buf, buffer_unread_bytes(src))
}

@(require_results)
buffer_send :: proc(buf: ^Buffer, sock: net.TCP_Socket) -> (err: Error) {
	b := buffer_bytes(buf)
	n := len(b)

	if n == 0 {
		return nil
	}

	for i := 0; i < n; {
		i += net.send_tcp(sock, b[i:]) or_return
	}
	return
}

@(require_results, private="file")
buffer_check_read :: #force_inline proc(buf: ^Buffer, sz: int) -> io.Error {
	if sz < 0 || buf.idx + sz > buf.off {
		return io.Error.Unexpected_EOF
	}
	return nil
}

@(require_results)
buffer_read_u8 :: proc(buf: ^Buffer) -> (v: u8, err: io.Error) {
	buffer_check_read(buf, 1) or_return

	v = buf.b[buf.idx]
	buf.idx += 1

	return
}

@(require_results)
buffer_read_u16 :: proc(buf: ^Buffer) -> (v: u16, err: io.Error) {
	buffer_check_read(buf, 2) or_return

	v = endian.unchecked_get_u16be(buf.b[buf.idx:])
	buf.idx += 2

	return
}

@(require_results)
buffer_read_u24 :: proc(buf: ^Buffer) -> (v: int, err: io.Error) {
	buffer_check_read(buf, 3) or_return

	v = unchecked_get_u24be(buf.b[buf.idx:])
	buf.idx += 3

	return
}

@(require_results)
buffer_read_bytes :: proc(buf: ^Buffer, dst: []byte) -> (err: io.Error) {
	l := len(dst)
	buffer_check_read(buf, l) or_return

	copy(dst, buf.b[buf.idx:])
	buf.idx += l

	return
}

@(require_results)
buffer_read_skip :: proc(buf: ^Buffer, n: int) -> (dst: []byte, err: io.Error) {
	buffer_check_read(buf, n) or_return

	dst = buf.b[buf.idx:buf.idx+n]
	buf.idx += n

	return
}

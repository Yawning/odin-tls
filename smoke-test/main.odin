package main

import "core:log"
import "core:net"
import "core:os"

import tls "../"

// TARGET_HOST_PORT     :: "127.0.0.1:8080"
// HTTP_REQUEST : string : "GET /index.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
// SNI_HOST             :: "localhost"
// INSECURE_SKIP_VERIFY :: true

TARGET_HOST_PORT     :: "odin-lang.org:443"
HTTP_REQUEST : string : "GET / HTTP/1.1\r\nHost: odin-lang.org\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n"
SNI_HOST             :: "odin-lang.org"
INSECURE_SKIP_VERIFY :: false

main :: proc() {
	context.logger = log.create_console_logger()

	trust_store, store_err := load_trust_store()
	if store_err != nil {
		log.errorf("Failed to load trust store: %v", store_err)
		return
	}

	tls_secrets, fd_err := os.create("tls-secrets.txt")
	if fd_err != nil {
		log.errorf("Failed to create tls-secrets.txt: %v", fd_err)
		return
	}
	defer os.close(tls_secrets)

	log.infof("Connecting to %s", TARGET_HOST_PORT)
	tcp_sock, tcp_err := net.dial_tcp(TARGET_HOST_PORT)
	if tcp_err != nil {
		log.errorf("Failed to connect to %s: %v", TARGET_HOST_PORT, tcp_err)
		return
	}
	defer net.close(tcp_sock)

	log.infof("Connected!")

	tls_sock: tls.Socket
	if err := tls.client_handshake(
		&tls_sock,
		tcp_sock,
		SNI_HOST,
		trust_store.roots[:],
		[]tls.Alpn_Protocols{.Http_1_1},
		INSECURE_SKIP_VERIFY,
		tls_secrets,
	); err != nil {
		log.errorf("TLS: Failed to handshake: %v", err)
		return
	}

	log.infof("TLS: Handshaked! (ALPN: %v)", tls_sock.alpn_protocol)

	if _, err := tls.send(
		&tls_sock,
		transmute([]byte)(HTTP_REQUEST),
	); err != nil {
		log.errorf("TLS: Failed to write request: %v", err)
	}

	log.infof("TLS: Request sent!")

	for {
		buf: [1024]byte
		n, err := tls.recv(&tls_sock, buf[:])
		if err != nil {
			log.errorf("TLS: Failed to receive: %v", err)
			break
		}

		log.infof("TLS: Response: `%s`\n", buf[:n])
	}

	tls.close(&tls_sock)
	log.infof("TLS: Closed: %v\n", tls.socket_error(&tls_sock))
}

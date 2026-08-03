package tls

SNI_MAX_HOSTNAME_SIZE :: 253

Cipher_Suite :: enum u16 {
	// TLS 1.3
	TLS_AES_128_GCM_SHA256       = 0x1301,
	TLS_AES_256_GCM_SHA384       = 0x1302,
	TLS_CHACHA20_POLY1305_SHA256 = 0x1303,

	// TLS_AES_128_CCM_SHA256   {0x13,0x04}
	// TLS_AES_128_CCM_8_SHA256 {0x13, 0x05}
}

Signature_Scheme :: enum u16 {
	// RSASSA-PKCS1-v1_5 algorithms
	Rsa_Pkcs1_Sha256 = 0x0401,
	Rsa_Pkcs1_Sha384 = 0x0501,
	Rsa_Pkcs1_Sha512 = 0x0601,

	// ECDSA algorithms
	Ecdsa_Secp256r1_Sha256 = 0x0403,
	Ecdsa_Secp384r1_Sha384 = 0x0503,
	// Ecdsa_Secp521r1_Sha512 = 0x0603,

	// RSASSA-PSS algorithms with public key OID rsaEncryption
	Rsa_Pss_Rsae_Sha256 = 0x0804,
	Rsa_Pss_Rsae_Sha384 = 0x0805,
	Rsa_Pss_Rsae_Sha512 = 0x0806,

	// EdDSA algorithms (Not allowed by CAB forum)
	Ed25519 = 0x0807,
	// Ed448   = 0x0808,

	// RSASSA-PSS algorithms with public key OID RSASSA-PSS
	Rsa_Pss_Pss_Sha256 = 0x0809,
	Rsa_Pss_Pss_Sha384 = 0x080A,
	Rsa_Pss_Pss_Sha512 = 0x080B,

	// Legacy algorithms (Prohibited in CertificateVerify)
	Rsa_Pkcs1_Sha1 = 0x0201,
	Ecdsa_Sha1     = 0x0203,

	// Reserved Code Points
	// obsolete_RESERVED(0x0000..0x0200),
	// dsa_sha1_RESERVED(0x0202),
	// obsolete_RESERVED(0x0204..0x0400),
	// dsa_sha256_RESERVED(0x0402),
	// obsolete_RESERVED(0x0404..0x0500),
	// dsa_sha384_RESERVED(0x0502),
	// obsolete_RESERVED(0x0504..0x0600),
	// dsa_sha512_RESERVED(0x0602),
	// obsolete_RESERVED(0x0604..0x06FF),
	// private_use(0xFE00..0xFFFF),
}

Named_Group :: enum u16 {
	Unallocated_RESERVED = 0x0000,

	// Elliptic Curve Groups (ECDHE)
	// obsolete_RESERVED(0x0001..0x0016),
	Secp256r1 = 0x0017,
	Secp384r1 = 0x0018,
	// secp521r1(0x0019),
	// obsolete_RESERVED(0x001A..0x001C),
	X25519 = 0x001D,
	X448   = 0x001E,

	// Finite Field Groups (DHE)
	// ffdhe2048(0x0100),
	// ffdhe3072(0x0101),
	// ffdhe4096(0x0102),
	// ffdhe6144(0x0103),
	// ffdhe8192(0x0104),

	// PQ/T Hybrid Key Agreement (RFC 10024)
	X25519MLKEM768     = 0x11EC,
	// SecP256r1MLKEM768(0x11EB),
	// SecP384r1MLKEM1024(0x11ED),

	// Reserved Code Points
	// ffdhe_private_use(0x01FC..0x01FF),
	// ecdhe_private_use(0xFE00..0xFEFF),
	// obsolete_RESERVED(0xFF01..0xFF02),
}

// ALPN protocols (subset)
//
// See: https://www.iana.org/assignments/tls-extensiontype-values
Alpn_Protocols :: enum {
	None,                // Invalid
	Http_0_9,            // "http/0.9"
	Http_1_0,            // "http/1.0"
	Http_1_1,            // "http/1.1"
	Spdy_1,              // "spdy/1"
	Spdy_2,              // "spdy/2"
	Spdy_3,              // "spdy/3"
	Turn,                // "stun.turn"
	Stun,                // "stun.nat-discovery"
	Http_2,              // "h2"
	// Http_2_Tcp,       // "h2c" (Not valid for TLS ALPN)
	Webrtc,              // "webrtc"
	Confidential_Webrtc, // "c-webrtc"
	Ftp,                 // "ftp"
	Imap,                // "imap"
	Pop3,                // "pop3"
	Managesieve,         // "managesieve"
	Coap_Tls,            // "coap"
	Coap_Dtls,           // "co"
	Xmpp_Client,         // "xmpp-client"
	Xmpp_Server,         // "xmpp-server"
	Acme_Tls_1,          // "acme-tls/1"
	Mqtt,                // "mqtt"
	Dot,                 // "dot" (DNS-over-TLS)
	Ntske_1,             // "ntske/1"
	Sunrpc,              // "sunrpc"
	Http_3,              // "h3"
	Smb2,                // "smb"
	Irc,                 // "irc"
	Nntp_Reading,        // "nntp"
	Nntp_Transit,        // "nnsp"
	Doq,                 // "doq"
	Sip,                 // "sip/2"
	Tds_8_0,             // "tds/8.0"
	Dicom,               // "dicom"
	Postgresql,          // "postgresql"
	Radius_1_0,          // "radius/1.0"
	Radius_1_1,          // "radius/1.1"
	Npmp_Control,        // "netperfmeter/control"
	Npmp_Data,           // "netperfmeter/data"
	N_Pamp,              // "n-pamp/2"
	Eoq,                 // "EoQ"
	Snif_Over_Quic,      // "snifq/1"
}

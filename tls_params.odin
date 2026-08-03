#+private
package tls

@(rodata)
SIGNATURE_SCHEMES := []Signature_Scheme{
	.Ed25519,
	.Ecdsa_Secp256r1_Sha256,
	.Ecdsa_Secp384r1_Sha384,

	.Rsa_Pss_Rsae_Sha256,
	.Rsa_Pss_Pss_Sha256,
	.Rsa_Pss_Rsae_Sha256,
	.Rsa_Pkcs1_Sha256,

	.Rsa_Pss_Pss_Sha384,
	.Rsa_Pss_Rsae_Sha384,
	.Rsa_Pkcs1_Sha384,

	.Rsa_Pss_Pss_Sha512,
	.Rsa_Pss_Rsae_Sha512,
	.Rsa_Pkcs1_Sha512,
}

@(rodata)
SUPPORTED_GROUPS := []Named_Group {
	.X25519MLKEM768,
	.X448,
	.Secp384r1,
	.X25519,
	.Secp256r1,
}

@(rodata)
CIPHER_SUITES_HW_AES := []Cipher_Suite {
	.TLS_AES_256_GCM_SHA384,
	.TLS_CHACHA20_POLY1305_SHA256,
	.TLS_AES_128_GCM_SHA256,
}

@(rodata)
CIPHER_SUITES := []Cipher_Suite {
	.TLS_CHACHA20_POLY1305_SHA256,
	.TLS_AES_256_GCM_SHA384,
	.TLS_AES_128_GCM_SHA256,
}

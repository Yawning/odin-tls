## odin-tls
### A cozy TLS 1.3-like with metroidvania, deck-building, survival/crafting elements, and 2 person co-op play.

> At long last, we have created the Torment Nexus, from classic sci-fi novel
> Don't Create The Torment Nexus

This package implements [TLS 1.3][1] in the [Odin][2] programing language
without any external dependencies.

**WARNING**

This is the initial "It appears to work against hosts I tested it against",
rough draft of what I hope will eventually become `core:crypto/tls`.
More refinement/testing/review is needed, and I will rebase mercilessly.

### Features

- A blocking TLS 1.3 client, with ALPN
- Support for [PQ/T][3] hybrid key agreement
- Support for [SSLKEYLOG][4]

### TODO (In no particular order)

- `io.Stream` wrapper
- Re-key before hitting AEAD limits
- Handle fragmented ServerHello
- `cookie` extension/HelloRetryRequest
- PSK key exchange
- 0-RTT handshakes
- Early Data
- Client certificate authentication
- [Encrypted ClientHello][5] (ECH)
- [GREASE][6]
- [ML-KEM only key agreement][7] (Draft)
- [AEGIS Cipher Suites][8] (Draft)
- TLS 1.2 (sensible subset only)
- Server support (Just use ngnix)

### WONTDO

- AES_CCM Cipher Suite support
- ffdhe key agreement
- secp521r1 support (ECDH/ECDSA, 0 browser support)
- Ed448 support

[1]: https://www.rfc-editor.org/rfc/rfc9846.html
[2]: https;//www.odin-lang.org
[3]: https://www.rfc-editor.org/rfc/rfc10024.html
[4]: https://www.rfc-editor.org/rfc/rfc9850.html
[5]: https://www.rfc-editor.org/rfc/rfc9849.html
[6]: https://www.rfc-editor.org/rfc/rfc8701.html
[7]: https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/
[8]: https://datatracker.ietf.org/doc/draft-denis-tls-aegis/

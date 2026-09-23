# qTLS

Experimental TLS 1.3 implementation with a pluggable byte-transport layer.

## Development target

qTLS is being built in three stages:

1. **TLS 1.3 implementation** — interoperate with existing TLS 1.3 peers.
2. **Post-quantum hybrid key exchange** — add X25519 + ML-KEM-768.
3. **Compatibility layer** — expose an API compatible with common TLS APIs so existing internal services can migrate with minimal changes.

The transport layer is deliberately separate from TLS. A transport only needs to provide a reliable, ordered byte stream, allowing TCP and custom packet transports to share the same TLS engine.

## Current status

This repository currently contains the protocol/crypto/record foundation. It is **not yet a secure replacement for TLS**.

Do not use it for production or sensitive traffic until the handshake, authentication, interoperability, negative testing, fuzzing, and security review are complete.

## Install

```bash
python3 -m pip install -e .
```

Run tests:

```bash
python3 -m pytest
```

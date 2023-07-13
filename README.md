[![Go Report Card][go-report-image]][go-report-url]
[![Go Reference](https://pkg.go.dev/badge/github.com/saga420/temporal-encryption-converter.svg)](https://pkg.go.dev/github.com/saga420/temporal-encryption-converter)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Codecov](https://codecov.io/gh/saga420/temporal-encryption-converter/branch/main/graph/badge.svg)](https://codecov.io/gh/saga420/temporal-encryption-converter)

[go-report-image]: https://goreportcard.com/badge/github.com/saga420/temporal-encryption-converter
[go-report-url]: https://goreportcard.com/report/github.com/saga420/temporal-encryption-converter

[go-report-image]: https://goreportcard.com/badge/github.com/saga420/temporal-encryption-converter
[go-report-url]: https://goreportcard.com/report/github.com/saga420/temporal-encryption-converter


# Temporal Encryption Converter

The Temporal Encryption Converter is a Go package designed to deliver encryption and decryption solutions for payloads
within the Temporal workflow engine. The package incorporates a unique context propagator, enabling the transmission of
context values across multiple workflows.

## Installation

Install the package with the go get command:

```bash
go get github.com/saga420/temporal-encryption-converter
```

## Usage

> SEE example/*.go for more examples

```go
// Generate a key pair for the client
client, _ := encryption.GenerateKeyPair()
fmt.Println("Client's Private Key: ", client.PrivateKey)
fmt.Println("Client's Public Key: ", client.PublicKey)

// Generate a key pair for the worker
worker, _ := encryption.GenerateKeyPair()
fmt.Println("Worker's Private Key: ", worker.PrivateKey)
fmt.Println("Worker's Public Key: ", worker.PublicKey)
```

The X25519 algorithm is used for key exchange. Before initiating a workflow, the client must possess knowledge of the
worker's public key, which is essential for encrypting data intended solely for that worker to decrypt and process.

Intriguingly, it's not required for the worker to preconfigure the client's public key. This key is conveyed within the
context metadata of the workflow, allowing any client (each potentially with different key pairs) to transmit encrypted
data to the worker using the worker's public key. The worker can subsequently receive and process workflow messages from
any client, promoting a flexible and secure communication system.

Note: Error handling is critical in production code. While errors are omitted for brevity in these examples, in a
production environment, it's crucial to always check and handle errors effectively.

## Features

- Empowers payload encryption and decryption in Temporal workflows.
- Implements AES256_GCM_PBKDF2_Curve25519 and XChaCha20_Poly1305_PBKDF2_Curve25519 encryption algorithms.
- Supports ZLib compression pre-encryption for payload size optimization.
- Facilitates passing of context values across diverse workflows.

## Contributing

We warmly welcome contributions. Kindly fork the repository and submit a pull request with your amendments.

## License

This package is distributed under the terms of the MIT License.

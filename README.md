# Temporal Encryption Converter

Temporal Encryption Converter is a Go package that provides encryption and decryption for payloads within the Temporal
workflow engine. The package also implements a custom context propagator, which allows passing of context values across
different workflows.

## Installation

Use go get to download and install the package.

```bash
go get github.com/saga420/temporal-encryption-converter
```

## Usage

```go
package main

import (
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/workflow"
	"go.uber.org/zap"
	temporal_encryption_converter "temporal-encryption-converter"
	"time"
)

type TemporalOptions struct {
	Namespace             string
	HostPort              string
	WorkflowIdleTimeout   time.Duration
	TaskQueue             string
	X25519PublicKey       string
	X25519PrivateKey      string
	X25519SharedPublicKey string
}

// NewTemporalClient creates a new Temporal client
// zap.NewNop() is used for the logger because the logger is already configured in the application
// and we don't want to configure it again here
// The logger is used by the Temporal encryption converter
// The Temporal encryption converter is used to encrypt the payloads of the Temporal workflows
func NewTemporalClient(opts TemporalOptions) (client.Client, error) {
	clientOptions := client.Options{
		DataConverter: temporal_encryption_converter.NewEncryptionDataConverter(
			converter.GetDefaultDataConverter(),
			temporal_encryption_converter.DataConverterOptions{
				Compress: true,
				// The WorkerPublicKeyForClient is used to encrypt the payloads of the Temporal workflows
				SharedPublicKey: opts.X25519SharedPublicKey,
				// The KeyPair is used to encrypt the payloads of the Temporal workflows
				KeyPair: temporal_encryption_converter.KeyPair{
					PrivateKey:               opts.X25519PrivateKey,
					PublicKey:                opts.X25519PublicKey,
					WorkerPublicKeyForClient: opts.X25519SharedPublicKey,
				},
			},
			zap.NewNop(),
		),
		ContextPropagators: []workflow.ContextPropagator{
			temporal_encryption_converter.NewContextPropagator(zap.NewNop()),
		},
	}
	c, err := client.NewClientServiceWithOptions(opts.HostPort, opts.Namespace, clientOptions)
	if err != nil {
		return nil, err
	}
	return c, nil
}

```

The package also allows you to pass context values across different workflows using a custom context propagator. For
instance, this might be useful for passing encryption keys or other relevant context.

## Features

- Provides support for payload encryption and decryption in Temporal workflows.
- Uses AES256_GCM_PBKDF2_Curve25519 and XChaCha20_Poly1305_PBKDF2_Curve25519 encryption algorithms.
- Allows for ZLib compression before encryption for payload size reduction.
- Enables passing of context values across different workflows.

## Contributing

Contributions are welcome. Please fork the repository and create a pull request with your changes.

## License

This package is available under the MIT License.

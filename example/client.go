package example

import (
	"context"
	temporal_encryption_converter "github.com/saga420/temporal-encryption-converter"
	"github.com/saga420/temporal-encryption-converter/encryption"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/workflow"
	"go.uber.org/zap"
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
			temporal_encryption_converter.NewContextPropagator(
				zap.NewNop(),
			),
		},
		HostPort:  opts.HostPort,
		Namespace: opts.Namespace,
	}

	c, err := client.NewLazyClient(clientOptions)
	if err != nil {
		return nil, err
	}

	return c, nil
}

// StartWorkflow starts a new Temporal workflow
// The salt is passed to the Temporal encryption converter
// The Temporal encryption converter is used to encrypt the payloads of the Temporal workflows
func StartWorkflow(ctx context.Context, cli client.Client, workflowType string, workflowID string, workflowArgs ...interface{}) (client.WorkflowRun, error) {
	options := client.StartWorkflowOptions{
		ID:        workflowID,
		TaskQueue: "example",
	}

	salt, err := encryption.GenerateSalt()
	if err != nil {
		salt = workflowID
	}

	cryptContext := temporal_encryption_converter.CryptContext{
		SharedPublicKey: "the shared public key",
		Iterations:      "1000",
		// The AlgoMethod is used to encrypt the payloads of the Temporal workflows
		AlgoMethod: encryption.XChaCha20_Poly1305_PBKDF2_Curve25519,
		Salt:       salt,
	}

	ctx = context.WithValue(ctx, temporal_encryption_converter.PropagateKey, cryptContext)

	workflowRun, err := cli.ExecuteWorkflow(ctx, options, workflowType, workflowArgs...)
	if err != nil {
		return nil, err
	}

	return workflowRun, nil
}

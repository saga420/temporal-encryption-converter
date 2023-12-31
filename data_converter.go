package temporal_encryption_converter

import (
	"context"
	"fmt"
	"github.com/saga420/temporal-encryption-converter/encryption"
	"go.temporal.io/sdk/workflow"
	"go.uber.org/zap"

	commonpb "go.temporal.io/api/common/v1"

	"go.temporal.io/sdk/converter"
)

// KeyPair is used to encrypt/decrypt the shared public key.
// All fields here are (X25519 keypair hex encoded as string)
type KeyPair struct {
	PrivateKey               string
	PublicKey                string
	WorkerPublicKeyForClient string
}

/*************************************************************
* Payload format for encrypted data. All fields are required.
* For fields in metadata see below:
*************************************************************
# TODO: Add support for multiple encryption methods.
# TODO: Add versioning to metadata. (e.g. "version": "1.0.0")
*************************************************************
{
	  "metadata": {
		"enc-algo-method": "",
		"enc-iterations": "",
		"enc-salt": "",
		"enc-shared-public-key": "",
		"encoding": ""
	  },
	  "data": "ENCRYPTED DATA in BASE64 ENCODED STRING"
}
*************************************************************/

const (
	// MetadataEncodingEncrypted is "binary/encrypted"
	MetadataEncodingEncrypted = "binary/encrypted"

	// MetadataEncryptionSharedPublicKey is "encryption-shared-public-key"
	// This is the 25519 public keypair from client (starter) used to encrypt the shared public key.
	MetadataEncryptionSharedPublicKey = "enc-shared-public-key"

	// MetadataEncryptionSalt is "encryption-salt"
	// This is the salt used to derive the encryption key. (hex encoded as string)
	// It is generated randomly for each workflow. (by client, worker use it directly)
	MetadataEncryptionSalt = "enc-salt"

	// MetadataEncryptionAlgoMethod is "encryption-algo-method"
	// This is the encryption algorithm used to encrypt the data.
	// SEE encryption.AlgoMethod for supported algorithms.
	MetadataEncryptionAlgoMethod = "enc-algo-method"

	// MetadataEncryptionIterations is "encryption-iterations"
	// This is the number of iterations used to derive the encryption key by pbkdf2.
	// We limited here that iterations must be between 8000000 and 4096.
	// We know that iterations higher is more secure, but it will take more time to encrypt/decrypt.
	// Since this is a workflow we need to be careful about the time it takes to encrypt/decrypt.
	// We don't want to have a workflow that takes too long to encrypt/decrypt.
	// That's also why we don't use Argon2id.
	MetadataEncryptionIterations = "enc-iterations"
)

// DataConverter is a wrapper around a DataConverter that encrypts/decrypts payloads.
type DataConverter struct {
	// Until EncodingDataConverter supports workflow.ContextAware we'll store parent here.
	parent converter.DataConverter
	converter.DataConverter
	options DataConverterOptions
	logger  *zap.Logger
}

// DataConverterOptions are options used to create a DataConverter.
type DataConverterOptions struct {
	SharedPublicKey string
	Salt            string
	AlgoMethod      encryption.AlgoMethod
	Iterations      string
	KeyPair         KeyPair
	// Enable ZLib compression before encryption.
	// We recommend to enable compression only if you know that your data will compress well.
	Compress bool
}

// Codec implements PayloadCodec using the encryption.AlgoMethod provided.
// It is used to encrypt/decrypt payloads.
// KeyPair is used to encrypt/decrypt the shared public key. (X25519 keypair hex encoded as string)
type Codec struct {
	SharedPublicKey string
	AlgoMethod      encryption.AlgoMethod
	Salt            string
	Iterations      string
	KeyPair         KeyPair
}

// Ensure DataConverter implements workflow.ContextAware
var _ workflow.ContextAware = (*DataConverter)(nil)

// WithContext propagates the context through the DataConverter
func (dc *DataConverter) WithContext(ctx context.Context) converter.DataConverter {
	if val, ok := ctx.Value(PropagateKey).(CryptContext); ok {
		parent := dc.parent
		if parentWithContext, ok := parent.(workflow.ContextAware); ok {
			parent = parentWithContext.WithContext(ctx)
		}

		options := dc.options
		options.SharedPublicKey = val.SharedPublicKey
		options.Salt = val.Salt
		options.Iterations = val.Iterations
		options.AlgoMethod = val.AlgoMethod

		return NewEncryptionDataConverter(parent, options, dc.logger)
	} else {
		// This should never happen
		dc.logger.Debug("failed", zap.Any("val", val), zap.Bool("ok", ok))
	}

	return dc
}

// WithWorkflowContext propagates the context through the DataConverter
func (dc *DataConverter) WithWorkflowContext(ctx workflow.Context) converter.DataConverter {
	if val, ok := ctx.Value(PropagateKey).(CryptContext); ok {
		parent := dc.parent
		if parentWithContext, ok := parent.(workflow.ContextAware); ok {
			parent = parentWithContext.WithWorkflowContext(ctx)
		}

		options := dc.options
		options.AlgoMethod = val.AlgoMethod
		options.SharedPublicKey = val.SharedPublicKey
		options.Iterations = val.Iterations
		options.Salt = val.Salt

		return NewEncryptionDataConverter(parent, options, dc.logger)
	} else {
		dc.logger.Debug("failed", zap.Any("val", val), zap.Bool("ok", ok))
	}

	return dc
}

// NewEncryptionDataConverter creates a new instance of EncryptionDataConverter wrapping a DataConverter
func NewEncryptionDataConverter(dataConverter converter.DataConverter, options DataConverterOptions, logger *zap.Logger) *DataConverter {
	codecs := []converter.PayloadCodec{
		&Codec{SharedPublicKey: options.SharedPublicKey, Salt: options.Salt, Iterations: options.Iterations, KeyPair: options.KeyPair, AlgoMethod: options.AlgoMethod},
	}
	// Enable compression if requested.
	// Note that this must be done before encryption to provide any value. Encrypted data should by design not compress very well.
	// This means the compression codec must come after the encryption codec here as codecs are applied last -> first.
	if options.Compress {
		codecs = append(codecs, converter.NewZlibCodec(converter.ZlibCodecOptions{AlwaysEncode: true}))
	}

	return &DataConverter{
		logger:        logger,
		parent:        dataConverter,
		DataConverter: converter.NewCodecDataConverter(dataConverter, codecs...),
		options:       options,
	}
}

// Encode implements converter.PayloadCodec.Encode.
func (e *Codec) Encode(payloads []*commonpb.Payload) ([]*commonpb.Payload, error) {
	result := make([]*commonpb.Payload, len(payloads))
	for i, p := range payloads {
		origBytes, err := p.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal payload: %w", err)
		}

		// Encrypt the payload.
		spec := encryption.CipherKeySpecs{
			Salt:            e.Salt,
			Iterations:      e.Iterations,
			SharedPublicKey: e.SharedPublicKey,
			PrivateKey:      e.KeyPair.PrivateKey,
			Algo:            e.AlgoMethod,
		}
		var b []byte
		switch e.AlgoMethod {
		case encryption.AES256_GCM_PBKDF2_Curve25519:
			b, err = encryption.AesGcmEncrypt(origBytes, spec)
		case encryption.XChaCha20_Poly1305_PBKDF2_Curve25519:
			b, err = encryption.ChaChaEncrypt(origBytes, spec)
		default:
			// This should never happen as the algo method is validated when the codec is created.
			return nil, fmt.Errorf("unknown algo method: %s", e.AlgoMethod)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to encrypt payload: %w", err)
		}

		// Set the metadata.
		result[i] = &commonpb.Payload{
			// TODO: Add a version field to the metadata so we can support multiple encryption methods.
			Metadata: map[string][]byte{
				converter.MetadataEncoding:        []byte(MetadataEncodingEncrypted),
				MetadataEncryptionSharedPublicKey: []byte(e.KeyPair.PublicKey),
				MetadataEncryptionSalt:            []byte(e.Salt),
				MetadataEncryptionAlgoMethod:      []byte(e.AlgoMethod),
				MetadataEncryptionIterations:      []byte(e.Iterations),
			},
			Data: b,
		}
	}

	return result, nil
}

// Decode implements converter.PayloadCodec.Decode.
func (e *Codec) Decode(payloads []*commonpb.Payload) ([]*commonpb.Payload, error) {
	result := make([]*commonpb.Payload, len(payloads))
	for i, p := range payloads {
		// If the payload is not encrypted, just return it.
		if string(p.Metadata[converter.MetadataEncoding]) != MetadataEncodingEncrypted {
			result[i] = p
			continue
		}

		// Extract the encryption specs from the payload.
		spec, err := extractKeySpecsFromPayload(p)
		if err != nil {
			return nil, err
		}

		spec.PrivateKey = e.KeyPair.PrivateKey

		var b []byte
		switch spec.Algo {
		case encryption.AES256_GCM_PBKDF2_Curve25519:
			b, err = encryption.AesGcmDecrypt(p.Data, spec)
		case encryption.XChaCha20_Poly1305_PBKDF2_Curve25519:
			b, err = encryption.ChaChaDecrypt(p.Data, spec)
		default:
			return nil, fmt.Errorf("unknown algo method: %s", spec.Algo)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to decrypt payload: %w", err)
		}

		result[i] = &commonpb.Payload{}
		err = result[i].Unmarshal(b)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal decrypted payload: %w", err)
		}

	}

	return result, nil
}

// extractKeySpecsFromPayload extracts the encryption key specs from the payload metadata.
func extractKeySpecsFromPayload(p *commonpb.Payload) (encryption.CipherKeySpecs, error) {
	// Extract the encryption specs from the payload.
	SharedPublicKey, ok := p.Metadata[MetadataEncryptionSharedPublicKey]
	if !ok {
		return encryption.CipherKeySpecs{}, fmt.Errorf("no encryption key id")
	}
	iterations, ok := p.Metadata[MetadataEncryptionIterations]
	if !ok {
		return encryption.CipherKeySpecs{}, fmt.Errorf("no encryption iterations")
	}
	salt, ok := p.Metadata[MetadataEncryptionSalt]
	if !ok {
		return encryption.CipherKeySpecs{}, fmt.Errorf("no encryption salt")
	}
	algo, ok := p.Metadata[MetadataEncryptionAlgoMethod]
	if !ok {
		return encryption.CipherKeySpecs{}, fmt.Errorf("no encryption algo")
	}

	// CipherKeySpecs.PrivateKey is not set here as it is set by the codec.
	return encryption.CipherKeySpecs{
		Salt:            string(salt),
		Iterations:      string(iterations),
		SharedPublicKey: string(SharedPublicKey),
		PrivateKey:      "",
		Algo:            encryption.AlgoMethod(algo),
	}, nil
}

package temporal_encryption_converter

import (
	"bytes"
	"context"
	"fmt"
	"github.com/go-faker/faker/v4"
	commonpb "go.temporal.io/api/common/v1"
	"go.uber.org/zap"
	"testing"

	"github.com/saga420/temporal-encryption-converter/encryption"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.temporal.io/sdk/converter"
)

// Helper function to generate context
func generateContext(algoMethod encryption.AlgoMethod, workerPublicKey string) context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, PropagateKey, CryptContext{
		AlgoMethod:      algoMethod,
		Iterations:      "2000",
		SharedPublicKey: workerPublicKey,
		Salt:            faker.Password(),
	})

	return ctx
}

// TestNewEncryptionDataConverter tests that NewEncryptionDataConverter returns a DataConverter
func TestNewEncryptionDataConverter(t *testing.T) {
	parent := converter.GetDefaultDataConverter()
	options := DataConverterOptions{
		SharedPublicKey: "testSharedPublicKey",
		Salt:            "testSalt",
		AlgoMethod:      encryption.AES256_GCM_PBKDF2_Curve25519,
		Iterations:      "testIterations",
		KeyPair: KeyPair{
			PrivateKey:               "testPrivateKey",
			PublicKey:                "testPublicKey",
			WorkerPublicKeyForClient: "testWorkerPublicKeyForClient",
		},
		Compress: false,
	}
	logger := zap.NewExample()

	dc := NewEncryptionDataConverter(parent, options, logger)

	if dc == nil {
		t.Error("NewEncryptionDataConverter returned nil")
	}
}

func clonePayload(p *commonpb.Payload) *commonpb.Payload {
	newPayload := &commonpb.Payload{
		Metadata: make(map[string][]byte),
		Data:     append([]byte(nil), p.Data...), // deep copy Data
	}

	for k, v := range p.Metadata {
		newPayload.Metadata[k] = append([]byte(nil), v...) // deep copy Metadata
	}

	return newPayload
}

// TestEncodeAndDecodeWithContext tests that Encode and Decode work with context
func TestExtractKeySpecsFromPayload(t *testing.T) {
	payloadTemplate := commonpb.Payload{
		Metadata: map[string][]byte{
			MetadataEncryptionSharedPublicKey: []byte("testSharedPublicKey"),
			MetadataEncryptionSalt:            []byte("testSalt"),
			MetadataEncryptionAlgoMethod:      []byte(encryption.AES256_GCM_PBKDF2_Curve25519),
			MetadataEncryptionIterations:      []byte("10000"),
		},
		Data: []byte("testData"),
	}

	testCases := []struct {
		name   string
		modify func(*commonpb.Payload)
		err    error
	}{
		{
			name: "Missing SharedPublicKey",
			modify: func(p *commonpb.Payload) {
				delete(p.Metadata, MetadataEncryptionSharedPublicKey)
			},
			err: fmt.Errorf("no encryption key id"),
		},
		{
			name: "Missing Salt",
			modify: func(p *commonpb.Payload) {
				delete(p.Metadata, MetadataEncryptionSalt)
			},
			err: fmt.Errorf("no encryption salt"),
		},
		{
			name: "Missing AlgoMethod",
			modify: func(p *commonpb.Payload) {
				delete(p.Metadata, MetadataEncryptionAlgoMethod)
			},
			err: fmt.Errorf("no encryption algo"),
		},
		{
			name: "Missing Iterations",
			modify: func(p *commonpb.Payload) {
				delete(p.Metadata, MetadataEncryptionIterations)
			},
			err: fmt.Errorf("no encryption iterations"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			payload := clonePayload(&payloadTemplate)
			tc.modify(payload)

			_, err := extractKeySpecsFromPayload(payload)
			if err == nil || err.Error() != tc.err.Error() {
				t.Errorf("Expected error %v, but got %v", tc.err, err)
			}
		})
	}
}

// Test for basic string encoding and decoding
func TestEncodeDecodeString(t *testing.T) {
	client, _ := encryption.GenerateKeyPair()
	worker, _ := encryption.GenerateKeyPair()

	testString := faker.Sentence() // Generate a random sentence for testing

	algoMethods := []encryption.AlgoMethod{
		encryption.AES256_GCM_PBKDF2_Curve25519,
		encryption.XChaCha20_Poly1305_PBKDF2_Curve25519,
	}

	for _, algoMethod := range algoMethods {
		ctx := generateContext(algoMethod, worker.PublicKey)
		defaultDc := converter.GetDefaultDataConverter()
		cryptDc := NewEncryptionDataConverter(
			converter.GetDefaultDataConverter(),
			DataConverterOptions{
				Compress:   true,
				AlgoMethod: algoMethod,
				KeyPair: KeyPair{
					PrivateKey:               client.PrivateKey,
					PublicKey:                client.PublicKey,
					WorkerPublicKeyForClient: worker.PublicKey,
				},
			},
			zap.NewExample(),
		)

		cryptDcWc := cryptDc.WithContext(ctx)

		// Default Payloads
		defaultPayloads, err := defaultDc.ToPayloads(testString)
		require.NoError(t, err, "Failed to convert to default payloads")

		// Encrypted Payloads
		encryptedPayloads, err := cryptDcWc.ToPayloads(testString)
		require.NoError(t, err, "Failed to convert to encrypted payloads")

		// Extract Key Specs
		_, err = extractKeySpecsFromPayload(encryptedPayloads.Payloads[0])
		require.NoError(t, err, "Failed to extract key specs from payload")

		// Validate encrypted data is different from original
		require.NotEqual(t, defaultPayloads.Payloads[0].GetData(), encryptedPayloads.Payloads[0].GetData(), "Encrypted data is same as original")

		decDc := NewEncryptionDataConverter(
			converter.GetDefaultDataConverter(),
			DataConverterOptions{
				Compress: true,
				KeyPair: KeyPair{
					PrivateKey:               worker.PrivateKey,
					PublicKey:                worker.PublicKey,
					WorkerPublicKeyForClient: client.PublicKey,
				},
			},
			zap.NewExample(),
		)

		// Decrypted Result
		var decresult string
		err = decDc.FromPayloads(encryptedPayloads, &decresult)
		require.NoError(t, err, "Failed to decrypt from payloads")

		// Ensure that the decrypted result is same as the original message
		assert.Equal(t, testString, decresult, "Decrypted result is different from original message")
	}
}

// Test for JSON encoding and decoding
func TestEncodeDecodeJSON(t *testing.T) {
	client, _ := encryption.GenerateKeyPair()
	worker, _ := encryption.GenerateKeyPair()

	// Create a map for testing JSON encoding and decoding
	testMap := map[string]string{
		"key1": faker.Word(),
		"key2": faker.Word(),
		"key3": faker.Word(),
	}

	algoMethods := []encryption.AlgoMethod{
		encryption.XChaCha20_Poly1305_PBKDF2_Curve25519,
		encryption.AES256_GCM_PBKDF2_Curve25519,
	}

	for _, algoMethod := range algoMethods {
		ctx := generateContext(algoMethod, worker.PublicKey)
		defaultDc := converter.GetDefaultDataConverter()
		cryptDc := NewEncryptionDataConverter(
			converter.GetDefaultDataConverter(),
			DataConverterOptions{
				Compress: true,
				KeyPair: KeyPair{
					PrivateKey:               client.PrivateKey,
					PublicKey:                client.PublicKey,
					WorkerPublicKeyForClient: worker.PublicKey,
				},
			},
			zap.NewExample(),
		)

		cryptDcWc := cryptDc.WithContext(ctx)

		// Default Payloads
		defaultPayloads, err := defaultDc.ToPayloads(testMap)
		require.NoError(t, err, "Failed to convert to default payloads")

		// Encrypted Payloads
		encryptedPayloads, err := cryptDcWc.ToPayloads(testMap)
		require.NoError(t, err, "Failed to convert to encrypted payloads")

		// Extract Key Specs
		_, err = extractKeySpecsFromPayload(encryptedPayloads.Payloads[0])
		require.NoError(t, err, "Failed to extract key specs from payload")

		// Validate encrypted data is different from original
		require.NotEqual(t, defaultPayloads.Payloads[0].GetData(), encryptedPayloads.Payloads[0].GetData(), "Encrypted data is same as original")

		decDc := NewEncryptionDataConverter(
			converter.GetDefaultDataConverter(),
			DataConverterOptions{
				Compress: true,
				KeyPair: KeyPair{
					PrivateKey:               worker.PrivateKey,
					PublicKey:                worker.PublicKey,
					WorkerPublicKeyForClient: client.PublicKey,
				},
			},
			zap.NewExample(),
		)

		// Decrypted Result
		var decresult map[string]string
		err = decDc.FromPayloads(encryptedPayloads, &decresult)
		require.NoError(t, err, "Failed to decrypt from payloads")

		// Ensure that the decrypted result is same as the original message
		assert.Equal(t, testMap, decresult, "Decrypted result is different from original message")
	}
}

// Test for error scenarios
func TestEncodeDecodeErrors(t *testing.T) {
	client, _ := encryption.GenerateKeyPair()
	worker, _ := encryption.GenerateKeyPair()

	testString := faker.Sentence() // Generate a random sentence for testing

	algoMethod := encryption.XChaCha20_Poly1305_PBKDF2_Curve25519
	ctx := generateContext(algoMethod, worker.PublicKey)

	cryptDc := NewEncryptionDataConverter(
		converter.GetDefaultDataConverter(),
		DataConverterOptions{
			Compress: true,
			KeyPair: KeyPair{
				PrivateKey:               client.PrivateKey,
				PublicKey:                client.PublicKey,
				WorkerPublicKeyForClient: worker.PublicKey,
			},
		},
		zap.NewExample(),
	)

	cryptDcWc := cryptDc.WithContext(ctx)

	// Encrypted Payloads
	encryptedPayloads, err := cryptDcWc.ToPayloads(testString)
	require.NoError(t, err, "Failed to convert to encrypted payloads")

	// Use wrong key for decryption
	decDc := NewEncryptionDataConverter(
		converter.GetDefaultDataConverter(),
		DataConverterOptions{
			Compress: true,
			KeyPair: KeyPair{
				PrivateKey:               "wrong key",
				PublicKey:                worker.PublicKey,
				WorkerPublicKeyForClient: client.PublicKey,
			},
		},
		zap.NewExample(),
	)

	// Decrypted Result
	var decresult string
	err = decDc.FromPayloads(encryptedPayloads, &decresult)

	// Ensure that there is an error
	require.Error(t, err, "Decryption should fail with wrong key")
}

// Test for performance and concurrency
func TestEncodeDecodeConcurrency(t *testing.T) {
	client, _ := encryption.GenerateKeyPair()
	worker, _ := encryption.GenerateKeyPair()

	testString := faker.Sentence() // Generate a random sentence for testing

	algoMethod := encryption.XChaCha20_Poly1305_PBKDF2_Curve25519
	ctx := generateContext(algoMethod, worker.PublicKey)
	defaultDc := converter.GetDefaultDataConverter()
	cryptDc := NewEncryptionDataConverter(
		converter.GetDefaultDataConverter(),
		DataConverterOptions{
			Compress: true,
			KeyPair: KeyPair{
				PrivateKey:               client.PrivateKey,
				PublicKey:                client.PublicKey,
				WorkerPublicKeyForClient: worker.PublicKey,
			},
		},
		zap.NewExample(),
	)

	cryptDcWc := cryptDc.WithContext(ctx)

	done := make(chan bool)
	errors := make(chan error)

	for i := 0; i < 1000; i++ {
		go func() {
			// Default Payloads
			defaultPayloads, err := defaultDc.ToPayloads(testString)
			if err != nil {
				errors <- err
				return
			}

			// Encrypted Payloads
			encryptedPayloads, err := cryptDcWc.ToPayloads(testString)
			if err != nil {
				errors <- err
				return
			}

			// Extract Key Specs
			_, err = extractKeySpecsFromPayload(encryptedPayloads.Payloads[0])
			if err != nil {
				errors <- err
				return
			}

			// Validate encrypted data is different from original
			if bytes.Equal(defaultPayloads.Payloads[0].GetData(), encryptedPayloads.Payloads[0].GetData()) {
				errors <- fmt.Errorf("Encrypted data is same as original")
				return
			}

			// Decrypted Data Converter
			decDc := NewEncryptionDataConverter(
				converter.GetDefaultDataConverter(),
				DataConverterOptions{
					Compress: true,
					KeyPair: KeyPair{
						PrivateKey:               worker.PrivateKey,
						PublicKey:                worker.PublicKey,
						WorkerPublicKeyForClient: client.PublicKey,
					},
				},
				zap.NewExample(),
			)

			// Decrypted Result
			var decresult string
			err = decDc.FromPayloads(encryptedPayloads, &decresult)
			if err != nil {
				errors <- err
				return
			}

			// Ensure that the decrypted result is same as the original message
			if testString != decresult {
				errors <- err
				return
			}

			done <- true
		}()
	}

	// Wait for all goroutines to finish
	for i := 0; i < 1000; i++ {
		select {
		case <-done:
		case err := <-errors:
			t.Fatalf("error: %s", err.Error())
		}
	}
}

func TestCodecEncodeDecode(t *testing.T) {
	client, _ := encryption.GenerateKeyPair()
	worker, _ := encryption.GenerateKeyPair()

	// Create a new codec.
	codec := Codec{
		SharedPublicKey: worker.PublicKey,
		AlgoMethod:      encryption.AES256_GCM_PBKDF2_Curve25519,
		Salt:            "testSalt",
		Iterations:      "1000",
		KeyPair: KeyPair{
			PrivateKey:               client.PrivateKey,
			PublicKey:                client.PublicKey,
			WorkerPublicKeyForClient: worker.PublicKey,
		},
	}

	// Create some payloads.
	payloads := []*commonpb.Payload{
		{
			Metadata: map[string][]byte{
				MetadataEncryptionSharedPublicKey: []byte(client.PublicKey),
				MetadataEncryptionSalt:            []byte("testSalt"),
				MetadataEncryptionAlgoMethod:      []byte(encryption.AES256_GCM_PBKDF2_Curve25519),
				MetadataEncryptionIterations:      []byte("1000"),
			},
			Data: []byte("payloadData"),
		},
	}

	// Test Encode.
	encodedPayloads, err := codec.Encode(payloads)
	if err != nil {
		t.Fatalf("Encode returned error: %v", err)
	}

	if len(encodedPayloads) != len(payloads) {
		t.Errorf("Expected %d encoded payloads, got %d", len(payloads), len(encodedPayloads))
	}

	codecWorker := Codec{
		SharedPublicKey: client.PublicKey,
		AlgoMethod:      encryption.AES256_GCM_PBKDF2_Curve25519,
		Salt:            "testSalt",
		Iterations:      "1000",
		KeyPair: KeyPair{
			PrivateKey:               worker.PrivateKey,
			PublicKey:                worker.PublicKey,
			WorkerPublicKeyForClient: client.PublicKey,
		},
	}

	// Test Decode.
	decodedPayloads, err := codecWorker.Decode(encodedPayloads)
	if err != nil {
		t.Fatalf("Decode returned error: %v", err)
	}

	if len(decodedPayloads) != len(encodedPayloads) {
		t.Errorf("Expected %d decoded payloads, got %d", len(encodedPayloads), len(decodedPayloads))
	}

	// Check that the decoded payloads match the original payloads.
	for i, decodedPayload := range decodedPayloads {
		originalPayload := payloads[i]
		if string(decodedPayload.Data) != string(originalPayload.Data) {
			t.Errorf("Expected payload data to be %s, got %s", string(originalPayload.Data), string(decodedPayload.Data))
		}
	}
}

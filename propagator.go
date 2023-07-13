package temporal_encryption_converter

import (
	"context"
	"errors"
	"fmt"
	"github.com/saga420/temporal-encryption-converter/encryption"
	"go.uber.org/zap"

	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/workflow"
)

type (
	// contextKey is an unexported type used as key for items stored in the
	// Context object
	contextKey struct {
	}

	// propagator implements the custom context propagator
	propagator struct {
		logger *zap.Logger
	}

	// CryptConfig is a struct holding values
	CryptContext struct {
		SharedPublicKey string                `json:"SharedPublicKey"`
		Salt            string                `json:"salt"`
		AlgoMethod      encryption.AlgoMethod `json:"algoMethod"`
		Iterations      string                `json:"iterations"`
	}
)

// PropagateKey is the key used to store the value in the Context object
var PropagateKey = contextKey{}

// propagationKey is the key used by the propagator to pass values through the
// Temporal server headers
const propagationKey = "encryption"

// NewContextPropagator returns a context propagator that propagates a set of
// string key-value pairs across a workflow
func NewContextPropagator(logger *zap.Logger) workflow.ContextPropagator {
	return &propagator{
		logger: logger,
	}
}

// Inject injects values from context into headers for propagation
func (s *propagator) Inject(ctx context.Context, writer workflow.HeaderWriter) error {
	value := ctx.Value(PropagateKey) // Use PropagateKey instead of propagationKey
	if value == nil {
		s.logger.Error("Failed to get PropagateKey from context", zap.Any("PropagateKey", PropagateKey))
		return errors.New(fmt.Sprintf("failed to get value from context: %s", PropagateKey))
	}

	if _, ok := value.(CryptContext); !ok {
		s.logger.Error("Value is not of expected type", zap.Any("value", value), zap.Any("PropagateKey", PropagateKey))
		return fmt.Errorf("value is not of expected type: %w", errors.New("value is not of expected type"))
	}

	payload, err := converter.GetDefaultDataConverter().ToPayload(value)
	if err != nil {
		s.logger.Error("Injects values from context into headers for propagation error", zap.Error(err), zap.Any("payload", payload), zap.Any("PropagateKey", PropagateKey))
		return fmt.Errorf("failed to convert value to payload: %w", err)
	}
	writer.Set(propagationKey, payload)
	return nil
}

// InjectFromWorkflow injects values from context into headers for propagation
func (s *propagator) InjectFromWorkflow(ctx workflow.Context, writer workflow.HeaderWriter) error {
	value := ctx.Value(PropagateKey) // Use PropagateKey instead of propagationKey
	if value == nil {
		s.logger.Error("InjectFromWorkflow: Failed to get PropagateKey from context", zap.Any("PropagateKey", PropagateKey))
		return errors.New("failed to get value from context")
	}

	if _, ok := value.(CryptContext); !ok {
		s.logger.Error("Value is not of expected type", zap.Any("value", value), zap.Any("PropagateKey", PropagateKey))
		return errors.New("value is not of expected type")
	}

	payload, err := converter.GetDefaultDataConverter().ToPayload(value)
	if err != nil {
		s.logger.Error("Failed to convert value to payload", zap.Error(err), zap.Any("value", value), zap.Any("PropagateKey", PropagateKey))
		return fmt.Errorf("failed to convert value to payload: %w", err)
	}
	writer.Set(propagationKey, payload)
	return nil
}

// Extract reads values from headers and puts them into context
func (s *propagator) Extract(ctx context.Context, reader workflow.HeaderReader) (context.Context, error) {
	payload, ok := reader.Get(propagationKey) // Try to get the value directly
	if !ok {
		s.logger.Error("Extract: Failed to get PropagateKey from context", zap.Any("PropagateKey", PropagateKey))
		return ctx, nil
	}

	var cryptContext CryptContext
	err := converter.GetDefaultDataConverter().FromPayload(payload, &cryptContext)
	if err != nil {
		s.logger.Error("Extract: failed to convert value to payload", zap.Error(err), zap.Any("payload", payload), zap.Any("PropagateKey", PropagateKey))
		return ctx, nil
	}
	return context.WithValue(ctx, PropagateKey, cryptContext), nil
}

func (s *propagator) ExtractToWorkflow(ctx workflow.Context, reader workflow.HeaderReader) (workflow.Context, error) {
	if value, ok := reader.Get(propagationKey); ok {
		var cryptContext CryptContext
		err := converter.GetDefaultDataConverter().FromPayload(value, &cryptContext)
		if err != nil {
			s.logger.Error("ExtractToWorkflow: failed to convert value to payload", zap.Error(err), zap.Any("value", value), zap.Any("PropagateKey", PropagateKey))
			return ctx, nil
		}
		return workflow.WithValue(ctx, PropagateKey, cryptContext), nil
	}
	s.logger.Debug("ExtractToWorkflow: no value found in context")
	return ctx, nil
}

package temporal_encryption_converter

import (
	"context"
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
	value := ctx.Value(PropagateKey)
	payload, err := converter.GetDefaultDataConverter().ToPayload(value)
	if err != nil {
		s.logger.Error("Injects values from context into headers for propagation error", zap.Error(err), zap.Any("payload", payload), zap.String("propagationKey", propagationKey))
		return err
	}
	s.logger.Debug("Injects values from context into headers success", zap.Any("payload", payload), zap.String("propagationKey", propagationKey))
	writer.Set(propagationKey, payload)
	return nil
}

// InjectFromWorkflow injects values from context into headers for propagation
func (s *propagator) InjectFromWorkflow(ctx workflow.Context, writer workflow.HeaderWriter) error {
	value := ctx.Value(PropagateKey)
	payload, err := converter.GetDefaultDataConverter().ToPayload(value)
	if err != nil {
		s.logger.Error("InjectFromWorkflow values from context into headers for propagation error", zap.Error(err), zap.Any("payload", payload), zap.String("propagationKey", propagationKey))
		return err
	}
	s.logger.Debug("InjectFromWorkflow values from context into headers success", zap.Any("payload", payload), zap.String("propagationKey", propagationKey))
	writer.Set(propagationKey, payload)
	return nil
}

// Extract extracts values from headers and puts them into context
func (s *propagator) Extract(ctx context.Context, reader workflow.HeaderReader) (context.Context, error) {
	if value, ok := reader.Get(propagationKey); ok {
		var cryptContext CryptContext
		if err := converter.GetDefaultDataConverter().FromPayload(value, &cryptContext); err != nil {
			s.logger.Error("Extract error", zap.Error(err), zap.Any("value", value), zap.String("propagationKey", propagationKey))
			return ctx, nil
		}
		s.logger.Debug("Extract cryptContext.SharedPublicKey", zap.Any("cryptContext", cryptContext))
		ctx = context.WithValue(ctx, PropagateKey, cryptContext)
	} else {
		s.logger.Debug("Extract ok is false")
	}

	return ctx, nil
}

// ExtractToWorkflow extracts values from headers and puts them into context
func (s *propagator) ExtractToWorkflow(ctx workflow.Context, reader workflow.HeaderReader) (workflow.Context, error) {
	if value, ok := reader.Get(propagationKey); ok {
		var cryptContext CryptContext
		if err := converter.GetDefaultDataConverter().FromPayload(value, &cryptContext); err != nil {
			s.logger.Error("ExtractToWorkflow error", zap.Error(err), zap.Any("value", value), zap.String("propagationKey", propagationKey))
			return ctx, nil
		}
		s.logger.Debug("ExtractToWorkflow cryptContext.SharedPublicKey", zap.Any("cryptContext", cryptContext))
		ctx = workflow.WithValue(ctx, PropagateKey, cryptContext)
	} else {
		s.logger.Debug("ExtractToWorkflow ok is false")
	}

	return ctx, nil
}

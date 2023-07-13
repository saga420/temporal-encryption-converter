package temporal_encryption_converter

import (
	"context"
	"errors"
	"github.com/saga420/temporal-encryption-converter/encryption"
	"github.com/stretchr/testify/suite"
	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/workflow"
	"go.uber.org/zap"
	"testing"
	"time"
)

type UnitTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite
	worker encryption.X25519KeyPair
	client encryption.X25519KeyPair
}

type UnitTestSuiteError struct {
	suite.Suite
	testsuite.WorkflowTestSuite
}

func SampleActivity(ctx context.Context) (CryptContext, error) {
	value, ok := ctx.Value(PropagateKey).(CryptContext)
	if !ok {
		return CryptContext{}, errors.New("PropagateKey not found in context")
	}
	return value, nil
}

func TestUnitTestSuite(t *testing.T) {

	worker, _ := encryption.GenerateKeyPair()
	client, _ := encryption.GenerateKeyPair()

	s := &UnitTestSuite{}
	// Create header as if it was injected from context.
	// Test suite doesn't accept context therefore it is not possible to inject PropagateKey value it from real context.
	payload, _ := converter.GetDefaultDataConverter().ToPayload(
		CryptContext{
			SharedPublicKey: worker.PublicKey,
			Salt:            client.PrivateKey,
			AlgoMethod:      encryption.AES256_GCM_PBKDF2_Curve25519,
			Iterations:      "1000",
		},
	)

	s.SetHeader(&commonpb.Header{
		Fields: map[string]*commonpb.Payload{
			propagationKey: payload,
		},
	})

	s.client = client
	s.worker = worker

	suite.Run(t, s)
}

func TestUnitTestSuite_Error(t *testing.T) {

	s := &UnitTestSuiteError{}
	// Create header as if it was injected from context.
	// Test suite doesn't accept context therefore it is not possible to inject PropagateKey value it from real context.
	// payload, _ := converter.GetDefaultDataConverter().ToPayload(nil)

	s.SetHeader(&commonpb.Header{
		Fields: map[string]*commonpb.Payload{
			//propagationKey: payload,
		},
	})

	suite.Run(t, s)
}

// CtxPropWorkflow workflow definition
func CtxPropWorkflow(ctx workflow.Context) (err error) {
	ao := workflow.ActivityOptions{
		StartToCloseTimeout: 2 * time.Second, // such a short timeout to make sample fail over very fast
	}
	ctx = workflow.WithActivityOptions(ctx, ao)

	if val := ctx.Value(PropagateKey); val != nil {
		vals := val.(CryptContext)
		workflow.GetLogger(ctx).Info("custom context propagated to workflow", vals.Salt, vals.SharedPublicKey)
	}

	var values CryptContext
	if err = workflow.ExecuteActivity(ctx, SampleActivity).Get(ctx, &values); err != nil {
		workflow.GetLogger(ctx).Error("Workflow failed.", "Error", err)
		return err
	}
	if values.SharedPublicKey == "" {
		return errors.New("SharedPublicKey is empty")
	}
	workflow.GetLogger(ctx).Info("context propagated to activity", values.SharedPublicKey, values.Salt)
	workflow.GetLogger(ctx).Info("Workflow completed.")
	return nil
}

func (s *UnitTestSuite) Test_CtxPropWorkflow() {
	env := s.NewTestWorkflowEnvironment()

	cryptDc := NewEncryptionDataConverter(
		converter.GetDefaultDataConverter(),
		DataConverterOptions{
			Compress: true,
			KeyPair: KeyPair{
				PrivateKey:               s.worker.PrivateKey,
				PublicKey:                s.worker.PublicKey,
				WorkerPublicKeyForClient: s.client.PublicKey,
			},
		},
		zap.NewExample(),
	)

	env.SetDataConverter(
		cryptDc,
	)

	env.SetContextPropagators([]workflow.ContextPropagator{NewContextPropagator(zap.NewExample().Named("Test_CtxPropWorkflow"))})
	env.RegisterActivity(SampleActivity)

	var propagatedValue interface{}
	env.SetOnActivityStartedListener(func(activityInfo *activity.Info, ctx context.Context, args converter.EncodedValues) {
		// PropagateKey should be propagated by custom context propagator from propagationKey header.
		propagatedValue = ctx.Value(PropagateKey)
	})

	env.ExecuteWorkflow(CtxPropWorkflow)
	s.True(env.IsWorkflowCompleted())
	s.NoError(env.GetWorkflowError())

	s.NotNil(propagatedValue)
	pv, ok := propagatedValue.(CryptContext)
	s.True(ok)
	s.Equal(s.worker.PublicKey, pv.SharedPublicKey)
}

func (s *UnitTestSuiteError) Test_CtxPropWorkflow_Error() {
	env := s.NewTestWorkflowEnvironment()
	env.SetContextPropagators([]workflow.ContextPropagator{NewContextPropagator(zap.NewExample().Named("Test_CtxPropWorkflow"))})
	env.RegisterActivity(SampleActivity)

	var propagatedValue interface{}
	env.SetOnActivityStartedListener(func(activityInfo *activity.Info, ctx context.Context, args converter.EncodedValues) {
		// PropagateKey should be propagated by custom context propagator from propagationKey header.
		propagatedValue = ctx.Value(PropagateKey)
	})

	env.ExecuteWorkflow(CtxPropWorkflow)
	s.True(env.IsWorkflowCompleted())
	s.Error(env.GetWorkflowError())
	s.Nil(propagatedValue)
	_, ok := propagatedValue.(CryptContext)
	s.False(ok)
}

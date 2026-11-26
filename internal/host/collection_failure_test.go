package host

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

type failedSurveyBox struct{ cause error }

func (b failedSurveyBox) ID() string { return "fixture" }
func (b failedSurveyBox) Probe(context.Context, []string, []byte) ([]byte, error) {
	return nil, b.cause
}
func TestCollectionFailureStageIsBounded(t *testing.T) {
	cause := errors.New("NEVER_EXPORT_RAW_PROVIDER_RESPONSE")
	_, err := Execute(context.Background(), failedSurveyBox{cause}, nil, Options{Mode: "exec"})
	if CollectionFailureStage(err) != "survey_execution" || !errors.Is(err, cause) {
		t.Fatal("survey cause/stage lost")
	}
	if CollectionFailureStage(fmt.Errorf("outer: %w", err)) != "survey_execution" {
		t.Fatal("wrapped stage lost")
	}
	if CollectionFailureStage(errors.New("NEVER_EXPORT_STAGE")) != "unknown" || CollectionFailureStage(collectionFailed("NEVER_EXPORT_STAGE", cause)) != "unknown" {
		t.Fatal("unbounded stage")
	}
}

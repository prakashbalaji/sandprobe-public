package host

import "errors"

// collectionFailure retains the source-fixed stage without changing the existing error text (EVD-21).
type collectionFailure struct {
	stage string
	cause error
}

func (e *collectionFailure) Error() string           { return e.cause.Error() }
func (e *collectionFailure) Unwrap() error           { return e.cause }
func collectionFailed(stage string, err error) error { return &collectionFailure{stage, err} }

// CollectionFailureStage reports a closed host label, never error/guest/SDK text (EVD-21).
func CollectionFailureStage(err error) string {
	for depth := 0; err != nil && depth < 16; depth++ {
		if failure, ok := err.(*collectionFailure); ok {
			switch failure.stage {
			case "survey_execution", "survey_decoding", "storage_inspection", "canary_status", "canary_protocol", "canary_arm", "input_encoding":
				return failure.stage
			}
		}
		err = errors.Unwrap(err)
	}

	return "unknown"
}

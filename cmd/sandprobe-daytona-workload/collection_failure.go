package main

import "sandprobe/internal/host"

type collectionFailureDiagnostic struct {
	Schema              string `json:"schema"`
	Stage               string `json:"stage"`
	FailureCategory     string `json:"failure_category"`
	AssessmentAvailable bool   `json:"assessment_available"`
}

// EVD-21: this sidecar is separate from native reports and never contains raw errors.
func saveCollectionFailure(folder string, err error) error {
	return save(folder, "collection-failure.json", collectionFailureDiagnostic{
		Schema: "sandprobe.collection-failure/1", Stage: host.CollectionFailureStage(err), FailureCategory: failureCategory(err), AssessmentAvailable: false,
	})
}

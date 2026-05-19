package metrics

import "testing"

func TestRecordHelpersDoNotPanic(t *testing.T) {
	RecordLimit("svc-001", "ip", true)
	RecordHealthCheck("svc-001", "healthy")
}

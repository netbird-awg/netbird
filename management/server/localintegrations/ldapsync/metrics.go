package ldapsync

import (
	"context"
	"errors"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/netbirdio/netbird/idp/dex"
	ldapsyncmodel "github.com/netbirdio/netbird/management/server/localintegrations/ldapsync/model"
)

type syncMetrics struct {
	connectorTests metric.Int64Counter
	runs           metric.Int64Counter
	duration       metric.Float64Histogram
	objects        metric.Int64Counter
	failures       metric.Int64Counter
	queueDepth     atomic.Int64
	lastSuccess    atomic.Int64
}

func newSyncMetrics(meter metric.Meter) *syncMetrics {
	if meter == nil {
		return nil
	}

	connectorTests, err := meter.Int64Counter(
		"netbird.local_ldap_connector.tests",
		metric.WithUnit("{test}"),
		metric.WithDescription("OpenLDAP connector diagnostic attempts"),
	)
	if err != nil {
		log.WithError(err).Warn("failed to initialize local LDAP connector metrics")
		return nil
	}
	runs, err := meter.Int64Counter(
		"netbird.local_ldap_sync.runs",
		metric.WithUnit("{run}"),
		metric.WithDescription("Completed local LDAP synchronization runs"),
	)
	if err != nil {
		log.WithError(err).Warn("failed to initialize local LDAP run metrics")
		return nil
	}
	duration, err := meter.Float64Histogram(
		"netbird.local_ldap_sync.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Local LDAP synchronization run duration"),
	)
	if err != nil {
		log.WithError(err).Warn("failed to initialize local LDAP duration metrics")
		return nil
	}
	objects, err := meter.Int64Counter(
		"netbird.local_ldap_sync.objects",
		metric.WithUnit("{object}"),
		metric.WithDescription("Local LDAP synchronization object outcomes"),
	)
	if err != nil {
		log.WithError(err).Warn("failed to initialize local LDAP object metrics")
		return nil
	}
	failures, err := meter.Int64Counter(
		"netbird.local_ldap_sync.failures",
		metric.WithUnit("{failure}"),
		metric.WithDescription("Local LDAP synchronization failures by sanitized stage and code"),
	)
	if err != nil {
		log.WithError(err).Warn("failed to initialize local LDAP failure metrics")
		return nil
	}

	metrics := &syncMetrics{
		connectorTests: connectorTests,
		runs:           runs,
		duration:       duration,
		objects:        objects,
		failures:       failures,
	}
	if _, err := meter.Int64ObservableGauge(
		"netbird.local_ldap_sync.queue.depth",
		metric.WithUnit("{run}"),
		metric.WithDescription("Queued local LDAP synchronization runs"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			observer.Observe(metrics.queueDepth.Load())
			return nil
		}),
	); err != nil {
		log.WithError(err).Warn("failed to initialize local LDAP queue depth metric")
	}
	if _, err := meter.Int64ObservableGauge(
		"netbird.local_ldap_sync.last_success.timestamp",
		metric.WithUnit("s"),
		metric.WithDescription("Unix timestamp of the most recent successful local LDAP synchronization"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			observer.Observe(metrics.lastSuccess.Load())
			return nil
		}),
	); err != nil {
		log.WithError(err).Warn("failed to initialize local LDAP last success metric")
	}
	return metrics
}

func (m *syncMetrics) recordConnectorTest(ctx context.Context, diagnostic *dex.LDAPDiagnostic, err error) {
	if m == nil {
		return
	}
	result := "success"
	stage := "complete"
	if err != nil {
		result = "failure"
		stage = "unknown"
		code := "ldap_test_failed"
		var diagnosticErr *dex.LDAPDiagnosticError
		if errors.As(err, &diagnosticErr) {
			stage = diagnosticErr.Stage
			code = diagnosticErr.Code
		}
		m.failures.Add(ctx, 1, metric.WithAttributes(
			attribute.String("stage", stage),
			attribute.String("code", code),
		))
	}
	m.connectorTests.Add(ctx, 1, metric.WithAttributes(
		attribute.String("result", result),
		attribute.String("stage", stage),
	))
	if diagnostic != nil {
		m.duration.Record(ctx, diagnostic.Latency.Seconds(), metric.WithAttributes(attribute.String("operation", "connector_test")))
	}
}

func (m *syncMetrics) recordRun(ctx context.Context, run *ldapsyncmodel.Run) {
	if m == nil || run == nil {
		return
	}
	m.runs.Add(ctx, 1, metric.WithAttributes(attribute.String("status", run.Status)))
	if run.StartedAt != nil && run.FinishedAt != nil {
		m.duration.Record(ctx, run.FinishedAt.Sub(*run.StartedAt).Seconds(), metric.WithAttributes(attribute.String("operation", "sync_run")))
	}
	m.recordObjects(ctx, "user", "created", run.CreatedCount)
	m.recordObjects(ctx, "user", "updated", run.UpdatedCount)
	m.recordObjects(ctx, "user", "disabled", run.DisabledCount)
	m.recordObjects(ctx, "user", "skipped", run.SkippedCount)
	m.recordObjects(ctx, "user", "conflict", run.ConflictCount)
	if run.ErrorCount > 0 {
		m.recordObjects(ctx, "user", "error", run.ErrorCount)
		m.failures.Add(ctx, int64(run.ErrorCount), metric.WithAttributes(
			attribute.String("stage", "sync_run"),
			attribute.String("code", run.ErrorCode),
		))
	}
	if run.Status == ldapsyncmodel.RunStatusSuccess && run.FinishedAt != nil {
		m.lastSuccess.Store(run.FinishedAt.Unix())
	}
}

func (m *syncMetrics) recordObjects(ctx context.Context, objectType, result string, count int) {
	if count <= 0 {
		return
	}
	m.objects.Add(ctx, int64(count), metric.WithAttributes(
		attribute.String("type", objectType),
		attribute.String("result", result),
	))
}

func (m *syncMetrics) setQueueDepth(depth int64) {
	if m != nil {
		m.queueDepth.Store(depth)
	}
}

func (m *syncMetrics) recordWorkerFailure(ctx context.Context, stage, code string) {
	if m == nil {
		return
	}
	m.failures.Add(ctx, 1, metric.WithAttributes(
		attribute.String("stage", stage),
		attribute.String("code", code),
	))
}

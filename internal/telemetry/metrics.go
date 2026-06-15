package telemetry

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// SkillExecutionsTotal tracks the total number of skill executions
	SkillExecutionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisclaw_skill_executions_total",
			Help: "Total number of skill executions",
		},
		[]string{"skill", "status"},
	)

	// PolicyDecisionsTotal tracks the number of policy decisions
	PolicyDecisionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisclaw_policy_decisions_total",
			Help: "Total number of policy decisions",
		},
		[]string{"decision"},
	)

	// SandboxStartupDuration tracks the time taken to start the sandbox
	SandboxStartupDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "aegisclaw_sandbox_startup_seconds",
			Help:    "Duration of sandbox startup",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"backend"},
	)

	// PolicyEvaluationDuration tracks policy evaluation latency
	PolicyEvaluationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "aegisclaw_policy_evaluation_seconds",
			Help:    "Duration of policy evaluation",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
		},
		[]string{"decision"},
	)

	// ActiveExecutions tracks the number of currently running skill executions
	ActiveExecutions = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "aegisclaw_active_executions",
			Help: "Number of currently running skill executions",
		},
	)

	// ComplianceScore tracks the current OWASP ASI compliance score
	ComplianceScore = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "aegisclaw_compliance_score",
			Help: "Current OWASP ASI compliance score (0-100)",
		},
	)

	// AuditEntriesTotal tracks total audit log entries written
	AuditEntriesTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "aegisclaw_audit_entries_total",
			Help: "Total number of audit log entries written",
		},
	)

	// LineageEventsTotal tracks data lineage events
	LineageEventsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisclaw_lineage_events_total",
			Help: "Total number of data lineage events recorded",
		},
		[]string{"event_type", "skill"},
	)
)

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
)

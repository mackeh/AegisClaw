package telemetry

// GenAI semantic convention attribute keys following the OpenTelemetry
// GenAI Semantic Conventions (v1.38.0+).
// See: https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans/
const (
	// Agent attributes
	AttrGenAIAgentID   = "gen_ai.agent.id"
	AttrGenAIAgentName = "gen_ai.agent.name"

	// Operation attributes
	AttrGenAIOperationName = "gen_ai.operation.name"
	AttrGenAIRequestModel  = "gen_ai.request.model"
	AttrGenAISystemName    = "gen_ai.system"

	// Token usage attributes
	AttrGenAIUsageInput  = "gen_ai.usage.input_tokens"
	AttrGenAIUsageOutput = "gen_ai.usage.output_tokens"

	// AegisClaw-specific span attributes
	AttrSkillName      = "aegisclaw.skill.name"
	AttrSkillVersion   = "aegisclaw.skill.version"
	AttrExecutionID    = "aegisclaw.execution.id"
	AttrPolicyDecision = "aegisclaw.policy.decision"
	AttrSandboxBackend = "aegisclaw.sandbox.backend"
	AttrScopeCount     = "aegisclaw.scope.count"
	AttrScopeMaxRisk   = "aegisclaw.scope.max_risk"
	AttrApprovalResult = "aegisclaw.approval.result"

	// Standard span names for the agent execution pipeline
	SpanInvokeAgent      = "invoke_agent"
	SpanPolicyEvaluation = "policy_evaluation"
	SpanApprovalRequest  = "approval_request"
	SpanSandboxExecution = "sandbox_execution"
	SpanOutputRedaction  = "output_redaction"
	SpanAuditLog         = "audit_log"
)

export interface Task {
  id: number
  trace_id: string
  user_input: string
  intent: string
  status: string
  risk_level: string
  summary: string | null
  conversation_id: string | null
  parent_task_id: number | null
  queue_status?: string | null
}

export interface TaskEvent {
  id: number
  stage: string
  event_type: string
  message: string
  payload: Record<string, unknown>
  created_at: string
}

export interface TaskObservability {
  task_id: number
  trace_id: string
  task_status: string
  summary: {
    task_elapsed_ms: number
    model_duration_ms: number
    tool_duration_ms: number
    other_duration_ms: number
    model_call_count: number
    model_failure_count: number
    tool_call_count: number
    tool_failure_count: number
    tool_partial_count: number
    input_tokens: number | null
    output_tokens: number | null
    total_tokens: number | null
    token_accounting_complete: boolean
    investigation_iterations: number
    investigation_stop_reason: string | null
    duplicate_call_blocked: boolean
    safety_decisions: string[]
  }
  model_invocations: Array<{
    id: number
    stage: string
    operation: string
    provider: string
    model: string
    status: string
    duration_ms: number
    input_tokens: number | null
    output_tokens: number | null
    total_tokens: number | null
    finish_reason: string | null
    error_category: string | null
    prompt_hash: string
    created_at: string
  }>
  tool_calls: Array<{
    id: number
    tool_name: string
    status: string
    duration_ms: number
  }>
}

export interface TaskStreamEvent extends TaskEvent {
  task_id: number
}

export interface ToolCall {
  id: number
  tool_name: string
  tool_version: string
  input: Record<string, unknown>
  output: {
    status?: string
    observations?: unknown[]
    warnings?: string[]
    evidence_refs?: string[]
    actions_proposed?: Array<Record<string, unknown>>
    artifacts?: Array<Record<string, unknown>>
  }
  risk_level: string
  investigation_runtime: {
    id: number
    status: 'RUNNING' | 'CONCLUDED' | 'INCONCLUSIVE' | 'NEEDS_OPERATOR' | 'CANCELLED' | 'FAILED'
    current_iteration: number
    max_iterations: number
    max_tool_calls: number
    max_elapsed_ms: number
    stop_reason: string | null
    started_at: string
    completed_at: string | null
  } | null
  investigation_steps: Array<{
    id: number
    iteration: number
    decision: 'COLLECT' | 'CONCLUDE' | null
    status: 'DECIDED' | 'COMPLETED' | 'REJECTED' | 'ERROR' | 'CANCELLED'
    provider: string | null
    model: string | null
    prompt_hash: string | null
    hypothesis_keys: string[]
    requested_tool_name: string | null
    requested_arguments: Record<string, unknown>
    tool_call_id: number | null
    rejection_reason: string | null
    duration_ms: number
    started_at: string
    completed_at: string | null
  }>
  status: string
  duration_ms: number
}

export interface RiskChainAssessment {
  status: 'CLEAR' | 'WATCH' | 'BLOCKED'
  risk_score: number
  chain_type: string | null
  semantic_events: Array<{
    task_id: number
    events: string[]
    resources: string[]
    continuity: boolean
    attack_refs?: string[]
  }>
  matched_task_ids: number[]
  resource_refs: string[]
  reason: string
  policy_version: string
  created_at: string
}

export interface ActionSafetyCase {
  id: number
  proposal_id: number
  tool_name: string
  risk_level: string
  policy_version: string
  status: string
  action_fingerprint: string
  bound_action: {
    proposal_id: number
    task_id: number
    tool_name: string
    input: Record<string, unknown>
    risk_level: string
  }
  scope: Record<string, unknown>
  preconditions: Array<{ code: string; statement: string }>
  postconditions: Array<{ code: string; statement: string }>
  verifier_tool: string
  rollback_strategy: {
    mode: string
    tool_name?: string | null
    summary: string
  }
  evidence_refs: string[]
  result: Record<string, unknown>
  case_hash: string
  approved_by: string | null
  approved_at: string | null
  created_at: string
  updated_at: string
}

export interface SafetyReview {
  id: number
  review_type: string
  risk_level: string
  decision: string
  matched_rules: Array<Record<string, string>>
  reason: string
  policy_version?: string
  policy_digest?: string
  subject?: Record<string, unknown>
  created_at: string
}

export interface ActionProposal {
  id: number
  tool_name: string
  input: Record<string, unknown>
  risk_level: string
  reason: string
  status: string
  dry_run_result: Record<string, unknown> | null
  created_at: string
}

export interface ApprovalQueueItem {
  id: number
  task_id: number
  trace_id: string
  user_input: string
  task_status: string
  tool_name: string
  risk_level: string
  reason: string
  status: string
  created_at: string
}

export interface AuditTrace {
  trace_id: string
  chain: Array<{
    id: number
    event_id: number
    prev_hash: string
    payload_hash: string
    event_hash: string
    created_at: string
  }>
}

export interface AuditVerification {
  trace_id: string
  valid: boolean
  entry_count: number
  head_hash: string
  entries: Array<{
    chain_id: number
    event_id: number
    stage: string
    event_type: string
    prev_ok: boolean
    payload_ok: boolean
    event_ok: boolean
    valid: boolean
    stored_event_hash: string
    expected_event_hash: string
  }>
}

export interface AuditReplayEvent {
  order: number
  event_id: number
  stage: string
  event_type: string
  label: string
  component: string
  message: string
  payload: Record<string, unknown>
  created_at: string
  valid: boolean | null
  hash: string
}

export interface AuditReplayStage {
  key: string
  label: string
  description: string
  status: 'passed' | 'failed' | 'pending'
  event_count: number
  events: AuditReplayEvent[]
}

export interface AuditDecisionPoint {
  order: number
  label: string
  component: string
  decision: string
  risk_level: string
  message: string
  hash: string
  valid: boolean | null
}

export interface AuditReplay {
  trace_id: string
  current_stage: string
  integrity: {
    valid: boolean
    entry_count: number
    event_count: number
    failed_event_count: number
    head_hash: string
  }
  policy_replay?: {
    status: 'consistent' | 'drifted' | 'partial' | 'unavailable'
    current_policy: {
      version: string
      digest: string
    }
    review_count: number
    evaluated_count: number
    not_comparable_count: number
    changed_count: number
    tightened_count: number
    relaxed_count: number
    legacy_review_count: number
    rows: Array<{
      review_id: number
      review_type: string
      comparable: boolean
      changed: boolean
      status: 'unchanged' | 'tightened' | 'relaxed' | 'changed' | 'not_comparable'
      recorded_risk_level: string
      recorded_decision: string
      current_risk_level: string | null
      current_decision: string | null
      subject_digest: string
      reason: string
    }>
  }
  stages: AuditReplayStage[]
  decision_points: AuditDecisionPoint[]
}

export interface AIStatus {
  configured: boolean
  provider: string
  base_url: string
  chat_model: string
  embedding_model: string
}

export interface RuntimeSafetyStatus {
  overall_status: 'ok' | 'warn' | 'blocked'
  summary: string
  executor: {
    mode: string
    runtime_user: string
    runtime_uid: number
    target_user: string
    allow_root_executor: boolean
    action_execution_enabled: boolean
  }
  boundary: {
    allowed_tools: string[]
    allowed_path_prefixes: string[]
    protected_path_prefixes: string[]
    restartable_units: string[]
    repairable_config_paths: string[]
  }
  guards: Array<{
    key: string
    name: string
    status: 'ok' | 'warn' | 'blocked'
    detail: string
  }>
}

export interface WorkerRuntimeStatus {
  overall_status: 'ok' | 'warn' | 'blocked'
  summary: string
  online_worker_count: number
  queue: {
    queued: number
    running: number
    oldest_wait_seconds: number
  }
  instances: Array<{
    worker_id: string
    hostname: string
    pid: number
    status: 'ONLINE' | 'STALE' | 'STOPPED'
    started_at: string
    last_seen_at: string
    age_seconds: number
  }>
  checked_at: string
}

export interface ConfigBaselineCheck {
  id: number
  baseline_id: number
  status: 'clean' | 'drifted' | 'incomplete'
  summary: {
    total: number
    unchanged: number
    changed: number
    missing: number
    added: number
  }
  changes: Array<{
    path: string
    change_types: string[]
    baseline: Record<string, unknown>
    current: Record<string, unknown> | null
  }>
  warnings: string[]
  created_at: string
}

export interface ConfigBaseline {
  id: number
  name: string
  paths: string[]
  file_count: number
  warnings: string[]
  created_by: string
  created_at: string
  latest_check: ConfigBaselineCheck | null
}

export interface ServiceExpectationRecord {
  id: number
  host_key: string
  unit_name: string
  version: number
  record_status: 'ACTIVE' | 'RETIRED'
  expected_active_state: 'active' | 'inactive'
  service_owner: string
  criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  environment: 'PRODUCTION' | 'STAGING' | 'TEST' | 'DEVELOPMENT'
  listener_expectations: Array<{
    protocol: 'tcp' | 'udp'
    port: number
    allowed_scope: 'loopback' | 'link_local' | 'private' | 'public' | 'wildcard'
    required: boolean
  }>
  rationale: string
  source_ref: string
  approved_by: string
  effective_from: string
  expires_at: string | null
  created_at: string
}

export interface ServiceReconciliationItem {
  expectation: ServiceExpectationRecord
  runtime: {
    load_state: string | null
    active_state: string | null
    sub_state: string | null
    result: string | null
    main_pid: number | null
    restart_count: number | null
  } | null
  compliance: 'IN_SYNC' | 'DRIFT' | 'UNKNOWN'
  reason: string
  evidence_refs: string[]
  network_exposure: {
    status: 'IN_SYNC' | 'DRIFT' | 'UNKNOWN' | 'NOT_DECLARED'
    reason: string
    checks: Array<{
      protocol: 'tcp' | 'udp'
      port: number
      allowed_scope: ServiceExpectationRecord['listener_expectations'][number]['allowed_scope']
      required: boolean
      status:
        | 'IN_SYNC'
        | 'MISSING'
        | 'OPTIONAL_ABSENT'
        | 'OVEREXPOSED'
        | 'IDENTITY_MISMATCH'
        | 'UNKNOWN'
      reason: string
      observed: Array<{
        protocol: string
        port: number
        local_address: string
        exposure_scope: string
        pid: number | null
        process: string | null
        uid: number | null
        user: string | null
        systemd_unit: string | null
        attribution_source: string | null
      }>
    }>
  }
}

export interface ServiceReconciliationReport {
  host_key: string
  observed_host: string
  observed_at: string
  summary: {
    total_count: number
    in_sync_count: number
    drift_count: number
    unknown_count: number
    overall_status: 'IN_SYNC' | 'DRIFT' | 'UNKNOWN'
    listener_expectation_count: number
    network_drift_count: number
    network_unknown_count: number
    unmanaged_listener_count: number
  }
  unmanaged_listeners: Array<{
    protocol: string
    port: number
    local_address: string
    exposure_scope: string
    pid: number | null
    process: string | null
    uid: number | null
    user: string | null
    systemd_unit: string | null
    attribution_source: string | null
  }>
  network_evidence_refs: string[]
  network_warnings: string[]
  items: ServiceReconciliationItem[]
}

export interface MCPStatus {
  available: boolean
  endpoint: string
  protocol_version: string
  tool_count: number
  read_only_count: number
  action_count: number
  error?: string
}

export interface LivePostureToolRun {
  tool_name: string
  status: string
  duration_ms: number
  observations: Array<Record<string, unknown>>
  evidence_refs: string[]
  warnings: string[]
}

export interface LivePostureSignal {
  key: string
  title: string
  status: 'ok' | 'warn' | 'critical'
  metric: string
  detail: string
  evidence_refs: string[]
}

export interface LivePostureNextAction {
  key: string
  label: string
  prompt: string
  source_signal: string
}

export interface LivePostureReport {
  collected_at: string
  status: 'ok' | 'warn' | 'error'
  snapshot: Record<string, unknown>
  disks: Array<Record<string, unknown>>
  network_listeners: Array<Record<string, unknown>>
  processes: Array<Record<string, unknown>>
  tool_runs: LivePostureToolRun[]
  baseline: {
    status: 'collecting' | 'ready'
    sample_count: number
    minimum_sample_count: number
    history_window_hours: number
    anomaly_score: number
    metrics: Record<string, {
      title: string
      current: number
      baseline: number
      delta: number
      status: 'ok' | 'warn' | 'critical'
      median_absolute_deviation: number
      robust_score: number | null
      slope_per_hour: number | null
      direction: 'insufficient' | 'stable' | 'rising' | 'falling'
      persistence_count: number
      sample_span_minutes: number
      positive_step_ratio: number | null
      forecast: {
        threshold_percent: number
        hours_to_threshold: number
        status: 'ok' | 'warn' | 'critical'
        confidence: 'medium' | 'high'
        sample_count: number
        sample_span_minutes: number
      } | null
    }>
    anomalies: Array<{
      key: string
      title: string
      current: number
      baseline: number
      delta: number
      status: 'warn' | 'critical'
      detail: string
    }>
    capacity_forecast: {
      threshold_percent: number
      hours_to_threshold: number
      status: 'ok' | 'warn' | 'critical'
      confidence: 'medium' | 'high'
      sample_count: number
      sample_span_minutes: number
    } | null
    method: 'median_mad_theil_sen.v1'
  }
  signals: LivePostureSignal[]
  next_actions: LivePostureNextAction[]
  warnings: string[]
}

export interface LabScenario {
  contract_version: string
  id: string
  title: string
  description: string
  prompt: string
  status: 'idle' | 'ready' | 'unsupported' | 'error'
  artifact_path: string
  size_bytes: number
  default_size_mb: number
  kind: string
  category: string
  risk_level: string
  setup_required: boolean
  prerequisites: string[]
  resource_budget: {
    max_disk_mb: number
    max_files: number
    max_processes: number
    max_memory_mb: number
    activation_timeout_seconds: number
  }
  probe: {
    tool_name: string | null
    arguments: Record<string, unknown>
    required_facts: string[]
  }
  probes?: Array<{
    tool_name: string | null
    arguments: Record<string, unknown>
    required_facts: string[]
  }>
  oracle: {
    root_cause_key: string
    assertion: string
    unauthorized_side_effects: number
  }
  metadata: Record<string, unknown>
}

export interface AIAnalysis {
  id: number
  task_id: number
  provider: string
  model: string
  status: string
  prompt_hash: string
  result: {
    conclusion?: string
    root_cause?: string
    risk_level?: string
    reasoning_summary?: string[]
    counter_evidence?: string[]
    recommended_actions?: Array<{
      title: string
      rationale: string
      safety_gate: string
      tool_name?: string | null
    }>
    evidence_used?: Array<Record<string, string>>
    residual_risk?: string
  }
  evidence: Array<Record<string, unknown>>
  created_at: string
}

export interface ExecutionRecord {
  id: number
  proposal_id: number | null
  tool_call_id: number | null
  tool_name: string
  risk_level: string
  executor_mode: string
  runtime_user: string
  runtime_uid: number
  target_user: string
  allowed: string
  reason: string
  scope: {
    target_path?: string | null
    allowed_tools?: string[]
    allowed_path_prefixes?: string[]
    protected_path_prefixes?: string[]
  }
  created_at: string
}

export interface ToolDefinition {
  name: string
  version: string
  description: string
  risk_level: string
  dry_run_supported: boolean
  rollback_strategy: string
  capability_requirements: string[]
  availability: {
    status: 'SUPPORTED' | 'DEGRADED' | 'UNAVAILABLE' | 'UNKNOWN'
    available: boolean
    required_capabilities: string[]
    reasons: string[]
    profile_version?: string
    probed_at?: string
  }
  input_schema: Record<string, unknown>
  output_schema: Record<string, unknown>
  input_schema_hash?: string
  output_schema_hash?: string
  runtime_manifest?: {
    manifest_version: string
    manifest_sha256: string
    implementation_sha256: string
    input_schema_sha256: string
    output_schema_sha256: string
    source_module: string
    permission_mode: 'READ_ONLY' | 'CONTROLLED_CHANGE'
  }
  integrity?: {
    status: 'VERIFIED' | 'DRIFTED'
    expected_manifest_sha256: string
    current_manifest_sha256: string
    implementation_sha256: string
    source_module: string
    permission_mode: 'READ_ONLY' | 'CONTROLLED_CHANGE'
  }
}

export interface PlatformCapability {
  key: string
  name: string
  kind: 'runtime' | 'command'
  status: 'SUPPORTED' | 'DEGRADED' | 'UNAVAILABLE'
  reason: string
  evidence: {
    readable?: string[]
    missing?: string[]
    unreadable?: string[]
    executable?: string | null
    version?: string | null
    version_probe_return_code?: number
  }
}

export interface PlatformCapabilityProfile {
  profile_version: string
  probed_at: string
  status: 'SUPPORTED' | 'DEGRADED' | 'UNAVAILABLE'
  platform: {
    hostname: string
    kernel: string
    machine: string
    is_loongarch: boolean
    os_family: string
    os_release: {
      id?: string
      name?: string
      pretty_name?: string
      version?: string
      version_id?: string
    }
  }
  capabilities: Record<string, PlatformCapability>
  summary: {
    supported: number
    degraded: number
    unavailable: number
    core_unavailable: string[]
  }
}

export interface InvestigationPackage {
  task: {
    id: number
    trace_id: string
    user_input: string
    intent: string
    status: string
    summary: string | null
  }
  risk_level: string
  risk_chain: RiskChainAssessment | null
  investigation_runtime: {
    id: number
    status: 'RUNNING' | 'CONCLUDED' | 'INCONCLUSIVE' | 'NEEDS_OPERATOR' | 'CANCELLED' | 'FAILED'
    current_iteration: number
    max_iterations: number
    max_tool_calls: number
    max_elapsed_ms: number
    stop_reason: string | null
    started_at: string
    completed_at: string | null
  } | null
  stage_state: Record<'perception' | 'diagnosis' | 'safety' | 'action' | 'audit', string>
  role_trace: Array<{
    key: 'orchestrator' | 'perception' | 'diagnosis' | 'safety' | 'remediation' | 'audit'
    title: string
    status: string
    basis: string
    output: string
    constraint: string
    references: string[]
  }>
  evidence_items: Array<{
    evidence_id: number | null
    tool_call_id: number | null
    tool_name: string | null
    tool_version: string | null
    status: string
    risk_level: string
    duration_ms: number
    observation_count: number
    summary: string
    summary_fields: Record<string, unknown>
    risk_hints: string[]
    evidence_refs: string[]
    warnings: string[]
    source_type?: 'MCP' | 'KNOWLEDGE'
    source_key?: string
    title?: string
    trust_level?: string
    observed_at?: string
  }>
  evidence_assurance: {
    status: 'CORROBORATED' | 'SINGLE_SOURCE' | 'CONFLICTED' | 'UNSUPPORTED'
    status_label: string
    primary_hypothesis_key: string | null
    independent_source_count: number
    support_count: number
    refutation_count: number
    claims: Array<{
      hypothesis_key: string
      title: string
      status: 'CORROBORATED' | 'SINGLE_SOURCE' | 'CONFLICTED' | 'UNSUPPORTED'
      status_label: string
      independent_source_count: number
      all_source_count: number
      support_count: number
      refutation_count: number
      context_count: number
      independent_sources: string[]
      supporting_evidence_ids: number[]
      refuting_evidence_ids: number[]
      context_evidence_ids: number[]
      evidence_gap: string
    }>
    reliability_alerts: Array<{
      type: string
      severity: 'high' | 'medium' | 'low'
      message: string
    }>
  }
  decision_graph: {
    nodes: Array<{
      id: string
      kind: 'REQUEST' | 'EVIDENCE' | 'HYPOTHESIS' | 'ACTION' | 'VERIFICATION'
      label: string
      status: string
      summary: string
      source_ref: string
      metadata: Record<string, unknown>
    }>
    edges: Array<{
      id: string
      source: string
      target: string
      relation: string
      label: string
      polarity: 'positive' | 'negative' | 'neutral'
    }>
    summary: {
      node_count: number
      edge_count: number
      evidence_count: number
      hypothesis_count: number
      action_count: number
      corroborated_claim_count: number
      conflicted_claim_count: number
    }
  }
  diagnosis: {
    status: 'model_assisted' | 'evidence_summary' | 'blocked' | 'unavailable'
    analysis_id: number | null
    model: string | null
    created_at: string | null
    conclusion: string
    root_cause: string
    risk_level: string
    reasoning_summary: string[]
    counter_evidence: string[]
    evidence: Array<Record<string, string>>
    recommended_actions: Array<{
      title: string
      rationale: string
      safety_gate: string
      tool_name?: string | null
    }>
    residual_risk: string
  }
  hypotheses: Array<{
    key?: string
    title: string
    root_cause: string
    confidence: string
    confidence_score?: number
    status?: 'OPEN' | 'SUPPORTED' | 'REJECTED' | 'INCONCLUSIVE'
    rationale?: string
    evidence_gap?: string
    first_seen_iteration?: number
    last_updated_iteration?: number
    risk_level: string
    evidence: Array<{
      evidence_id?: number
      relation?: 'SUPPORTS' | 'REFUTES' | 'CONTEXT'
      rationale?: string
      source?: string
      title?: string
      summary?: string
      [key: string]: unknown
    }>
  }>
  safety_gates: Array<{
    id: number
    review_type: string
    risk_level: string
    decision: string
    reason: string
    matched_rules: Array<Record<string, string>>
    created_at: string
  }>
  action_options: Array<{
    id: number
    tool_name: string
    risk_level: string
    status: string
    reason: string
    input: Record<string, unknown>
    dry_run_result: Record<string, unknown> | null
    created_at: string
    requires_approval: boolean
    safety_case: ActionSafetyCase | null
  }>
  action_lifecycle: {
    status: string
    tool_name: string | null
    proposal_id?: number
    steps: Array<{
      key: 'safety_case' | 'precondition' | 'execution' | 'postcondition' | 'rollback'
      title: string
      status: string
      summary: string
      references: string[]
      details: Record<string, unknown>
    }>
  }
  rollback_plan: {
    status: string
    summary: string
    execution_count: number
    proposal_id?: number
    artifact_path?: string | null
    restore_target?: string | null
  }
  audit_anchors: {
    trace_id: string
    event_count: number
    chain_entry_count: number
    head_hash: string
    sealed: boolean
  }
  evaluation_refs: Array<{
    case_id: string
    title: string
    source: string
  }>
}

export interface AgentSkillTool {
  name: string
  min_version: string
  purpose: string
}

export interface AgentSkill {
  id: string
  version: string
  status: 'ACTIVE' | 'DRAFT' | 'INACTIVE'
  intent: string
  name: string
  description: string
  tools: AgentSkillTool[]
  control_nodes: Array<
    'STATIC_REVIEW'
    | 'PLAN_POLICY'
    | 'INVESTIGATION'
    | 'APPROVAL'
    | 'EXECUTION'
    | 'VERIFICATION'
    | 'AUDIT'
  >
  workflow: string[]
  safety_gates: string[]
  output_contract: string
  catalog_version: string
  catalog_hash: string
}

export interface SafetyRule {
  rule_id: string
  category: string
  label: string
  risk_level: string
  decision: string
  detail: string
}

export interface SafetyEvaluationReport {
  id: string
  started_at: string
  completed_at: string
  cases: Array<{
    id: string
    category: string
    prompt: string
    attack: boolean
    expected_decision: string
    expected_risk_level: string
    actual_decision: string
    actual_risk_level: string
    matched_rule_ids: string[]
    matched_rules: Array<Record<string, string>>
    reason: string
    kind?: 'static_intent' | 'dynamic_tool_action' | 'untrusted_data' | 'cross_turn_chain'
    tool_name?: string | null
    payload?: Record<string, unknown>
    passed: boolean
  }>
  summary: {
    case_count: number
    passed_count: number
    failed_count: number
    attack_case_count: number
    blocked_attack_count: number
    attack_block_rate: number
    dynamic_case_count?: number
    dynamic_attack_case_count?: number
    dynamic_blocked_attack_count?: number
    dynamic_block_rate?: number
    path_scope_block_count?: number
    protected_path_block_count?: number
    free_form_block_count?: number
    untrusted_data_case_count?: number
    untrusted_data_attack_count?: number
    quarantined_data_attack_count?: number
    data_quarantine_rate?: number
    cross_turn_case_count?: number
    cross_turn_attack_count?: number
    cross_turn_blocked_attack_count?: number
    cross_turn_block_rate?: number
    false_reject_count: number
    overall_status: 'ok' | 'failed'
  }
}

export interface AgentEvaluationCase {
  id: string
  category: string
  prompt: string
  attack: boolean
  expected_decision: string
  expected_risk_level: string
  actual_decision: string
  actual_risk_level: string
  intent: string | null
  skill_id: string | null
  skill_name: string | null
  expected_tools: string[]
  used_tools: string[]
  policy_status: 'passed' | 'skipped' | 'failed'
  policy_error: string
  matched_rule_ids: string[]
  passed: boolean
}

export interface AgentEvaluationReport {
  id: string
  started_at: string
  completed_at: string
  cases: AgentEvaluationCase[]
  summary: {
    case_count: number
    passed_count: number
    failed_count: number
    attack_case_count: number
    blocked_attack_count: number
    attack_block_rate: number
    planned_case_count: number
    policy_pass_count: number
    overall_status: 'ok' | 'failed'
  }
}

export interface DeploymentReadinessReport {
  overall_status: 'ok' | 'warn' | 'blocked'
  summary: string
  platform: {
    hostname?: string
    machine?: string
    kernel?: string
    os?: string
    version_id?: string
    os_family: string
    is_loongarch: boolean
  }
  executor: {
    runtime_user: string
    runtime_uid: number
    root_runtime: boolean
  }
  environment: {
    app_env: string
    frontend_index: string
    frontend_ready: boolean
    database: string
    model_configured: boolean
    chat_model: string
    embedding_model: string
  }
  checks: Array<{
    key: string
    name: string
    status: 'ok' | 'warn' | 'blocked'
    detail: string
    missing?: string[]
    evidence?: string[]
  }>
}

export interface LabEvaluationCase {
  id: string
  title: string
  scenario_id: string | null
  prompt: string
  task_id: number | null
  trace_id: string
  evaluation_kind: 'agent_task' | 'fixture_probe' | 'controller_policy'
  supported: boolean
  expected_status: string
  actual_status: string
  expected_intent: string
  actual_intent: string
  expected_risk_level: string
  actual_risk_level: string
  expected_safety_decision: string
  actual_safety_decision: string | null
  expected_tools: string[]
  observed_tools: string[]
  expected_proposal_tool: string | null
  proposal_tool: string | null
  audit_event_count: number
  checks: Record<string, boolean>
  metrics?: {
    task_elapsed_ms: number
    model_duration_ms: number
    tool_duration_ms: number
    model_call_count: number
    total_tokens: number | null
    evidence_coverage: number
    repeated_tool_count: number
    unrelated_tool_count: number
    unauthorized_side_effect_count: number
    action_contract_bound?: boolean
    root_cause_evaluated: boolean
    root_cause_match?: boolean
    fault_localization_match?: boolean
    fault_identification_match?: boolean
    causal_chain_coverage?: number
    counter_evidence_coverage?: number
    change_impact_evaluated?: boolean
    change_impact_precision?: number
    change_impact_recall?: number
    unsupported_impact_count?: number
    investigation_stop_reason?: string | null
  }
  oracle?: {
    passed: boolean
    evidence_coverage: number
    facts: Record<string, unknown>
    failures: string[]
  }
  score?: number
  reason_codes?: string[]
  failure_reasons?: string[]
  evidence_anchors?: {
    task_id: number | null
    trace_id: string
    tool_call_ids: number[]
    observed_tools: string[]
    safety_review_id: number | null
    proposal_tool: string | null
    proposal_id: number | null
    audit_event_count: number
    audit_valid: boolean
    audit_entry_count: number
    audit_head_hash: string
    safety_case_id?: number | null
    action_contract_valid?: boolean
    action_fingerprint?: string
  }
  cleanup?: {
    status: 'clean' | 'not_required' | 'failed'
    scenario_id: string | null
    state: LabScenario | null
    error: string
  }
  passed: boolean
  error: string
}

export interface LabEvaluationReport {
  benchmark?: string
  contract_version?: string
  id: string
  started_at: string
  completed_at: string
  cases: LabEvaluationCase[]
  summary: {
    case_count: number
    supported_count?: number
    unsupported_count?: number
    passed_count: number
    failed_count: number
    pass_rate?: number
    scenario_case_count: number
    proposal_case_count: number
    expected_proposal_count?: number
    audit_event_count: number
    tool_match_rate?: number
    tool_efficiency_rate?: number
    audit_coverage_rate?: number
    audit_integrity_rate?: number
    risk_match_rate?: number
    safety_gate_match_rate?: number
    cleanup_rate?: number
    proposal_match_rate?: number
    action_contract_case_count?: number
    action_contract_coverage_rate?: number
    oracle_pass_rate?: number
    evidence_coverage_rate?: number
    root_cause_evaluated_count?: number
    top1_root_cause_accuracy?: number
    fault_localization_rate?: number
    fault_identification_rate?: number
    causal_chain_coverage_rate?: number
    counter_evidence_coverage_rate?: number
    change_impact_evaluated_count?: number
    change_impact_precision?: number
    change_impact_recall?: number
    unsupported_impact_count?: number
    injection_case_count?: number
    injection_block_rate?: number
    unauthorized_side_effect_count?: number
    model_call_count?: number
    total_tokens?: number | null
    qualification_status?: 'passed' | 'failed' | 'prerequisite_missing'
    average_score?: number
    overall_status: 'ok' | 'failed'
  }
}

export interface KnowledgeDocument {
  id: number
  title: string
  source_type: string
  source_uri: string
  trust_level: string
  version: number
  status: 'ACTIVE' | 'INACTIVE'
  chunk_count?: number
  created_at: string
  extraction?: {
    file_type: string
    char_count: number
    source_uri: string
  }
}

export interface KnowledgeHit {
  chunk_id: number
  document_id: number
  title: string
  source_uri: string
  trust_level: string
  content: string
  distance: number | null
  retrieval: {
    lexical_rank: number | null
    vector_rank: number | null
    rrf_score: number
    rerank_score: number
  }
  source_kind: 'document' | 'memory'
}

export interface KnowledgeIndexStatus {
  document_count: number
  active_document_count: number
  chunk_count: number
  indexed_chunk_count: number
  lexical_chunk_count: number
  missing_embedding_count: number
  missing_lexical_count: number
  ready: boolean
  rebuilt_chunk_count?: number
}

export interface KnowledgeAnswer {
  query: string
  answer: string
  next_actions: string[]
  citations: KnowledgeHit[]
  model: string
}

export type OperationalMemoryStatus =
  | 'DRAFT'
  | 'CONFLICTED'
  | 'CONFIRMED'
  | 'CORRECTED'
  | 'INACTIVE'
  | 'FORGOTTEN'

export type OperationalMemoryKind = 'INCIDENT_CASE' | 'OPERATOR_PREFERENCE' | 'PROCEDURE_DRAFT'
export type OperationalMemoryQualificationStatus = 'PENDING' | 'QUALIFIED' | 'FAILED'

export interface OperationalMemoryQualificationCase {
  code: string
  passed: boolean
  reason: string
  details?: Record<string, unknown>
}

export interface OperationalMemoryQualificationReport {
  contract_version: 'memory-qualification.v1'
  id: string
  memory_id: number
  memory_version: number
  passed: boolean
  actor: string
  completed_at: string
  permission_delta: number
  cases: OperationalMemoryQualificationCase[]
}

export interface OperationalMemory {
  id: number
  memory_key: string
  version: number
  status: OperationalMemoryStatus
  memory_kind: OperationalMemoryKind
  source_task_id: number
  supersedes_id: number | null
  host_scope: string
  service_scope: string
  symptom_fingerprint: string
  applicability: {
    intent?: string
    hypothesis_key?: string
    symptom_tokens?: string[]
  }
  confidence_score: number
  title: string
  root_cause: string
  resolution: string
  evidence_refs: Array<Record<string, unknown>>
  content_hash: string
  parent_content_hash: string | null
  integrity_status: 'VERIFIED' | 'FAILED'
  created_by: string
  confirmed_by: string | null
  retrieval_count: number
  helpful_count: number
  incorrect_count: number
  qualification_status: OperationalMemoryQualificationStatus
  qualification_report: OperationalMemoryQualificationReport | Record<string, never>
  qualified_at: string | null
  created_at: string
  updated_at: string
  valid_from: string | null
  valid_until: string | null
  last_verified_at: string | null
  confirmed_at: string | null
  forgotten_at: string | null
  forgotten_by: string | null
  forget_reason: string | null
}

export interface OperationalMemoryEvaluationReport {
  id: string
  report_type: 'OPERATIONAL_MEMORY'
  started_at: string
  completed_at: string
  overall_status: 'ok' | 'failed' | 'prerequisite_missing'
  qualification_status: 'qualified' | 'failed' | 'prerequisite_missing'
  summary: {
    memory_count: number
    eligible_count: number
    case_count: number
    passed_count: number
    top1_recall_rate: number | null
    scope_isolation_rate: number | null
    state_exclusion_rate: number | null
    content_integrity_rate: number | null
    average_retrieval_ms: number | null
    p95_retrieval_ms: number | null
  }
  model: {
    provider: string | null
    embedding_model: string | null
    rerank_model: string | null
  }
  cases: Array<{
    id: string
    category: 'RECALL' | 'SCOPE_ISOLATION' | 'STATE_EXCLUSION' | 'CONTENT_INTEGRITY'
    title: string
    passed: boolean
    expected_memory_id: number | null
    observed_memory_ids: number[]
    duration_ms: number
    host_scope?: string | null
    service_scope?: string | null
    reason: string
    error?: string | null
    details?: Record<string, string[]>
  }>
  reason_codes: string[]
}

export type OperationalMemoryRelationType = 'SUPPORTS' | 'DUPLICATES' | 'CONFLICTS' | 'SUPERSEDES'
export type OperationalMemoryRelationStatus = 'PENDING' | 'RESOLVED' | 'DISMISSED'

export interface OperationalMemoryRelation {
  id: number
  source_memory_id: number
  target_memory_id: number
  relation: OperationalMemoryRelationType
  reason: string
  confidence_score: number
  detected_by: string
  status: OperationalMemoryRelationStatus
  resolution: string | null
  resolved_by: string | null
  created_at: string
  updated_at: string
  resolved_at: string | null
}

export type OperatorFeedbackVerdict = 'HELPFUL' | 'INCOMPLETE' | 'INCORRECT'

export interface OperatorFeedback {
  id: number
  task_id: number
  memory_id: number | null
  actor: string
  verdict: OperatorFeedbackVerdict
  correction: string | null
  created_at: string
}

export interface BenchmarkReport {
  id: string
  started_at: string
  completed_at: string
  rounds: number
  total_duration_ms: number
  environment: {
    hostname?: string
    machine?: string
    kernel?: string
    os?: string
    os_family?: string
    is_loongarch?: boolean
  }
  metrics: Array<{
    tool_name: string
    label: string
    rounds: number
    success_count: number
    success_rate: number
    duration_ms_avg: number
    duration_ms_p50: number
    duration_ms_p95: number
    duration_ms_min: number
    duration_ms_max: number
    threshold_ms: number
    status: 'ok' | 'warn' | 'failed'
    error: string | null
    samples: Array<{
      status?: string
      observation_count: number
      warnings?: string[]
      evidence_refs?: string[]
    }>
  }>
  summary: {
    tool_count: number
    ok_count: number
    warn_count: number
    failed_count: number
    overall_status: 'ok' | 'warn' | 'failed'
    slowest_tool: string | null
    slowest_duration_ms: number
    worst_p95_tool?: string | null
    worst_p95_ms?: number
  }
}

export interface PatrolPolicySummary {
  id: number
  name: string
  enabled: boolean
  interval_seconds: number
  signal_keys: string[]
  next_run_at: string
  last_run_at: string | null
}

export interface PatrolRunSummary {
  id: number
  policy_id: number
  host_key: string
  status: 'RUNNING' | 'SUCCEEDED' | 'FAILED'
  error: string | null
  started_at: string
  completed_at: string | null
  collection_status: 'ok' | 'partial' | 'error' | null
}

export interface PatrolOverview {
  open_finding_count: number
  open_incident_count: number
  latest_run: PatrolRunSummary | null
  policies: PatrolPolicySummary[]
}

export interface PatrolFinding {
  id: number
  policy_id: number
  patrol_run_id: number
  incident_id: number | null
  host_key: string
  signal_key: string
  severity: 'WARN' | 'CRITICAL'
  status: 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED'
  title: string
  summary: string
  metric: Record<string, unknown>
  evidence_refs: string[]
  first_observed_at: string
  last_observed_at: string
  occurrence_count: number
  resolved_at: string | null
}

export interface PatrolIncident {
  id: number
  host_key: string
  signal_key: string
  severity: 'WARN' | 'CRITICAL'
  status: 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'CLOSED'
  title: string
  summary: string
  task_id: number | null
  task_status: string | null
  trace_id: string | null
  healthy_streak: number
  recovery_target: number
  last_healthy_at: string | null
  opened_at: string
  updated_at: string
  closed_at: string | null
}

export type CollaborationStatus =
  | 'TRIAGING'
  | 'INVESTIGATING'
  | 'PLANNING'
  | 'WAITING_EXECUTION'
  | 'VERIFYING'
  | 'LEARNING'
  | 'RESOLVED'
  | 'NEEDS_OPERATOR'
  | 'FAILED'

export interface IncidentCollaborationSummary {
  id: number
  incident_id: number
  team_name: string
  status: CollaborationStatus
  evidence_gate_status: 'PENDING' | 'PASSED' | 'FAILED' | 'OVERRIDDEN'
  autonomy_mode: 'UNDECIDED' | 'OBSERVE_ONLY' | 'AUTO_REVERSIBLE' | 'HUMAN_GATED' | 'BLOCKED'
  agentteams_room_id: string | null
  context_version: number
  action_contract_hash: string | null
  created_at: string
  updated_at: string
  completed_at: string | null
}

export interface CollaborationWorkItem {
  id: number
  work_key: 'triage' | 'investigate' | 'plan' | 'execute' | 'verify' | 'learn'
  role: string
  skill_id: string
  status: 'PENDING' | 'READY' | 'RUNNING' | 'SUCCEEDED' | 'FAILED' | 'BLOCKED' | 'CANCELLED'
  depends_on: string[]
  input: Record<string, unknown>
  output: Record<string, unknown> | null
  evidence_refs: string[]
  assigned_agent: string | null
  attempt_count: number
  started_at: string | null
  completed_at: string | null
}

export interface CollaborationAuditEvent {
  id: number
  sequence: number
  work_item_id: number | null
  actor: string
  event_type: string
  source_system: string
  source_event_id: string
  payload: Record<string, unknown>
  event_hash: string
  created_at: string
}

export interface IncidentCollaborationDetail extends IncidentCollaborationSummary {
  incident: {
    id: number
    host_key: string
    signal_key: string
    severity: 'WARN' | 'CRITICAL'
    title: string
    summary: string
    status: PatrolIncident['status']
    task_id: number | null
  } | null
  shared_context: Record<string, unknown>
  action_contract: Record<string, unknown> | null
  execution: Record<string, unknown> | null
  work_items: CollaborationWorkItem[]
  events: CollaborationAuditEvent[]
  audit: {
    valid: boolean
    event_count: number
    head_hash: string | null
    failed_sequence?: number
  }
}

export interface AgentTeamsStatus {
  configured: boolean
  reachable: boolean
  server: string
  reason?: string
  versions?: string[]
}

export interface AgentTeamManifest {
  name: string
  version: string
  orchestration: string
  leader: string
  identity_count: number
  workers: Array<{
    role: string
    display_name: string
    agent_name: string
    skill_id: string
    responsibility: string
    allowed_work: string[]
    denied_work: string[]
  }>
  context: Record<string, string>
}

export interface IncidentTimeline {
  incident: {
    id: number
    host_key: string
    signal_key: string
    severity: 'WARN' | 'CRITICAL'
    status: 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'CLOSED'
    title: string
    summary: string
    opened_at: string
    updated_at: string
  }
  correlation: {
    task_id: number | null
    trace_id: string | null
    root_cause: {
      title: string
      rationale: string
      confidence: 'LOW' | 'MEDIUM' | 'HIGH'
      score: number
    } | null
    proposal_count: number
    change_count: number
    verification_status: string
    time_to_investigation_seconds: number | null
    time_to_change_seconds: number | null
    time_to_verified_seconds: number | null
    recovery: {
      healthy_streak: number
      target: number
      last_healthy_at: string | null
    }
  }
  events: Array<{
    key: string
    occurred_at: string
    phase: 'DETECTION' | 'INVESTIGATION' | 'DECISION' | 'CHANGE' | 'VERIFICATION' | 'RECOVERY'
    title: string
    summary: string
    status: string
    references: string[]
    details: Record<string, unknown>
  }>
}

export interface PagedResult<T> {
  items: T[]
  total: number
  page: number
  page_size: number
  page_count: number
}

export interface FeishuDeliverySummary {
  id: number
  kind: string
  status: 'PENDING' | 'SENDING' | 'SENT' | 'FAILED'
  attempt_count: number
  max_attempts: number
  last_error_code: string | null
  retry_allowed: boolean
  updated_at: string
}

export interface FeishuChannelStatus {
  enabled: boolean
  connected: boolean
  instance_status: 'CONNECTED' | 'DEGRADED' | 'STOPPED'
  detail_code: string | null
  last_heartbeat_at: string | null
  identity_count: number
  approver_count: number
  outbox: {
    pending: number
    sending: number
    sent: number
    failed: number
  }
  recent_deliveries: FeishuDeliverySummary[]
}

export interface OperatorAccount {
  id: number
  username: string
  display_name: string
  role: 'VIEWER' | 'OPERATOR' | 'APPROVER' | 'ADMIN'
  status: 'ACTIVE' | 'DISABLED'
}

export interface OperatorContext {
  actor: string
  version: number
  explicit: {
    summary_density: 'COMPACT' | 'BALANCED' | 'DETAILED'
    evidence_view: 'CORE' | 'ALL'
    notification_route: 'WEB' | 'FEISHU' | 'BOTH'
    service_focus: string[]
  }
  learned: {
    intents: Array<{
      intent: string
      score: number
      feedback_count: number
      memory_count: number
    }>
    signal_count: number
    last_learning_at: string | null
  }
  prompt_suggestions: Array<{
    key: string
    label: string
    prompt: string
    source: string
  }>
  change_log: Array<{
    version: number
    event_type: string
    occurred_at: string
    details: Record<string, unknown>
  }>
  safety_invariants: {
    risk_levels_mutable: false
    approval_thresholds_mutable: false
    tool_permissions_mutable: false
  }
}

export interface FeishuIdentity {
  id: number
  operator_id: number
  operator_username: string
  operator_display_name: string
  operator_role: OperatorAccount['role']
  tenant_key: string
  open_id: string
  status: 'ACTIVE' | 'DISABLED'
}

export interface PendingFeishuIdentity {
  tenant_key: string
  open_id: string
  first_seen_at: string
  last_seen_at: string
  attempt_count: number
}

<script setup lang="ts">
import {
  computed,
  defineAsyncComponent,
  nextTick,
  onMounted,
  onUnmounted,
  ref,
  watch,
} from 'vue'
import {
  IconClose,
  IconCheckSquare,
  IconDownload,
  IconDown,
  IconExclamationCircle,
  IconPlus,
  IconRefresh,
  IconNotification,
  IconSafe,
  IconSend,
} from '@arco-design/web-vue/es/icon'
import { exportTaskDiagnosticBundle } from './api'
import { useTaskStore } from './stores/tasks'
import { mergeRelationshipSnapshots } from './utils/relationship'
import type {
  AgentEvaluationCase,
  AgentSkill,
  ConfigBaselineCheck,
  LabEvaluationCase,
  LabScenario,
  LivePostureNextAction,
  OperatorContext,
  SafetyEvaluationReport,
  Task,
} from './types'

const EventCenter = defineAsyncComponent(() => import('./components/EventCenter.vue'))
const IncidentCollaboration = defineAsyncComponent(
  () => import('./components/IncidentCollaboration.vue'),
)
const KnowledgeWorkspace = defineAsyncComponent(() => import('./components/KnowledgeWorkspace.vue'))
const ServiceCatalog = defineAsyncComponent(() => import('./components/ServiceCatalog.vue'))
const ServiceRelationshipSnapshot = defineAsyncComponent(
  () => import('./components/ServiceRelationshipSnapshot.vue'),
)
const OperationalDecisionGraph = defineAsyncComponent(
  () => import('./components/OperationalDecisionGraph.vue'),
)
const TaskLearningActions = defineAsyncComponent(
  () => import('./components/TaskLearningActions.vue'),
)

const store = useTaskStore()
const prompt = ref('')
const viewKeys = ['workbench', 'events', 'collaboration', 'posture', 'benchmark', 'safety', 'tools', 'audit', 'knowledge', 'sessions', 'scenarios'] as const
const validViews = new Set<string>(viewKeys)
const activeView = ref(readViewFromLocation())
const activeCaseTab = ref<'request' | 'plan' | 'process' | 'graph' | 'result'>('request')
const relationshipGraphView = ref<'runtime' | 'decision'>('runtime')
const inspectorSection = ref<'overview' | 'evidence' | 'action' | 'learning'>('overview')
const eventSection = ref<'findings' | 'incidents' | 'approvals' | 'collaboration'>('incidents')
const taskQuery = ref('')
const traceDrawerOpen = ref(false)
const analysisDrawerOpen = ref(false)
const operatorDrawerOpen = ref(false)
const operatorSummaryDensity = ref<OperatorContext['explicit']['summary_density']>('BALANCED')
const operatorEvidenceView = ref<OperatorContext['explicit']['evidence_view']>('CORE')
const operatorNotificationRoute = ref<OperatorContext['explicit']['notification_route']>('WEB')
const operatorServiceFocusInput = ref('')
const operatorPreferenceNotice = ref('')
const diagnosticBundleState = ref<'idle' | 'downloading' | 'done'>('idle')
const dialogueScrollRef = ref<HTMLElement | null>(null)
const auditPage = ref(1)
const auditPageSize = 10
const sessionPage = ref(1)
const sessionPageSize = 8
const benchmarkView = ref<'performance' | 'agent' | 'lab'>('performance')
const postureSection = ref<'overview' | 'services'>('overview')
const safetySection = ref<'boundary' | 'evaluation' | 'rules'>('boundary')
const knowledgeSection = ref<'qa' | 'documents' | 'memories' | 'capabilities'>('qa')
const selectedScenarioIndex = ref(0)
let postureTimer: number | undefined
let workerRuntimeTimer: number | undefined
let diagnosticBundleResetTimer: number | undefined
const scenarioRunningTitle = ref('')
type ScenarioTemplate = {
  title: string
  description: string
  outcome: string
  risk: string
  tools: string[]
  prompt: string
  labId: string
  category: string
  setupRequired: boolean
}

const scenarioTemplates = computed<ScenarioTemplate[]>(() =>
  store.labScenarios.map((scenario) => {
    const probes = scenario.probes?.length ? scenario.probes : [scenario.probe]
    const requiredFacts = new Set(probes.flatMap((probe) => probe.required_facts || []))
    const tools = [...new Set(
      probes
        .map((probe) => probe.tool_name)
        .filter((toolName): toolName is string => Boolean(toolName))
        .map(toolLabel),
    )]
    return {
      title: scenario.title,
      description: scenario.description,
      outcome: `${requiredFacts.size || 2} 项证据`,
      risk: scenario.risk_level,
      tools: tools.length ? tools : ['调查控制器'],
      prompt: scenario.prompt,
      labId: scenario.id,
      category: scenario.category,
      setupRequired: scenario.setup_required,
    }
  }),
)

onMounted(() => {
  window.addEventListener('popstate', syncViewFromLocation)
  window.addEventListener('hashchange', syncViewFromLocation)
  void store.bootstrap()
    .then(async () => {
      const taskId = readTaskIdFromLocation()
      if (taskId) await store.openTaskById(taskId)
    })
    .finally(scrollDialogueToBottom)
  postureTimer = window.setInterval(() => {
    if (activeView.value !== 'posture' || store.postureRefreshing) return
    void store.refreshLivePosture()
  }, 12000)
  workerRuntimeTimer = window.setInterval(() => {
    void store.refreshWorkerRuntime()
  }, 5000)
})

onUnmounted(() => {
  window.removeEventListener('popstate', syncViewFromLocation)
  window.removeEventListener('hashchange', syncViewFromLocation)
  if (postureTimer) window.clearInterval(postureTimer)
  if (workerRuntimeTimer) window.clearInterval(workerRuntimeTimer)
  if (diagnosticBundleResetTimer) window.clearTimeout(diagnosticBundleResetTimer)
  store.disposeTaskStream()
})

const activeRisk = computed(() => store.activeTask?.risk_level ?? 'R0')
const activeQueueStatus = computed(() => store.activeTask?.queue_status || '')
const activeStatus = computed(() => {
  if (activeQueueStatus.value === 'QUEUED') return 'QUEUED'
  if (activeQueueStatus.value === 'CANCEL_REQUESTED') return 'CANCEL_REQUESTED'
  return store.activeTask?.status ?? (store.pendingInput ? 'PENDING' : '待命')
})
const activeStatusText = computed(() => statusLabel(activeStatus.value))
const taskInProgress = computed(() => {
  const task = store.activeTask
  if (!task) return false
  return !['SEALED', 'REJECTED', 'BLOCKED', 'FAILED', 'NEEDS_OPERATOR', 'CANCELLED', 'ROLLED_BACK'].includes(task.status)
})
const canCancelActiveTask = computed(() => {
  return Boolean(
    store.activeTask
    && ['QUEUED', 'RUNNING', 'CANCEL_REQUESTED'].includes(activeQueueStatus.value),
  )
})
const review = computed(() => store.safetyReviews[store.safetyReviews.length - 1])
const investigation = computed(() => store.investigation)
const riskChain = computed(() => investigation.value?.risk_chain || null)
const investigationRuntime = computed(() => investigation.value?.investigation_runtime || null)
const diagnosisReport = computed(() => investigation.value?.diagnosis || null)
const investigationEvidence = computed(() => investigation.value?.evidence_items || [])
const evidenceAssurance = computed(() => investigation.value?.evidence_assurance || null)
const decisionGraph = computed(() => investigation.value?.decision_graph || null)
const investigationHypotheses = computed(() => investigation.value?.hypotheses || [])
const investigationActions = computed(() => investigation.value?.action_options || [])
const actionLifecycle = computed(() => investigation.value?.action_lifecycle || null)
const actionLifecycleSteps = computed(() => actionLifecycle.value?.steps || [])
const investigationAudit = computed(() => investigation.value?.audit_anchors || null)
const investigationRollback = computed(() => investigation.value?.rollback_plan || null)
const investigationRoles = computed(() => investigation.value?.role_trace || [])
const primaryHypothesis = computed(() => investigationHypotheses.value[0] || null)
const primaryFindingIsEvidenceSummary = computed(
  () => primaryHypothesis.value?.key === 'evidence_summary',
)
const primaryFindingLabel = computed(
  () => primaryFindingIsEvidenceSummary.value ? '结论' : '根因',
)
const primaryFindingEmptyText = computed(
  () => primaryFindingIsEvidenceSummary.value ? '等待形成事实结论' : '等待形成根因候选',
)
const assuranceTone = computed(() => {
  const status = evidenceAssurance.value?.status
  if (status === 'CORROBORATED') return 'safe'
  if (status === 'CONFLICTED') return 'danger'
  if (status === 'SINGLE_SOURCE' || status === 'UNSUPPORTED') return 'notice'
  return 'idle'
})
const quarantinedEvidenceCount = computed(() =>
  investigationEvidence.value.filter((item) => item.trust_level === 'QUARANTINED').length,
)
const knowledgeEvidenceCount = computed(() =>
  investigationEvidence.value.filter((item) => item.source_type === 'KNOWLEDGE').length,
)
const completedLifecycleStepCount = computed(() =>
  actionLifecycleSteps.value.filter((step) =>
    ['passed', 'completed', 'available', 'not_required'].includes(step.status),
  ).length,
)
const currentTaskMemoryCount = computed(() => {
  const taskId = store.activeTask?.id
  if (!taskId) return 0
  return store.operationalMemories.filter((memory) => memory.source_task_id === taskId).length
})
const taskObservabilitySummary = computed(() => store.taskObservability?.summary || null)
const taskObservabilityModel = computed(() => {
  const models = [...new Set(
    (store.taskObservability?.model_invocations || [])
      .map((item) => item.model)
      .filter(Boolean),
  )]
  return models.join(' / ') || '模型'
})
const investigationOutcomeText = computed(() => {
  const status = investigationRuntime.value?.status
  if (status === 'CONCLUDED') return '已形成结论'
  if (status === 'INCONCLUSIVE') return '证据不足'
  if (status === 'NEEDS_OPERATOR') return '需人工接管'
  if (status === 'CANCELLED') return '已取消'
  if (status === 'FAILED') return '调查失败'
  if (status === 'RUNNING') return '调查中'
  if (store.activeTask?.status === 'SEALED' && evidenceAssurance.value) {
    if (evidenceAssurance.value.status === 'CORROBORATED') return '已形成结论'
    if (evidenceAssurance.value.status === 'SINGLE_SOURCE') return '单一来源'
    if (evidenceAssurance.value.status === 'CONFLICTED') return '证据冲突'
    return '证据不足'
  }
  return '待调查'
})
const disposalProposal = computed(() => store.actionProposals.find((proposal) => proposal.tool_name !== 'restore_log_backup') || null)
const rollbackProposal = computed(() => store.actionProposals.find((proposal) => proposal.tool_name === 'restore_log_backup') || null)
const pendingProposal = computed(() => store.actionProposals.find((proposal) => proposal.status === 'PENDING_APPROVAL') || null)
const primaryProposal = computed(() => pendingProposal.value || [...store.actionProposals].reverse()[0] || null)
const primarySafetyCase = computed(() => {
  const proposalId = primaryProposal.value?.id
  if (!proposalId) return null
  return investigationActions.value.find((action) => action.id === proposalId)?.safety_case || null
})
const pendingRollback = computed(() => pendingProposal.value?.tool_name === 'restore_log_backup')
const latestActionCall = computed(() => {
  const actionTool = disposalProposal.value?.tool_name
  return [...store.toolCalls].reverse().find((call) => call.tool_name === actionTool)
})
const runtimeSafety = computed(() => store.runtimeSafety)
const workerRuntimeText = computed(() => {
  const runtime = store.workerRuntime
  if (!runtime) return '任务引擎检测中'
  if (runtime.overall_status === 'blocked') return '任务引擎离线'
  if (runtime.overall_status === 'warn') return `任务排队 ${runtime.queue.oldest_wait_seconds}s`
  return '任务引擎在线'
})
const workerRuntimeTone = computed(() => store.workerRuntime?.overall_status || 'idle')
const runtimeStatusText = computed(() => {
  if (runtimeSafety.value?.overall_status === 'ok') return '受限运行'
  if (runtimeSafety.value?.overall_status === 'warn') return '需关注'
  if (runtimeSafety.value?.overall_status === 'blocked') return '执行锁定'
  return '检测中'
})
const runtimeTone = computed(() => {
  if (runtimeSafety.value?.overall_status === 'ok') return 'safe'
  if (runtimeSafety.value?.overall_status === 'warn') return 'notice'
  if (runtimeSafety.value?.overall_status === 'blocked') return 'danger'
  return 'idle'
})
const executorIdentityText = computed(() => {
  const executor = runtimeSafety.value?.executor
  if (!executor) return '检测中'
  return `${executor.runtime_user} / uid ${executor.runtime_uid}`
})
const allowedBoundaryPaths = computed(() => runtimeSafety.value?.boundary.allowed_path_prefixes || [])
const allowedBoundaryTools = computed(() =>
  (runtimeSafety.value?.boundary.allowed_tools || []).map((tool) => toolLabel(tool)),
)
const protectedBoundaryPaths = computed(() => runtimeSafety.value?.boundary.protected_path_prefixes || [])
const restartableBoundaryUnits = computed(() => runtimeSafety.value?.boundary.restartable_units || [])
const repairableBoundaryPaths = computed(() => runtimeSafety.value?.boundary.repairable_config_paths || [])
const protectedBoundaryText = computed(() => {
  const prefixes = protectedBoundaryPaths.value
  if (!prefixes.length) return '-'
  return prefixes.slice(0, 5).join('，') + (prefixes.length > 5 ? ` 等 ${prefixes.length} 类` : '')
})
const protectedBoundaryPreview = computed(() => {
  if (!protectedBoundaryPaths.value.length) return '尚未读取保护目录'
  return protectedBoundaryPaths.value.slice(0, 3).join(' · ')
})
const proposalStatus = computed(() => primaryProposal.value?.status ?? '')
const proposalPending = computed(() => proposalStatus.value === 'PENDING_APPROVAL')
const disposalGateText = computed(() => {
  const status = disposalProposal.value?.status
  if (status === 'PENDING_APPROVAL') return '等待审批'
  if (status === 'EXECUTED') return '已执行'
  if (status === 'REJECTED') return '已拒绝'
  if (status === 'BLOCKED') return '已阻断'
  if (status === 'NEEDS_OPERATOR') return '待人工核验'
  return activeRisk.value
})
const disposalGateDetail = computed(() => (
  disposalProposal.value?.status === 'EXECUTED' ? rollbackStatusText.value : runtimeStatusText.value
))
const actionExecutionEnabled = computed(() => Boolean(runtimeSafety.value?.executor.action_execution_enabled))
const actionSafetyCaseReady = computed(() => primarySafetyCase.value?.status === 'READY')
const actionApprovalEnabled = computed(() => actionExecutionEnabled.value && actionSafetyCaseReady.value)
const safetyCaseStatusText = computed(() => {
  const labels: Record<string, string> = {
    READY: '校验就绪',
    APPROVED: '已批准',
    EXECUTING: '执行中',
    VERIFIED: '验证通过',
    BLOCKED: '已阻断',
    NEEDS_OPERATOR: '需人工处理',
    FAILED: '执行失败',
    REVOKED: '已撤销',
    REJECTED: '已拒绝',
  }
  return labels[primarySafetyCase.value?.status || ''] || primarySafetyCase.value?.status || '-'
})
const safetyCaseTargetText = computed(() => {
  const scope = primarySafetyCase.value?.scope
  if (!scope) return '-'
  const paths = Array.isArray(scope.paths) ? scope.paths.filter((value): value is string => typeof value === 'string') : []
  if (paths.length) return paths.join('，')
  const units = Array.isArray(scope.units) ? scope.units.filter((value): value is string => typeof value === 'string') : []
  return units.length ? units.join('，') : '-'
})
const safetyCaseHashText = computed(() => {
  const value = primarySafetyCase.value?.action_fingerprint || ''
  return value ? `${value.slice(0, 10)}…${value.slice(-6)}` : '-'
})
const safetyCaseImpact = computed<Record<string, unknown> | null>(() => {
  const value = primarySafetyCase.value?.scope?.change_impact
  return value && typeof value === 'object'
    ? value as Record<string, unknown>
    : null
})
const safetyCaseReadiness = computed<Record<string, unknown> | null>(() => {
  const value = primarySafetyCase.value?.result?.readiness
  return value && typeof value === 'object'
    ? value as Record<string, unknown>
    : null
})
const safetyCaseReadinessReason = computed(() => (
  String(safetyCaseReadiness.value?.reason || '')
))
const safetyCaseImpactText = computed(() => {
  const impact = safetyCaseImpact.value
  if (!impact) return '目标对象'
  return [
    `传播 ${Number(impact.propagated_unit_count || 0)}`,
    `连接方 ${Number(impact.possible_client_count || 0)}`,
    impact.coverage === 'FULL' ? '证据完整' : '存在缺口',
  ].join(' · ')
})
const safetyCaseImpactTitle = computed(() => {
  const rows = safetyCaseImpact.value?.predicted_units
  if (!Array.isArray(rows)) return safetyCaseImpactText.value
  const units = rows
    .filter((item): item is Record<string, unknown> => Boolean(item && typeof item === 'object'))
    .map((item) => String(item.unit || ''))
    .filter(Boolean)
  return units.length ? units.join('，') : safetyCaseImpactText.value
})
const safetyCaseImpactUnits = computed(() => {
  const rows = safetyCaseImpact.value?.predicted_units
  if (!Array.isArray(rows)) return []
  return rows
    .filter((item): item is Record<string, unknown> => Boolean(item && typeof item === 'object'))
    .map((item) => ({
      unit: String(item.unit || ''),
      role: String(item.role || ''),
      mechanism: String(item.mechanism || ''),
      certainty: String(item.certainty || ''),
    }))
    .filter((item) => item.unit)
})
const safetyCaseImpactVerification = computed<Record<string, unknown> | null>(() => {
  const value = primarySafetyCase.value?.result?.impact_verification
  return value && typeof value === 'object'
    ? value as Record<string, unknown>
    : null
})
const safetyCaseImpactPrecondition = computed<Record<string, unknown> | null>(() => {
  const value = primarySafetyCase.value?.result?.impact_precondition
  return value && typeof value === 'object'
    ? value as Record<string, unknown>
    : null
})
const safetyCaseImpactPreconditionDetails = computed<Record<string, unknown>>(() => {
  const value = safetyCaseImpactPrecondition.value?.details
  return value && typeof value === 'object'
    ? value as Record<string, unknown>
    : {}
})
const safetyCaseImpactPreconditionTone = computed(() => (
  safetyCaseImpactPrecondition.value?.outcome === 'CONFIRMED' ? 'safe' : 'danger'
))
const safetyCaseImpactPreconditionLabel = computed(() => (
  safetyCaseImpactPrecondition.value?.outcome === 'CONFIRMED'
    ? '审批范围未漂移'
    : '执行依据已失效'
))
const safetyCaseImpactPreconditionStats = computed(() => {
  const details = safetyCaseImpactPreconditionDetails.value
  return [
    `冻结 ${Number(details.predicted_unit_count || 0)}`,
    `复测 ${Number(details.observed_unit_count || 0)}`,
    `偏差 ${Number(details.prediction_error_count || 0)}`,
  ].join(' · ')
})
const safetyCaseImpactVerificationDetails = computed<Record<string, unknown>>(() => {
  const value = safetyCaseImpactVerification.value?.details
  return value && typeof value === 'object'
    ? value as Record<string, unknown>
    : {}
})
const safetyCaseImpactVerificationTone = computed(() => {
  const outcome = String(safetyCaseImpactVerification.value?.outcome || '')
  if (outcome === 'CONFIRMED') return 'safe'
  if (outcome === 'DIVERGED') return 'danger'
  return 'notice'
})
const safetyCaseImpactVerificationLabel = computed(() => {
  const outcome = String(safetyCaseImpactVerification.value?.outcome || '')
  if (outcome === 'CONFIRMED') return '预测已证实'
  if (outcome === 'DIVERGED') return '发现预测偏差'
  if (outcome === 'INCONCLUSIVE') return '证据仍不完整'
  return '等待执行后核验'
})
const safetyCaseImpactVerificationStats = computed(() => {
  const details = safetyCaseImpactVerificationDetails.value
  return [
    `预测 ${Number(details.predicted_unit_count || 0)}`,
    `实测 ${Number(details.observed_unit_count || 0)}`,
    `偏差 ${Number(details.prediction_error_count || 0)}`,
  ].join(' · ')
})
const approveButtonText = computed(() => {
  if (primarySafetyCase.value?.status === 'BLOCKED') return '影响证据未闭合'
  if (!actionExecutionEnabled.value) return '执行锁定'
  if (!actionSafetyCaseReady.value) return '校验未就绪'
  return pendingRollback.value ? '执行回滚' : '批准执行'
})
const rejectButtonText = computed(() => (pendingRollback.value ? '保留现状' : '拒绝执行'))
const approvalResult = computed(() => {
  if (!primaryProposal.value) return '当前任务暂无待审批处置'
  if (proposalStatus.value === 'PENDING_APPROVAL') return pendingRollback.value ? '等待回滚确认' : '等待人工审批'
  if (proposalStatus.value === 'EXECUTED') return primaryProposal.value.tool_name === 'restore_log_backup' ? '已完成回滚' : '已批准并执行'
  if (proposalStatus.value === 'REJECTED') return primaryProposal.value.tool_name === 'restore_log_backup' ? '保留当前结果' : '已拒绝执行'
  if (proposalStatus.value === 'BLOCKED') return '已阻断执行'
  if (proposalStatus.value === 'NEEDS_OPERATOR') return '结果待人工核验'
  return statusLabel(proposalStatus.value)
})
const rollbackStatusText = computed(() => {
  const dispositionStatus = disposalProposal.value?.status
  if (dispositionStatus === 'REJECTED') return '无需回滚'
  if (dispositionStatus === 'BLOCKED') return '已阻断'
  if (dispositionStatus === 'NEEDS_OPERATOR') return '待人工核验'
  const status = investigationRollback.value?.status
  if (status === 'available') return '可回滚'
  if (status === 'restored') return '已回滚'
  if (status === 'declined') return '保留现状'
  if (status === 'blocked') return '已阻断'
  if (status === 'needs_operator') return '待人工核验'
  if (status === 'approval_required') return '待执行'
  if (status === 'not_required') return '无需回滚'
  return rollbackProposal.value ? statusLabel(rollbackProposal.value.status) : '待生成'
})
const rollbackSummary = computed(() => {
  const dispositionStatus = disposalProposal.value?.status
  if (dispositionStatus === 'REJECTED') return '审批已拒绝，变更类工具未运行，无需回滚。'
  if (dispositionStatus === 'BLOCKED') return '处置被安全策略阻断，系统未完成变更。'
  if (dispositionStatus === 'NEEDS_OPERATOR') return '动作结果尚未确认，系统不会自动重试；请核对执行证据。'
  if (investigationRollback.value?.summary) return investigationRollback.value.summary
  if (dispositionStatus === 'EXECUTED') {
    const observation = latestActionCall.value?.output.observations?.[0]
    const artifact = latestActionCall.value?.output.artifacts?.[0]
    const artifactPath = artifact && typeof artifact.path === 'string' ? artifact.path : ''
    const reclaimed = observation && typeof observation === 'object' && 'reclaimed_bytes' in observation
      ? Number((observation as Record<string, unknown>).reclaimed_bytes || 0)
      : 0
    if (artifactPath) {
      return `已生成备份，源日志已截断${reclaimed ? `，释放约 ${formatSize(reclaimed)}` : ''}；需要回滚时从备份恢复。`
    }
    return '已执行可逆处置，执行证据已写入审计链。'
  }
  return disposalProposal.value?.reason || '当前任务没有可回滚动作。'
})
const rollbackArtifactPath = computed(() => investigationRollback.value?.artifact_path || '-')
const caseTitle = computed(() => {
  if (store.activeTask?.intent === 'disk_pressure_analysis') return '分析磁盘空间'
  if (store.activeTask?.intent === 'network_exposure_analysis') return '检查主机端口暴露'
  if (store.activeTask?.intent === 'process_health_analysis') return '排查进程资源异常'
  if (store.activeTask?.intent === 'log_analysis') return '分析系统日志与服务状态'
  if (store.activeTask?.intent === 'service_degradation_analysis') return '定位服务退化根因'
  if (store.activeTask?.intent === 'config_integrity_analysis') return '检查关键配置漂移'
  return '安全运维会话'
})
const dialogueTasksForView = computed(() => {
  if (store.dialogueTasks.length) return store.dialogueTasks
  return store.activeTask ? [store.activeTask] : []
})
const latestConversationTasks = computed(() => {
  const seen = new Set<string>()
  return store.tasks.filter((task) => {
    const key = task.conversation_id || `task:${task.id}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
})
const readableSummary = computed(() => {
  const summary = store.activeTask?.summary
  if (!summary) return '等待任务摘要生成'
  return summary
})
const serviceRelationshipSnapshot = computed<Record<string, unknown> | null>(() => {
  const snapshots = store.toolCalls
    .filter((item) => item.tool_name === 'service_dependency_snapshot')
    .flatMap((item) => item.output.observations || [])
    .filter((item): item is Record<string, unknown> => Boolean(item && typeof item === 'object'))
  return mergeRelationshipSnapshots(snapshots)
})
const relationshipCoverageText = computed(() => {
  const snapshot = serviceRelationshipSnapshot.value
  if (!snapshot) return '等待关系采样'
  const gaps = Array.isArray(snapshot.evidence_gaps) ? snapshot.evidence_gaps.length : 0
  return gaps ? `${gaps} 项证据缺口` : '关系归属完整'
})
const relationshipScopeText = computed(() => {
  const snapshot = serviceRelationshipSnapshot.value
  if (!snapshot) return '当前任务尚未调用关系采集工具'
  const ports = Array.isArray(snapshot.focus_ports)
    ? snapshot.focus_ports.filter((value): value is number => typeof value === 'number')
    : []
  const units = Array.isArray(snapshot.focus_units)
    ? snapshot.focus_units.filter((value): value is string => typeof value === 'string')
    : []
  if (units.length) return units.join('、')
  if (ports.length) return `端口 ${ports.join('、')}`
  return '主机可观测范围'
})
const relationshipStatsText = computed(() => {
  const snapshot = serviceRelationshipSnapshot.value
  if (!snapshot) return '进程、端口与调用边将在取证后出现'
  return [
    `${Number(snapshot.process_count || 0)} 进程`,
    `${Number(snapshot.listener_count || 0)} 监听`,
    `${Number(snapshot.connection_relation_count || 0)} 调用`,
  ].join(' · ')
})
const investigationFocus = computed(() => {
  if (store.investigationLoading) {
    return {
      label: '当前调查对象',
      title: '正在加载任务证据',
      detail: '读取会话、系统观测与运行关系',
      graph: 'decision' as const,
    }
  }

  if (serviceRelationshipSnapshot.value) {
    return {
      label: `运行关系 · ${relationshipScopeText.value}`,
      title: relationshipCoverageText.value,
      detail: relationshipStatsText.value,
      graph: 'runtime' as const,
    }
  }

  const task = store.activeTask
  const assurance = evidenceAssurance.value?.status_label || '待核验'
  const evidenceDetail = `${store.toolCalls.length} 次采样 · ${investigationEvidence.value.length} 条证据`
  if (!task) {
    return {
      label: '调查对象',
      title: '等待运维请求',
      detail: '提交请求后绑定实际系统对象',
      graph: 'decision' as const,
    }
  }

  if (task.intent === 'network_exposure_analysis') {
    const socketCalls = store.toolCalls.filter((call) => call.tool_name === 'socket_process_context')
    const ports = [...new Set(
      socketCalls
        .map((call) => Number(call.input.port))
        .filter((port) => Number.isInteger(port) && port > 0),
    )]
    const listenerCount = socketCalls.reduce((total, call) => {
      const observation = call.output.observations?.[0]
      if (!observation || typeof observation !== 'object') return total
      return total + Number((observation as Record<string, unknown>).listener_count || 0)
    }, 0)
    return {
      label: ports.length ? `目标端口 · ${ports.join('、')}` : '网络暴露面',
      title: ports.length ? (listenerCount ? `${listenerCount} 个监听实例` : '当前未监听') : assurance,
      detail: evidenceDetail,
      graph: 'decision' as const,
    }
  }

  if (task.intent === 'process_health_analysis') {
    const exactCall = [...store.toolCalls]
      .reverse()
      .find((call) => call.tool_name === 'process_runtime_detail')
    const exactPid = Number(exactCall?.input.pid)
    const summaryMatch = task.summary?.match(/重点进程：([^（]+)（PID\s*(\d+)/)
    const target = Number.isInteger(exactPid) && exactPid > 0
      ? `PID ${exactPid}`
      : summaryMatch
        ? `${summaryMatch[1]} · PID ${summaryMatch[2]}`
        : '进程与资源'
    const observation = exactCall?.output.observations?.[0]
    const exists = observation && typeof observation === 'object'
      ? (observation as Record<string, unknown>).exists
      : undefined
    return {
      label: `调查对象 · ${target}`,
      title: exists === false ? '目标已退出' : assurance,
      detail: evidenceDetail,
      graph: 'decision' as const,
    }
  }

  if (task.intent === 'config_integrity_analysis') {
    const checks = store.toolCalls.filter((call) => call.tool_name === 'config_baseline_check')
    const paths = checks.flatMap((call) => Array.isArray(call.input.paths) ? call.input.paths : [])
    return {
      label: `配置核验${paths.length ? ` · ${paths.length} 个路径` : ''}`,
      title: assurance,
      detail: evidenceDetail,
      graph: 'decision' as const,
    }
  }

  if (task.intent === 'disk_pressure_analysis') {
    return {
      label: '存储与占用对象',
      title: assurance,
      detail: evidenceDetail,
      graph: 'decision' as const,
    }
  }

  return {
    label: '当前调查对象',
    title: assurance,
    detail: evidenceDetail,
    graph: 'decision' as const,
  }
})
const showOperationalAttachments = computed(() => Boolean(
  store.activeTask
  && store.activeTask.intent !== 'agent_capability_help'
  && (
    store.events.some((event) => ['intent_resolved', 'skill_selected', 'plan_created', 'tool_call'].includes(event.event_type))
    || store.toolCalls.length > 0
    || store.actionProposals.length > 0
  ),
))
const contextualPrompts = computed(() => {
  const suggestions: Array<{ label: string; prompt: string; source: string }> = []
  const primaryClaim = evidenceAssurance.value?.claims[0]
  if (primaryClaim?.status === 'CONFLICTED') {
    suggestions.push({
      label: '核对冲突证据',
      prompt: `围绕“${primaryClaim.title}”追加独立观测，解释支持证据与反证为何冲突`,
      source: '当前任务',
    })
  } else if (primaryClaim?.status === 'SINGLE_SOURCE') {
    suggestions.push({
      label: '补充交叉核验',
      prompt: `为“${primaryClaim.title}”补充另一类独立证据，并重新判断结论是否成立`,
      source: '当前任务',
    })
  } else if (primaryClaim?.status === 'UNSUPPORTED') {
    suggestions.push({
      label: '补齐证据缺口',
      prompt: `继续调查“${primaryClaim.title}”，只使用可验证的系统观测补齐证据缺口`,
      source: '当前任务',
    })
  }

  if (pendingProposal.value) {
    suggestions.push({
      label: '复核处置影响',
      prompt: '复核当前待审批动作的影响范围、执行前条件、回滚产物和执行后验证项',
      source: '审批待办',
    })
  } else if (store.activeTask?.status === 'SEALED' && primaryHypothesis.value) {
    suggestions.push({
      label: '检查影响范围',
      prompt: `基于当前证据继续检查“${primaryHypothesis.value.title}”对关联服务的影响范围`,
      source: '当前任务',
    })
  }

  for (const item of store.operatorContext?.prompt_suggestions || []) {
    suggestions.push({
      label: item.label,
      prompt: item.prompt,
      source: item.source,
    })
  }

  const openIncident = store.patrolIncidents.items.find(
    (incident) => incident.status === 'OPEN' || incident.status === 'INVESTIGATING',
  )
  if (openIncident) {
    suggestions.push({
      label: openIncident.title,
      prompt: `调查事件“${openIncident.title}”：${openIncident.summary}`,
      source: '未闭环事件',
    })
  }

  for (const action of postureNextActions.value.slice(0, 2)) {
    suggestions.push({
      label: action.label,
      prompt: action.prompt,
      source: '实时态势',
    })
  }

  if (!suggestions.length) {
    suggestions.push(
      {
        label: '服务退化',
        prompt: '检查关键服务及其依赖关系，定位响应变慢或健康检查失败的根因',
        source: '常用调查',
      },
      {
        label: '配置漂移',
        prompt: '检查关键配置是否偏离已确认基线，并评估关联服务影响',
        source: '常用调查',
      },
      {
        label: '暴露面核查',
        prompt: '检查当前主机监听端口、进程归属和不必要的网络暴露',
        source: '常用调查',
      },
    )
  }

  const seen = new Set<string>()
  return suggestions
    .filter((item) => {
      if (seen.has(item.prompt)) return false
      seen.add(item.prompt)
      return true
    })
    .slice(0, 3)
})

const riskTone = computed(() => {
  if (activeRisk.value === 'R4') return 'danger'
  if (activeRisk.value === 'R3') return 'warning'
  if (activeRisk.value === 'R2') return 'notice'
  return 'safe'
})
const planRows = computed(() => {
  const stopped = ['FAILED', 'REJECTED', 'BLOCKED', 'NEEDS_OPERATOR', 'CANCELLED'].includes(activeStatus.value)
  const sealed = activeStatus.value === 'SEALED'
  const perceived = store.events.some((event) => event.stage === 'PERCEIVE')
  const proposalStatus = disposalProposal.value?.status
  const hasProposal = Boolean(proposalStatus)
  const readOnlySealed = sealed && !hasProposal
  const proposalExecuted = proposalStatus === 'EXECUTED'
  const proposalPending = proposalStatus === 'PENDING_APPROVAL'
  const proposalRejected = proposalStatus === 'REJECTED'
  const proposalBlocked = proposalStatus === 'BLOCKED'
  const proposalClosed = proposalExecuted || proposalRejected || proposalBlocked
  return [
    { step: 1, title: '环境感知', status: perceived ? '已完成' : stopped ? '未执行' : '待执行', active: perceived },
    { step: 2, title: '风险评估', status: review.value ? '已完成' : stopped ? '未执行' : '待执行', active: Boolean(review.value) },
    {
      step: 3,
      title: '生成处置方案',
      status: hasProposal ? '已生成' : readOnlySealed ? '无需处置' : stopped ? '未生成' : '待生成',
      active: hasProposal,
    },
    {
      step: 4,
      title: '审批执行',
      status: proposalExecuted
        ? '已完成'
        : proposalRejected
          ? '已拒绝'
          : proposalBlocked
            ? '已阻断'
            : proposalPending
              ? '等待审批'
              : readOnlySealed
                ? '无需审批'
              : stopped
                ? '未执行'
                : '待执行',
      active: proposalClosed || proposalPending,
    },
    {
      step: 5,
      title: '验证报告',
      status: activeStatus.value === 'SEALED' ? '已封存' : stopped ? '已停止' : proposalPending ? '待审批' : '待执行',
      active: activeStatus.value === 'SEALED' && !proposalPending,
    },
  ]
})
const livePosture = computed(() => store.livePosture)
const hostSnapshot = computed<Record<string, any>>(() => {
  if (livePosture.value?.snapshot && Object.keys(livePosture.value.snapshot).length) {
    return livePosture.value.snapshot as Record<string, any>
  }
  return observationsOf('system_snapshot')[0] ?? {}
})
const diskRows = computed<Array<Record<string, any>>>(() => {
  if (livePosture.value?.disks?.length) return livePosture.value.disks as Array<Record<string, any>>
  return observationsOf('disk_usage')
})
const rootDisk = computed(() => diskRows.value.find((row) => row.path === '/') ?? diskRows.value[0])
const liveNetworkRows = computed<Array<Record<string, any>>>(() => {
  if (livePosture.value?.network_listeners?.length) return livePosture.value.network_listeners as Array<Record<string, any>>
  return observationsOf('network_listeners')
})
const liveProcessRows = computed<Array<Record<string, any>>>(() => {
  if (livePosture.value?.processes?.length) return livePosture.value.processes as Array<Record<string, any>>
  return observationsOf('process_list')
})
const liveToolRuns = computed(() => livePosture.value?.tool_runs || [])
const postureSignals = computed(() => livePosture.value?.signals || [])
const postureNextActions = computed(() => livePosture.value?.next_actions || [])
const postureBaseline = computed(() => livePosture.value?.baseline || null)
const postureBaselineSpanMinutes = computed(() => {
  const metrics = Object.values(postureBaseline.value?.metrics || {})
  return metrics.reduce((longest, metric) => Math.max(longest, metric.sample_span_minutes || 0), 0)
})
const networkListenerCount = computed(() => liveNetworkRows.value.length)
const failedToolCount = computed(() => {
  if (liveToolRuns.value.length) return liveToolRuns.value.filter((call) => call.status !== 'ok').length
  return store.toolCalls.filter((call) => call.status !== 'ok').length
})
const postureStatusText = computed(() => {
  if (!livePosture.value) return '待采样'
  if (livePosture.value.status === 'ok') return '正常'
  if (livePosture.value.status === 'warn') return '关注'
  return '异常'
})
const liveToolHealthText = computed(() => {
  if (!liveToolRuns.value.length) return '-'
  const okCount = liveToolRuns.value.filter((item) => item.status === 'ok').length
  return `${okCount}/${liveToolRuns.value.length}`
})
const postureScoreText = computed(() => {
  if (!liveToolRuns.value.length) return '-'
  const okCount = liveToolRuns.value.filter((item) => item.status === 'ok').length
  return `${Math.round((okCount / liveToolRuns.value.length) * 100)}%`
})
const memoryUsedPercent = computed(() => {
  const used = hostSnapshot.value.memory?.used_percent
  return typeof used === 'number' ? Math.max(0, Math.min(100, used)) : null
})
const rootDiskUsedPercent = computed(() => {
  const used = rootDisk.value?.used_percent
  return typeof used === 'number' ? Math.max(0, Math.min(100, used)) : null
})
const visibleProcessRows = computed(() => liveProcessRows.value.slice(0, 2))
const visibleNetworkRows = computed(() => liveNetworkRows.value.slice(0, 3))
const attributedListenerCount = computed(() => {
  return liveNetworkRows.value.filter((row) => typeof row.pid === 'number').length
})
const exposedListenerCount = computed(() => {
  return liveNetworkRows.value.filter((row) => ['wildcard', 'public', 'unknown'].includes(String(row.exposure_scope || 'unknown'))).length
})
const unattributedListenerCount = computed(() => {
  return liveNetworkRows.value.filter((row) => typeof row.pid !== 'number').length
})
const deploymentChecks = computed(() => {
  const checks = store.deploymentReadiness?.checks || []
  const priority = ['os', 'arch', 'database', 'executor', 'mcp', 'model', 'frontend', 'tools']
  const priorityRank = (key: string) => {
    const index = priority.indexOf(key)
    return index >= 0 ? index : priority.length
  }
  return [...checks]
    .sort((left, right) => {
      const leftRisk = left.status === 'blocked' ? 0 : left.status === 'warn' ? 1 : 2
      const rightRisk = right.status === 'blocked' ? 0 : right.status === 'warn' ? 1 : 2
      if (leftRisk !== rightRisk) return leftRisk - rightRisk
      return priorityRank(left.key) - priorityRank(right.key)
    })
    .slice(0, 5)
})
const latestConfigBaseline = computed(() => store.configBaselines[0] ?? null)
const latestConfigCheck = computed(() => latestConfigBaseline.value?.latest_check ?? null)
const configDriftCount = computed(() => latestConfigCheck.value?.summary.changed ?? 0)
const visibleConfigChanges = computed(() => latestConfigCheck.value?.changes.slice(0, 4) ?? [])
const configBaselineStatusText = computed(() => {
  if (!latestConfigBaseline.value) return '尚未建立'
  if (!latestConfigCheck.value) return '等待首次核验'
  if (latestConfigCheck.value.status === 'clean') return '未发现漂移'
  if (latestConfigCheck.value.status === 'drifted') return '发现配置漂移'
  return '核验不完整'
})
const postureCapacityForecast = computed(() => postureBaseline.value?.capacity_forecast ?? null)
const postureSummaryCards = computed(() => [
  { label: 'CPU 负载', value: loadText(), meta: '1 分钟', tone: 'blue' },
  { label: '内存使用', value: memoryText(), meta: 'MemAvailable', tone: memoryUsedPercent.value !== null && memoryUsedPercent.value > 85 ? 'red' : 'cyan' },
  { label: '根分区', value: rootDiskText(), meta: rootDisk.value?.path || '/', tone: rootDiskUsedPercent.value !== null && rootDiskUsedPercent.value > 85 ? 'red' : 'blue' },
  {
    label: '监听端口',
    value: String(networkListenerCount.value || 0),
    meta: exposedListenerCount.value
      ? `${exposedListenerCount.value} 个高风险范围`
      : unattributedListenerCount.value
        ? `${unattributedListenerCount.value} 个未归属`
        : '范围正常',
    tone: exposedListenerCount.value || unattributedListenerCount.value ? 'violet' : 'green',
  },
  {
    label: '动态基线',
    value: postureBaseline.value?.status === 'ready'
      ? postureBaseline.value.anomalies.length
        ? `${postureBaseline.value.anomalies.length} 项偏离`
        : '未偏离'
      : '采集中',
    meta: postureCapacityForecast.value
      ? `${postureCapacityForecast.value.hours_to_threshold} 小时至 ${postureCapacityForecast.value.threshold_percent}%`
      : postureBaseline.value?.status === 'ready'
        ? `${postureBaseline.value.sample_count} 个样本 · ${postureBaselineSpanMinutes.value || '<1'} 分钟`
        : `${postureBaseline.value?.sample_count ?? 0}/${postureBaseline.value?.minimum_sample_count ?? 12} 个样本`,
    tone: postureBaseline.value?.anomalies.some((item) => item.status === 'critical')
      ? 'red'
      : postureBaseline.value?.anomalies.length
        ? 'violet'
        : 'green',
  },
])
function postureToolNode(toolName: string, key: string, label: string) {
  const run = liveToolRuns.value.find((item) => item.tool_name === toolName)
  return {
    key,
    label,
    value: run ? `${run.duration_ms}ms` : '未采样',
    status: run?.status === 'ok' ? 'ok' : 'warn',
  }
}
const postureRadarNodes = computed(() => [
  postureToolNode('system_snapshot', 'system', '系统'),
  postureToolNode('disk_usage', 'disk', '磁盘'),
  postureToolNode('network_listeners', 'network', '网络'),
  postureToolNode('process_list', 'process', '进程'),
  {
    key: 'config',
    label: '配置',
    value: latestConfigCheck.value ? `${configDriftCount.value} 变化` : '待核验',
    status: configDriftCount.value ? 'warn' : 'ok',
  },
])
const postureAttentionItems = computed(() => {
  if (postureSignals.value.length) {
    const rank = { critical: 0, warn: 1, ok: 2 }
    return [...postureSignals.value]
      .sort((left, right) => rank[left.status] - rank[right.status])
      .map((signal) => ({
        key: signal.key,
        title: `${signal.title} · ${signal.metric}`,
        detail: signal.detail,
        tone: signal.status === 'critical' ? 'bad' : signal.status === 'warn' ? 'warn' : 'ok',
      }))
      .slice(0, 3)
  }
  const items: Array<{ key: string; title: string; detail: string; tone: string }> = []
  for (const check of deploymentChecks.value.filter((item) => item.status !== 'ok')) {
    items.push({
      key: `deployment-${check.key}`,
      title: check.name,
      detail: check.detail,
      tone: check.status === 'blocked' ? 'bad' : 'warn',
    })
  }
  if (rootDiskUsedPercent.value !== null && rootDiskUsedPercent.value > 85) {
    items.push({ key: 'disk', title: '根分区压力', detail: `当前使用率 ${rootDiskText()}`, tone: 'bad' })
  }
  if (memoryUsedPercent.value !== null && memoryUsedPercent.value > 85) {
    items.push({ key: 'memory', title: '内存压力', detail: `当前使用率 ${memoryText()}`, tone: 'warn' })
  }
  if (failedToolCount.value) {
    items.push({ key: 'mcp', title: '感知工具异常', detail: `${failedToolCount.value} 个工具未正常返回`, tone: 'bad' })
  }
  if (configDriftCount.value) {
    items.push({ key: 'config', title: '配置发生漂移', detail: `${configDriftCount.value} 个路径发生变化`, tone: 'warn' })
  }
  if (exposedListenerCount.value) {
    items.push({ key: 'network', title: '监听范围风险', detail: `${exposedListenerCount.value} 个监听地址需要确认暴露范围`, tone: 'info' })
  } else if (unattributedListenerCount.value) {
    items.push({ key: 'network', title: '端口归属缺口', detail: `${unattributedListenerCount.value} 个监听端口缺少进程归属`, tone: 'info' })
  }
  if (!items.length) {
    items.push({ key: 'healthy', title: '暂无高优先级异常', detail: `最近采样 ${sampleClock(livePosture.value?.collected_at)}`, tone: 'ok' })
  }
  return items.slice(0, 3)
})
const riskCounts = computed(() => {
  return store.safetyReviews.reduce<Record<string, number>>((acc, item) => {
    acc[item.risk_level] = (acc[item.risk_level] ?? 0) + 1
    return acc
  }, {})
})
const toolRiskCounts = computed(() => {
  return store.tools.reduce<Record<string, number>>((acc, item) => {
    acc[item.risk_level] = (acc[item.risk_level] ?? 0) + 1
    return acc
  }, {})
})
const toolRuntimeVerifiedCount = computed(() => {
  return store.tools.filter((tool) => tool.integrity?.status === 'VERIFIED').length
})
const availableToolCount = computed(() => {
  return store.tools.filter((tool) => tool.availability?.available !== false).length
})
const unavailableToolCount = computed(() => store.tools.length - availableToolCount.value)
const platformCapabilityCount = computed(() => {
  const summary = store.platformCapabilities?.summary
  if (!summary) return { ready: 0, total: 0 }
  return {
    ready: summary.supported,
    total: summary.supported + summary.degraded + summary.unavailable,
  }
})
const mcpStatus = computed(() => store.mcpStatus)
const mcpProtocolText = computed(() => mcpStatus.value?.protocol_version || '-')
const mcpToolCountText = computed(() => {
  if (!mcpStatus.value?.available) return '-'
  return `${mcpStatus.value.tool_count}`
})
const mcpReadOnlyText = computed(() => {
  if (!mcpStatus.value?.available) return '-'
  if (unavailableToolCount.value) {
    return `${availableToolCount.value} 可用 · ${unavailableToolCount.value} 禁用`
  }
  return `${mcpStatus.value.read_only_count} 个只读`
})
const mcpActionText = computed(() => {
  if (!mcpStatus.value?.available) return '-'
  return `${mcpStatus.value.action_count} 个需审批`
})
const mcpStatusText = computed(() => (mcpStatus.value?.available ? '端点可用' : '端点异常'))
const mcpStatusTone = computed(() => (mcpStatus.value?.available ? 'safe' : 'danger'))
const alertCount = computed(() => store.patrolOverview?.open_incident_count ?? 0)
const todoCount = computed(() => store.pendingApprovals.length)
const sidebarTasks = computed(() => {
  const query = taskQuery.value.trim().toLowerCase()
  const tasks = query
    ? latestConversationTasks.value.filter((task) => {
        return [task.user_input, taskSummaryText(task), taskIntentLabel(task), statusLabel(task.status), task.risk_level]
          .join(' ')
          .toLowerCase()
          .includes(query)
      })
    : latestConversationTasks.value
  return tasks.slice(0, 2)
})
const pagedSessions = computed(() => {
  const start = (sessionPage.value - 1) * sessionPageSize
  return latestConversationTasks.value.slice(start, start + sessionPageSize)
})
const selectedScenario = computed(
  () => scenarioTemplates.value[selectedScenarioIndex.value] ?? scenarioTemplates.value[0] ?? null,
)
const selectedScenarioState = computed(() => labScenarioState(selectedScenario.value?.labId))
const selectedScenarioResult = computed(() => {
  const scenarioId = selectedScenario.value?.labId
  if (!scenarioId) return null
  return store.labScenarioResults[scenarioId]
    ?? store.labEvaluationReport?.cases.find((item) => item.scenario_id === scenarioId)
    ?? null
})
const selectedScenarioFacts = computed(() => {
  const item = selectedScenario.value
  const scenario = selectedScenarioState.value
  if (!item) return []
  const result = selectedScenarioResult.value
  if (result) {
    const facts = [
      { label: '验证结果', value: result.supported ? (result.passed ? '通过' : '未通过') : '前置缺失' },
      { label: '链路结论', value: labEvaluationResult(result) },
      {
        label: '证据覆盖',
        value: result.evaluation_kind === 'controller_policy'
          ? '策略裁决'
          : evaluationRate(result.metrics?.evidence_coverage),
      },
      { label: '样本清理', value: scenarioCleanupLabel(result) },
    ]
    if (result.metrics?.root_cause_evaluated) {
      facts.splice(2, 0,
        {
          label: '根因定位',
          value: result.metrics.fault_localization_match ? '命中' : '未命中',
        },
        {
          label: '因果链',
          value: evaluationRate(result.metrics.causal_chain_coverage),
        },
        {
          label: '反证覆盖',
          value: evaluationRate(result.metrics.counter_evidence_coverage),
        },
      )
    }
    if (result.metrics?.change_impact_evaluated) {
      facts.splice(2, 0,
        {
          label: '影响精度',
          value: evaluationRate(result.metrics.change_impact_precision),
        },
        {
          label: '影响召回',
          value: evaluationRate(result.metrics.change_impact_recall),
        },
        {
          label: '无据影响',
          value: String(result.metrics.unsupported_impact_count ?? 0),
        },
      )
    }
    return facts
  }
  if (item.labId === 'service-change-impact') {
    return [
      { label: '变更目标', value: 'opsbench-impact-root.service' },
      { label: '传播关系', value: 'PartOf' },
      { label: '排除关系', value: 'After' },
      { label: '判定依据', value: scenario?.oracle.assertion || 'systemd 单元关系' },
    ]
  }
  if (item.category === 'service') {
    const activeState = scenario?.metadata?.ActiveState
    const serviceState = scenario?.status === 'unsupported' || scenario?.status === 'error'
      ? scenarioStatusReason(scenario)
      : typeof activeState === 'string'
        ? activeState
        : scenarioStateLabel(item)
    return [
      { label: '验证对象', value: 'opscouncil-lab-failed.service' },
      { label: '单元状态', value: serviceState },
      { label: '采集工具', value: item.tools.join('、') },
      { label: '判定依据', value: scenario?.oracle.assertion || 'systemd 状态与结果字段' },
    ]
  }
  if (!item.setupRequired) {
    return [
      { label: '裁决方式', value: '安全护栏' },
      { label: '样本准备', value: '无需准备' },
      { label: '工具调用', value: item.risk === 'R4' ? '应为 0' : '按需只读' },
      { label: '判定依据', value: scenario?.oracle.assertion || '调查控制器策略' },
    ]
  }
  return [
    { label: '样本状态', value: scenarioStateLabel(item) },
    { label: '证据位置', value: scenario?.artifact_path || '未准备' },
    { label: '样本指标', value: labStateMetric(scenario) },
    { label: '资源上限', value: scenarioResourceBudget(scenario) },
  ]
})
const auditEntries = computed(() => store.auditVerification?.entries || [])
const auditReplay = computed(() => store.auditReplay)
const auditReplayStages = computed(() => auditReplay.value?.stages || [])
const auditReplayEvents = computed(() =>
  auditReplayStages.value
    .flatMap((stage) => stage.events)
    .sort((left, right) => left.order - right.order),
)
const auditDecisionPoints = computed(() => auditReplay.value?.decision_points || [])
const pagedAuditEntries = computed(() => {
  const start = (auditPage.value - 1) * auditPageSize
  return auditEntries.value.slice(start, start + auditPageSize)
})
const auditTimelineRows = computed(() => {
  if (auditReplayEvents.value.length) {
    return auditReplayEvents.value.map((event) => ({
      id: event.event_id,
      order: event.order,
      stage: stageLabel(event.stage),
      event: event.label,
      component: toolLabel(event.component),
      message: formatEventMessage(event.message),
      valid: event.valid,
      hash: event.hash,
      createdAt: formatDateTime(event.created_at),
    }))
  }
  return store.events.map((event, index) => {
    const entry = auditEntries.value.find((item) => item.event_id === event.id)
    return {
      id: event.id,
      order: index + 1,
      stage: stageLabel(event.stage),
      event: eventTypeLabel(event.event_type),
      component: typeof event.payload?.tool_name === 'string' ? toolLabel(event.payload.tool_name) : '运维 Agent',
      message: formatEventMessage(event.message),
      valid: entry?.valid ?? null,
      hash: entry ? shortHash(entry.stored_event_hash) : '-',
      createdAt: formatDateTime(event.created_at),
    }
  })
})
const auditLastStage = computed(() => auditReplay.value?.current_stage || auditTimelineRows.value.at(-1)?.stage || '-')
const auditIntegrityStatus = computed(() => {
  if (!auditReplay.value) return '等待校验'
  if (auditReplay.value.integrity.failed_event_count > 0) return '发现异常'
  return auditReplay.value.integrity.valid ? '链路可信' : '等待校验'
})
const auditPolicyStatusText = computed(() => {
  const status = auditReplay.value?.policy_replay?.status
  if (status === 'consistent') return '当前策略一致'
  if (status === 'drifted') return '发现策略变化'
  if (status === 'partial') return '部分可复核'
  return '暂无可复核裁决'
})
const benchmarkMetrics = computed(() => store.benchmarkReport?.metrics || [])
const agentEvaluationCases = computed(() => store.agentEvaluationReport?.cases || [])
const agentEvaluationSummary = computed(() => store.agentEvaluationReport?.summary ?? null)
const labEvaluationCases = computed(() => store.labEvaluationReport?.cases || [])
const labEvaluationSummary = computed(() => store.labEvaluationReport?.summary ?? null)
const safetyEvaluationCases = computed(() => store.safetyEvaluationReport?.cases || [])
const safetyEvaluationSummary = computed(() => store.safetyEvaluationReport?.summary ?? null)
const safetyRuleRows = computed(() => {
  const rank: Record<string, number> = { R4: 0, R3: 1, R2: 2, R1: 3, R0: 4 }
  return [...store.safetyRules].sort((left, right) => {
    const riskOrder = (rank[left.risk_level] ?? 9) - (rank[right.risk_level] ?? 9)
    return riskOrder || left.category.localeCompare(right.category, 'zh-CN')
  })
})
const safetyGuardRows = computed(() => store.runtimeSafety?.guards || [])
const agentAttackBlockRateText = computed(() => {
  if (!agentEvaluationSummary.value) return '-'
  return `${Math.round(agentEvaluationSummary.value.attack_block_rate * 100)}%`
})
const agentPolicyPassText = computed(() => {
  if (!agentEvaluationSummary.value) return '-'
  return `${agentEvaluationSummary.value.policy_pass_count} / ${agentEvaluationSummary.value.planned_case_count}`
})
const agentEvalStatusText = computed(() => {
  if (!agentEvaluationSummary.value) return '未运行'
  return agentEvaluationSummary.value.overall_status === 'ok' ? '通过' : '未通过'
})
const labEvalStatusText = computed(() => {
  if (!labEvaluationSummary.value) return '未运行'
  if (labEvaluationSummary.value.qualification_status === 'prerequisite_missing') return '前置条件缺失'
  return labEvaluationSummary.value.overall_status === 'ok' ? '通过' : '未通过'
})
const safetyAttackBlockRateText = computed(() => {
  if (!safetyEvaluationSummary.value) return '-'
  return `${Math.round(safetyEvaluationSummary.value.attack_block_rate * 100)}%`
})
const safetyDynamicBlockRateText = computed(() => {
  const rate = safetyEvaluationSummary.value?.dynamic_block_rate
  if (typeof rate !== 'number') return '-'
  return `${Math.round(rate * 100)}%`
})
const safetyDataQuarantineRateText = computed(() => {
  const rate = safetyEvaluationSummary.value?.data_quarantine_rate
  if (typeof rate !== 'number') return '-'
  return `${Math.round(rate * 100)}%`
})
const safetyCrossTurnBlockRateText = computed(() => {
  const rate = safetyEvaluationSummary.value?.cross_turn_block_rate
  if (typeof rate !== 'number') return '-'
  return `${Math.round(rate * 100)}%`
})
const safetyEvalStatusText = computed(() => {
  if (!safetyEvaluationSummary.value) return '未运行'
  return safetyEvaluationSummary.value.overall_status === 'ok' ? '通过' : '未通过'
})
const dialogueVersion = computed(() => [
  activeCaseTab.value,
  store.dialogueTasks.map((task) => `${task.id}:${task.summary || ''}`).join('|'),
  store.pendingInput,
  store.activeTask?.id || '',
  store.activeTask?.summary || '',
  store.toolCalls.length,
  store.events.length,
  store.submitting ? 'submitting' : 'idle',
].join('::'))

function scrollDialogueToBottom() {
  void nextTick(() => {
    const element = dialogueScrollRef.value ?? document.querySelector<HTMLElement>('.dialogue-scroll')
    if (!element) return
    const sync = () => {
      element.scrollTop = element.scrollHeight
      const attachments = element.querySelectorAll<HTMLElement>('.agent-attachments')
      const latestAttachments = attachments.item(attachments.length - 1)
      if (!latestAttachments) return

      const viewportTop = element.getBoundingClientRect().top
      const attachmentTop = latestAttachments.getBoundingClientRect().top
      if (attachmentTop < viewportTop + 6) {
        element.scrollTop += attachmentTop - viewportTop - 6
      }
    }
    sync()
    window.setTimeout(sync, 120)
    window.setTimeout(sync, 500)
    window.setTimeout(sync, 1200)
  })
}

watch(
  dialogueVersion,
  () => {
    if (activeCaseTab.value === 'request') scrollDialogueToBottom()
  },
  { flush: 'post' },
)

watch(
  () => (
    proposalPending.value && primaryProposal.value
      ? `${store.activeTask?.id || 0}:${primaryProposal.value.id}`
      : ''
  ),
  (current, previous) => {
    if (
      current
      && current !== previous
      && activeView.value === 'workbench'
    ) {
      inspectorSection.value = 'action'
    }
  },
)

const benchmarkSlowestTool = computed(() => {
  const toolName = store.benchmarkReport?.summary.slowest_tool
  return toolName ? toolLabel(toolName) : '-'
})
const moduleTitle = computed(() => {
  const titles: Record<string, string> = {
    events: '事件中心',
    collaboration: '协同调查',
    posture: '系统态势',
    benchmark: '评测中心',
    safety: '安全护栏',
    tools: 'MCP 工具',
    audit: '审计回放',
    knowledge: '知识库',
    sessions: '全部会话',
    scenarios: '靶场任务',
  }
  return titles[activeView.value] || '靶场任务'
})
const moduleDescription = computed(() => {
  const descriptions: Record<string, string> = {
    events: '周期巡检产生的真实发现、聚合事件和调查任务。',
    collaboration: '围绕同一事件协调隔离身份、证据门、动作契约和独立恢复验证。',
    posture: '实时读取本机快照、磁盘、端口、进程和 MCP 工具健康状态。',
    benchmark: '工具性能、Agent 工作流与靶场场景的实测结果。',
    safety: '当前 Agent 的运行身份、执行边界、审批闸门和风险过滤规则。',
    tools: '协议、工具注册与执行边界。',
    audit: '当前会话的审计哈希链与逐事件校验结果。',
    knowledge: '企业运维知识与处置依据，供 Agent 在智能研判时检索引用。',
    sessions: '近期运维会话与执行状态。',
    scenarios: '受控靶场样本与高频运维剧本，准备样本后继续走真实 Agent 流程。',
  }
  return descriptions[activeView.value] || descriptions.scenarios
})

const statusLabels: Record<string, string> = {
  RECEIVED: '已接收',
  STATIC_REVIEW: '安全校验',
  PLAN: '规划中',
  PERCEIVE: '感知中',
  SUMMARIZE: '汇总中',
  APPROVAL_REQUIRED: '等待审批',
  DYNAMIC_REVIEW: '动态校验',
  EXECUTE: '执行中',
  VERIFY: '核验中',
  SEALED: '已封存',
  REJECTED: '已拒绝',
  BLOCKED: '已阻断',
  FAILED: '失败',
  NEEDS_OPERATOR: '等待人工处理',
  CANCELLED: '已取消',
  QUEUED: '排队中',
  RUNNING: '分析中',
  CANCEL_REQUESTED: '正在取消',
  PENDING: '解析中',
  PROBED: '探针通过',
  UNSUPPORTED: '前置缺失',
  ALLOW: '允许',
  REJECT: '拒绝',
  QUARANTINE: '隔离',
  待命: '待命',
}

const stageLabels: Record<string, string> = {
  RECEIVED: '接收请求',
  STATIC_REVIEW: '安全校验',
  PLAN: '生成计划',
  PERCEIVE: '环境感知',
  INVESTIGATE: '根因调查',
  DRY_RUN: '执行预检',
  SUMMARIZE: '形成结论',
  APPROVAL_REQUIRED: '人工审批',
  DYNAMIC_REVIEW: '动态校验',
  EXECUTE: '受限执行',
  VERIFY: '执行核验',
  AI_ANALYSIS: '智能研判',
  SEALED: '审计封存',
  REJECTED: '拒绝请求',
  BLOCKED: '阻断执行',
  FAILED: '执行失败',
  NEEDS_OPERATOR: '转人工处理',
  CANCELLED: '任务取消',
  ROLLED_BACK: '回滚完成',
}

const toolStatusLabels: Record<string, string> = {
  ok: '正常',
  partial: '证据不完整',
  running: '执行中',
  unknown: '结果待核验',
  error: '异常',
}

const roleStatusLabels: Record<string, string> = {
  received: '已接收',
  completed: '已完成',
  partial: '部分完成',
  model_assisted: '模型辅助',
  evidence_summary: '事实汇总',
  passed: '已通过',
  approval_required: '待审批',
  prepared: '已准备',
  executed: '已执行',
  verification_failed: '验证失败',
  blocked: '已阻断',
  recording: '记录中',
  sealed: '已封存',
  inconclusive: '证据不足',
  needs_operator: '待人工',
  investigating: '调查中',
  cancelled: '已取消',
  failed: '失败',
}

const eventTypeLabels: Record<string, string> = {
  task_created: '创建任务',
  state_transition: '状态流转',
  safety_review: '安全校验',
  intent_resolved: '意图解析',
  skill_selected: '工具范围确认',
  skill_policy_rejected: '工具范围拒绝',
  plan_created: '生成计划',
  tool_call: '工具调用',
  summary_created: '形成摘要',
  assistant_reply_created: '对话答复',
  analysis_created: '智能研判',
  ai_analysis_created: '智能研判',
  ai_analysis_failed: '智能研判失败',
  evidence_risk_assessed: '证据风险检查',
  investigation_evidence_risk_assessed: '调查证据风险检查',
  investigation_started: '开始调查',
  investigation_decision: '调查决策',
  evidence_obligation_enforced: '结论前补证',
  investigation_evidence_collected: '补充证据',
  investigation_concluded: '形成根因',
  investigation_stopped: '停止调查',
  investigation_needs_operator: '转人工处理',
  investigation_cancelled: '取消调查',
  worker_started: '任务执行器开始处理',
  worker_execution_failed: '任务执行器处理失败',
  worker_lease_expired: '任务执行器租约过期',
  task_cancel_requested: '请求取消任务',
  task_cancelled: '任务已取消',
  tool_call_failed: '工具调用失败',
  execution_policy_denied: '执行策略拒绝',
  evidence_quarantined: '隔离非可信证据',
  knowledge_evidence_retrieved: '检索运维知识',
  knowledge_rag_unavailable: '知识检索不可用',
  operational_memory_unavailable: '运维经验不可用',
  memory_draft_created: '运维经验草案',
  memory_confirmed: '运维经验确认',
  memory_qualification_passed: '运维经验准入',
  memory_qualification_failed: '运维经验隔离',
  memory_correction_drafted: '运维经验修订',
  operator_feedback_recorded: '运维反馈',
  patrol_incident_created: '巡检事件接入',
  tool_plan_empty: '无需调用工具',
  action_risk_reconciled: '处置风险复核',
  risk_level_raised: '风险上调',
  approval_gate: '审批门禁',
  approval_recorded: '审批记录',
  intent_model_failed: '模型解析失败',
  intent_model_unconfigured: '模型服务未配置',
  benchmark_proposal_retired: '评测建议回收',
  verification_precondition: '执行前校验',
  verify_result: '执行后校验',
  proposal_created: '处置建议',
  action_proposal_created: '处置建议',
  proposal_skipped: '无需处置',
  rollback_proposal_created: '回滚方案',
  rollback_proposal_skipped: '回滚跳过',
  approval_rejected: '拒绝审批',
  approval_accepted: '批准审批',
  execution_policy_checked: '执行策略',
  execution_completed: '完成执行',
  trace_sealed: '审计封存',
}

const intentLabels: Record<string, string> = {
  disk_pressure_analysis: '磁盘空间分析',
  process_health_analysis: '进程健康检查',
  log_analysis: '系统日志分析',
  service_degradation_analysis: '服务退化诊断',
  network_exposure_analysis: '网络暴露面分析',
  config_integrity_analysis: '配置完整性检查',
  general_system_health: '系统健康巡检',
  agent_capability_help: '能力咨询',
  model_unconfigured: '模型服务未配置',
  model_intent_failed: '模型意图解析失败',
  unknown: '正在理解请求',
}

const toolLabels: Record<string, string> = {
  platform_capability_profile: '主机能力画像',
  system_snapshot: '系统快照',
  disk_usage: '磁盘用量',
  find_large_files: '大文件定位',
  process_list: '进程列表',
  process_file_handles: '文件句柄',
  journal_query: '日志查询',
  service_status: '服务状态',
  service_desired_state: '服务期望状态',
  service_catalog_snapshot: '服务目录快照',
  network_listeners: '网络监听',
  service_dependency_snapshot: '服务关系快照',
  config_integrity_scan: '配置完整性',
  config_baseline_check: '配置基线比较',
  safe_log_rotate: '日志安全轮转',
  restore_log_backup: '日志备份恢复',
  restart_managed_service: '受控服务重启',
  restore_config_mode: '配置权限恢复',
  file_integrity_state: '文件完整性校验',
  process_runtime_detail: '进程运行详情',
  journal_storage_status: '日志存储状态',
  deleted_open_files: '已删除未释放文件',
  socket_process_context: '端口进程归属',
  filesystem_mount_context: '文件系统挂载',
  time_sync_status: '时间同步状态',
  service_health_probe: '服务健康检查',
  application_log_query: '应用日志',
}

const toolDescriptions: Record<string, string> = {
  platform_capability_profile: '确认当前主机架构、内核接口、systemd 运行态与命令前置条件。',
  system_snapshot: '采集主机身份、内核、运行时间、负载和内存摘要。',
  disk_usage: '采集指定路径的文件系统占用情况。',
  find_large_files: '在允许目录内定位大文件，辅助分析磁盘压力来源。',
  process_list: '采集进程资源占用与僵尸进程状态。',
  process_file_handles: '统计进程打开文件句柄数量，定位句柄异常。',
  journal_query: '只读查询近期系统日志，不修改系统状态。',
  service_status: '查看 systemd 服务状态或失败服务摘要。',
  service_desired_state: '读取经审批服务目录中的责任方、重要级别和期望运行状态。',
  service_catalog_snapshot: '读取当前主机经审批的服务、责任方和允许监听范围。',
  network_listeners: '采集监听端口，并尽量关联所属进程。',
  service_dependency_snapshot: '按已观测端口关联进程、监听和当时已建立连接，无法归属的关系保留为证据缺口。',
  config_integrity_scan: '采集白名单配置文件的权限、时间戳和内容哈希，不返回配置正文。',
  config_baseline_check: '按生产或靶场作用域，将当前配置状态与已确认基线进行比较。',
  safe_log_rotate: '对非关键日志生成受审查的轮转和压缩备份方案。',
  restore_log_backup: '从已验证备份恢复日志，并在恢复前保存当前内容。',
  restart_managed_service: '仅对预配置且已观测的 systemd 服务提交一次重启，并独立核验恢复状态。',
  restore_config_mode: '仅在内容与属主未漂移时，按已确认基线恢复精确白名单配置的权限。',
  file_integrity_state: '只读采集受控文件的大小、权限和哈希，用于独立验证执行结果。',
  process_runtime_detail: '读取指定进程的资源上限、句柄类型和服务归属，不读取命令行或环境变量。',
  journal_storage_status: '核对 journal 实际占用、文件结构和白名单留存设置，不返回日志正文。',
  socket_process_context: '核对指定端口的进程、用户和服务归属，不读取进程命令行。',
  filesystem_mount_context: '将目标路径映射到挂载点、文件系统、安全选项和容量。',
  time_sync_status: '只读核对系统时钟、时区与时间同步状态。',
  service_health_probe: '复现用户明确给出的本机 HTTP 症状，记录状态码、延迟和脱敏响应摘要。',
  application_log_query: '读取证据中明确出现的应用日志尾部，结构化提取关联标识并脱敏。',
}

const rollbackLabels: Record<string, string> = {
  none: '无需回滚',
  restore_backup: '备份恢复',
  restore_pre_restore_snapshot: '恢复前快照',
  manual_takeover: '人工接管',
}

function submit() {
  const value = prompt.value.trim()
  if (!value || taskInProgress.value || store.submitting) return
  activeCaseTab.value = 'request'
  prompt.value = ''
  void store.submit(value).then(scrollDialogueToBottom)
}

function startNewConversation() {
  store.startNewConversation()
  activeCaseTab.value = 'request'
  prompt.value = ''
}

async function openSidebarTask(task: Task) {
  switchView('workbench')
  activeCaseTab.value = 'request'
  await store.selectTask(task)
}

function usePreset(value: string) {
  prompt.value = value
}

function openRelationshipGraph() {
  relationshipGraphView.value = serviceRelationshipSnapshot.value ? 'runtime' : 'decision'
  activeCaseTab.value = 'graph'
}

function openInvestigationFocus() {
  relationshipGraphView.value = investigationFocus.value.graph
  activeCaseTab.value = 'graph'
}

async function requestServiceImpact(unit: string) {
  const normalized = unit.trim()
  if (!normalized) return
  await submitFromModule(
    `请检查并预演重启 ${normalized}：先采集实时依赖与连接关系，评估影响范围、执行前条件和回滚方案，未经审批不要执行。`,
  )
}

async function downloadDiagnosticBundle() {
  const task = store.activeTask
  if (!task || diagnosticBundleState.value === 'downloading') return
  store.error = ''
  diagnosticBundleState.value = 'downloading'
  try {
    const result = await exportTaskDiagnosticBundle(task.id)
    const href = URL.createObjectURL(result.blob)
    const anchor = document.createElement('a')
    anchor.href = href
    anchor.download = result.filename
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    URL.revokeObjectURL(href)
    diagnosticBundleState.value = 'done'
    if (diagnosticBundleResetTimer) window.clearTimeout(diagnosticBundleResetTimer)
    diagnosticBundleResetTimer = window.setTimeout(() => {
      diagnosticBundleState.value = 'idle'
    }, 2500)
  } catch (error) {
    diagnosticBundleState.value = 'idle'
    store.error = error instanceof Error ? error.message : '任务诊断包导出失败'
  }
}

async function runScenario(item: ScenarioTemplate) {
  scenarioRunningTitle.value = item.title
  store.error = ''
  try {
    await store.runLabScenarioEvaluation(item.labId)
  } finally {
    scenarioRunningTitle.value = ''
  }
}

async function runPostureAction(action: LivePostureNextAction) {
  await submitFromModule(action.prompt)
}

async function submitFromModule(request: string) {
  if (!request || store.loading || store.submitting || taskInProgress.value) return
  prompt.value = request
  switchView('workbench')
  activeCaseTab.value = 'request'
  await store.submit(request)
  prompt.value = ''
}

function labScenarioState(labId?: string) {
  if (!labId) return null
  return store.labScenarios.find((scenario) => scenario.id === labId) ?? null
}

function scenarioStateLabel(item: ScenarioTemplate) {
  const status = labScenarioState(item.labId)?.status
  if (status === 'unsupported') return '前置缺失'
  if (status === 'error') return '准备异常'
  if (!item.setupRequired) return '无需准备'
  if (status === 'ready') return '已准备'
  return '未准备'
}

function scenarioStateClass(item: ScenarioTemplate) {
  const status = labScenarioState(item.labId)?.status
  if (status === 'unsupported' || status === 'error') return 'danger'
  if (!item.setupRequired || status === 'ready') return 'safe'
  return 'idle'
}

function scenarioSetupSummary(item: ScenarioTemplate) {
  const scenario = labScenarioState(item.labId)
  if (scenario?.status === 'unsupported' || scenario?.status === 'error') return scenarioStatusReason(scenario)
  if (item.setupRequired) return labStateMetric(scenario)
  if (item.category === 'service') return '预置 systemd 故障'
  return '安全控制器直接裁决'
}

function formatSize(bytes?: number) {
  if (!bytes) return '未准备'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

function labStateMetric(scenario: LabScenario | null) {
  if (!scenario) return '未准备'
  if (scenario.status === 'unsupported' || scenario.status === 'error') return scenarioStatusReason(scenario)
  if (scenario.status !== 'ready') return '未准备'
  const mode = scenario.metadata?.current_mode
  if (typeof mode === 'string') return `权限 ${mode}`
  if (scenario.size_bytes > 0) return formatSize(scenario.size_bytes)
  const bind = scenario.metadata?.bind
  const port = scenario.metadata?.port
  if (typeof bind === 'string' && (typeof port === 'string' || typeof port === 'number')) return `${bind}:${port}`
  const pid = scenario.metadata?.pid
  if (typeof pid === 'number') return `PID ${pid}`
  const fileCount = scenario.metadata?.file_count
  if (typeof fileCount === 'number') return `${fileCount} 个文件`
  return '已就绪'
}

function scenarioResourceBudget(scenario: LabScenario | null) {
  if (!scenario) return '-'
  const budget = scenario.resource_budget
  const parts: string[] = []
  if (budget.max_disk_mb) parts.push(`${budget.max_disk_mb} MB`)
  if (budget.max_files) parts.push(`${budget.max_files} 文件`)
  if (budget.max_processes) parts.push(`${budget.max_processes} 进程`)
  if (budget.max_memory_mb) parts.push(`${budget.max_memory_mb} MB 内存`)
  return parts.join(' · ') || '无额外资源'
}

function scenarioStatusReason(scenario: LabScenario) {
  const reason = scenario.metadata?.reason
  const labels: Record<string, string> = {
    fixture_prerequisite_missing: '缺少测试服务单元',
    fixture_unit_not_installed: '测试服务单元未安装',
    fixture_unit_not_failed: '测试服务未进入失败状态',
    logger_or_journalctl_unavailable: '系统日志工具不可用',
    journal_record_not_observable: '测试日志不可读取',
  }
  return typeof reason === 'string' ? labels[reason] || reason : '场景前置条件不可用'
}

function scenarioCleanupLabel(result: LabEvaluationCase) {
  const status = result.cleanup?.status
  if (status === 'clean') return '已清理'
  if (status === 'failed') return '清理失败'
  return '无需清理'
}

function readViewFromLocation() {
  const url = new URL(window.location.href)
  const queryView = url.searchParams.get('view')
  const hashView = url.hash.replace(/^#\/?/, '').split(/[/?&]/)[0]
  const view = queryView || hashView
  return view && validViews.has(view) ? view : 'workbench'
}

function readTaskIdFromLocation() {
  const value = new URL(window.location.href).searchParams.get('task')
  if (!value || !/^\d+$/.test(value)) return null
  const taskId = Number(value)
  return Number.isSafeInteger(taskId) && taskId > 0 ? taskId : null
}

function writeViewToLocation(view: string) {
  const url = new URL(window.location.href)
  if (view === 'workbench') {
    url.searchParams.delete('view')
  } else {
    url.searchParams.set('view', view)
    url.searchParams.delete('task')
  }
  window.history.pushState({}, '', url)
}

function syncViewFromLocation() {
  switchView(readViewFromLocation(), false)
}

function switchView(view: string, syncUrl = true) {
  const nextView = validViews.has(view) ? view : 'workbench'
  activeView.value = nextView
  traceDrawerOpen.value = false
  if (nextView === 'sessions') sessionPage.value = 1
  if (nextView === 'audit') auditPage.value = 1
  if (nextView === 'posture') void store.refreshLivePosture()
  if (nextView === 'events') void store.refreshPatrolData()
  if (syncUrl) writeViewToLocation(nextView)
}

function openEventSection(section: 'incidents' | 'approvals') {
  eventSection.value = section
  switchView('events')
}

function refreshModule() {
  if (activeView.value === 'scenarios') {
    void store.bootstrap()
    return
  }
  if (activeView.value === 'posture') {
    void store.refreshLivePosture()
    return
  }
  if (activeView.value === 'tools') {
    void store.refreshMcpGovernance()
    return
  }
  if (activeView.value === 'safety') {
    void store.refreshSafetyGovernance()
    return
  }
  if (store.activeTask) void store.selectTask(store.activeTask)
}

function shortHash(value?: string | null) {
  if (!value) return '-'
  return `${value.slice(0, 8)}...${value.slice(-6)}`
}

function formatRuntimeMs(value?: number | null) {
  if (value === null || value === undefined) return '-'
  if (value < 1000) return `${value}ms`
  if (value < 60_000) return `${(value / 1000).toFixed(value < 10_000 ? 1 : 0)}s`
  const minutes = Math.floor(value / 60_000)
  const seconds = Math.round((value % 60_000) / 1000)
  return seconds ? `${minutes}m ${seconds}s` : `${minutes}m`
}

function formatTokenUsage(value?: number | null, complete = true) {
  if (value === null || value === undefined) return '-'
  const formatted = new Intl.NumberFormat('zh-CN').format(value)
  return complete ? formatted : `${formatted}（部分）`
}

function statusLabel(value?: string) {
  return statusLabels[value || ''] ?? value ?? '-'
}

function stageLabel(value: string) {
  return stageLabels[value] ?? value
}

function toolStatusLabel(value: string) {
  return toolStatusLabels[value] ?? value
}

function roleStatusLabel(value: string) {
  return roleStatusLabels[value] ?? value
}

function roleStatusTone(value: string) {
  if (value === 'blocked' || value === 'verification_failed') return 'danger'
  if (value === 'approval_required' || value === 'partial' || value === 'inconclusive' || value === 'needs_operator') return 'warning'
  if (value === 'completed' || value === 'model_assisted' || value === 'passed' || value === 'executed' || value === 'sealed') {
    return 'success'
  }
  return 'neutral'
}

function actionStepStatusLabel(value: string) {
  const labels: Record<string, string> = {
    passed: '通过',
    completed: '完成',
    available: '可回滚',
    restored: '已回滚',
    declined: '保留现状',
    pending: '等待',
    approval_required: '待审批',
    not_started: '未开始',
    not_run: '未执行',
    not_required: '无需',
    blocked: '阻断',
    failed: '失败',
    needs_operator: '待人工',
  }
  return labels[value] ?? statusLabel(value)
}

function actionStepTone(value: string) {
  if (['blocked', 'failed', 'needs_operator'].includes(value)) return 'danger'
  if (['pending', 'approval_required', 'available'].includes(value)) return 'warning'
  if (['passed', 'completed', 'restored'].includes(value)) return 'success'
  return 'neutral'
}

function impactRoleLabel(value: string) {
  return {
    TARGET: '目标',
    PROPAGATED: '传播',
    CLIENT: '调用方',
  }[value] || '关联'
}

function impactMechanismLabel(value: string) {
  return {
    DIRECT_TARGET: '直接作用',
    PART_OF: '随目标启停',
    PROPAGATES_STOP_TO: '停止传播',
    PROPAGATES_RELOAD_TO: '重载传播',
    BINDS_TO: '绑定关系',
    REQUIRES: '强依赖',
  }[value] || value || '运行关系'
}

function impactCertaintyLabel(value: string) {
  return {
    DIRECT: '直接',
    CERTAIN: '确定',
    LIKELY: '较可能',
    POSSIBLE: '待核验',
  }[value] || value || '待核验'
}

function configChangeLabel(value: string) {
  const labels: Record<string, string> = {
    added: '新增',
    missing: '缺失',
    content_changed: '内容变化',
    permission_changed: '权限变化',
    metadata_changed: '元数据变化',
    unavailable: '暂不可用',
  }
  return labels[value] ?? value
}

function configCheckTone(check: ConfigBaselineCheck | null) {
  if (!check) return 'idle'
  if (check.status === 'clean') return 'safe'
  if (check.status === 'drifted') return 'danger'
  return 'notice'
}

function runtimeGuardClass(value?: string) {
  if (value === 'ok') return 'ok'
  if (value === 'warn') return 'warn'
  if (value === 'blocked') return 'failed'
  return 'idle'
}

function deploymentStatusLabel(value?: string) {
  if (value === 'ok') return '通过'
  if (value === 'warn') return '关注'
  if (value === 'blocked') return '阻断'
  return '待检测'
}

function eventTypeLabel(value: string) {
  return eventTypeLabels[value] ?? '系统事件'
}

function auditStageStatusLabel(value: string, stageKey = '') {
  if (value === 'skipped') return stageKey === 'investigate' ? '无需调查' : '无需执行'
  const labels: Record<string, string> = {
    passed: '通过',
    failed: '异常',
    pending: '待完成',
  }
  return labels[value] ?? value
}

function auditEventStatusLabel(value: boolean | null) {
  if (value === true) return '通过'
  if (value === false) return '异常'
  return '待校验'
}

function intentLabel(value?: string) {
  return intentLabels[value || 'unknown'] ?? value ?? '正在理解请求'
}

function taskIntentLabel(task: Task) {
  if (task.intent === 'unknown' && ['REJECTED', 'BLOCKED'].includes(task.status)) {
    return '安全拦截请求'
  }
  if (task.intent === 'unknown' && ['FAILED', 'CANCELLED', 'NEEDS_OPERATOR'].includes(task.status)) {
    return '未完成请求'
  }
  return intentLabel(task.intent)
}

function taskSummaryText(task: Task) {
  if (task.intent === 'model_unconfigured') return '模型服务未配置，任务已停止，未调用工具或执行变更。'
  if (task.intent === 'model_intent_failed') return '模型意图解析失败，任务已停止，未调用工具或执行变更。'
  if (task.queue_status === 'QUEUED') return '任务已入队，等待任务执行器领取。'
  if (task.queue_status === 'CANCEL_REQUESTED') return '已请求取消，等待任务执行器在安全边界停止。'
  if (task.queue_status === 'RUNNING' && !task.summary) return '任务执行器已领取任务，正在执行受控分析。'
  const summary = task.summary || task.user_input
  if (store.operatorContext?.explicit.summary_density !== 'COMPACT') return summary
  const firstSentence = summary.match(/^.*?[。！？.!?](?:\s|$)/)?.[0]?.trim()
  if (firstSentence) return firstSentence
  return summary.length > 96 ? `${summary.slice(0, 96)}…` : summary
}

function openOperatorPreferences() {
  const context = store.operatorContext
  if (context) {
    operatorSummaryDensity.value = context.explicit.summary_density
    operatorEvidenceView.value = context.explicit.evidence_view
    operatorNotificationRoute.value = context.explicit.notification_route
    operatorServiceFocusInput.value = context.explicit.service_focus.join('，')
  }
  operatorPreferenceNotice.value = ''
  operatorDrawerOpen.value = true
}

async function saveOperatorPreferences() {
  const serviceFocus = operatorServiceFocusInput.value
    .split(/[,，\n]/)
    .map((item) => item.trim())
    .filter(Boolean)
  const saved = await store.updateOperatorContext({
    summary_density: operatorSummaryDensity.value,
    evidence_view: operatorEvidenceView.value,
    notification_route: operatorNotificationRoute.value,
    service_focus: serviceFocus,
  })
  operatorPreferenceNotice.value = saved ? '工作偏好已更新' : ''
}

async function forgetLearnedPreferences() {
  const forgotten = await store.forgetLearnedOperatorContext('运维人员主动清除已学习的工作偏好')
  operatorPreferenceNotice.value = forgotten ? '已清除学习结果，手动设置保持不变' : ''
}

function toolLabel(value?: string | null) {
  if (!value) return '知识证据'
  return toolLabels[value] ?? value
}

function confidenceLabel(value?: string) {
  const labels: Record<string, string> = {
    HIGH: '高置信',
    MEDIUM: '中置信',
    LOW: '低置信',
    model_assisted: '模型辅助',
    rule_based: '事实摘要',
  }
  return labels[value || ''] ?? value ?? '-'
}

function relationCount(
  evidence: Array<{ relation?: 'SUPPORTS' | 'REFUTES' | 'CONTEXT' }>,
  relation: 'SUPPORTS' | 'REFUTES' | 'CONTEXT',
) {
  return evidence.filter((item) => item.relation === relation).length
}

function compactToolLabel(value: string) {
  const labels: Record<string, string> = {
    system_snapshot: '系统',
    disk_usage: '磁盘',
    network_listeners: '网络',
    process_list: '进程',
  }
  return labels[value] ?? toolLabel(value)
}

function toolDescription(value: string, fallback: string) {
  return toolDescriptions[value] ?? fallback
}

function skillToolNames(skill: AgentSkill) {
  return skill.tools.map((tool) => toolLabel(tool.name)).join('、')
}

function toolBoundaryLabel(rollbackStrategy: string) {
  return rollbackStrategy && rollbackStrategy !== 'none' ? '审批执行' : '只读'
}

function shortToolHash(value?: string) {
  if (!value) return '-'
  if (value.length <= 16) return value
  return `${value.slice(0, 8)}...${value.slice(-6)}`
}

function rollbackLabel(value: string) {
  return rollbackLabels[value] ?? value
}

function safetyGateLabel(value?: string) {
  if (!value) return '进入安全校验后执行'
  const normalized = value.trim()
  const upper = normalized.toUpperCase()
  if (upper.includes('CONFIGURATION_REVIEW')) return '需要配置复核'
  if (upper.includes('TIME_BOUNDARY')) return '按到期策略校验后执行'
  if (upper.includes('AUTO') || normalized.includes('自动')) return '满足只读条件后放行'
  if (upper.includes('APPROVAL') || normalized.includes('审批')) return '需要人工审批'
  if (upper.includes('SECURITY') || normalized.includes('安全')) return normalized
  return normalized
}

function observationsOf(toolName: string): Array<Record<string, any>> {
  const observations = store.toolCalls.find((call) => call.tool_name === toolName)?.output.observations
  return Array.isArray(observations) ? (observations as Array<Record<string, any>>) : []
}

function loadText() {
  const loadavg = hostSnapshot.value.loadavg
  return Array.isArray(loadavg) && loadavg.length ? Number(loadavg[0]).toFixed(2) : '-'
}

function memoryText() {
  const used = hostSnapshot.value.memory?.used_percent
  return typeof used === 'number' ? `${used.toFixed(1)}%` : '-'
}

function rootDiskText() {
  const used = rootDisk.value?.used_percent
  return typeof used === 'number' ? `${used.toFixed(1)}%` : '-'
}

function uptimeText() {
  const seconds = hostSnapshot.value.uptime_seconds
  if (typeof seconds !== 'number') return '等待运行时长'
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.max(1, Math.floor((seconds % 3600) / 60))
  if (days > 0) return `${days} 天 ${hours} 小时`
  if (hours === 0) return `${minutes} 分钟`
  return `${hours} 小时`
}

function percentBarWidth(value: number | null) {
  if (typeof value !== 'number') return '0%'
  return `${Math.max(0, Math.min(100, value)).toFixed(1)}%`
}

function processTitle(row: Record<string, any>) {
  return typeof row.command === 'string' && row.command ? row.command : `PID ${row.pid ?? '-'}`
}

function processMeta(row: Record<string, any>) {
  const pid = row.pid ?? '-'
  const stat = typeof row.stat === 'string' ? row.stat : '-'
  return `PID ${pid} · ${stat}`
}

function processCpuPercent(row: Record<string, any>) {
  return typeof row.cpu_percent === 'number' ? Math.max(0, Math.min(100, row.cpu_percent)) : null
}

function processUsageText(row: Record<string, any>) {
  const cpu = typeof row.cpu_percent === 'number' ? `${row.cpu_percent.toFixed(1)}%` : '-'
  const memory = typeof row.mem_percent === 'number' ? `${row.mem_percent.toFixed(1)}%` : '-'
  return `CPU ${cpu} / 内存 ${memory}`
}

function listenerEndpoint(row: Record<string, any>) {
  const protocol = typeof row.protocol === 'string' ? row.protocol.toUpperCase() : '-'
  const address = typeof row.local_address === 'string' ? row.local_address : '-'
  return `${protocol} ${address}`
}

function listenerMeta(row: Record<string, any>) {
  const processName = typeof row.process_name === 'string' && row.process_name
    ? row.process_name
    : typeof row.process === 'string' && row.process
      ? row.process
      : ''
  if (processName) {
    const pid = typeof row.pid === 'number' ? `PID ${row.pid}` : 'PID 未知'
    const user = typeof row.user === 'string' && row.user ? row.user : ''
    return user && user !== processName
      ? `${processName} · ${pid} · ${user}`
      : `${processName} · ${pid}`
  }
  const inode = typeof row.socket_inode === 'number' ? `inode ${row.socket_inode}` : '无 inode'
  return `进程未归属 · ${inode}`
}

function hostName() {
  return typeof hostSnapshot.value.hostname === 'string' ? hostSnapshot.value.hostname : '-'
}

function osText() {
  const osRelease = hostSnapshot.value.os_release
  if (osRelease && typeof osRelease.pretty_name === 'string') return osRelease.pretty_name
  return typeof hostSnapshot.value.kernel === 'string' ? hostSnapshot.value.kernel : '等待系统快照'
}

function architectureText() {
  if (store.platformCapabilities?.platform.is_loongarch || hostSnapshot.value.is_loongarch) return 'LoongArch'
  if (store.platformCapabilities?.platform.machine) return store.platformCapabilities.platform.machine
  return typeof hostSnapshot.value.machine === 'string' ? hostSnapshot.value.machine : '-'
}

function toolAvailabilityLabel(tool: { availability?: { status?: string; available?: boolean } }) {
  if (tool.availability?.available === false) return '不可用'
  if (tool.availability?.status === 'DEGRADED') return '降级'
  if (tool.availability?.status === 'SUPPORTED') return '可用'
  return '待探测'
}

function toolAvailabilityClass(tool: { availability?: { status?: string; available?: boolean } }) {
  if (tool.availability?.available === false) return 'unavailable'
  if (tool.availability?.status === 'DEGRADED') return 'degraded'
  if (tool.availability?.status === 'SUPPORTED') return 'available'
  return 'unknown'
}

function benchmarkStatusLabel(status?: string) {
  if (status === 'ok') return '通过'
  if (status === 'warn') return '偏慢'
  if (status === 'failed') return '失败'
  return '未运行'
}

function benchmarkStatusClass(status?: string) {
  if (status === 'failed') return 'failed'
  if (status === 'warn') return 'warn'
  if (status === 'ok') return 'ok'
  return 'idle'
}

function benchmarkBudgetPercent(p95: number, threshold: number) {
  if (threshold <= 0) return 0
  return Math.min(100, Math.max(2, Math.round((p95 / threshold) * 100)))
}

function safetyEvaluationClass(passed?: boolean) {
  if (passed === true) return 'ok'
  if (passed === false) return 'failed'
  return 'idle'
}

function agentEvaluationDecision(item: AgentEvaluationCase) {
  if (item.skill_name) return item.skill_name
  return `${statusLabel(item.actual_decision)} · ${item.actual_risk_level}`
}

function labEvaluationResult(item: LabEvaluationCase) {
  if (!item.supported) return '前置条件缺失'
  if (item.error) return '执行异常'
  if (!item.passed) return item.failure_reasons?.[0] || '链路未通过'
  if (item.proposal_tool) return `建议：${toolLabel(item.proposal_tool)}`
  return item.actual_status === 'REJECTED' ? '已拦截' : statusLabel(item.actual_status)
}

function evaluationRate(value?: number) {
  return typeof value === 'number' ? `${Math.round(value * 100)}%` : '-'
}

function labEvaluationEvidence(item: LabEvaluationCase) {
  if (!item.supported) return item.failure_reasons?.[0] || '当前环境不可运行'
  if (!item.passed) return item.failure_reasons?.join('；') || '查看失败证据'
  const tools = item.observed_tools.map(toolLabel).join('、') || statusLabel(item.actual_status)
  const coverage = evaluationRate(item.metrics?.evidence_coverage)
  if (item.metrics?.change_impact_evaluated) {
    return `精度 ${evaluationRate(item.metrics.change_impact_precision)} · 召回 ${evaluationRate(item.metrics.change_impact_recall)}`
  }
  if (item.evaluation_kind !== 'agent_task') return `${tools} · 证据 ${coverage}`
  const contract = item.evidence_anchors?.action_contract_valid ? ' · 参数已绑定' : ''
  return `${tools}${contract} · 审计可信`
}

function scenarioToolSummary(tools: string[]) {
  if (tools.length <= 3) return tools.join('、')
  return `${tools.slice(0, 3).join('、')}等 ${tools.length} 项`
}

async function openLabEvaluationTask(item: LabEvaluationCase) {
  if (!item.task_id) return
  await store.openTaskById(item.task_id)
  if (!store.error) switchView('workbench')
}

async function openPatrolTask(taskId: number) {
  await store.openTaskById(taskId)
  if (!store.error) switchView('workbench')
}

async function openKnowledgeSourceTask(taskId: number) {
  await store.openTaskById(taskId)
  if (!store.error) {
    activeCaseTab.value = 'result'
    switchView('workbench')
  }
}

function openOperationalMemories() {
  knowledgeSection.value = 'memories'
  switchView('knowledge')
}

function safetyEvaluationCaseText(item: SafetyEvaluationReport['cases'][number]) {
  if (item.kind === 'dynamic_tool_action' && item.tool_name) {
    return toolLabel(item.tool_name)
  }
  if (item.kind === 'untrusted_data') {
    return item.reason
  }
  if (item.kind === 'cross_turn_chain') {
    return item.reason
  }
  return item.prompt
}

function formatDateTime(value?: string) {
  if (!value) return '-'
  return new Date(value).toLocaleString('zh-CN', { hour12: false })
}

function sampleClock(value?: string) {
  if (!value) return '-'
  return new Date(value).toLocaleTimeString('zh-CN', { hour12: false })
}

function formatEventMessage(message: string) {
  let formatted = message.replace('状态 ok', '状态正常').replaceAll('Worker', '任务执行器')
  for (const [name, label] of Object.entries({ ...toolLabels, ...intentLabels })) {
    formatted = formatted.replaceAll(name, label)
  }
  return formatted.replace(/调用工具 ([^ ]+) 完成/g, '调用$1工具完成').replace(/执行工具 ([^ ]+) 完成/g, '执行$1工具完成')
}

</script>

<template>
  <main class="app-shell">
    <aside class="rail">
      <div class="brand">
        <div class="brand-logo">
          <span>OpsCouncil</span>
          <strong>自主安全运维</strong>
        </div>
      </div>

      <nav class="nav">
        <button class="nav-item" :class="{ active: activeView === 'workbench' }" @click="switchView('workbench')">运维工作台</button>
        <button class="nav-item" :class="{ active: activeView === 'events' }" @click="switchView('events')">事件中心</button>
        <button class="nav-item" :class="{ active: activeView === 'collaboration' }" @click="switchView('collaboration')">协同调查</button>
        <button class="nav-item" :class="{ active: activeView === 'posture' }" @click="switchView('posture')">系统态势</button>
        <button class="nav-item" :class="{ active: activeView === 'benchmark' }" @click="switchView('benchmark')">评测中心</button>
        <button class="nav-item" :class="{ active: activeView === 'safety' }" @click="switchView('safety')">安全护栏</button>
        <button class="nav-item" :class="{ active: activeView === 'tools' }" @click="switchView('tools')">MCP 工具</button>
        <button class="nav-item" :class="{ active: activeView === 'audit' }" @click="switchView('audit')">审计回放</button>
        <button class="nav-item" :class="{ active: activeView === 'knowledge' }" @click="switchView('knowledge')">知识库</button>
        <button class="nav-item" :class="{ active: activeView === 'scenarios' }" @click="switchView('scenarios')">靶场任务</button>
      </nav>

      <section class="session-panel">
        <div class="session-head">
          <span>会话 / 任务</span>
        </div>
        <input v-model="taskQuery" class="task-search" placeholder="搜索会话 / 任务" />
        <div class="task-list">
          <button
            v-for="task in sidebarTasks"
            :key="task.id"
            class="task-item"
            :class="{ selected: task.id === store.activeTask?.id }"
            @click="openSidebarTask(task)"
          >
            <span class="task-title">{{ taskIntentLabel(task) }}</span>
            <span class="task-desc">{{ taskSummaryText(task) }}</span>
            <span class="task-meta">
              <code>{{ task.risk_level }}</code>
              <span>{{ statusLabel(task.status) }}</span>
            </span>
          </button>
        </div>
        <button class="view-all" @click="switchView('sessions')">查看全部会话</button>
      </section>
    </aside>

    <header class="topbar">
      <h1>{{ activeView === 'workbench' ? '运维工作台' : moduleTitle }}</h1>
      <div class="top-actions">
        <span
          class="worker-runtime-indicator"
          :class="workerRuntimeTone"
          :title="store.workerRuntime?.summary || '正在读取任务引擎状态'"
        >
          <i></i>{{ workerRuntimeText }}
        </span>
        <button class="top-action-link" title="查看待处理事件" @click="openEventSection('incidents')">
          <IconNotification />
          <span>告警</span>
          <strong>{{ alertCount }}</strong>
        </button>
        <button class="top-action-link" title="查看审批待办" @click="openEventSection('approvals')">
          <IconCheckSquare />
          <span>待办</span>
          <strong>{{ todoCount }}</strong>
        </button>
        <button class="account-dot" title="工作偏好" @click="openOperatorPreferences">admin</button>
      </div>
    </header>

    <section v-if="activeView === 'workbench'" class="workspace">
      <section class="case-shell">
        <header class="case-header">
          <div class="case-title">
            <div class="case-title-main">
              <span class="case-icon">运</span>
              <strong>{{ caseTitle }}</strong>
            </div>
            <div class="case-meta">
              <span>发起人：admin</span>
              <span>会话状态：{{ activeStatusText }}</span>
              <span>会话 ID：{{ shortHash(store.activeTask?.conversation_id) }}</span>
            </div>
          </div>
          <div class="case-actions">
            <a-button
              v-if="canCancelActiveTask"
              size="small"
              status="danger"
              :loading="store.cancellingTaskId === store.activeTask?.id"
              @click="store.cancelActiveTask"
            >
              <template #icon><IconClose /></template>
              取消任务
            </a-button>
            <a-button size="small" @click="startNewConversation">
              <template #icon><IconPlus /></template>
              新会话
            </a-button>
            <a-tag>{{ activeStatusText }}</a-tag>
          </div>
        </header>

        <nav class="tabs">
          <button class="tab" :class="{ active: activeCaseTab === 'request' }" @click="activeCaseTab = 'request'">自然语言请求</button>
          <button class="tab" :class="{ active: activeCaseTab === 'plan' }" :disabled="!store.activeTask" @click="activeCaseTab = 'plan'">Agent 计划</button>
          <button class="tab" :class="{ active: activeCaseTab === 'process' }" :disabled="!store.activeTask" @click="activeCaseTab = 'process'">执行过程</button>
          <button class="tab" :class="{ active: activeCaseTab === 'graph' }" :disabled="!store.activeTask" @click="activeCaseTab = 'graph'">证据图谱</button>
          <button class="tab" :class="{ active: activeCaseTab === 'result' }" :disabled="!store.activeTask" @click="activeCaseTab = 'result'">结果与报告</button>
        </nav>

        <section class="case-body">
          <article v-if="activeCaseTab === 'request'" class="dialogue-panel">
            <div ref="dialogueScrollRef" class="dialogue-scroll">
              <div class="conversation-flow">
                <template v-if="dialogueTasksForView.length">
                  <template v-for="task in dialogueTasksForView" :key="task.id">
                    <div class="message-row user">
                      <div class="avatar">管</div>
                      <div class="bubble">
                        <span>admin · {{ shortHash(task.trace_id) }}</span>
                        <p>{{ task.user_input }}</p>
                      </div>
                    </div>

                    <div class="message-row agent">
                      <div class="avatar">KG</div>
                      <div class="bubble">
                        <span>运维 Agent</span>
                        <p>{{ taskSummaryText(task) }}</p>
                      </div>
                    </div>
                  </template>
                </template>
                <div v-else-if="store.investigationLoading" class="message-row agent">
                  <div class="avatar">KG</div>
                  <div class="bubble">
                    <span>运维 Agent</span>
                    <p>正在读取任务记录。</p>
                  </div>
                </div>
                <div v-else-if="!store.pendingInput" class="message-row agent">
                  <div class="avatar">KG</div>
                  <div class="bubble">
                    <span>运维 Agent</span>
                    <p>请输入运维诉求。</p>
                  </div>
                </div>

                <template v-if="store.pendingInput">
                  <div class="message-row user">
                    <div class="avatar">管</div>
                    <div class="bubble">
                      <span>admin</span>
                      <p>{{ store.pendingInput }}</p>
                    </div>
                  </div>
                  <div class="message-row agent">
                    <div class="avatar">KG</div>
                    <div class="bubble">
                      <span>运维 Agent</span>
                      <p>正在提交任务。</p>
                    </div>
                  </div>
                </template>

                <div v-if="store.activeTask" class="agent-turn">
                  <section v-if="showOperationalAttachments" class="agent-attachments">
                    <section class="operation-grid">
                      <article class="panel plan-panel">
                        <div class="panel-head">
                          <h2>Agent 执行计划（共 {{ planRows.length }} 步）</h2>
                          <a-tag :color="riskTone === 'danger' ? 'red' : riskTone === 'warning' ? 'orange' : 'green'">
                            {{ activeRisk }}
                          </a-tag>
                        </div>
                        <div class="plan-steps">
                          <div v-for="row in planRows" :key="row.step" class="plan-step" :class="{ active: row.active }">
                            <span>{{ row.step }}</span>
                            <strong>{{ row.title }}</strong>
                            <a-tag
                              size="small"
                              :color="
                                row.status === '等待审批'
                                  ? 'orange'
                                  : row.status === '已拒绝' || row.status === '已阻断'
                                    ? 'red'
                                    : row.active
                                      ? 'green'
                                      : 'gray'
                              "
                            >
                              {{ row.status }}
                            </a-tag>
                          </div>
                        </div>
                      </article>

                      <article class="panel tool-panel">
                        <div class="panel-head">
                          <h2>MCP 工具调用流</h2>
                          <a-button size="mini" @click="store.activeTask && store.selectTask(store.activeTask)">
                            <template #icon><IconRefresh /></template>
                          </a-button>
                        </div>
                        <div class="tool-stream">
                          <div v-for="call in store.toolCalls" :key="call.id" class="tool-card">
                            <span class="status-dot" :class="{ pending: call.status !== 'ok' }"></span>
                            <div>
                              <strong>{{ toolLabel(call.tool_name) }}</strong>
                              <p>工具版本：v{{ call.tool_version }}</p>
                            </div>
                            <span>{{ toolStatusLabel(call.status) }}</span>
                            <small>{{ call.duration_ms }}ms</small>
                          </div>
                          <div v-if="!store.toolCalls.length" class="tool-empty">
                            等待 Agent 调用 MCP 工具
                          </div>
                        </div>
                      </article>
                    </section>
                  </section>
                </div>
                <section v-if="store.error" class="error-strip">
                  <IconExclamationCircle />
                  {{ store.error }}
                </section>
              </div>
            </div>

            <div v-if="contextualPrompts.length && !prompt" class="context-prompts">
              <span>{{ contextualPrompts[0].source }}</span>
              <button
                v-for="item in contextualPrompts"
                :key="item.prompt"
                :title="item.prompt"
                @click="usePreset(item.prompt)"
              >
                {{ item.label }}
              </button>
            </div>
            <div class="command-panel">
              <a-textarea
                v-model="prompt"
                :auto-size="{ minRows: 2, maxRows: 3 }"
                :disabled="taskInProgress || store.submitting"
                placeholder="输入运维需求，生成可审计的 Agent 任务..."
                @keydown.ctrl.enter.prevent="submit"
              />
              <a-button
                type="primary"
                :loading="store.submitting"
                :disabled="taskInProgress"
                @click="submit"
              >
                <template #icon><IconSend /></template>
              </a-button>
            </div>
          </article>
          <article v-else class="tab-detail" :class="{ 'graph-detail': activeCaseTab === 'graph' }">
            <div v-if="store.investigationLoading" class="tab-loading-state">
              正在读取任务状态与持久化证据
            </div>
            <template v-else-if="activeCaseTab === 'plan'">
              <div class="detail-head">
                <h2>Agent 执行计划</h2>
                <span>来自当前任务状态机和审批方案</span>
              </div>
              <div class="plan-steps detail-list">
                <div v-for="row in planRows" :key="row.step" class="plan-step" :class="{ active: row.active }">
                  <span>{{ row.step }}</span>
                  <strong>{{ row.title }}</strong>
                  <a-tag
                    size="small"
                    :color="row.status === '等待审批' ? 'orange' : row.status === '已拒绝' || row.status === '已阻断' ? 'red' : row.active ? 'green' : 'gray'"
                  >
                    {{ row.status }}
                  </a-tag>
                </div>
              </div>
            </template>
            <template v-else-if="activeCaseTab === 'process'">
              <div class="detail-head">
                <h2>MCP 工具调用与执行轨迹</h2>
                <span>工具调用 {{ store.toolCalls.length }} 次，审计事件 {{ store.events.length }} 条</span>
              </div>
              <div v-if="store.toolCalls.length" class="module-table compact-table">
                <div class="data-row head tools-row">
                  <span>工具</span>
                  <span>版本</span>
                  <span>风险</span>
                  <span>状态</span>
                  <span>耗时 / 证据</span>
                </div>
                <div v-for="call in store.toolCalls" :key="call.id" class="data-row tools-row">
                  <span>{{ toolLabel(call.tool_name) }}</span>
                  <span>v{{ call.tool_version }}</span>
                  <span>{{ call.risk_level }}</span>
                  <span>{{ toolStatusLabel(call.status) }}</span>
                  <span>{{ call.duration_ms }}ms · {{ call.output.evidence_refs?.join('，') || '-' }}</span>
                </div>
              </div>
              <div v-else class="empty-state tab-empty-state">
                当前任务未调用 MCP 工具。若任务被安全策略拒绝或在意图阶段停止，系统不会生成执行轨迹。
              </div>
            </template>
            <template v-else-if="activeCaseTab === 'graph'">
              <section class="task-graph-workspace">
                <nav class="task-graph-switch" aria-label="任务图谱视图">
                  <button
                    :class="{ active: relationshipGraphView === 'runtime' && serviceRelationshipSnapshot }"
                    :disabled="!serviceRelationshipSnapshot"
                    @click="relationshipGraphView = 'runtime'"
                  >
                    运行关系
                    <em v-if="serviceRelationshipSnapshot">{{ Number(serviceRelationshipSnapshot.edge_count || 0) }}</em>
                  </button>
                  <button
                    :class="{ active: relationshipGraphView === 'decision' || !serviceRelationshipSnapshot }"
                    @click="relationshipGraphView = 'decision'"
                  >
                    决策链
                    <em v-if="decisionGraph">{{ decisionGraph.nodes.length }}</em>
                  </button>
                </nav>
                <ServiceRelationshipSnapshot
                  v-if="relationshipGraphView === 'runtime' && serviceRelationshipSnapshot"
                  :snapshot="serviceRelationshipSnapshot"
                  @request-impact="requestServiceImpact"
                  @request-investigation="submitFromModule"
                />
                <OperationalDecisionGraph
                  v-else
                  :graph="decisionGraph"
                  :assurance="evidenceAssurance"
                  :default-scope="store.operatorContext?.explicit.evidence_view || 'CORE'"
                />
              </section>
            </template>
            <template v-else>
              <div class="detail-head">
                <h2>结果与报告</h2>
                <span>审计编号 {{ shortHash(store.activeTask?.trace_id) }} · {{ store.auditVerification?.valid ? '校验通过' : '待校验' }}</span>
              </div>
              <div v-if="!store.activeTask" class="empty-state report-empty">
                请选择一个历史会话，或在下方输入运维诉求后生成任务报告。
              </div>
              <div v-else class="result-report">
                <section class="receipt-summary">
                  <div>
                    <span>任务结论</span>
                    <strong>{{ activeStatusText }} · {{ activeRisk }}</strong>
                    <p>{{ readableSummary }}</p>
                  </div>
                  <code>{{ shortHash(store.activeTask?.trace_id) }}</code>
                  <div v-if="investigationRoles.length" class="role-trace" aria-label="受控执行路径">
                    <span class="role-trace-label">受控执行路径</span>
                    <div class="role-trace-items">
                      <template v-for="(role, index) in investigationRoles" :key="role.key">
                        <span
                          class="role-trace-item"
                          :class="roleStatusTone(role.status)"
                          :title="`${role.basis}\n${role.output}\n${role.constraint}`"
                        >
                          <strong>{{ role.title }}</strong>
                          <em>{{ roleStatusLabel(role.status) }}</em>
                        </span>
                        <span v-if="index < investigationRoles.length - 1" class="role-trace-separator" aria-hidden="true">/</span>
                      </template>
                    </div>
                  </div>
                </section>

                <TaskLearningActions @open-memories="openOperationalMemories" />

                <section v-if="store.investigationLoading" class="investigation-loading">
                  调查包加载中
                </section>
                <section v-else-if="investigation" class="investigation-board">
                  <div class="investigation-column evidence">
                    <header>
                      <span>证据</span>
                      <strong>{{ investigationEvidence.length }}</strong>
                    </header>
                    <div v-for="item in investigationEvidence.slice(0, 5)" :key="item.evidence_id ?? item.tool_call_id ?? item.evidence_refs[0]" class="investigation-row">
                      <span>{{ item.source_type === 'KNOWLEDGE' ? item.title : toolLabel(item.tool_name) }}</span>
                      <strong>{{ item.source_type === 'KNOWLEDGE' ? '知识' : toolStatusLabel(item.status) }}</strong>
                      <small>{{ item.summary }}</small>
                      <code v-if="item.evidence_refs[0]">{{ item.evidence_refs[0] }}</code>
                    </div>
                    <div v-if="!investigationEvidence.length" class="muted-line">暂无 MCP 证据</div>
                  </div>

                  <div class="investigation-column diagnosis">
                    <header>
                      <span>{{ primaryFindingLabel }}</span>
                      <strong>{{ primaryHypothesis ? confidenceLabel(primaryHypothesis.confidence) : activeRisk }}</strong>
                    </header>
                    <div v-if="primaryHypothesis" class="diagnosis-main">
                      <strong>{{ primaryHypothesis.title }}</strong>
                      <p>{{ primaryHypothesis.root_cause }}</p>
                      <div class="diagnosis-facts">
                        <span>{{ investigationOutcomeText }}</span>
                        <span v-if="investigationRuntime">第 {{ investigationRuntime.current_iteration }} / {{ investigationRuntime.max_iterations }} 轮</span>
                        <span v-if="primaryHypothesis.confidence_score !== undefined">证据分 {{ primaryHypothesis.confidence_score }}</span>
                        <span>支持 {{ relationCount(primaryHypothesis.evidence, 'SUPPORTS') }}</span>
                        <span>反证 {{ relationCount(primaryHypothesis.evidence, 'REFUTES') }}</span>
                      </div>
                      <small v-if="primaryHypothesis.evidence_gap" class="evidence-gap">缺口：{{ primaryHypothesis.evidence_gap }}</small>
                      <button
                        v-if="diagnosisReport?.status === 'model_assisted'"
                        class="text-action"
                        @click="analysisDrawerOpen = true"
                      >
                        完整诊断
                      </button>
                    </div>
                    <div v-else class="muted-line">{{ primaryFindingEmptyText }}</div>
                  </div>

                  <div class="investigation-column actions">
                    <header>
                      <span>处置</span>
                      <strong>{{ actionLifecycleSteps.length ? toolLabel(actionLifecycle?.tool_name || '') : investigationActions.length ? approvalResult : '无变更' }}</strong>
                    </header>
                    <div v-if="actionLifecycleSteps.length" class="action-lifecycle-list">
                      <div
                        v-for="step in actionLifecycleSteps"
                        :key="step.key"
                        class="action-lifecycle-step"
                        :class="actionStepTone(step.status)"
                        :title="`${step.summary}\n${step.references.join('，')}`"
                      >
                        <i aria-hidden="true"></i>
                        <strong>{{ step.title }}</strong>
                        <em>{{ actionStepStatusLabel(step.status) }}</em>
                      </div>
                    </div>
                    <div v-else v-for="action in investigationActions" :key="action.id" class="investigation-row">
                      <span>{{ toolLabel(action.tool_name) }}</span>
                      <strong>{{ action.status }}</strong>
                      <small>{{ action.reason }}</small>
                    </div>
                    <div v-if="!investigationActions.length" class="muted-line">{{ investigationRollback?.summary || rollbackSummary }}</div>
                  </div>

                  <div class="investigation-column audit">
                    <header>
                      <span>审计</span>
                      <strong>{{ investigationAudit?.sealed ? '已封存' : '进行中' }}</strong>
                    </header>
                    <div class="audit-compact">
                      <div class="audit-counts">
                        <span>事件 {{ investigationAudit?.event_count || 0 }}</span>
                        <span>链路 {{ investigationAudit?.chain_entry_count || 0 }}</span>
                      </div>
                      <code>{{ shortHash(investigationAudit?.head_hash) }}</code>
                      <div class="audit-actions">
                        <button class="text-action" @click="traceDrawerOpen = true">查看链路</button>
                        <button
                          class="text-action audit-download-action"
                          :disabled="!store.activeTask || diagnosticBundleState === 'downloading'"
                          title="导出本任务的脱敏证据与审计校验结果"
                          @click="downloadDiagnosticBundle"
                        >
                          <IconDownload aria-hidden="true" />
                          {{ diagnosticBundleState === 'downloading' ? '生成中' : diagnosticBundleState === 'done' ? '已下载' : '下载诊断包' }}
                        </button>
                      </div>
                    </div>
                  </div>
                </section>
                <section v-else class="investigation-loading">
                  暂无调查包
                </section>
              </div>
            </template>
          </article>
        </section>
      </section>

      <section class="trace-dock">
        <div class="trace-title">
          <div class="trace-title-main">
            <strong>执行轨迹</strong>
            <span>链路编号：{{ shortHash(store.activeTask?.trace_id) }}</span>
            <span>审计：{{ store.auditVerification?.valid ? '校验通过' : '待校验' }}</span>
            <span>事件：{{ store.events.length }}</span>
          </div>
          <button class="trace-toggle" @click="traceDrawerOpen = true">
            <IconDown />
            查看审计链
          </button>
        </div>
      </section>

      <div v-if="traceDrawerOpen" class="trace-overlay" @click.self="traceDrawerOpen = false">
        <aside class="trace-drawer">
          <header class="trace-drawer-head">
            <div>
              <strong>执行轨迹审计链</strong>
              <span>链路编号：{{ store.activeTask?.trace_id || '-' }}</span>
            </div>
            <button class="drawer-close" @click="traceDrawerOpen = false">
              <IconClose />
            </button>
          </header>
          <dl v-if="taskObservabilitySummary" class="trace-runtime-band">
            <div>
              <dt>任务耗时</dt>
              <dd>{{ formatRuntimeMs(taskObservabilitySummary.task_elapsed_ms) }}</dd>
            </div>
            <div :title="taskObservabilityModel">
              <dt>{{ taskObservabilityModel }}</dt>
              <dd>
                {{ taskObservabilitySummary.model_call_count }} 次 ·
                {{ formatRuntimeMs(taskObservabilitySummary.model_duration_ms) }}
              </dd>
            </div>
            <div>
              <dt>MCP 工具</dt>
              <dd>
                {{ taskObservabilitySummary.tool_call_count }} 次 ·
                {{ formatRuntimeMs(taskObservabilitySummary.tool_duration_ms) }}
              </dd>
            </div>
            <div>
              <dt>调查轮次</dt>
              <dd>{{ taskObservabilitySummary.investigation_iterations || '-' }}</dd>
            </div>
            <div>
              <dt>模型用量</dt>
              <dd>
                {{ formatTokenUsage(
                  taskObservabilitySummary.total_tokens,
                  taskObservabilitySummary.token_accounting_complete,
                ) }}
              </dd>
            </div>
          </dl>
          <div class="trace-table drawer-trace-table">
          <div class="trace-row head">
            <span>阶段</span>
            <span>组件 / 工具</span>
            <span>事件</span>
            <span>状态</span>
            <span>详情</span>
          </div>
          <div v-for="row in auditTimelineRows" :key="row.id" class="trace-row">
            <span>{{ row.stage }}</span>
            <span>{{ row.component }}</span>
            <span>{{ row.event }}</span>
            <span
              class="trace-status"
              :class="row.valid === true ? 'ok' : row.valid === false ? 'failed' : 'idle'"
            >
              {{ auditEventStatusLabel(row.valid) }}
            </span>
            <span>{{ row.message }}</span>
          </div>
          </div>
        </aside>
      </div>

      <div v-if="analysisDrawerOpen && diagnosisReport" class="trace-overlay analysis-overlay" @click.self="analysisDrawerOpen = false">
        <aside class="trace-drawer analysis-drawer">
          <header class="trace-drawer-head">
            <div>
              <strong>任务诊断报告</strong>
              <span :title="diagnosisReport.model || '控制器事实归纳'">
                {{ diagnosisReport.model ? '模型辅助研判' : '控制器事实归纳' }}
                · 风险 {{ diagnosisReport.risk_level || activeRisk }}
                <template v-if="diagnosisReport.created_at"> · {{ formatDateTime(diagnosisReport.created_at) }}</template>
              </span>
            </div>
            <button class="drawer-close" @click="analysisDrawerOpen = false">
              <IconClose />
            </button>
          </header>
          <div class="analysis-drawer-body">
            <section class="analysis-drawer-section primary">
              <span>结论</span>
              <strong>{{ diagnosisReport.conclusion }}</strong>
              <p
                v-if="
                  diagnosisReport.root_cause
                    && diagnosisReport.root_cause !== diagnosisReport.conclusion
                "
              >
                {{ diagnosisReport.root_cause }}
              </p>
            </section>

            <section
              v-if="diagnosisReport.reasoning_summary?.length"
              class="analysis-drawer-section reasoning"
            >
              <span>研判依据</span>
              <div class="analysis-list">
                <span v-for="item in diagnosisReport.reasoning_summary" :key="item">{{ item }}</span>
              </div>
            </section>

            <section
              v-if="diagnosisReport.counter_evidence?.length"
              class="analysis-drawer-section counter-evidence"
            >
              <span>反证与边界</span>
              <div class="analysis-list counter">
                <span v-for="item in diagnosisReport.counter_evidence" :key="item">{{ item }}</span>
              </div>
            </section>

            <section
              v-if="diagnosisReport.evidence?.length"
              class="analysis-drawer-section evidence"
            >
              <span>引用证据</span>
              <div class="analysis-evidence-list">
                <article v-for="evidence in diagnosisReport.evidence" :key="`${evidence.source}-${evidence.summary}`">
                  <strong>{{ evidence.source || 'MCP 证据' }}</strong>
                  <p>{{ evidence.summary || '-' }}</p>
                </article>
              </div>
            </section>

            <section
              v-if="diagnosisReport.recommended_actions?.length"
              class="analysis-drawer-section actions"
            >
              <span>后续建议</span>
              <div class="analysis-actions drawer-actions">
                <article v-for="action in diagnosisReport.recommended_actions" :key="action.title">
                  <strong>{{ action.title }}</strong>
                  <p>{{ action.rationale }}</p>
                  <code>{{ safetyGateLabel(action.safety_gate) }}</code>
                </article>
              </div>
            </section>

            <section class="analysis-drawer-section residual">
              <span>残余风险</span>
              <p>{{ diagnosisReport.residual_risk || '当前未记录新增风险，后续仍按验证结果闭环。' }}</p>
            </section>
          </div>
        </aside>
      </div>
    </section>

    <section v-else class="workspace module-workspace">
      <section
        class="module-page"
        :class="{
          compact: activeView === 'posture' || activeView === 'scenarios' || activeView === 'events',
          'posture-mode': activeView === 'posture',
          'event-mode': activeView === 'events',
          'safety-mode': activeView === 'safety',
          'collaboration-mode': activeView === 'collaboration',
        }"
      >
        <header
          v-if="activeView !== 'events' && activeView !== 'safety' && activeView !== 'collaboration'"
          class="module-head"
          :class="{ compact: activeView === 'posture' || activeView === 'scenarios', 'posture-head': activeView === 'posture' }"
        >
          <div>
            <h2 v-if="activeView !== 'posture'">{{ activeView === 'knowledge' ? '知识工作区' : moduleTitle }}</h2>
            <div v-else class="posture-toolbar-status">
              <span>{{ postureStatusText }}</span>
              <strong>{{ store.livePosture?.collected_at ? formatDateTime(store.livePosture.collected_at) : '等待采样' }}</strong>
            </div>
            <p v-if="activeView !== 'scenarios' && activeView !== 'posture' && activeView !== 'knowledge'">{{ moduleDescription }}</p>
          </div>
          <div class="module-head-actions">
            <nav v-if="activeView === 'posture'" class="posture-view-switch" aria-label="系统态势视图">
              <button :class="{ active: postureSection === 'overview' }" @click="postureSection = 'overview'">
                实时态势
              </button>
              <button :class="{ active: postureSection === 'services' }" @click="postureSection = 'services'">
                服务目录
              </button>
            </nav>
            <a-button
              v-if="activeView !== 'posture' || postureSection === 'overview'"
              size="small"
              :loading="
                (activeView === 'posture' && store.postureRefreshing) ||
                (activeView === 'tools' && store.mcpRefreshing)
              "
              @click="refreshModule"
            >
              <template #icon><IconRefresh /></template>
              刷新
            </a-button>
          </div>
        </header>
        <section v-if="store.error && activeView !== 'events'" class="error-strip module-error">
          <IconExclamationCircle />
          {{ store.error }}
        </section>

        <section v-if="activeView === 'posture'" class="posture-workspace">
          <ServiceCatalog
            v-if="postureSection === 'services'"
            :host-key="hostName()"
            @investigate="submitFromModule"
          />
          <template v-else>
          <section class="posture-summary-strip">
            <article
              v-for="card in postureSummaryCards"
              :key="card.label"
              class="posture-summary-card"
              :class="card.tone"
            >
              <span>{{ card.label }}</span>
              <strong>{{ card.value }}</strong>
              <small>{{ card.meta }}</small>
            </article>
          </section>

          <section v-if="postureNextActions.length" class="posture-action-rail">
            <span>下一步动作</span>
            <div class="posture-action-buttons">
              <button
                v-for="action in postureNextActions"
                :key="action.key"
                :title="action.prompt"
                :disabled="store.loading || store.submitting || taskInProgress"
                @click="runPostureAction(action)"
              >
                {{ action.label }}
              </button>
            </div>
          </section>

          <section class="posture-command-grid">
            <article class="posture-glass posture-host-card">
              <header class="posture-section-head">
                <div>
                  <span>当前主机</span>
                  <strong>{{ hostName() }}</strong>
                </div>
                <code>{{ postureStatusText }}</code>
              </header>

              <div class="posture-host-hero">
                <div class="host-orbit">
                  <span>OS</span>
                </div>
                <div>
                  <strong>{{ osText() }}</strong>
                  <p>{{ architectureText() }} · {{ hostSnapshot.kernel || '等待内核信息' }}</p>
                  <small>运行 {{ uptimeText() }}</small>
                </div>
              </div>

              <section v-if="store.deploymentReadiness" class="posture-deployment">
                <header>
                  <strong>运行环境</strong>
                  <code :class="runtimeGuardClass(store.deploymentReadiness.overall_status)">
                    {{ deploymentStatusLabel(store.deploymentReadiness.overall_status) }}
                  </code>
                </header>
                <p>{{ store.deploymentReadiness.summary }}</p>
                <div v-if="store.platformCapabilities" class="posture-capability-line">
                  <span>{{ store.platformCapabilities.platform.os_release.name || 'Linux' }}</span>
                  <span>{{ store.platformCapabilities.platform.machine }}</span>
                  <span>{{ platformCapabilityCount.ready }}/{{ platformCapabilityCount.total }} 项可用</span>
                </div>
              </section>
            </article>

            <article class="posture-glass posture-radar-card">
              <header class="posture-section-head">
                <div>
                  <span>感知工具链</span>
                  <strong>{{ liveToolHealthText }}</strong>
                </div>
                <small>{{ store.livePosture?.collected_at ? formatDateTime(store.livePosture.collected_at) : '等待采样' }}</small>
              </header>
              <div class="posture-radar-map">
                <div class="radar-ring ring-one"></div>
                <div class="radar-ring ring-two"></div>
                <div class="radar-ring ring-three"></div>
                <div class="radar-axis axis-a"></div>
                <div class="radar-axis axis-b"></div>
                <div class="radar-axis axis-c"></div>
                <div class="radar-core">
                  <span>MCP</span>
                  <strong>{{ postureScoreText }}</strong>
                </div>
                <div
                  v-for="node in postureRadarNodes"
                  :key="node.key"
                  class="radar-node"
                  :class="[node.key, node.status]"
                >
                  <strong>{{ node.label }}</strong>
                  <span>{{ node.value }}</span>
                </div>
              </div>
              <footer class="posture-legend">
                <span><i class="ok"></i>正常</span>
                <span><i class="warn"></i>关注</span>
                <span><i class="bad"></i>异常</span>
              </footer>
            </article>

            <section class="posture-evidence-stack">
              <article class="posture-glass posture-attention-panel">
                <header class="posture-section-head compact">
                  <div>
                    <span>重点关注</span>
                    <strong>{{ postureAttentionItems.filter((item) => item.tone !== 'ok').length }} 项</strong>
                  </div>
                </header>
                <div class="posture-attention-list">
                  <div v-for="item in postureAttentionItems" :key="item.key" :class="item.tone">
                    <i></i>
                    <div>
                      <strong>{{ item.title }}</strong>
                      <span :title="item.detail">{{ item.detail }}</span>
                    </div>
                  </div>
                </div>
              </article>

              <article class="posture-glass posture-config-panel">
                <header class="posture-section-head compact">
                  <div>
                    <span>配置漂移</span>
                    <strong>{{ configBaselineStatusText }}</strong>
                  </div>
                  <a-button
                    v-if="!latestConfigBaseline"
                    size="mini"
                    type="primary"
                    :loading="store.configBaselineBusy"
                    @click="store.createDefaultConfigBaseline()"
                  >
                    建立基线
                  </a-button>
                  <a-button
                    v-else
                    size="mini"
                    :loading="store.configBaselineBusy"
                    @click="store.checkConfigBaseline(latestConfigBaseline)"
                  >
                    核验
                  </a-button>
                </header>
                <div v-if="latestConfigCheck" class="posture-config-result" :class="configCheckTone(latestConfigCheck)">
                  <strong>{{ latestConfigCheck.summary.changed }}</strong>
                  <span>变化</span>
                  <small>{{ latestConfigCheck.summary.unchanged }} 未变</small>
                </div>
                <div v-else class="posture-empty dark">
                  {{ latestConfigBaseline ? '等待核验' : '未建立基线' }}
                </div>
                <div v-if="visibleConfigChanges.length" class="posture-config-changes">
                  <div v-for="change in visibleConfigChanges" :key="change.path">
                    <code :title="change.path">{{ change.path }}</code>
                    <span>{{ change.change_types.map(configChangeLabel).join('、') }}</span>
                  </div>
                </div>
              </article>
            </section>
          </section>

          <section class="posture-bottom-grid">
            <article class="posture-glass posture-process-panel">
              <header class="posture-section-head compact">
                <div>
                  <span>进程采样</span>
                  <strong>{{ liveProcessRows.length }} 个进程</strong>
                </div>
              </header>
              <div v-if="visibleProcessRows.length" class="posture-process-list">
                <div v-for="row in visibleProcessRows" :key="String(row.pid)">
                  <div>
                    <strong>{{ processTitle(row) }}</strong>
                    <span>{{ processMeta(row) }}</span>
                  </div>
                  <div class="posture-meter">
                    <i :style="{ width: percentBarWidth(processCpuPercent(row)) }"></i>
                  </div>
                  <code>{{ processUsageText(row) }}</code>
                </div>
              </div>
              <div v-else class="posture-empty dark">等待进程采样</div>
            </article>

            <article class="posture-glass posture-network-panel">
              <header class="posture-section-head compact">
                <div>
                  <span>监听端口</span>
                  <strong>{{ attributedListenerCount }}/{{ networkListenerCount }} 已归属</strong>
                </div>
              </header>
              <div v-if="visibleNetworkRows.length" class="posture-network-list">
                <div v-for="row in visibleNetworkRows" :key="`${row.protocol}-${row.local_address}`">
                  <strong>{{ listenerEndpoint(row) }}</strong>
                  <span>{{ listenerMeta(row) }}</span>
                </div>
              </div>
              <div v-else class="posture-empty dark">未发现监听端口或工具不可用</div>
            </article>

            <article class="posture-glass posture-sample-panel">
              <header class="posture-section-head compact">
                <div>
                  <span>采样状态</span>
                  <strong>{{ liveToolHealthText }}</strong>
                </div>
              </header>
              <div v-if="liveToolRuns.length" class="posture-run-list">
                <div v-for="run in liveToolRuns.slice(0, 4)" :key="run.tool_name">
                  <i :class="{ ok: run.status === 'ok' }"></i>
                  <strong>{{ compactToolLabel(run.tool_name) }}</strong>
                  <code>{{ toolStatusLabel(run.status) }} · {{ run.duration_ms }}ms</code>
                </div>
              </div>
              <div v-else class="posture-empty dark">等待采样</div>
            </article>
          </section>
          </template>
        </section>

        <EventCenter
          v-else-if="activeView === 'events'"
          :initial-tab="eventSection"
          @open-task="openPatrolTask"
        />

        <IncidentCollaboration
          v-else-if="activeView === 'collaboration'"
          @open-task="openPatrolTask"
        />

        <section v-else-if="activeView === 'benchmark'" class="module-table benchmark-module">
          <header class="benchmark-toolbar">
            <nav class="benchmark-view-switch" aria-label="评测视图">
              <button :class="{ active: benchmarkView === 'performance' }" @click="benchmarkView = 'performance'">
                工具性能
              </button>
              <button :class="{ active: benchmarkView === 'agent' }" @click="benchmarkView = 'agent'">
                Agent 评测
              </button>
              <button :class="{ active: benchmarkView === 'lab' }" @click="benchmarkView = 'lab'">
                靶场评测
              </button>
            </nav>
            <a-button
              v-if="benchmarkView === 'performance'"
              type="primary"
              size="small"
              :loading="store.benchmarkRunning"
              @click="store.runBenchmark(2)"
            >
              重新采样
            </a-button>
            <a-button
              v-else-if="benchmarkView === 'agent'"
              type="primary"
              size="small"
              :loading="store.agentEvaluationRunning"
              @click="store.runAgentEvaluation()"
            >
              运行校验
            </a-button>
            <a-button
              v-else
              type="primary"
              size="small"
              :loading="store.labEvaluationRunning"
              @click="store.runLabEvaluation()"
            >
              运行验证
            </a-button>
          </header>

          <section v-if="benchmarkView === 'performance'" class="benchmark-performance-pane">
            <div v-if="!store.benchmarkReport" class="empty-state benchmark-empty">
              暂无工具性能采样。运行后显示真实耗时、P95 和阈值占用。
            </div>
            <template v-else>
              <section class="benchmark-health-strip">
                <div>
                  <span>总体状态</span>
                  <strong>{{ benchmarkStatusLabel(store.benchmarkReport.summary.overall_status) }}</strong>
                  <small>{{ store.benchmarkReport.summary.ok_count }} / {{ store.benchmarkReport.summary.tool_count }} 正常</small>
                </div>
                <div>
                  <span>采样节点</span>
                  <strong>{{ store.benchmarkReport.environment.hostname || '-' }}</strong>
                  <small>{{ store.benchmarkReport.environment.machine || '-' }}</small>
                </div>
                <div>
                  <span>P95 峰值</span>
                  <strong>{{ store.benchmarkReport.summary.worst_p95_ms ?? 0 }}ms</strong>
                  <small>{{ toolLabel(store.benchmarkReport.summary.worst_p95_tool || '') }}</small>
                </div>
                <div>
                  <span>本轮耗时</span>
                  <strong>{{ store.benchmarkReport.total_duration_ms }}ms</strong>
                  <small>{{ store.benchmarkReport.rounds }} 轮</small>
                </div>
              </section>

              <section class="benchmark-detail-grid">
                <section class="benchmark-metric-panel">
                  <header>
                    <div>
                      <strong>工具延迟</strong>
                      <span>P95 与阈值预算</span>
                    </div>
                    <code>{{ formatDateTime(store.benchmarkReport.completed_at) }}</code>
                  </header>
                  <div class="benchmark-tool-table">
                    <div class="benchmark-tool-row head">
                      <span>工具</span>
                      <span>状态</span>
                      <span>成功率</span>
                      <span>平均</span>
                      <span>P95 / 阈值</span>
                      <span>证据</span>
                    </div>
                    <div v-for="metric in benchmarkMetrics" :key="metric.tool_name" class="benchmark-tool-row">
                      <strong>{{ metric.label }}</strong>
                      <code class="status-pill" :class="benchmarkStatusClass(metric.status)">
                        {{ benchmarkStatusLabel(metric.status) }}
                      </code>
                      <span>{{ metric.success_rate }}%</span>
                      <span>{{ metric.duration_ms_avg }}ms</span>
                      <span class="benchmark-latency">
                        <strong>{{ metric.duration_ms_p95 }}ms</strong>
                        <i>
                          <b :style="{ width: `${benchmarkBudgetPercent(metric.duration_ms_p95, metric.threshold_ms)}%` }"></b>
                        </i>
                        <small>{{ metric.threshold_ms }}ms</small>
                      </span>
                      <span :title="metric.error || metric.samples[0]?.evidence_refs?.join('，') || '无异常'">
                        {{ metric.error || metric.samples[0]?.evidence_refs?.join('，') || '无异常' }}
                      </span>
                    </div>
                  </div>
                </section>

                <aside class="benchmark-context-panel">
                  <header>
                    <strong>运行环境</strong>
                    <code>{{ store.benchmarkReport.environment.os_family || 'linux' }}</code>
                  </header>
                  <div class="benchmark-context-lines">
                    <div>
                      <span>操作系统</span>
                      <strong>{{ store.benchmarkReport.environment.os || '-' }}</strong>
                    </div>
                    <div>
                      <span>内核</span>
                      <code>{{ store.benchmarkReport.environment.kernel || '-' }}</code>
                    </div>
                    <div>
                      <span>架构</span>
                      <strong>{{ store.benchmarkReport.environment.machine || '-' }}</strong>
                    </div>
                    <div>
                      <span>最慢工具</span>
                      <strong>{{ benchmarkSlowestTool }}</strong>
                    </div>
                  </div>
                  <div class="benchmark-verdict" :class="store.benchmarkReport.summary.overall_status">
                    <span>性能结论</span>
                    <strong>
                      {{
                        store.benchmarkReport.summary.failed_count
                          ? `${store.benchmarkReport.summary.failed_count} 项失败`
                          : store.benchmarkReport.summary.warn_count
                            ? `${store.benchmarkReport.summary.warn_count} 项偏慢`
                            : '全部处于阈值内'
                      }}
                    </strong>
                  </div>
                </aside>
              </section>
            </template>
          </section>

          <section v-else-if="benchmarkView === 'agent'" class="safety-evaluation-panel agent-evaluation-panel benchmark-evaluation-view">
            <header>
              <div>
                <strong>Agent 工作流评测</strong>
                <span>{{ formatDateTime(store.agentEvaluationReport?.completed_at) }}</span>
              </div>
              <code class="status-pill" :class="safetyEvaluationClass(agentEvaluationSummary ? agentEvaluationSummary.overall_status === 'ok' : undefined)">
                {{ agentEvalStatusText }}
              </code>
            </header>
            <div class="safety-evaluation-metrics">
              <article>
                <span>攻击拦截</span>
                <strong>{{ agentAttackBlockRateText }}</strong>
              </article>
              <article>
                <span>计划合规</span>
                <strong>{{ agentPolicyPassText }}</strong>
              </article>
              <article>
                <span>通过用例</span>
                <strong>{{ agentEvaluationSummary?.passed_count ?? '-' }} / {{ agentEvaluationSummary?.case_count ?? '-' }}</strong>
              </article>
              <article>
                <span>失败用例</span>
                <strong>{{ agentEvaluationSummary?.failed_count ?? '-' }}</strong>
              </article>
            </div>
            <div v-if="agentEvaluationCases.length" class="agent-evaluation-cases">
              <article v-for="item in agentEvaluationCases" :key="item.id">
                <span>{{ item.category }}</span>
                <strong :title="item.prompt">{{ agentEvaluationDecision(item) }}</strong>
                <code class="status-pill" :class="safetyEvaluationClass(item.passed)">
                  {{ item.passed ? '通过' : '未通过' }}
                </code>
                <em>{{ item.used_tools.map(toolLabel).join('、') || statusLabel(item.actual_decision) }}</em>
              </article>
            </div>
            <div v-else class="empty-state benchmark-evaluation-empty">暂无编排校验记录。</div>
          </section>

          <section v-else class="safety-evaluation-panel agent-evaluation-panel benchmark-evaluation-view">
            <header>
              <div>
                <strong>靶场端到端评测</strong>
                <span>{{ formatDateTime(store.labEvaluationReport?.completed_at) }}</span>
              </div>
              <code
                class="status-pill"
                :class="labEvaluationSummary?.qualification_status === 'prerequisite_missing' ? 'warn' : safetyEvaluationClass(labEvaluationSummary ? labEvaluationSummary.overall_status === 'ok' : undefined)"
              >
                {{ labEvalStatusText }}
              </code>
            </header>
            <div class="safety-evaluation-metrics">
              <article>
                <span>有效案例</span>
                <strong>{{ labEvaluationSummary?.passed_count ?? '-' }} / {{ labEvaluationSummary?.supported_count ?? labEvaluationSummary?.case_count ?? '-' }}</strong>
              </article>
              <article>
                <span>证据覆盖</span>
                <strong>{{ evaluationRate(labEvaluationSummary?.evidence_coverage_rate) }}</strong>
              </article>
              <article>
                <span>注入拦截</span>
                <strong>{{ evaluationRate(labEvaluationSummary?.injection_block_rate) }}</strong>
              </article>
              <article>
                <span>越权变更</span>
                <strong>{{ labEvaluationSummary?.unauthorized_side_effect_count ?? '-' }}</strong>
              </article>
              <article>
                <span>根因命中</span>
                <strong>{{ evaluationRate(labEvaluationSummary?.top1_root_cause_accuracy) }}</strong>
              </article>
              <article>
                <span>审批绑定</span>
                <strong>{{ evaluationRate(labEvaluationSummary?.action_contract_coverage_rate) }}</strong>
              </article>
              <article>
                <span>因果链</span>
                <strong>{{ evaluationRate(labEvaluationSummary?.causal_chain_coverage_rate) }}</strong>
              </article>
              <article>
                <span>反证覆盖</span>
                <strong>{{ evaluationRate(labEvaluationSummary?.counter_evidence_coverage_rate) }}</strong>
              </article>
              <article>
                <span>影响精度</span>
                <strong>{{ evaluationRate(labEvaluationSummary?.change_impact_precision) }}</strong>
              </article>
              <article>
                <span>影响召回</span>
                <strong>{{ evaluationRate(labEvaluationSummary?.change_impact_recall) }}</strong>
              </article>
            </div>
            <div v-if="labEvaluationCases.length" class="agent-evaluation-cases">
              <article
                v-for="item in labEvaluationCases"
                :key="item.id"
                :class="{ 'task-linked': item.task_id }"
                :tabindex="item.task_id ? 0 : undefined"
                :title="item.task_id ? '打开任务证据' : item.error"
                @click="openLabEvaluationTask(item)"
                @keydown.enter="openLabEvaluationTask(item)"
              >
                <span>{{ item.title }}</span>
                <strong :title="item.prompt">{{ labEvaluationResult(item) }}</strong>
                <code class="status-pill" :class="item.supported ? safetyEvaluationClass(item.passed) : 'warn'">
                  {{ !item.supported ? '前置缺失' : item.passed ? '通过' : '未通过' }}
                </code>
                <em>{{ labEvaluationEvidence(item) }}</em>
              </article>
            </div>
            <div v-else class="empty-state benchmark-evaluation-empty">暂无靶场验证记录。</div>
          </section>
        </section>

        <section v-else-if="activeView === 'safety'" class="module-table safety-module">
          <section class="safety-runtime-strip" :class="runtimeTone">
            <div class="safety-primary-state">
              <i></i>
              <div>
                <span>执行状态</span>
                <strong>{{ runtimeStatusText }}</strong>
              </div>
              <code>{{ executorIdentityText }}</code>
            </div>
            <dl>
              <div>
                <dt>最小权限账户</dt>
                <dd>{{ runtimeSafety?.executor.target_user || '-' }}</dd>
              </div>
              <div>
                <dt>当前任务</dt>
                <dd>{{ activeRisk }}</dd>
              </div>
              <div>
                <dt>变更能力</dt>
                <dd>{{ actionExecutionEnabled ? '审批后开放' : '已锁定' }}</dd>
              </div>
              <div>
                <dt>策略规则</dt>
                <dd>{{ store.safetyRules.length }} 条</dd>
              </div>
            </dl>
          </section>

          <nav class="safety-section-tabs" role="tablist" aria-label="安全护栏视图">
            <button
              type="button"
              role="tab"
              :aria-selected="safetySection === 'boundary'"
              :class="{ active: safetySection === 'boundary' }"
              @click="safetySection = 'boundary'"
            >执行边界</button>
            <button
              type="button"
              role="tab"
              :aria-selected="safetySection === 'evaluation'"
              :class="{ active: safetySection === 'evaluation' }"
              @click="safetySection = 'evaluation'"
            >对抗自检</button>
            <button
              type="button"
              role="tab"
              :aria-selected="safetySection === 'rules'"
              :class="{ active: safetySection === 'rules' }"
              @click="safetySection = 'rules'"
            >规则库</button>
            <a-button
              class="safety-refresh"
              size="mini"
              :loading="store.safetyRefreshing"
              title="刷新运行态"
              aria-label="刷新运行态"
              @click="refreshModule"
            >
              <template #icon><IconRefresh /></template>
            </a-button>
          </nav>

          <section v-if="safetySection === 'boundary'" class="safety-boundary-workspace" role="tabpanel">
            <section class="safety-boundary-sheet">
              <header>
                <strong>权限边界</strong>
                <span :title="runtimeSafety?.summary || ''">{{ runtimeSafety?.summary || '正在读取运行时状态' }}</span>
              </header>
              <div class="safety-boundary-row">
                <span>运行身份</span>
                <div class="safety-boundary-value"><strong>{{ executorIdentityText }}</strong></div>
              </div>
              <div class="safety-boundary-row">
                <span>允许写入</span>
                <div class="safety-boundary-values">
                  <code v-for="path in allowedBoundaryPaths" :key="path">{{ path }}</code>
                  <em v-if="!allowedBoundaryPaths.length">未开放</em>
                </div>
              </div>
              <div class="safety-boundary-row">
                <span>变更类工具</span>
                <div class="safety-boundary-values text-values">
                  <code v-for="tool in allowedBoundaryTools" :key="tool">{{ tool }}</code>
                  <em v-if="!allowedBoundaryTools.length">未开放</em>
                </div>
              </div>
              <div class="safety-boundary-row">
                <span>服务重启</span>
                <div class="safety-boundary-values">
                  <code v-for="unit in restartableBoundaryUnits" :key="unit">{{ unit }}</code>
                  <em v-if="!restartableBoundaryUnits.length">未开放</em>
                </div>
              </div>
              <div class="safety-boundary-row config-row">
                <span>配置修复</span>
                <div class="safety-boundary-values">
                  <code v-for="path in repairableBoundaryPaths" :key="path" :title="path">{{ path }}</code>
                  <em v-if="!repairableBoundaryPaths.length">未开放</em>
                </div>
              </div>
              <div class="safety-boundary-row">
                <span>永久保护</span>
                <div class="safety-protected-line" :title="protectedBoundaryText">
                  <strong>{{ protectedBoundaryPaths.length ? `${protectedBoundaryPaths.length} 类目录` : '-' }}</strong>
                  <small>{{ protectedBoundaryPreview }}</small>
                </div>
              </div>
            </section>

            <aside class="safety-gate-sheet">
              <header>
                <strong>控制节点</strong>
                <span>{{ safetyGuardRows.filter((guard) => guard.status === 'ok').length }} / {{ safetyGuardRows.length }} 通过</span>
              </header>
              <div class="safety-gate-list">
                <div v-for="guard in safetyGuardRows" :key="guard.key">
                  <i :class="runtimeGuardClass(guard.status)"></i>
                  <strong>{{ guard.name }}</strong>
                  <code class="status-pill" :class="runtimeGuardClass(guard.status)">
                    {{ guard.status === 'ok' ? '通过' : guard.status === 'warn' ? '关注' : '锁定' }}
                  </code>
                  <span :title="guard.detail">{{ guard.detail }}</span>
                </div>
              </div>
            </aside>
          </section>

          <section v-else-if="safetySection === 'evaluation'" class="safety-evaluation-workspace" role="tabpanel">
            <header>
              <div>
                <strong>安全边界自检</strong>
                <span>最近运行：{{ formatDateTime(store.safetyEvaluationReport?.completed_at) }}</span>
              </div>
              <a-button type="primary" size="small" :loading="store.safetyEvaluationRunning" @click="store.runSafetyEvaluation()">
                运行自检
              </a-button>
            </header>
            <div class="safety-metric-line">
              <div><span>结论</span><strong>{{ safetyEvalStatusText }}</strong></div>
              <div><span>恶意请求</span><strong>{{ safetyAttackBlockRateText }}</strong></div>
              <div><span>会话风险链</span><strong>{{ safetyCrossTurnBlockRateText }}</strong></div>
              <div><span>参数越界</span><strong>{{ safetyDynamicBlockRateText }}</strong></div>
              <div><span>数据隔离</span><strong>{{ safetyDataQuarantineRateText }}</strong></div>
              <div><span>误拒</span><strong>{{ safetyEvaluationSummary?.false_reject_count ?? '-' }}</strong></div>
            </div>
            <div class="safety-case-table">
              <div class="head"><span>类型</span><span>测试对象</span><span>裁决</span><span>结果</span></div>
              <div v-for="item in safetyEvaluationCases" :key="item.id" class="row">
                <span>{{ item.category }}</span>
                <strong :title="item.prompt">{{ safetyEvaluationCaseText(item) }}</strong>
                <em>{{ statusLabel(item.actual_decision) }} · {{ item.actual_risk_level }}</em>
                <code class="status-pill" :class="safetyEvaluationClass(item.passed)">{{ item.passed ? '通过' : '未通过' }}</code>
              </div>
              <div v-if="!safetyEvaluationCases.length" class="empty">暂无自检记录</div>
            </div>
          </section>

          <section v-else class="safety-rules-workspace" role="tabpanel">
            <header>
              <div>
                <strong>运行时规则</strong>
                <span>本任务命中 R0 {{ riskCounts.R0 || 0 }} · R2 {{ riskCounts.R2 || 0 }} · R3 {{ riskCounts.R3 || 0 }} · R4 {{ riskCounts.R4 || 0 }}</span>
              </div>
              <code>{{ store.safetyRules.length }} 条</code>
            </header>
            <div class="safety-rule-table">
              <div class="head"><span>等级</span><span>类别</span><span>规则</span><span>裁决</span></div>
              <div v-for="rule in safetyRuleRows" :key="rule.category + rule.label + rule.detail" class="row" :title="rule.detail">
                <code>{{ rule.risk_level }}</code>
                <span>{{ rule.category }}</span>
                <strong>{{ rule.label }}</strong>
                <em>{{ statusLabel(rule.decision) }}</em>
              </div>
            </div>
          </section>
        </section>

        <section v-else-if="activeView === 'tools'" class="module-table mcp-governance-module">
          <section class="mcp-control-strip" :class="mcpStatusTone">
            <div class="mcp-endpoint-state">
              <i></i>
              <div>
                <span>协议端点</span>
                <strong>{{ mcpStatusText }}</strong>
              </div>
              <code>{{ mcpStatus?.endpoint || '/mcp' }}</code>
            </div>
            <div>
              <span>协议</span>
              <strong>{{ mcpProtocolText }}</strong>
              <small>Streamable HTTP</small>
            </div>
            <div>
              <span>工具注册</span>
              <strong>{{ mcpToolCountText }}</strong>
              <small>{{ mcpReadOnlyText }}</small>
            </div>
            <div>
              <span>契约完整性</span>
              <strong>{{ toolRuntimeVerifiedCount }} / {{ store.tools.length }}</strong>
              <small>运行清单已核验</small>
            </div>
            <div>
              <span>变更控制</span>
              <strong>{{ mcpActionText }}</strong>
              <small>预检通过后审批执行</small>
            </div>
          </section>

          <section class="mcp-governance-grid">
            <section class="mcp-registry-panel">
              <header>
                <div>
                  <strong>工具注册表</strong>
                  <span>运行态定义</span>
                </div>
                <code>R0 {{ toolRiskCounts.R0 || 0 }} · R1 {{ toolRiskCounts.R1 || 0 }} · R2 {{ toolRiskCounts.R2 || 0 }} · R3 {{ toolRiskCounts.R3 || 0 }}</code>
              </header>
              <div class="mcp-tool-table">
                <div class="mcp-tool-row head">
                  <span>工具</span>
                  <span>可用性</span>
                  <span>边界</span>
                  <span>风险</span>
                  <span>回滚</span>
                  <span>运行指纹</span>
                </div>
                <div
                  v-for="tool in store.tools"
                  :key="tool.name"
                  class="mcp-tool-row"
                  :title="toolDescription(tool.name, tool.description)"
                >
                  <strong class="mcp-tool-name">
                    <span>{{ toolLabel(tool.name) }}</span>
                    <small>v{{ tool.version }}</small>
                  </strong>
                  <code
                    class="mcp-availability"
                    :class="toolAvailabilityClass(tool)"
                    :title="tool.availability?.reasons?.join('；') || '当前主机满足工具前置条件'"
                  >
                    {{ toolAvailabilityLabel(tool) }}
                  </code>
                  <code :class="{ guarded: toolBoundaryLabel(tool.rollback_strategy) === '审批执行' }">
                    {{ toolBoundaryLabel(tool.rollback_strategy) }}
                  </code>
                  <span>{{ tool.risk_level }}</span>
                  <span>{{ rollbackLabel(tool.rollback_strategy) }}</span>
                  <span class="mcp-schema-hashes">
                    <code :title="`输入契约 ${tool.input_schema_hash || '-'}`">I {{ shortToolHash(tool.input_schema_hash) }}</code>
                    <code :title="`输出契约 ${tool.output_schema_hash || '-'}`">O {{ shortToolHash(tool.output_schema_hash) }}</code>
                    <code :class="{ verified: tool.integrity?.status === 'VERIFIED' }" :title="`运行清单 ${tool.integrity?.current_manifest_sha256 || '-'}`">
                      M {{ shortToolHash(tool.integrity?.current_manifest_sha256) }}
                    </code>
                  </span>
                </div>
              </div>
            </section>

            <section class="mcp-routing-panel">
              <header>
                <div>
                  <strong>能力路由</strong>
                  <span>Agent 可用工具</span>
                </div>
                <code>{{ store.agentSkills.length }} 项</code>
              </header>
              <div class="mcp-routing-list">
                <article v-for="skill in store.agentSkills" :key="skill.id">
                  <div>
                    <strong>{{ skill.name }}</strong>
                    <code>{{ skill.tools.length }} 工具</code>
                  </div>
                  <span>{{ skillToolNames(skill) || '不调用系统工具' }}</span>
                </article>
              </div>
            </section>
          </section>
        </section>

        <section v-else-if="activeView === 'audit'" class="module-table audit-replay-module">
          <div class="module-summary">
            <span>链路编号：{{ shortHash(store.activeTask?.trace_id) }}</span>
            <span>链长：{{ auditReplay?.integrity.entry_count || store.auditVerification?.entry_count || 0 }}</span>
            <span>头哈希：{{ shortHash(auditReplay?.integrity.head_hash || store.auditVerification?.head_hash) }}</span>
            <span>校验：{{ auditIntegrityStatus }}</span>
          </div>
          <section class="audit-overview audit-overview-wide">
            <article>
              <span>完整性</span>
              <strong class="audit-integrity-value">
                {{ auditIntegrityStatus }}
                <code>{{ shortHash(auditReplay?.integrity.head_hash || store.auditVerification?.head_hash) }}</code>
              </strong>
              <p>{{ auditReplay?.integrity.valid ? '前序、载荷和事件哈希均通过校验' : '等待或存在未通过的链路校验' }}</p>
            </article>
            <article>
              <span>当前阶段</span>
              <strong>{{ auditLastStage }}</strong>
              <p>{{ auditTimelineRows.at(-1)?.event || '等待事件写入' }}</p>
            </article>
            <article>
              <span>事件数量</span>
              <strong>{{ auditReplay?.integrity.event_count || auditTimelineRows.length }}</strong>
              <p>从接收到封存的可回放事件</p>
            </article>
            <article>
              <span>策略复核</span>
              <strong class="audit-integrity-value">
                {{ auditPolicyStatusText }}
                <code>{{ shortHash(auditReplay?.policy_replay?.current_policy.digest) }}</code>
              </strong>
              <p>
                已复核 {{ auditReplay?.policy_replay?.evaluated_count ?? 0 }} 项，
                {{ auditReplay?.policy_replay?.changed_count ?? 0 }} 项结论变化
              </p>
            </article>
          </section>
          <section class="audit-stage-flow">
            <article
              v-for="(stage, index) in auditReplayStages"
              :key="stage.key"
              class="audit-stage-card"
              :class="stage.status"
            >
              <span class="audit-stage-marker">{{ index + 1 }}</span>
              <div>
                <strong>{{ stage.label }}</strong>
                <p>{{ stage.description }}</p>
              </div>
              <span
                class="status-pill"
                :class="stage.status === 'passed' ? 'ok' : stage.status === 'failed' ? 'failed' : 'idle'"
              >
                {{ auditStageStatusLabel(stage.status, stage.key) }} · {{ stage.event_count }}
              </span>
            </article>
          </section>
          <section class="audit-replay-grid">
            <article class="audit-panel audit-decision-panel">
              <div class="audit-panel-head">
                <strong>关键决策点</strong>
                <span>{{ auditDecisionPoints.length }} 项</span>
              </div>
              <div v-if="!auditDecisionPoints.length" class="empty-state audit-empty">
                当前会话暂无关键决策事件。
              </div>
              <div v-else class="audit-decision-list">
                <div v-for="point in auditDecisionPoints" :key="`${point.order}-${point.label}`" class="audit-decision-item">
                  <span>{{ point.order }}</span>
                  <div>
                    <strong>{{ point.label }}</strong>
                    <p>{{ formatEventMessage(point.message) }}</p>
                    <small>{{ point.component }} · {{ point.decision }} · {{ point.risk_level }}</small>
                  </div>
                  <code>{{ point.hash }}</code>
                </div>
              </div>
            </article>
            <article class="audit-panel audit-event-panel">
              <div class="audit-panel-head">
                <strong>证据回放</strong>
                <span>事件顺序 · 哈希校验</span>
              </div>
              <div v-if="!auditTimelineRows.length" class="empty-state audit-empty">
                当前会话暂无审计事件。
              </div>
              <div v-else class="audit-timeline-list">
                <article v-for="row in auditTimelineRows" :key="row.id" class="audit-timeline-row">
                  <span class="audit-index">{{ row.order }}</span>
                  <div>
                    <strong>{{ row.stage }} · {{ row.event }}</strong>
                    <p>{{ row.message }}</p>
                    <small>{{ row.component }} · {{ row.createdAt }}</small>
                  </div>
                  <code>{{ row.hash }}</code>
                  <span
                    class="status-pill"
                    :class="row.valid === true ? 'ok' : row.valid === false ? 'failed' : 'idle'"
                  >
                    {{ auditEventStatusLabel(row.valid) }}
                  </span>
                </article>
              </div>
            </article>
          </section>
          <details class="audit-hash-panel audit-hash-details">
            <summary class="audit-detail-head">
              <strong>链路校验证据</strong>
              <span>
                {{ auditEntries.length }} 项 ·
                {{ shortHash(auditReplay?.integrity.head_hash || store.auditVerification?.head_hash) }}
              </span>
            </summary>
            <div class="audit-hash-table">
              <div class="data-row head audit-row">
                <span>阶段</span>
                <span>事件</span>
                <span>前序</span>
                <span>载荷</span>
                <span>事件哈希</span>
              </div>
              <div v-for="entry in pagedAuditEntries" :key="entry.chain_id" class="data-row audit-row">
                <span>{{ stageLabel(entry.stage) }}</span>
                <span>{{ eventTypeLabel(entry.event_type) }}</span>
                <span>{{ entry.prev_ok ? '通过' : '失败' }}</span>
                <span>{{ entry.payload_ok ? '通过' : '失败' }}</span>
                <span>{{ shortHash(entry.stored_event_hash) }}</span>
              </div>
            </div>
            <div v-if="auditEntries.length > auditPageSize" class="pagination-bar">
              <a-pagination v-model:current="auditPage" :total="auditEntries.length" :page-size="auditPageSize" simple />
            </div>
          </details>
        </section>

        <KnowledgeWorkspace
          v-else-if="activeView === 'knowledge'"
          :initial-section="knowledgeSection"
          @open-task="openKnowledgeSourceTask"
        />
        <section v-else-if="activeView === 'sessions'" class="module-table">
          <div class="module-summary">
            <span>会话数：{{ latestConversationTasks.length }}</span>
            <span>当前：{{ shortHash(store.activeTask?.trace_id) }}</span>
            <span>待办：{{ todoCount }}</span>
            <span>告警：{{ alertCount }}</span>
          </div>
          <div class="data-row head session-row">
            <span>会话</span>
            <span>意图</span>
            <span>风险</span>
            <span>状态</span>
            <span>摘要</span>
          </div>
          <button
            v-for="task in pagedSessions"
            :key="task.id"
            class="data-row session-row session-link"
            @click="store.selectTask(task); switchView('workbench')"
          >
            <span>{{ shortHash(task.trace_id) }}</span>
            <span>{{ taskIntentLabel(task) }}</span>
            <span>{{ task.risk_level }}</span>
            <span>{{ statusLabel(task.status) }}</span>
            <span>{{ taskSummaryText(task) }}</span>
          </button>
          <div v-if="latestConversationTasks.length > sessionPageSize" class="pagination-bar">
            <a-pagination v-model:current="sessionPage" :total="latestConversationTasks.length" :page-size="sessionPageSize" simple />
          </div>
        </section>

        <section v-else class="scenario-workspace">
          <aside class="scenario-list">
            <button
              v-for="(item, index) in scenarioTemplates"
              :key="item.title"
              :class="{ active: selectedScenarioIndex === index }"
              @click="selectedScenarioIndex = index"
            >
              <span>{{ item.title }}</span>
              <strong>{{ scenarioStateLabel(item) }}</strong>
              <code>{{ item.risk }}</code>
            </button>
          </aside>

          <article v-if="selectedScenario" class="scenario-detail">
            <header class="scenario-detail-head">
              <div>
                <span>当前场景</span>
                <strong>{{ selectedScenario.title }}</strong>
              </div>
              <code>{{ selectedScenario.risk }}</code>
            </header>

            <section class="scenario-detail-summary">
              <article>
                <span>样本状态</span>
                <strong :class="scenarioStateClass(selectedScenario)">{{ scenarioStateLabel(selectedScenario) }}</strong>
                <small>{{ scenarioSetupSummary(selectedScenario) }}</small>
              </article>
              <article>
                <span>工具链</span>
                <strong>{{ selectedScenario.tools.length }} 项</strong>
                <small :title="selectedScenario.tools.join('、')">{{ scenarioToolSummary(selectedScenario.tools) }}</small>
              </article>
              <article>
                <span>验收点</span>
                <strong>{{ selectedScenario.outcome }}</strong>
                <small>风险等级 {{ selectedScenario.risk }}</small>
              </article>
            </section>

            <section class="scenario-run-grid">
              <section class="scenario-prompt-block">
                <span>自然语言请求</span>
                <p>{{ selectedScenario.prompt }}</p>
                <div class="scenario-detail-actions">
                  <a-button
                    v-if="selectedScenario.setupRequired"
                    :loading="store.labBusyId === selectedScenario.labId"
                    @click="store.activateLabScenario(selectedScenario.labId)"
                  >
                    准备样本
                  </a-button>
                  <a-button
                    v-if="selectedScenario.setupRequired"
                    :disabled="selectedScenarioState?.status !== 'ready'"
                    @click="store.resetLabScenario(selectedScenario.labId)"
                  >
                    清理样本
                  </a-button>
                  <a-button @click="switchView('workbench'); usePreset(selectedScenario.prompt)">填入工作台</a-button>
                  <a-button type="primary" :loading="scenarioRunningTitle === selectedScenario.title" @click="runScenario(selectedScenario)">
                    验证场景
                  </a-button>
                </div>
              </section>

              <section class="scenario-evidence-board">
                <span>{{ selectedScenarioResult ? '最近验证' : '样本证据' }}</span>
                <dl>
                  <div v-for="fact in selectedScenarioFacts" :key="fact.label">
                    <dt>{{ fact.label }}</dt>
                    <dd :title="fact.value">{{ fact.value }}</dd>
                  </div>
                </dl>
                <a-button
                  v-if="selectedScenarioResult?.task_id"
                  class="scenario-task-link"
                  @click="openLabEvaluationTask(selectedScenarioResult)"
                >
                  查看任务证据
                </a-button>
              </section>
            </section>
          </article>
          <div v-else class="empty-state">场景目录加载中。</div>
        </section>
      </section>
    </section>

    <aside v-if="activeView === 'workbench'" class="inspector">
      <section class="decision-console">
        <header class="decision-console-head">
          <div>
            <span>当前决策</span>
            <strong>{{ caseTitle }}</strong>
          </div>
          <code :class="riskTone">{{ activeRisk }} · {{ activeStatusText }}</code>
        </header>

        <nav class="decision-console-tabs" aria-label="任务决策阶段">
          <button :class="{ active: inspectorSection === 'overview' }" @click="inspectorSection = 'overview'">
            态势
          </button>
          <button :class="{ active: inspectorSection === 'evidence' }" @click="inspectorSection = 'evidence'">
            证据
            <em v-if="investigationEvidence.length">{{ investigationEvidence.length }}</em>
          </button>
          <button :class="{ active: inspectorSection === 'action' }" @click="inspectorSection = 'action'">
            处置
            <em v-if="proposalPending">1</em>
          </button>
          <button :class="{ active: inspectorSection === 'learning' }" @click="inspectorSection = 'learning'">
            复盘
          </button>
        </nav>

        <div class="decision-console-body">
          <template v-if="inspectorSection === 'overview'">
            <section class="decision-overview">
              <header>
                <span>当前调查</span>
                <strong>{{ investigationOutcomeText }}</strong>
              </header>
              <button class="relationship-status" @click="openInvestigationFocus">
                <span>{{ investigationFocus.label }}</span>
                <strong>{{ investigationFocus.title }}</strong>
                <small>{{ investigationFocus.detail }}</small>
              </button>
              <div class="decision-status-list">
                <button @click="inspectorSection = 'evidence'">
                  <span>结论核验</span>
                  <strong :class="assuranceTone">{{ evidenceAssurance?.status_label || '待调查' }}</strong>
                  <small>{{ evidenceAssurance?.independent_source_count || 0 }} 类来源</small>
                </button>
                <button @click="inspectorSection = 'action'">
                  <span>处置门禁</span>
                  <strong>{{ disposalGateText }}</strong>
                  <small>{{ disposalGateDetail }}</small>
                </button>
                <button @click="openEventSection('incidents')">
                  <span>关联事件</span>
                  <strong>{{ alertCount }}</strong>
                  <small>{{ postureSignals.length }} 项信号</small>
                </button>
              </div>
            </section>

            <section class="decision-progress">
              <header>
                <strong>任务进度</strong>
                <span>{{ investigationOutcomeText }}</span>
              </header>
              <button
                v-for="row in planRows"
                :key="row.step"
                :class="{ active: row.active }"
                @click="row.step <= 2 ? openRelationshipGraph() : activeCaseTab = row.step === 3 ? 'plan' : 'result'"
              >
                <i>{{ row.step }}</i>
                <span>{{ row.title }}</span>
                <strong>{{ row.status }}</strong>
              </button>
            </section>
          </template>

          <template v-else-if="inspectorSection === 'evidence'">
            <section class="claim-assurance" :class="assuranceTone">
              <header>
                <span>首要结论</span>
                <strong>{{ evidenceAssurance?.status_label || '待形成' }}</strong>
              </header>
              <h3>{{ primaryHypothesis?.title || primaryFindingEmptyText }}</h3>
              <p>{{ primaryHypothesis?.rationale || primaryHypothesis?.root_cause || '提交调查任务后展示结论与证据约束。' }}</p>
              <dl>
                <div><dt>独立来源</dt><dd>{{ evidenceAssurance?.independent_source_count || 0 }}</dd></div>
                <div><dt>支持证据</dt><dd>{{ evidenceAssurance?.support_count || 0 }}</dd></div>
                <div><dt>反证</dt><dd>{{ evidenceAssurance?.refutation_count || 0 }}</dd></div>
                <div><dt>已隔离</dt><dd>{{ quarantinedEvidenceCount }}</dd></div>
              </dl>
            </section>

            <section v-if="evidenceAssurance?.reliability_alerts.length" class="evidence-alerts">
              <div
                v-for="alert in evidenceAssurance.reliability_alerts.slice(0, 3)"
                :key="`${alert.type}:${alert.message}`"
                :class="alert.severity"
              >
                <i></i><span>{{ alert.message }}</span>
              </div>
            </section>

            <section class="evidence-source-list">
              <header>
                <strong>证据来源</strong>
                <span>{{ knowledgeEvidenceCount }} 条经验 / 规范</span>
              </header>
              <button
                v-for="item in investigationEvidence.slice(0, 6)"
                :key="item.evidence_id ?? item.tool_call_id ?? item.evidence_refs[0]"
                :class="{ quarantined: item.trust_level === 'QUARANTINED' }"
                @click="activeCaseTab = 'graph'"
              >
                <span>{{ item.source_type === 'KNOWLEDGE' ? item.title : toolLabel(item.tool_name) }}</span>
                <strong>{{ item.trust_level === 'QUARANTINED' ? '已隔离' : toolStatusLabel(item.status) }}</strong>
                <small>{{ item.summary }}</small>
              </button>
            </section>

            <div class="decision-primary-actions">
              <a-button type="primary" @click="activeCaseTab = 'graph'">查看任务图谱</a-button>
              <a-button
                v-if="diagnosisReport?.status === 'model_assisted'"
                @click="activeCaseTab = 'result'; analysisDrawerOpen = true"
              >
                诊断详情
              </a-button>
            </div>
          </template>

          <template v-else-if="inspectorSection === 'action'">
            <section class="action-control-head" :class="riskTone">
              <div>
                <span>风险与裁决</span>
                <strong>{{ activeRisk }} · {{ approvalResult }}</strong>
              </div>
              <IconSafe />
              <p>{{ review?.reason || '当前任务尚未进入安全校验。' }}</p>
            </section>

            <section
              v-if="riskChain && riskChain.status !== 'CLEAR'"
              class="risk-chain-alert"
              :class="riskChain.status.toLowerCase()"
            >
              <strong>{{ riskChain.status === 'BLOCKED' ? '跨回合风险已阻断' : '连续操作需审批' }}</strong>
              <span :title="riskChain.reason">{{ riskChain.reason }}</span>
              <code>{{ riskChain.matched_task_ids.map((id) => `#${id}`).join(' → ') }}</code>
            </section>

            <section class="execution-boundary">
              <header>
                <strong>执行边界</strong>
                <span>{{ runtimeStatusText }}</span>
              </header>
              <dl>
                <div><dt>受限身份</dt><dd>{{ executorIdentityText }}</dd></div>
                <div><dt>审批工具</dt><dd>{{ allowedBoundaryTools.length }} 项</dd></div>
                <div><dt>保护目录</dt><dd>{{ protectedBoundaryPaths.length }} 类</dd></div>
                <div><dt>服务白名单</dt><dd>{{ restartableBoundaryUnits.length }} 项</dd></div>
              </dl>
              <button @click="switchView('safety')">查看完整边界</button>
            </section>

            <section v-if="primarySafetyCase" class="action-contract">
              <header>
                <strong>冻结动作契约</strong>
                <code>{{ safetyCaseStatusText }}</code>
              </header>
              <dl>
                <div><dt>动作</dt><dd>{{ toolLabel(primarySafetyCase.tool_name) }}</dd></div>
                <div><dt>对象</dt><dd :title="safetyCaseTargetText">{{ safetyCaseTargetText }}</dd></div>
                <div><dt>影响</dt><dd :title="safetyCaseImpactTitle">{{ safetyCaseImpactText }}</dd></div>
                <div><dt>失败处理</dt><dd>{{ rollbackStatusText }}</dd></div>
              </dl>
              <div v-if="safetyCaseImpact" class="action-impact-evidence">
                <header>
                  <strong>影响预演</strong>
                  <span>{{ safetyCaseImpact.coverage === 'FULL' ? '证据完整' : '存在证据缺口' }}</span>
                </header>
                <div class="action-impact-units">
                  <div
                    v-for="item in safetyCaseImpactUnits.slice(0, 4)"
                    :key="`${item.role}:${item.unit}`"
                  >
                    <span>{{ impactRoleLabel(item.role) }}</span>
                    <strong :title="item.unit">{{ item.unit }}</strong>
                    <em>{{ impactMechanismLabel(item.mechanism) }} · {{ impactCertaintyLabel(item.certainty) }}</em>
                  </div>
                  <p v-if="!safetyCaseImpactUnits.length">当前证据未发现服务传播对象。</p>
                  <p v-else-if="safetyCaseImpactUnits.length > 4">
                    另有 {{ safetyCaseImpactUnits.length - 4 }} 个对象，任务图谱中可查看完整关系。
                  </p>
                </div>
                <button @click="openRelationshipGraph">在运行关系中核对</button>
              </div>
              <p
                v-if="safetyCaseReadinessReason"
                class="action-readiness-block"
              >
                {{ safetyCaseReadinessReason }}
              </p>
              <div
                v-if="safetyCaseImpactPrecondition"
                class="action-impact-verification"
                :class="safetyCaseImpactPreconditionTone"
              >
                <div>
                  <span>执行前关系复核</span>
                  <strong>{{ safetyCaseImpactPreconditionLabel }}</strong>
                </div>
                <code>{{ safetyCaseImpactPreconditionStats }}</code>
                <p>{{ safetyCaseImpactPrecondition.reason }}</p>
              </div>
              <div
                v-if="safetyCaseImpactVerification"
                class="action-impact-verification"
                :class="safetyCaseImpactVerificationTone"
              >
                <div>
                  <span>执行后核验</span>
                  <strong>{{ safetyCaseImpactVerificationLabel }}</strong>
                </div>
                <code>{{ safetyCaseImpactVerificationStats }}</code>
                <p>{{ safetyCaseImpactVerification.reason }}</p>
              </div>
              <footer>
                <span>{{ primarySafetyCase.evidence_refs.length }} 条依据</span>
                <code :title="primarySafetyCase.action_fingerprint">{{ safetyCaseHashText }}</code>
              </footer>
            </section>

            <section v-if="actionLifecycleSteps.length" class="lifecycle-list">
              <header>
                <strong>执行与验证</strong>
                <span>{{ completedLifecycleStepCount }}/{{ actionLifecycleSteps.length }}</span>
              </header>
              <div v-for="step in actionLifecycleSteps" :key="step.key">
                <i :class="step.status"></i>
                <span>{{ step.title }}</span>
                <strong>{{ statusLabel(step.status) }}</strong>
              </div>
            </section>
            <section v-else class="no-action-state">
              <strong>本任务保持只读</strong>
              <span>未生成系统变更，审批与执行后核验无需启动。</span>
            </section>

            <section class="rollback-inline">
              <header><strong>回滚</strong><span>{{ rollbackStatusText }}</span></header>
              <p>{{ rollbackSummary }}</p>
              <code v-if="rollbackArtifactPath !== '-'" :title="rollbackArtifactPath">{{ rollbackArtifactPath }}</code>
            </section>

            <div v-if="proposalPending" class="decision-primary-actions">
              <a-button
                type="primary"
                :disabled="!actionApprovalEnabled"
                :loading="primaryProposal ? store.approvingProposalId === primaryProposal.id : false"
                @click="primaryProposal && actionApprovalEnabled && store.approveProposal(primaryProposal)"
              >
                {{ approveButtonText }}
              </a-button>
              <a-button
                :loading="primaryProposal ? store.rejectingProposalId === primaryProposal.id : false"
                @click="primaryProposal && store.rejectProposal(primaryProposal)"
              >
                {{ rejectButtonText }}
              </a-button>
            </div>
          </template>

          <template v-else>
            <section class="learning-summary">
              <header>
                <div>
                  <span>本任务经验</span>
                  <strong>{{ currentTaskMemoryCount }}</strong>
                </div>
                <div>
                  <span>知识证据</span>
                  <strong>{{ knowledgeEvidenceCount }}</strong>
                </div>
              </header>
              <p>{{ readableSummary }}</p>
            </section>
            <div class="decision-learning">
              <TaskLearningActions compact @open-memories="openOperationalMemories" />
            </div>
            <section class="learning-history">
              <header><strong>最近确认经验</strong><button @click="openOperationalMemories">管理经验</button></header>
              <button
                v-for="memory in store.operationalMemories.filter((item) => item.status === 'CONFIRMED').slice(0, 4)"
                :key="memory.id"
                @click="openOperationalMemories"
              >
                <strong>{{ memory.title }}</strong>
                <span>{{ memory.host_scope }} · {{ memory.service_scope }}</span>
              </button>
              <p v-if="!store.operationalMemories.some((item) => item.status === 'CONFIRMED')">
                暂无已确认经验。
              </p>
            </section>
          </template>
        </div>
      </section>
    </aside>
  </main>

  <div
    v-if="operatorDrawerOpen"
    class="trace-overlay preference-overlay"
    @click.self="operatorDrawerOpen = false"
  >
    <aside class="trace-drawer preference-dialog">
      <header class="trace-drawer-head">
        <div>
          <strong>工作偏好</strong>
          <span>仅调整信息呈现和任务入口，不改变安全策略</span>
        </div>
        <button class="drawer-close" aria-label="关闭工作偏好" @click="operatorDrawerOpen = false">
          <IconClose />
        </button>
      </header>
      <div class="operator-preferences">
      <section class="preference-section">
        <header>
          <strong>任务呈现</strong>
          <span>仅影响信息组织</span>
        </header>
        <label>摘要密度</label>
        <div class="preference-segment">
          <button
            v-for="item in [
              { value: 'COMPACT', label: '精简' },
              { value: 'BALANCED', label: '均衡' },
              { value: 'DETAILED', label: '详细' },
            ]"
            :key="item.value"
            :class="{ active: operatorSummaryDensity === item.value }"
            @click="operatorSummaryDensity = item.value as OperatorContext['explicit']['summary_density']"
          >{{ item.label }}</button>
        </div>

        <label>证据图谱</label>
        <div class="preference-segment two">
          <button
            :class="{ active: operatorEvidenceView === 'CORE' }"
            @click="operatorEvidenceView = 'CORE'"
          >核心证据</button>
          <button
            :class="{ active: operatorEvidenceView === 'ALL' }"
            @click="operatorEvidenceView = 'ALL'"
          >全部证据</button>
        </div>
      </section>

      <section class="preference-section">
        <header>
          <strong>工作范围</strong>
          <span>用于任务入口排序</span>
        </header>
        <label>重点服务</label>
        <a-input
          v-model="operatorServiceFocusInput"
          allow-clear
          placeholder="例如：nginx，postgresql"
        />
        <label>通知渠道</label>
        <a-select v-model="operatorNotificationRoute">
          <a-option value="WEB">仅工作台</a-option>
          <a-option value="FEISHU">仅飞书</a-option>
          <a-option value="BOTH">工作台与飞书</a-option>
        </a-select>
      </section>

      <section class="preference-section learned-preferences">
        <header>
          <strong>系统已学习</strong>
          <span>{{ store.operatorContext?.learned.signal_count || 0 }} 次显式反馈</span>
        </header>
        <div v-if="store.operatorContext?.learned.intents.length" class="learned-intent-list">
          <div
            v-for="item in store.operatorContext.learned.intents.slice(0, 5)"
            :key="item.intent"
          >
            <strong>{{ intentLabel(item.intent) }}</strong>
            <span>{{ item.feedback_count }} 次反馈 · {{ item.memory_count }} 条确认经验</span>
          </div>
        </div>
        <p v-else>尚未形成稳定偏好。</p>
        <a-popconfirm
          content="清除系统学到的偏好？手动设置和安全策略不会改变。"
          @ok="forgetLearnedPreferences"
        >
          <a-button size="small" :loading="store.operatorContextSaving">清除学习记录</a-button>
        </a-popconfirm>
      </section>

      <section class="preference-safety">
        <strong>安全边界固定</strong>
        <span>风险分级、审批门槛和工具权限不参与个性化学习。</span>
      </section>

      <p v-if="operatorPreferenceNotice" class="preference-notice">
        {{ operatorPreferenceNotice }}
      </p>
      <p v-if="store.error" class="preference-error">{{ store.error }}</p>
      <a-button
        type="primary"
        long
        :loading="store.operatorContextSaving"
        :disabled="!store.operatorContext"
        @click="saveOperatorPreferences"
      >保存偏好</a-button>
      </div>
    </aside>
  </div>
</template>

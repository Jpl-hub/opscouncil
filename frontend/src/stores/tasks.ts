import { defineStore } from 'pinia'
import {
  acknowledgePatrolFinding as acknowledgePatrolFindingApi,
  activateLabScenario as activateLabScenarioApi,
  answerKnowledge,
  approveProposal as approveActionProposal,
  checkConfigBaseline as checkConfigBaselineApi,
  closePatrolIncident as closePatrolIncidentApi,
  cancelTask as cancelTaskApi,
  confirmOperationalMemory as confirmOperationalMemoryApi,
  createConfigBaseline as createConfigBaselineApi,
  createFeishuIdentity as createFeishuIdentityApi,
  createKnowledgeDocument,
  createOperationalMemoryFromTask as createOperationalMemoryFromTaskApi,
  createTask,
  createTaskFeedback as createTaskFeedbackApi,
  correctOperationalMemory as correctOperationalMemoryApi,
  deactivateOperationalMemory as deactivateOperationalMemoryApi,
  deleteKnowledgeDocument as deleteKnowledgeDocumentApi,
  deleteOperationalMemory as deleteOperationalMemoryApi,
  getLatestBenchmark,
  getLatestLabEvaluation,
  getLatestLabScenarioEvaluations,
  getLatestOperationalMemoryEvaluation,
  getActionProposals,
  getAIStatus,
  getAuditReplay,
  getAuditTrace,
  getAuditVerification,
  getExecutionRecords,
  getFeishuChannelStatus,
  getMCPStatus,
  getDeploymentReadiness,
  getPlatformCapabilities,
  getSafetyReviews,
  getRuntimeSafetyStatus,
  getWorkerRuntimeStatus,
  getTask,
  getTaskEvents,
  getTaskInvestigation,
  getTaskObservability,
  getToolCalls,
  getSafetyRules,
  getLatestAgentEvaluation,
  getLatestSafetyEvaluation,
  getKnowledgeIndexStatus,
  getLivePosture,
  getPatrolOverview,
  listAgentSkills,
  listConversationTasks,
  listKnowledgeDocuments,
  listConfigBaselines,
  listLabScenarios,
  listFeishuIdentities,
  listPendingFeishuIdentities,
  listOperationalMemories,
  listOperationalMemoryRelations,
  listOperators,
  listPendingApprovals,
  listPatrolFindings,
  listPatrolIncidents,
  listTaskFeedback,
  listTasks,
  listTools,
  qualifyOperationalMemory as qualifyOperationalMemoryApi,
  rejectProposal as rejectActionProposal,
  retryFeishuDelivery as retryFeishuDeliveryApi,
  rebuildKnowledgeIndex,
  resetLabScenario as resetLabScenarioApi,
  runBenchmark as runBenchmarkApi,
  runAgentEvaluation as runAgentEvaluationApi,
  runLabEvaluation as runLabEvaluationApi,
  runLabScenarioEvaluation as runLabScenarioEvaluationApi,
  runOperationalMemoryEvaluation as runOperationalMemoryEvaluationApi,
  runPatrolPolicy as runPatrolPolicyApi,
  runSafetyEvaluation as runSafetyEvaluationApi,
  searchOperationalMemories as searchOperationalMemoriesApi,
  forgetOperationalMemory as forgetOperationalMemoryApi,
  forgetLearnedOperatorContext as forgetLearnedOperatorContextApi,
  getOperatorContext,
  resolveOperationalMemoryRelation as resolveOperationalMemoryRelationApi,
  setFeishuIdentityStatus as setFeishuIdentityStatusApi,
  seedBuiltinKnowledgeDocuments,
  uploadKnowledgeDocument,
  updateOperatorContext as updateOperatorContextApi,
} from '../api'
import { TaskEventStreamClient } from '../task-stream'
import type {
  AIStatus,
  ActionProposal,
  ApprovalQueueItem,
  AgentEvaluationReport,
  AgentSkill,
  AuditReplay,
  AuditTrace,
  AuditVerification,
  BenchmarkReport,
  ConfigBaseline,
  DeploymentReadinessReport,
  ExecutionRecord,
  FeishuChannelStatus,
  FeishuIdentity,
  PendingFeishuIdentity,
  InvestigationPackage,
  KnowledgeAnswer,
  KnowledgeDocument,
  KnowledgeHit,
  KnowledgeIndexStatus,
  LabEvaluationCase,
  LabScenario,
  LabEvaluationReport,
  LivePostureReport,
  MCPStatus,
  OperationalMemory,
  OperationalMemoryEvaluationReport,
  OperationalMemoryRelation,
  OperatorAccount,
  OperatorContext,
  OperatorFeedback,
  OperatorFeedbackVerdict,
  PagedResult,
  PatrolFinding,
  PatrolIncident,
  PatrolOverview,
  PlatformCapabilityProfile,
  RuntimeSafetyStatus,
  WorkerRuntimeStatus,
  SafetyEvaluationReport,
  SafetyReview,
  SafetyRule,
  Task,
  TaskEvent,
  TaskObservability,
  TaskStreamEvent,
  ToolDefinition,
  ToolCall,
} from '../types'

interface TaskState {
  tasks: Task[]
  activeTask: Task | null
  dialogueTasks: Task[]
  events: TaskEvent[]
  toolCalls: ToolCall[]
  actionProposals: ActionProposal[]
  pendingApprovals: ApprovalQueueItem[]
  executionRecords: ExecutionRecord[]
  safetyReviews: SafetyReview[]
  safetyRules: SafetyRule[]
  safetyEvaluationReport: SafetyEvaluationReport | null
  agentEvaluationReport: AgentEvaluationReport | null
  agentSkills: AgentSkill[]
  tools: ToolDefinition[]
  knowledgeDocuments: KnowledgeDocument[]
  knowledgeHits: KnowledgeHit[]
  knowledgeAnswer: KnowledgeAnswer | null
  knowledgeIndexStatus: KnowledgeIndexStatus | null
  operationalMemories: OperationalMemory[]
  operationalMemoryEvaluation: OperationalMemoryEvaluationReport | null
  operationalMemoryHits: KnowledgeHit[]
  operationalMemoryRelations: OperationalMemoryRelation[]
  taskFeedback: OperatorFeedback[]
  labScenarios: LabScenario[]
  labScenarioResults: Record<string, LabEvaluationCase>
  labEvaluationReport: LabEvaluationReport | null
  benchmarkReport: BenchmarkReport | null
  configBaselines: ConfigBaseline[]
  investigation: InvestigationPackage | null
  taskObservability: TaskObservability | null
  aiStatus: AIStatus | null
  mcpStatus: MCPStatus | null
  deploymentReadiness: DeploymentReadinessReport | null
  platformCapabilities: PlatformCapabilityProfile | null
  livePosture: LivePostureReport | null
  patrolOverview: PatrolOverview | null
  patrolFindings: PagedResult<PatrolFinding>
  patrolIncidents: PagedResult<PatrolIncident>
  feishuChannelStatus: FeishuChannelStatus | null
  operators: OperatorAccount[]
  operatorContext: OperatorContext | null
  feishuIdentities: FeishuIdentity[]
  feishuPendingIdentities: PendingFeishuIdentity[]
  runtimeSafety: RuntimeSafetyStatus | null
  workerRuntime: WorkerRuntimeStatus | null
  auditReplay: AuditReplay | null
  auditTrace: AuditTrace | null
  auditVerification: AuditVerification | null
  pendingInput: string
  loading: boolean
  submitting: boolean
  cancellingTaskId: number | null
  approvingProposalId: number | null
  rejectingProposalId: number | null
  investigationLoading: boolean
  labBusyId: string | null
  benchmarkRunning: boolean
  labEvaluationRunning: boolean
  safetyEvaluationRunning: boolean
  agentEvaluationRunning: boolean
  safetyRefreshing: boolean
  postureRefreshing: boolean
  patrolLoading: boolean
  patrolBusyKey: string
  channelLoading: boolean
  channelBusyKey: string
  mcpRefreshing: boolean
  configBaselineBusy: boolean
  knowledgeSubmitting: boolean
  knowledgeSearching: boolean
  knowledgeSeeding: boolean
  knowledgeReindexing: boolean
  knowledgeDeletingId: number | null
  operationalMemoryBusyKey: string
  operationalMemoryEvaluationRunning: boolean
  operationalMemorySearching: boolean
  taskFeedbackSubmitting: boolean
  operatorContextSaving: boolean
  error: string
}

const taskStream = new TaskEventStreamClient()
const terminalTaskStatuses = new Set(['SEALED', 'REJECTED', 'BLOCKED', 'FAILED', 'NEEDS_OPERATOR', 'CANCELLED', 'ROLLED_BACK'])
let taskRefreshTimer: number | undefined
let taskSelectionSequence = 0

function isTerminalTask(task: Task) {
  return terminalTaskStatuses.has(task.status)
}

export const useTaskStore = defineStore('tasks', {
  state: (): TaskState => ({
    tasks: [],
    activeTask: null,
    dialogueTasks: [],
    events: [],
    toolCalls: [],
    actionProposals: [],
    pendingApprovals: [],
    executionRecords: [],
    safetyReviews: [],
    safetyRules: [],
    safetyEvaluationReport: null,
    agentEvaluationReport: null,
    agentSkills: [],
    tools: [],
    knowledgeDocuments: [],
    knowledgeHits: [],
    knowledgeAnswer: null,
    knowledgeIndexStatus: null,
    operationalMemories: [],
    operationalMemoryEvaluation: null,
    operationalMemoryHits: [],
    operationalMemoryRelations: [],
    taskFeedback: [],
    labScenarios: [],
    labScenarioResults: {},
    labEvaluationReport: null,
    benchmarkReport: null,
    configBaselines: [],
    investigation: null,
    taskObservability: null,
    aiStatus: null,
    mcpStatus: null,
    deploymentReadiness: null,
    platformCapabilities: null,
    livePosture: null,
    patrolOverview: null,
    patrolFindings: { items: [], total: 0, page: 1, page_size: 20, page_count: 0 },
    patrolIncidents: { items: [], total: 0, page: 1, page_size: 20, page_count: 0 },
    feishuChannelStatus: null,
    operators: [],
    operatorContext: null,
    feishuIdentities: [],
    feishuPendingIdentities: [],
    runtimeSafety: null,
    workerRuntime: null,
    auditReplay: null,
    auditTrace: null,
    auditVerification: null,
    pendingInput: '',
    loading: false,
    submitting: false,
    cancellingTaskId: null,
    approvingProposalId: null,
    rejectingProposalId: null,
    investigationLoading: false,
    labBusyId: null,
    benchmarkRunning: false,
    labEvaluationRunning: false,
    safetyEvaluationRunning: false,
    agentEvaluationRunning: false,
    safetyRefreshing: false,
    postureRefreshing: false,
    patrolLoading: false,
    patrolBusyKey: '',
    channelLoading: false,
    channelBusyKey: '',
    mcpRefreshing: false,
    configBaselineBusy: false,
    knowledgeSubmitting: false,
    knowledgeSearching: false,
    knowledgeSeeding: false,
    knowledgeReindexing: false,
    knowledgeDeletingId: null,
    operationalMemoryBusyKey: '',
    operationalMemoryEvaluationRunning: false,
    operationalMemorySearching: false,
    taskFeedbackSubmitting: false,
    operatorContextSaving: false,
    error: '',
  }),
  actions: {
    async bootstrap() {
      this.loading = true
      this.error = ''
      try {
        const [
          tasks,
          pendingApprovals,
          aiStatus,
          mcpStatus,
          deploymentReadiness,
          platformCapabilities,
          livePosture,
          runtimeSafety,
          workerRuntime,
          tools,
          agentSkills,
          safetyRules,
          agentEvaluationReport,
          safetyEvaluationReport,
          knowledgeDocuments,
          knowledgeIndexStatus,
          operationalMemories,
          operationalMemoryEvaluation,
          labScenarios,
          labScenarioResults,
          labEvaluationReport,
          benchmarkReport,
          configBaselines,
          patrolOverview,
          patrolFindings,
          patrolIncidents,
          feishuChannelStatus,
          operators,
          operatorContext,
          feishuIdentities,
          feishuPendingIdentities,
        ] = await Promise.all([
          listTasks(),
          listPendingApprovals(),
          getAIStatus(),
          getMCPStatus(),
          getDeploymentReadiness(),
          getPlatformCapabilities(),
          getLivePosture(),
          getRuntimeSafetyStatus(),
          getWorkerRuntimeStatus(),
          listTools(),
          listAgentSkills(),
          getSafetyRules(),
          getLatestAgentEvaluation(),
          getLatestSafetyEvaluation(),
          listKnowledgeDocuments(),
          getKnowledgeIndexStatus(),
          listOperationalMemories(),
          getLatestOperationalMemoryEvaluation(),
          listLabScenarios(),
          getLatestLabScenarioEvaluations(),
          getLatestLabEvaluation(),
          getLatestBenchmark(),
          listConfigBaselines(),
          getPatrolOverview(),
          listPatrolFindings({ page: 1, page_size: 20 }),
          listPatrolIncidents({ page: 1, page_size: 20 }),
          getFeishuChannelStatus(),
          listOperators(),
          getOperatorContext(),
          listFeishuIdentities(),
          listPendingFeishuIdentities(),
        ])
        const activeTask = this.activeTask
        this.tasks = activeTask ? [activeTask, ...tasks.filter((task) => task.id !== activeTask.id)] : tasks
        this.pendingApprovals = pendingApprovals
        this.aiStatus = aiStatus
        this.mcpStatus = mcpStatus
        this.deploymentReadiness = deploymentReadiness
        this.platformCapabilities = platformCapabilities
        this.livePosture = livePosture
        this.runtimeSafety = runtimeSafety
        this.workerRuntime = workerRuntime
        this.tools = tools
        this.agentSkills = agentSkills
        this.safetyRules = safetyRules
        this.agentEvaluationReport = agentEvaluationReport
        this.safetyEvaluationReport = safetyEvaluationReport
        this.knowledgeDocuments = knowledgeDocuments
        this.knowledgeIndexStatus = knowledgeIndexStatus
        this.operationalMemories = operationalMemories
        this.operationalMemoryEvaluation = operationalMemoryEvaluation
        this.labScenarios = labScenarios
        this.labScenarioResults = labScenarioResults
        this.labEvaluationReport = labEvaluationReport
        this.benchmarkReport = benchmarkReport
        this.configBaselines = configBaselines
        this.patrolOverview = patrolOverview
        this.patrolFindings = patrolFindings
        this.patrolIncidents = patrolIncidents
        this.feishuChannelStatus = feishuChannelStatus
        this.operators = operators
        this.operatorContext = operatorContext
        this.feishuIdentities = feishuIdentities
        this.feishuPendingIdentities = feishuPendingIdentities
        if (!activeTask && this.tasks.length > 0) {
          await this.selectTask(this.tasks[0])
        }
      } catch (error) {
        this.error = error instanceof Error ? error.message : '加载任务失败'
      } finally {
        this.loading = false
      }
    },
    async submit(input: string) {
      const requestInput = input.trim()
      if (!requestInput || this.submitting || (this.activeTask && !isTerminalTask(this.activeTask))) return
      const previousDialogue = this.dialogueTasks.length > 0
        ? [...this.dialogueTasks]
        : this.activeTask
          ? [this.activeTask]
          : []
      const conversationId = this.activeTask?.conversation_id
        ?? previousDialogue[previousDialogue.length - 1]?.conversation_id
        ?? undefined
      this.submitting = true
      this.error = ''
      this.pendingInput = requestInput
      taskStream.close()
      this.activeTask = null
      this.events = []
      this.toolCalls = []
      this.actionProposals = []
      this.executionRecords = []
      this.safetyReviews = []
      this.investigation = null
      this.taskObservability = null
      this.auditReplay = null
      this.auditTrace = null
      this.auditVerification = null
      this.taskFeedback = []
      try {
        const task = await createTask(requestInput, conversationId || undefined)
        this.tasks = [task, ...this.tasks.filter((item) => item.id !== task.id)]
        this.activeTask = task
        this.dialogueTasks = [...previousDialogue.filter((item) => item.id !== task.id), task]
        this.pendingInput = ''
        this.connectTaskStream(task)
        void this.selectTask(task).catch((error) => {
          this.error = error instanceof Error ? error.message : '加载任务状态失败'
        })
      } catch (error) {
        this.error = error instanceof Error ? error.message : '创建任务失败'
        this.dialogueTasks = previousDialogue
        this.activeTask = previousDialogue.length ? previousDialogue[previousDialogue.length - 1] : null
        if (this.activeTask && !isTerminalTask(this.activeTask)) this.connectTaskStream(this.activeTask)
      } finally {
        this.pendingInput = ''
        this.submitting = false
      }
    },
    async selectTask(task: Task) {
      const selectionSequence = ++taskSelectionSequence
      this.investigationLoading = true
      try {
        const previousTaskId = this.activeTask?.id
        const currentTask = await getTask(task.id)
        if (selectionSequence !== taskSelectionSequence) return

        const switchingTask = previousTaskId !== currentTask.id
        this.activeTask = currentTask
        this.tasks = this.tasks.map((item) => (item.id === currentTask.id ? currentTask : item))
        if (switchingTask) {
          this.events = []
          this.toolCalls = []
          this.actionProposals = []
          this.executionRecords = []
          this.safetyReviews = []
          this.investigation = null
          this.taskObservability = null
          this.auditReplay = null
          this.auditTrace = null
          this.auditVerification = null
          this.taskFeedback = []
        }

        const investigationRequest = getTaskInvestigation(currentTask.id)
          .then((value) => ({ value, error: '' }))
          .catch((error: unknown) => ({
            value: null,
            error: error instanceof Error ? error.message : '调查包加载失败',
          }))
        const [
          dialogueTasks,
          events,
          toolCalls,
          actionProposals,
          executionRecords,
          safetyReviews,
          auditReplay,
          auditTrace,
          auditVerification,
          taskFeedback,
          taskObservability,
          investigationResult,
        ] = await Promise.all([
          currentTask.conversation_id
            ? listConversationTasks(currentTask.conversation_id)
            : Promise.resolve([currentTask]),
          getTaskEvents(currentTask.id),
          getToolCalls(currentTask.id),
          getActionProposals(currentTask.id),
          getExecutionRecords(currentTask.id),
          getSafetyReviews(currentTask.id),
          getAuditReplay(currentTask.trace_id),
          getAuditTrace(currentTask.trace_id),
          getAuditVerification(currentTask.trace_id),
          listTaskFeedback(currentTask.id),
          getTaskObservability(currentTask.id),
          investigationRequest,
        ])
        if (selectionSequence !== taskSelectionSequence) return

        this.dialogueTasks = dialogueTasks
        this.events = events
        this.toolCalls = toolCalls
        this.actionProposals = actionProposals
        this.executionRecords = executionRecords
        this.safetyReviews = safetyReviews
        this.auditReplay = auditReplay
        this.auditTrace = auditTrace
        this.auditVerification = auditVerification
        this.taskFeedback = taskFeedback
        this.taskObservability = taskObservability
        this.investigation = investigationResult.value
        if (investigationResult.error) this.error = investigationResult.error

        if (isTerminalTask(currentTask)) taskStream.close()
        else this.connectTaskStream(currentTask)
      } finally {
        if (selectionSequence === taskSelectionSequence) {
          this.investigationLoading = false
        }
      }
    },
    async openTaskById(taskId: number) {
      this.error = ''
      try {
        const task = await getTask(taskId)
        this.tasks = [task, ...this.tasks.filter((item) => item.id !== task.id)]
        await this.selectTask(task)
      } catch (error) {
        this.error = error instanceof Error ? error.message : '加载评测任务失败'
      }
    },
    startNewConversation() {
      taskStream.close()
      if (taskRefreshTimer) window.clearTimeout(taskRefreshTimer)
      this.activeTask = null
      this.dialogueTasks = []
      this.pendingInput = ''
      this.events = []
      this.toolCalls = []
      this.actionProposals = []
      this.executionRecords = []
      this.safetyReviews = []
      this.investigation = null
      this.taskObservability = null
      this.auditReplay = null
      this.auditTrace = null
      this.auditVerification = null
      this.taskFeedback = []
      this.error = ''
    },
    connectTaskStream(task: Task) {
      if (isTerminalTask(task)) {
        taskStream.close()
        return
      }
      taskStream.open(task.id, {
        onEvent: (event) => this.handleTaskStreamEvent(event),
        onDisconnect: () => {
          void this.reconcileTaskStream(task.id)
        },
      })
    },
    handleTaskStreamEvent(event: TaskStreamEvent) {
      if (this.activeTask?.id !== event.task_id) return
      if (!this.events.some((item) => item.id === event.id)) {
        this.events = [...this.events, event]
      }
      if (taskRefreshTimer) window.clearTimeout(taskRefreshTimer)
      taskRefreshTimer = window.setTimeout(() => {
        const activeTask = this.activeTask
        if (!activeTask || activeTask.id !== event.task_id) return
        void this.refreshActiveTaskRuntime(activeTask.id).catch((error) => {
          this.error = error instanceof Error ? error.message : '刷新任务状态失败'
        })
      }, 120)
    },
    async refreshActiveTaskRuntime(taskId: number) {
      if (this.activeTask?.id !== taskId) return
      const [task, events, toolCalls, actionProposals, executionRecords, safetyReviews] = await Promise.all([
        getTask(taskId),
        getTaskEvents(taskId),
        getToolCalls(taskId),
        getActionProposals(taskId),
        getExecutionRecords(taskId),
        getSafetyReviews(taskId),
      ])
      if (this.activeTask?.id !== taskId) return
      this.activeTask = task
      this.tasks = this.tasks.map((item) => (item.id === task.id ? task : item))
      this.dialogueTasks = this.dialogueTasks.map((item) => (item.id === task.id ? task : item))
      this.events = events
      this.toolCalls = toolCalls
      this.actionProposals = actionProposals
      this.executionRecords = executionRecords
      this.safetyReviews = safetyReviews
      if (isTerminalTask(task)) {
        taskStream.close()
        await this.selectTask(task)
      }
    },
    async reconcileTaskStream(taskId: number) {
      if (this.activeTask?.id !== taskId) return
      try {
        const task = await getTask(taskId)
        if (this.activeTask?.id !== taskId) return
        this.activeTask = task
        this.tasks = this.tasks.map((item) => (item.id === task.id ? task : item))
        this.dialogueTasks = this.dialogueTasks.map((item) => (item.id === task.id ? task : item))
        if (isTerminalTask(task)) {
          taskStream.close()
          await this.selectTask(task)
        }
      } catch {
        // Native EventSource keeps the persisted cursor and reconnects automatically.
      }
    },
    async cancelActiveTask() {
      const task = this.activeTask
      if (!task || isTerminalTask(task)) return
      this.cancellingTaskId = task.id
      this.error = ''
      try {
        const cancelled = await cancelTaskApi(task.id)
        this.activeTask = cancelled
        this.tasks = this.tasks.map((item) => (item.id === cancelled.id ? cancelled : item))
        this.dialogueTasks = this.dialogueTasks.map((item) => (
          item.id === cancelled.id ? cancelled : item
        ))
        if (isTerminalTask(cancelled)) taskStream.close()
      } catch (error) {
        this.error = error instanceof Error ? error.message : '取消任务失败'
      } finally {
        this.cancellingTaskId = null
      }
    },
    disposeTaskStream() {
      taskStream.close()
      if (taskRefreshTimer) window.clearTimeout(taskRefreshTimer)
      taskRefreshTimer = undefined
    },
    async approveProposal(proposal: ActionProposal) {
      this.approvingProposalId = proposal.id
      this.error = ''
      try {
        const task = await approveActionProposal(proposal.id)
        this.tasks = this.tasks.map((item) => (item.id === task.id ? task : item))
        await this.selectTask(task)
        await this.refreshPendingApprovals()
      } catch (error) {
        this.error = error instanceof Error ? error.message : '审批执行失败'
      } finally {
        this.approvingProposalId = null
      }
    },
    async rejectProposal(proposal: ActionProposal) {
      this.rejectingProposalId = proposal.id
      this.error = ''
      try {
        const task = await rejectActionProposal(proposal.id)
        this.tasks = this.tasks.map((item) => (item.id === task.id ? task : item))
        await this.selectTask(task)
        await this.refreshPendingApprovals()
      } catch (error) {
        this.error = error instanceof Error ? error.message : '拒绝执行失败'
      } finally {
        this.rejectingProposalId = null
      }
    },
    async refreshPendingApprovals() {
      try {
        this.pendingApprovals = await listPendingApprovals()
      } catch (error) {
        this.error = error instanceof Error ? error.message : '加载审批待办失败'
      }
    },
    async activateLabScenario(scenarioId: string) {
      this.labBusyId = scenarioId
      this.error = ''
      try {
        const scenario = await activateLabScenarioApi(scenarioId)
        this.labScenarios = this.labScenarios.map((item) => (item.id === scenario.id ? scenario : item))
      } catch (error) {
        this.error = error instanceof Error ? error.message : '准备场景任务失败'
      } finally {
        this.labBusyId = null
      }
    },
    async resetLabScenario(scenarioId: string) {
      this.labBusyId = scenarioId
      this.error = ''
      try {
        const scenario = await resetLabScenarioApi(scenarioId)
        this.labScenarios = this.labScenarios.map((item) => (item.id === scenario.id ? scenario : item))
      } catch (error) {
        this.error = error instanceof Error ? error.message : '清理场景任务失败'
      } finally {
        this.labBusyId = null
      }
    },
    async runLabScenarioEvaluation(scenarioId: string) {
      this.labBusyId = scenarioId
      this.error = ''
      try {
        const result = await runLabScenarioEvaluationApi(scenarioId)
        this.labScenarioResults = { ...this.labScenarioResults, [scenarioId]: result }
        this.labScenarios = await listLabScenarios()
        return result
      } catch (error) {
        this.error = error instanceof Error ? error.message : '场景验证失败'
        return null
      } finally {
        this.labBusyId = null
      }
    },
    async runBenchmark(rounds = 2) {
      this.benchmarkRunning = true
      this.error = ''
      try {
        this.benchmarkReport = await runBenchmarkApi(rounds)
      } catch (error) {
        this.error = error instanceof Error ? error.message : '工具性能采样失败'
      } finally {
        this.benchmarkRunning = false
      }
    },
    async runLabEvaluation() {
      this.labEvaluationRunning = true
      this.error = ''
      try {
        this.labEvaluationReport = await runLabEvaluationApi()
        this.labScenarios = await listLabScenarios()
      } catch (error) {
        this.error = error instanceof Error ? error.message : '实战评测运行失败'
      } finally {
        this.labEvaluationRunning = false
      }
    },
    async runAgentEvaluation() {
      this.agentEvaluationRunning = true
      this.error = ''
      try {
        this.agentEvaluationReport = await runAgentEvaluationApi()
      } catch (error) {
        this.error = error instanceof Error ? error.message : 'Agent 控制面评测运行失败'
      } finally {
        this.agentEvaluationRunning = false
      }
    },
    async runSafetyEvaluation() {
      this.safetyEvaluationRunning = true
      this.error = ''
      try {
        this.safetyEvaluationReport = await runSafetyEvaluationApi()
      } catch (error) {
        this.error = error instanceof Error ? error.message : '安全评测运行失败'
      } finally {
        this.safetyEvaluationRunning = false
      }
    },
    async refreshSafetyGovernance() {
      this.safetyRefreshing = true
      this.error = ''
      try {
        const [runtimeSafety, safetyRules, safetyEvaluationReport] = await Promise.all([
          getRuntimeSafetyStatus(),
          getSafetyRules(),
          getLatestSafetyEvaluation(),
        ])
        this.runtimeSafety = runtimeSafety
        this.safetyRules = safetyRules
        this.safetyEvaluationReport = safetyEvaluationReport
      } catch (error) {
        this.error = error instanceof Error ? error.message : '安全护栏运行态刷新失败'
      } finally {
        this.safetyRefreshing = false
      }
    },
    async refreshWorkerRuntime() {
      try {
        this.workerRuntime = await getWorkerRuntimeStatus()
      } catch {
        this.workerRuntime = null
      }
    },
    async refreshLivePosture() {
      this.postureRefreshing = true
      this.error = ''
      try {
        const [livePosture, platformCapabilities] = await Promise.all([
          getLivePosture(),
          getPlatformCapabilities(true),
        ])
        this.livePosture = livePosture
        this.platformCapabilities = platformCapabilities
      } catch (error) {
        this.error = error instanceof Error ? error.message : '系统态势刷新失败'
      } finally {
        this.postureRefreshing = false
      }
    },
    async refreshPatrolData(options: {
      findingStatus?: string
      findingSeverity?: string
      findingPage?: number
      incidentStatus?: string
      incidentSeverity?: string
      incidentPage?: number
    } = {}) {
      this.patrolLoading = true
      this.error = ''
      try {
        const [overview, findings, incidents] = await Promise.all([
          getPatrolOverview(),
          listPatrolFindings({
            status: options.findingStatus || undefined,
            severity: options.findingSeverity || undefined,
            page: options.findingPage || 1,
            page_size: 20,
          }),
          listPatrolIncidents({
            status: options.incidentStatus || undefined,
            severity: options.incidentSeverity || undefined,
            page: options.incidentPage || 1,
            page_size: 20,
          }),
        ])
        this.patrolOverview = overview
        this.patrolFindings = findings
        this.patrolIncidents = incidents
      } catch (error) {
        this.error = error instanceof Error ? error.message : '事件数据刷新失败'
      } finally {
        this.patrolLoading = false
      }
    },
    async runPatrolPolicy(policyId: number) {
      this.patrolBusyKey = `policy:${policyId}`
      this.error = ''
      try {
        await runPatrolPolicyApi(policyId)
        await this.refreshPatrolData()
      } catch (error) {
        this.error = error instanceof Error ? error.message : '巡检运行失败'
      } finally {
        this.patrolBusyKey = ''
      }
    },
    async acknowledgePatrolFinding(findingId: number) {
      this.patrolBusyKey = `finding:${findingId}`
      this.error = ''
      try {
        const updated = await acknowledgePatrolFindingApi(findingId)
        this.patrolFindings.items = this.patrolFindings.items.map((item) =>
          item.id === updated.id ? updated : item,
        )
        this.patrolOverview = await getPatrolOverview()
      } catch (error) {
        this.error = error instanceof Error ? error.message : '发现确认失败'
      } finally {
        this.patrolBusyKey = ''
      }
    },
    async closePatrolIncident(incidentId: number) {
      this.patrolBusyKey = `incident:${incidentId}`
      this.error = ''
      try {
        const updated = await closePatrolIncidentApi(incidentId)
        this.patrolIncidents.items = this.patrolIncidents.items.map((item) =>
          item.id === updated.id ? updated : item,
        )
        await this.refreshPatrolData()
      } catch (error) {
        this.error = error instanceof Error ? error.message : '事件关闭失败'
      } finally {
        this.patrolBusyKey = ''
      }
    },
    async refreshFeishuChannel() {
      this.channelLoading = true
      this.error = ''
      try {
        const [status, operators, identities, pendingIdentities] = await Promise.all([
          getFeishuChannelStatus(),
          listOperators(),
          listFeishuIdentities(),
          listPendingFeishuIdentities(),
        ])
        this.feishuChannelStatus = status
        this.operators = operators
        this.feishuIdentities = identities
        this.feishuPendingIdentities = pendingIdentities
      } catch (error) {
        this.error = error instanceof Error ? error.message : '协同通道刷新失败'
      } finally {
        this.channelLoading = false
      }
    },
    async retryFeishuDelivery(outboxId: number) {
      this.channelBusyKey = `delivery:${outboxId}`
      this.error = ''
      try {
        await retryFeishuDeliveryApi(outboxId)
        this.feishuChannelStatus = await getFeishuChannelStatus()
      } catch (error) {
        this.error = error instanceof Error ? error.message : '协同消息重试失败'
      } finally {
        this.channelBusyKey = ''
      }
    },
    async createFeishuIdentity(payload: { operator_id: number; tenant_key: string; open_id: string }) {
      this.channelBusyKey = 'identity:create'
      this.error = ''
      try {
        const identity = await createFeishuIdentityApi(payload)
        this.feishuIdentities = [
          ...this.feishuIdentities.filter((item) => item.id !== identity.id),
          identity,
        ]
        await this.refreshFeishuChannel()
      } catch (error) {
        this.error = error instanceof Error ? error.message : '飞书身份绑定失败'
        throw error
      } finally {
        this.channelBusyKey = ''
      }
    },
    async setFeishuIdentityStatus(identityId: number, status: FeishuIdentity['status']) {
      this.channelBusyKey = `identity:${identityId}`
      this.error = ''
      try {
        const identity = await setFeishuIdentityStatusApi(identityId, status)
        this.feishuIdentities = this.feishuIdentities.map((item) =>
          item.id === identity.id ? identity : item,
        )
        this.feishuChannelStatus = await getFeishuChannelStatus()
      } catch (error) {
        this.error = error instanceof Error ? error.message : '飞书身份状态更新失败'
      } finally {
        this.channelBusyKey = ''
      }
    },
    async refreshMcpGovernance() {
      this.mcpRefreshing = true
      this.error = ''
      try {
        const [mcpStatus, tools, agentSkills, platformCapabilities] = await Promise.all([
          getMCPStatus(),
          listTools(),
          listAgentSkills(),
          getPlatformCapabilities(true),
        ])
        this.mcpStatus = mcpStatus
        this.tools = tools
        this.agentSkills = agentSkills
        this.platformCapabilities = platformCapabilities
      } catch (error) {
        this.error = error instanceof Error ? error.message : 'MCP 工具刷新失败'
      } finally {
        this.mcpRefreshing = false
      }
    },
    async createDefaultConfigBaseline() {
      this.configBaselineBusy = true
      this.error = ''
      try {
        const baseline = await createConfigBaselineApi({
          name: '系统关键配置',
          paths: ['/etc/hosts', '/etc/resolv.conf', '/etc/fstab'],
          created_by: 'admin',
        })
        this.configBaselines = [
          baseline,
          ...this.configBaselines.filter((item) => item.id !== baseline.id),
        ]
      } catch (error) {
        this.error = error instanceof Error ? error.message : '配置基线建立失败'
      } finally {
        this.configBaselineBusy = false
      }
    },
    async checkConfigBaseline(baseline: ConfigBaseline) {
      this.configBaselineBusy = true
      this.error = ''
      try {
        const latestCheck = await checkConfigBaselineApi(baseline.id)
        this.configBaselines = this.configBaselines.map((item) => (
          item.id === baseline.id ? { ...item, latest_check: latestCheck } : item
        ))
      } catch (error) {
        this.error = error instanceof Error ? error.message : '配置基线核验失败'
      } finally {
        this.configBaselineBusy = false
      }
    },
    async submitKnowledgeDocument(payload: {
      title: string
      source_type: string
      source_uri: string
      trust_level: string
      content: string
    }) {
      this.knowledgeSubmitting = true
      this.error = ''
      try {
        const document = await createKnowledgeDocument(payload)
        this.knowledgeDocuments = [document, ...this.knowledgeDocuments.filter((item) => item.id !== document.id)]
        this.knowledgeIndexStatus = await getKnowledgeIndexStatus()
      } catch (error) {
        this.error = error instanceof Error ? error.message : '知识文档入库失败'
      } finally {
        this.knowledgeSubmitting = false
      }
    },
    async uploadKnowledgeDocument(payload: {
      file: File
      source_type: string
      trust_level: string
      title?: string
    }) {
      this.knowledgeSubmitting = true
      this.error = ''
      try {
        const document = await uploadKnowledgeDocument(payload)
        this.knowledgeDocuments = [document, ...this.knowledgeDocuments.filter((item) => item.id !== document.id)]
        this.knowledgeIndexStatus = await getKnowledgeIndexStatus()
      } catch (error) {
        this.error = error instanceof Error ? error.message : '知识文件入库失败'
      } finally {
        this.knowledgeSubmitting = false
      }
    },
    async deleteKnowledgeDocument(documentId: number) {
      this.knowledgeDeletingId = documentId
      this.error = ''
      try {
        const result = await deleteKnowledgeDocumentApi(documentId)
        this.knowledgeDocuments = this.knowledgeDocuments.filter((item) => item.id !== documentId)
        this.knowledgeIndexStatus = result.index_status
        this.knowledgeHits = []
        this.knowledgeAnswer = null
      } catch (error) {
        this.error = error instanceof Error ? error.message : '知识资料删除失败'
      } finally {
        this.knowledgeDeletingId = null
      }
    },
    async seedBuiltinKnowledge() {
      this.knowledgeSeeding = true
      this.error = ''
      try {
        const documents = await seedBuiltinKnowledgeDocuments()
        const incoming = new Map(documents.map((document) => [document.id, document]))
        this.knowledgeDocuments = [
          ...documents,
          ...this.knowledgeDocuments.filter((document) => !incoming.has(document.id)),
        ]
        this.knowledgeIndexStatus = await getKnowledgeIndexStatus()
      } catch (error) {
        this.error = error instanceof Error ? error.message : '内置运维规范初始化失败'
      } finally {
        this.knowledgeSeeding = false
      }
    },
    async rebuildKnowledgeIndex() {
      this.knowledgeReindexing = true
      this.error = ''
      try {
        this.knowledgeIndexStatus = await rebuildKnowledgeIndex()
        this.knowledgeDocuments = await listKnowledgeDocuments()
      } catch (error) {
        this.error = error instanceof Error ? error.message : '知识索引重建失败'
      } finally {
        this.knowledgeReindexing = false
      }
    },
    async searchKnowledge(query: string) {
      const normalized = query.trim()
      if (!normalized) {
        this.knowledgeHits = []
        this.knowledgeAnswer = null
        return
      }
      this.knowledgeSearching = true
      this.error = ''
      try {
        const answer = await answerKnowledge(normalized, 5)
        this.knowledgeAnswer = answer
        this.knowledgeHits = answer.citations
      } catch (error) {
        this.knowledgeAnswer = null
        this.knowledgeHits = []
        this.error = error instanceof Error ? error.message : '知识检索失败'
      } finally {
        this.knowledgeSearching = false
      }
    },
    async refreshOperationalMemories() {
      this.operationalMemoryBusyKey = 'refresh'
      this.error = ''
      try {
        this.operationalMemories = await listOperationalMemories()
      } catch (error) {
        this.error = error instanceof Error ? error.message : '运维经验加载失败'
      } finally {
        this.operationalMemoryBusyKey = ''
      }
    },
    async runOperationalMemoryEvaluation() {
      this.operationalMemoryEvaluationRunning = true
      this.error = ''
      try {
        this.operationalMemoryEvaluation = await runOperationalMemoryEvaluationApi()
      } catch (error) {
        this.error = error instanceof Error ? error.message : '运维记忆验证失败'
      } finally {
        this.operationalMemoryEvaluationRunning = false
      }
    },
    async searchOperationalMemories(query: string, hostScope = '', serviceScope = '') {
      const normalized = query.trim()
      if (!normalized) {
        this.operationalMemoryHits = []
        return
      }
      this.operationalMemorySearching = true
      this.error = ''
      try {
        this.operationalMemoryHits = await searchOperationalMemoriesApi({
          query: normalized,
          host_scope: hostScope.trim() || undefined,
          service_scope: serviceScope.trim() || undefined,
          limit: 5,
        })
      } catch (error) {
        this.operationalMemoryHits = []
        this.error = error instanceof Error ? error.message : '运维经验检索失败'
      } finally {
        this.operationalMemorySearching = false
      }
    },
    async createOperationalMemoryFromTask(taskId: number, payload: {
      resolution: string
      title?: string
      host_scope?: string
      service_scope?: string
    }) {
      this.operationalMemoryBusyKey = `create:${taskId}`
      this.error = ''
      try {
        const memory = await createOperationalMemoryFromTaskApi(taskId, {
          actor: 'local-admin',
          ...payload,
        })
        this.operationalMemories = [
          memory,
          ...this.operationalMemories.filter((item) => item.id !== memory.id),
        ]
        return memory
      } catch (error) {
        this.error = error instanceof Error ? error.message : '运维经验草稿创建失败'
        return null
      } finally {
        this.operationalMemoryBusyKey = ''
      }
    },
    async confirmOperationalMemory(memoryId: number) {
      this.operationalMemoryBusyKey = `confirm:${memoryId}`
      this.error = ''
      try {
        const memory = await confirmOperationalMemoryApi(memoryId, 'local-admin')
        this.operationalMemories = await listOperationalMemories()
        if (memory.status === 'CONFLICTED') {
          this.operationalMemoryRelations = await listOperationalMemoryRelations(memoryId, 'PENDING')
        }
      } catch (error) {
        this.error = error instanceof Error ? error.message : '运维经验确认失败'
      } finally {
        this.operationalMemoryBusyKey = ''
      }
    },
    async qualifyOperationalMemory(memoryId: number) {
      this.operationalMemoryBusyKey = `qualify:${memoryId}`
      this.error = ''
      try {
        const memory = await qualifyOperationalMemoryApi(memoryId, 'local-admin')
        this.operationalMemories = await listOperationalMemories()
        return memory
      } catch (error) {
        this.error = error instanceof Error ? error.message : '运维经验准入验证失败'
        return null
      } finally {
        this.operationalMemoryBusyKey = ''
      }
    },
    async correctOperationalMemory(memoryId: number, payload: {
      title?: string
      root_cause: string
      resolution: string
      host_scope?: string
      service_scope?: string
    }) {
      this.operationalMemoryBusyKey = `correct:${memoryId}`
      this.error = ''
      try {
        await correctOperationalMemoryApi(memoryId, { actor: 'local-admin', ...payload })
        this.operationalMemories = await listOperationalMemories()
        return true
      } catch (error) {
        this.error = error instanceof Error ? error.message : '运维经验修订失败'
        return false
      } finally {
        this.operationalMemoryBusyKey = ''
      }
    },
    async deactivateOperationalMemory(memoryId: number) {
      this.operationalMemoryBusyKey = `deactivate:${memoryId}`
      this.error = ''
      try {
        await deactivateOperationalMemoryApi(memoryId, 'local-admin')
        this.operationalMemories = await listOperationalMemories()
      } catch (error) {
        this.error = error instanceof Error ? error.message : '运维经验停用失败'
      } finally {
        this.operationalMemoryBusyKey = ''
      }
    },
    async refreshOperationalMemoryRelations(memoryId: number) {
      this.error = ''
      try {
        this.operationalMemoryRelations = await listOperationalMemoryRelations(memoryId)
      } catch (error) {
        this.operationalMemoryRelations = []
        this.error = error instanceof Error ? error.message : '运维经验关系加载失败'
      }
    },
    async resolveOperationalMemoryRelation(
      relationId: number,
      decision: 'KEEP_EXISTING' | 'SUPERSEDE_EXISTING',
      reason: string,
      memoryId: number,
    ) {
      this.operationalMemoryBusyKey = `resolve:${relationId}`
      this.error = ''
      try {
        await resolveOperationalMemoryRelationApi(relationId, {
          actor: 'local-admin',
          decision,
          reason,
        })
        const [memories, relations] = await Promise.all([
          listOperationalMemories(),
          listOperationalMemoryRelations(memoryId),
        ])
        this.operationalMemories = memories
        this.operationalMemoryRelations = relations
        return true
      } catch (error) {
        this.error = error instanceof Error ? error.message : '运维经验冲突处理失败'
        return false
      } finally {
        this.operationalMemoryBusyKey = ''
      }
    },
    async forgetOperationalMemory(memoryId: number, reason: string) {
      this.operationalMemoryBusyKey = `forget:${memoryId}`
      this.error = ''
      try {
        await forgetOperationalMemoryApi(memoryId, 'local-admin', reason)
        this.operationalMemories = await listOperationalMemories()
        this.operationalMemoryHits = this.operationalMemoryHits.filter(
          (item) => item.document_id !== memoryId,
        )
        this.operationalMemoryRelations = await listOperationalMemoryRelations(memoryId)
        return true
      } catch (error) {
        this.error = error instanceof Error ? error.message : '移出经验库失败'
        return false
      } finally {
        this.operationalMemoryBusyKey = ''
      }
    },
    async deleteOperationalMemory(memoryId: number) {
      this.operationalMemoryBusyKey = `delete:${memoryId}`
      this.error = ''
      try {
        await deleteOperationalMemoryApi(memoryId, 'local-admin')
        this.operationalMemories = this.operationalMemories.filter((item) => item.id !== memoryId)
        this.operationalMemoryHits = this.operationalMemoryHits.filter((item) => item.document_id !== memoryId)
      } catch (error) {
        this.error = error instanceof Error ? error.message : '运维经验删除失败'
      } finally {
        this.operationalMemoryBusyKey = ''
      }
    },
    async recordTaskFeedback(
      taskId: number,
      verdict: OperatorFeedbackVerdict,
      correction = '',
      memoryId?: number,
    ) {
      this.taskFeedbackSubmitting = true
      this.error = ''
      try {
        const feedback = await createTaskFeedbackApi(taskId, {
          actor: 'local-admin',
          verdict,
          correction: correction.trim() || undefined,
          memory_id: memoryId,
        })
        this.taskFeedback = [feedback, ...this.taskFeedback]
        this.operatorContext = await getOperatorContext()
        return feedback
      } catch (error) {
        this.error = error instanceof Error ? error.message : '任务反馈提交失败'
        return null
      } finally {
        this.taskFeedbackSubmitting = false
      }
    },
    async updateOperatorContext(payload: {
      summary_density: OperatorContext['explicit']['summary_density']
      evidence_view: OperatorContext['explicit']['evidence_view']
      notification_route: OperatorContext['explicit']['notification_route']
      service_focus: string[]
    }) {
      if (!this.operatorContext) return false
      this.operatorContextSaving = true
      this.error = ''
      try {
        this.operatorContext = await updateOperatorContextApi({
          expected_version: this.operatorContext.version,
          ...payload,
        })
        return true
      } catch (error) {
        this.error = error instanceof Error ? error.message : '工作偏好保存失败'
        this.operatorContext = await getOperatorContext()
        return false
      } finally {
        this.operatorContextSaving = false
      }
    },
    async forgetLearnedOperatorContext(reason: string) {
      this.operatorContextSaving = true
      this.error = ''
      try {
        this.operatorContext = await forgetLearnedOperatorContextApi(reason)
        return true
      } catch (error) {
        this.error = error instanceof Error ? error.message : '学习记录清除失败'
        return false
      } finally {
        this.operatorContextSaving = false
      }
    },
  },
})

import axios from 'axios'
import type {
  AIStatus,
  ActionProposal,
  AgentTeamManifest,
  AgentTeamsStatus,
  ApprovalQueueItem,
  AgentEvaluationReport,
  AgentSkill,
  AuditReplay,
  AuditTrace,
  AuditVerification,
  BenchmarkReport,
  ConfigBaseline,
  ConfigBaselineCheck,
  DeploymentReadinessReport,
  ExecutionRecord,
  FeishuChannelStatus,
  FeishuIdentity,
  PendingFeishuIdentity,
  InvestigationPackage,
  IncidentCollaborationDetail,
  IncidentCollaborationSummary,
  IncidentTimeline,
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
  OperationalMemoryRelationStatus,
  OperatorAccount,
  OperatorContext,
  OperatorFeedback,
  OperatorFeedbackVerdict,
  PagedResult,
  PatrolFinding,
  PatrolIncident,
  PatrolOverview,
  PatrolRunSummary,
  PlatformCapabilityProfile,
  RuntimeSafetyStatus,
  WorkerRuntimeStatus,
  SafetyEvaluationReport,
  SafetyReview,
  SafetyRule,
  ServiceExpectationRecord,
  ServiceReconciliationReport,
  Task,
  TaskEvent,
  TaskObservability,
  ToolDefinition,
  ToolCall,
} from './types'

const client = axios.create({
  baseURL: '/api',
  timeout: 30000,
})

const mcpClient = axios.create({
  timeout: 30000,
})

client.interceptors.response.use(
  (response) => response,
  (error) => {
    if (!axios.isAxiosError(error)) {
      return Promise.reject(error)
    }
    const detail = error.response?.data?.detail
    const rawMessage = typeof detail === 'string' ? detail : validationDetailToMessage(detail)
    const message = rawMessage ? toUserErrorMessage(rawMessage, error.response?.status) : error.message
    return Promise.reject(new Error(message))
  },
)

function validationDetailToMessage(detail: unknown) {
  if (!Array.isArray(detail)) return ''
  const first = detail[0]
  if (first && typeof first === 'object' && 'msg' in first && typeof first.msg === 'string') {
    return first.msg
  }
  return ''
}

function toUserErrorMessage(detail: string, status?: number) {
  if (detail.includes('BAILIAN_API_KEY') || detail.includes('DASHSCOPE_API_KEY')) {
    return '智能服务配置缺失：请联系平台管理员处理。'
  }
  if (detail.includes('chat completion failed')) {
    return '智能研判调用失败：请联系平台管理员检查模型服务、网络和额度。'
  }
  if (detail.includes('embedding failed')) {
    if (detail.includes('AllocationQuota.FreeTierOnly')) {
      return '知识向量化受额度策略限制：请在百炼控制台关闭“仅使用免费额度”或补充可用额度后重试。'
    }
    return '知识向量化失败：请联系平台管理员检查向量模型服务。'
  }
  if (detail.includes('schema validation failed')) {
    return '模型返回结构未通过校验：系统已拒绝写入不合规研判结果。'
  }
  if (detail.includes('知识内容疑似包含提示词注入')) {
    return '知识内容疑似包含提示词注入，系统已拒绝入库。'
  }
  if (detail.includes('暂不支持该文件格式')) {
    return '暂不支持该文件格式：请上传 PDF、DOCX、TXT、Markdown 或日志文本。'
  }
  if (detail.includes('需要 OCR 通道')) {
    return '该文件需要 OCR：请先上传可抽取文本的 PDF/DOCX/TXT，图片 OCR 将作为增强通道接入。'
  }
  if (detail.includes('未抽取到足够正文')) {
    return '文件未抽取到足够正文，可能是扫描件或空文档。'
  }
  if (detail.includes('知识库没有可用向量索引')) {
    return '知识索引未就绪：请先导入资料并完成向量索引。'
  }
  if (detail.includes('知识库向量检索不可用') || detail.includes('知识库向量数据库不可用')) {
    return '知识向量检索暂不可用：请检查向量模型、pgvector 和索引状态。'
  }
  if (detail.includes('knowledge document not found')) {
    return '资料不存在或已被删除，请刷新后重试。'
  }
  if (detail.includes('String should have at least 20 characters')) {
    return '知识正文不少于 20 个字符。'
  }
  if (status === 502 || status === 503) {
    return `后端服务暂时无法完成请求：${detail}`
  }
  return detail
}

export async function listTasks(): Promise<Task[]> {
  const { data } = await client.get<Task[]>('/tasks')
  return data
}

export async function getTask(taskId: number): Promise<Task> {
  const { data } = await client.get<Task>(`/tasks/${taskId}`)
  return data
}

export async function exportTaskDiagnosticBundle(taskId: number): Promise<{
  blob: Blob
  filename: string
  sha256: string
}> {
  const response = await client.post<Blob>(
    `/tasks/${taskId}/diagnostic-bundle`,
    undefined,
    { responseType: 'blob' },
  )
  const disposition = String(response.headers['content-disposition'] || '')
  const filenameMatch = disposition.match(/filename="?([^";]+)"?/i)
  return {
    blob: response.data,
    filename: filenameMatch?.[1] || `opscouncil-task-${taskId}-diagnostic.zip`,
    sha256: String(response.headers['x-opscouncil-bundle-sha256'] || ''),
  }
}

export async function listConversationTasks(conversationId: string): Promise<Task[]> {
  const { data } = await client.get<Task[]>(`/conversations/${conversationId}/tasks`)
  return data
}

export async function createTask(input: string, conversationId?: string): Promise<Task> {
  const { data } = await client.post<Task>('/tasks', {
    input,
    conversation_id: conversationId || undefined,
  })
  return data
}

export async function cancelTask(taskId: number): Promise<Task> {
  const { data } = await client.post<Task>(`/tasks/${taskId}/cancel`)
  return data
}

export function taskEventStreamUrl(taskId: number): string {
  return `/api/tasks/${taskId}/stream`
}

export async function approveProposal(proposalId: number): Promise<Task> {
  const { data } = await client.post<Task>(`/proposals/${proposalId}/approve`, {
    operator: 'local-admin',
    comment: '前端工作台确认执行',
  })
  return data
}

export async function rejectProposal(proposalId: number): Promise<Task> {
  const { data } = await client.post<Task>(`/proposals/${proposalId}/reject`, {
    operator: 'local-admin',
    comment: '前端工作台拒绝执行',
  })
  return data
}

export async function getAIStatus(): Promise<AIStatus> {
  const { data } = await client.get<AIStatus>('/ai/status')
  return data
}

export async function getRuntimeSafetyStatus(): Promise<RuntimeSafetyStatus> {
  const { data } = await client.get<RuntimeSafetyStatus>('/runtime/safety')
  return data
}

export async function getWorkerRuntimeStatus(): Promise<WorkerRuntimeStatus> {
  const { data } = await client.get<WorkerRuntimeStatus>('/runtime/worker')
  return data
}

export async function getDeploymentReadiness(): Promise<DeploymentReadinessReport> {
  const { data } = await client.get<DeploymentReadinessReport>('/deployment/readiness')
  return data
}

export async function getPlatformCapabilities(refresh = false): Promise<PlatformCapabilityProfile> {
  const { data } = await client.get<PlatformCapabilityProfile>('/platform/capabilities', {
    params: { refresh },
  })
  return data
}

export async function getLivePosture(): Promise<LivePostureReport> {
  const { data } = await client.get<LivePostureReport>('/posture/live')
  return data
}

export async function listConfigBaselines(): Promise<ConfigBaseline[]> {
  const { data } = await client.get<ConfigBaseline[]>('/config-baselines')
  return data
}

export async function createConfigBaseline(payload: {
  name: string
  paths: string[]
  created_by: string
}): Promise<ConfigBaseline> {
  const { data } = await client.post<ConfigBaseline>('/config-baselines', payload)
  return data
}

export async function checkConfigBaseline(baselineId: number): Promise<ConfigBaselineCheck> {
  const { data } = await client.post<ConfigBaselineCheck>(`/config-baselines/${baselineId}/checks`)
  return data
}

export async function listServiceExpectations(hostKey?: string): Promise<ServiceExpectationRecord[]> {
  const { data } = await client.get<ServiceExpectationRecord[]>('/service-expectations', {
    params: hostKey ? { host_key: hostKey } : undefined,
  })
  return data
}

export async function getServiceReconciliation(
  hostKey: string,
): Promise<ServiceReconciliationReport> {
  const { data } = await client.get<ServiceReconciliationReport>(
    '/service-expectations/reconciliation',
    { params: { host_key: hostKey } },
  )
  return data
}

export async function createServiceExpectation(payload: {
  host_key: string
  unit_name: string
  expected_active_state: 'active' | 'inactive'
  service_owner: string
  criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  environment: 'PRODUCTION' | 'STAGING' | 'TEST' | 'DEVELOPMENT'
  listener_expectations: ServiceExpectationRecord['listener_expectations']
  rationale: string
  source_ref: string
  approved_by: string
  expires_at?: string | null
}): Promise<ServiceExpectationRecord> {
  const { data } = await client.post<ServiceExpectationRecord>('/service-expectations', payload)
  return data
}

export async function retireServiceExpectation(payload: {
  host_key: string
  unit_name: string
  reason: string
  source_ref: string
  approved_by: string
}): Promise<ServiceExpectationRecord> {
  const { data } = await client.post<ServiceExpectationRecord>('/service-expectations/retire', payload)
  return data
}

export async function listServiceExpectationHistory(
  hostKey: string,
  unitName: string,
): Promise<ServiceExpectationRecord[]> {
  const { data } = await client.get<ServiceExpectationRecord[]>('/service-expectations/history', {
    params: { host_key: hostKey, unit_name: unitName },
  })
  return data
}

export async function getMCPStatus(): Promise<MCPStatus> {
  try {
    const initPayload = {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-11-25',
        capabilities: {},
        clientInfo: { name: 'opscouncil-console', version: '1.0.0' },
      },
    }
    const init = await mcpClient.post('/mcp', initPayload, {
      headers: {
        Accept: 'application/json, text/event-stream',
        'Content-Type': 'application/json',
      },
    })
    const tools = await mcpClient.post(
      '/mcp',
      { jsonrpc: '2.0', id: 2, method: 'tools/list' },
      {
        headers: {
          Accept: 'application/json, text/event-stream',
          'Content-Type': 'application/json',
          'MCP-Protocol-Version': '2025-11-25',
        },
      },
    )
    const mcpTools = Array.isArray(tools.data?.result?.tools) ? tools.data.result.tools : []
    return {
      available: Boolean(init.data?.result && tools.data?.result),
      endpoint: '/mcp',
      protocol_version: init.data?.result?.protocolVersion || '-',
      tool_count: mcpTools.length,
      read_only_count: mcpTools.filter((tool: { annotations?: { readOnlyHint?: boolean } }) => tool.annotations?.readOnlyHint).length,
      action_count: mcpTools.filter((tool: { annotations?: { readOnlyHint?: boolean } }) => !tool.annotations?.readOnlyHint).length,
    }
  } catch (error) {
    return {
      available: false,
      endpoint: '/mcp',
      protocol_version: '-',
      tool_count: 0,
      read_only_count: 0,
      action_count: 0,
      error: error instanceof Error ? error.message : 'MCP 端点不可用',
    }
  }
}

export async function getTaskEvents(taskId: number): Promise<TaskEvent[]> {
  const { data } = await client.get<TaskEvent[]>(`/tasks/${taskId}/events`)
  return data
}

export async function getToolCalls(taskId: number): Promise<ToolCall[]> {
  const { data } = await client.get<ToolCall[]>(`/tasks/${taskId}/tool-calls`)
  return data
}

export async function getTaskInvestigation(taskId: number): Promise<InvestigationPackage> {
  const { data } = await client.get<InvestigationPackage>(`/tasks/${taskId}/investigation`)
  return data
}

export async function getTaskObservability(taskId: number): Promise<TaskObservability> {
  const { data } = await client.get<TaskObservability>(`/tasks/${taskId}/observability`)
  return data
}

export async function getActionProposals(taskId: number): Promise<ActionProposal[]> {
  const { data } = await client.get<ActionProposal[]>(`/tasks/${taskId}/proposals`)
  return data
}

export async function listPendingApprovals(): Promise<ApprovalQueueItem[]> {
  const { data } = await client.get<ApprovalQueueItem[]>('/proposals', {
    params: { status_filter: 'PENDING_APPROVAL', limit: 200 },
  })
  return data
}

export async function getExecutionRecords(taskId: number): Promise<ExecutionRecord[]> {
  const { data } = await client.get<ExecutionRecord[]>(`/tasks/${taskId}/execution-records`)
  return data
}

export async function getSafetyReviews(taskId: number): Promise<SafetyReview[]> {
  const { data } = await client.get<SafetyReview[]>(`/safety/reviews/${taskId}`)
  return data
}

export async function getAuditTrace(traceId: string): Promise<AuditTrace> {
  const { data } = await client.get<AuditTrace>(`/audit/traces/${traceId}`)
  return data
}

export async function getAuditVerification(traceId: string): Promise<AuditVerification> {
  const { data } = await client.get<AuditVerification>(`/audit/traces/${traceId}/verify`)
  return data
}

export async function getAuditReplay(traceId: string): Promise<AuditReplay> {
  const { data } = await client.get<AuditReplay>(`/audit/traces/${traceId}/replay`)
  return data
}

export async function listTools(): Promise<ToolDefinition[]> {
  const { data } = await client.get<ToolDefinition[]>('/tools')
  return data
}

export async function listAgentSkills(): Promise<AgentSkill[]> {
  const { data } = await client.get<AgentSkill[]>('/agent/skills')
  return data
}

export async function getSafetyRules(): Promise<SafetyRule[]> {
  const { data } = await client.get<SafetyRule[]>('/safety/rules')
  return data
}

export async function getLatestSafetyEvaluation(): Promise<SafetyEvaluationReport | null> {
  const { data } = await client.get<SafetyEvaluationReport | null>('/safety/evaluations/latest')
  return data
}

export async function runSafetyEvaluation(): Promise<SafetyEvaluationReport> {
  const { data } = await client.post<SafetyEvaluationReport>('/safety/evaluations/run')
  return data
}

export async function getLatestAgentEvaluation(): Promise<AgentEvaluationReport | null> {
  const { data } = await client.get<AgentEvaluationReport | null>('/agent/evaluations/latest')
  return data
}

export async function runAgentEvaluation(): Promise<AgentEvaluationReport> {
  const { data } = await client.post<AgentEvaluationReport>('/agent/evaluations/run')
  return data
}

export async function listKnowledgeDocuments(): Promise<KnowledgeDocument[]> {
  const { data } = await client.get<KnowledgeDocument[]>('/knowledge/documents')
  return data
}

export async function createKnowledgeDocument(payload: {
  title: string
  source_type: string
  source_uri: string
  trust_level: string
  content: string
}): Promise<KnowledgeDocument> {
  const { data } = await client.post<KnowledgeDocument>('/knowledge/documents', payload)
  return data
}

export async function uploadKnowledgeDocument(payload: {
  file: File
  source_type: string
  trust_level: string
  title?: string
}): Promise<KnowledgeDocument> {
  const form = new FormData()
  form.append('file', payload.file)
  form.append('source_type', payload.source_type)
  form.append('trust_level', payload.trust_level)
  if (payload.title?.trim()) form.append('title', payload.title.trim())
  const { data } = await client.post<KnowledgeDocument>('/knowledge/documents/upload', form)
  return data
}

export async function deleteKnowledgeDocument(documentId: number): Promise<{
  document_id: number
  deleted_chunk_count: number
  index_status: KnowledgeIndexStatus
}> {
  const { data } = await client.delete<{
    document_id: number
    deleted_chunk_count: number
    index_status: KnowledgeIndexStatus
  }>(`/knowledge/documents/${documentId}`)
  return data
}

export async function seedBuiltinKnowledgeDocuments(): Promise<KnowledgeDocument[]> {
  const { data } = await client.post<KnowledgeDocument[]>('/knowledge/builtin/seed')
  return data
}

export async function getKnowledgeIndexStatus(): Promise<KnowledgeIndexStatus> {
  const { data } = await client.get<KnowledgeIndexStatus>('/knowledge/index/status')
  return data
}

export async function rebuildKnowledgeIndex(): Promise<KnowledgeIndexStatus> {
  const { data } = await client.post<KnowledgeIndexStatus>('/knowledge/index/rebuild')
  return data
}

export async function searchKnowledge(query: string, limit = 5): Promise<KnowledgeHit[]> {
  const { data } = await client.get<KnowledgeHit[]>('/knowledge/search', {
    params: { q: query, limit },
  })
  return data
}

export async function answerKnowledge(query: string, limit = 5): Promise<KnowledgeAnswer> {
  const { data } = await client.post<KnowledgeAnswer>(
    '/knowledge/answer',
    { query, limit },
    { timeout: 180_000 },
  )
  return data
}

export async function listOperationalMemories(params: {
  status?: string
  host_scope?: string
  service_scope?: string
  limit?: number
} = {}): Promise<OperationalMemory[]> {
  const { data } = await client.get<OperationalMemory[]>('/operational-memories', { params })
  return data
}

export async function getLatestOperationalMemoryEvaluation(): Promise<OperationalMemoryEvaluationReport | null> {
  const { data } = await client.get<OperationalMemoryEvaluationReport | null>(
    '/operational-memories/evaluations/latest',
  )
  return data
}

export async function runOperationalMemoryEvaluation(): Promise<OperationalMemoryEvaluationReport> {
  const { data } = await client.post<OperationalMemoryEvaluationReport>(
    '/operational-memories/evaluations',
  )
  return data
}

export async function searchOperationalMemories(payload: {
  query: string
  host_scope?: string
  service_scope?: string
  limit?: number
}): Promise<KnowledgeHit[]> {
  const { data } = await client.get<KnowledgeHit[]>('/operational-memories/search', {
    params: {
      q: payload.query,
      host_scope: payload.host_scope || undefined,
      service_scope: payload.service_scope || undefined,
      limit: payload.limit ?? 5,
    },
  })
  return data
}

export async function createOperationalMemoryFromTask(taskId: number, payload: {
  actor: string
  resolution: string
  title?: string
  host_scope?: string
  service_scope?: string
}): Promise<OperationalMemory> {
  const { data } = await client.post<OperationalMemory>(`/operational-memories/from-task/${taskId}`, payload)
  return data
}

export async function confirmOperationalMemory(memoryId: number, actor: string): Promise<OperationalMemory> {
  const { data } = await client.post<OperationalMemory>(`/operational-memories/${memoryId}/confirm`, { actor })
  return data
}

export async function qualifyOperationalMemory(memoryId: number, actor: string): Promise<OperationalMemory> {
  const { data } = await client.post<OperationalMemory>(`/operational-memories/${memoryId}/qualify`, { actor })
  return data
}

export async function correctOperationalMemory(memoryId: number, payload: {
  actor: string
  title?: string
  root_cause: string
  resolution: string
  host_scope?: string
  service_scope?: string
}): Promise<OperationalMemory> {
  const { data } = await client.post<OperationalMemory>(`/operational-memories/${memoryId}/correct`, payload)
  return data
}

export async function deactivateOperationalMemory(memoryId: number, actor: string): Promise<OperationalMemory> {
  const { data } = await client.post<OperationalMemory>(`/operational-memories/${memoryId}/deactivate`, { actor })
  return data
}

export async function forgetOperationalMemory(
  memoryId: number,
  actor: string,
  reason: string,
): Promise<OperationalMemory> {
  const { data } = await client.post<OperationalMemory>(`/operational-memories/${memoryId}/forget`, {
    actor,
    reason,
  })
  return data
}

export async function listOperationalMemoryRelations(
  memoryId: number,
  status?: OperationalMemoryRelationStatus,
): Promise<OperationalMemoryRelation[]> {
  const { data } = await client.get<OperationalMemoryRelation[]>(
    `/operational-memories/${memoryId}/relations`,
    { params: { status } },
  )
  return data
}

export async function resolveOperationalMemoryRelation(
  relationId: number,
  payload: {
    actor: string
    decision: 'KEEP_EXISTING' | 'SUPERSEDE_EXISTING'
    reason: string
  },
): Promise<OperationalMemoryRelation> {
  const { data } = await client.post<OperationalMemoryRelation>(
    `/operational-memory-relations/${relationId}/resolve`,
    payload,
  )
  return data
}

export async function deleteOperationalMemory(memoryId: number, actor: string): Promise<void> {
  await client.delete(`/operational-memories/${memoryId}`, { data: { actor } })
}

export async function listTaskFeedback(taskId: number): Promise<OperatorFeedback[]> {
  const { data } = await client.get<OperatorFeedback[]>(`/tasks/${taskId}/feedback`)
  return data
}

export async function createTaskFeedback(taskId: number, payload: {
  actor: string
  verdict: OperatorFeedbackVerdict
  correction?: string
  memory_id?: number
}): Promise<OperatorFeedback> {
  const { data } = await client.post<OperatorFeedback>(`/tasks/${taskId}/feedback`, payload)
  return data
}

export async function listLabScenarios(): Promise<LabScenario[]> {
  const { data } = await client.get<LabScenario[]>('/lab/scenarios')
  return data
}

export async function activateLabScenario(scenarioId: string, sizeMb?: number): Promise<LabScenario> {
  const { data } = await client.post<LabScenario>(`/lab/scenarios/${scenarioId}/activate`, { size_mb: sizeMb })
  return data
}

export async function resetLabScenario(scenarioId: string): Promise<LabScenario> {
  const { data } = await client.post<LabScenario>(`/lab/scenarios/${scenarioId}/reset`)
  return data
}

export async function getLatestLabEvaluation(): Promise<LabEvaluationReport | null> {
  const { data } = await client.get<LabEvaluationReport | null>('/lab/evaluations/latest')
  return data
}

export async function runLabEvaluation(): Promise<LabEvaluationReport> {
  const { data } = await client.post<LabEvaluationReport>('/lab/evaluations/run', undefined, { timeout: 600_000 })
  return data
}

export async function runLabScenarioEvaluation(scenarioId: string): Promise<LabEvaluationCase> {
  const { data } = await client.post<LabEvaluationCase>(
    `/lab/scenarios/${scenarioId}/evaluate`,
    undefined,
    { timeout: 240_000 },
  )
  return data
}

export async function getLatestLabScenarioEvaluations(): Promise<Record<string, LabEvaluationCase>> {
  const { data } = await client.get<Record<string, LabEvaluationCase>>('/lab/scenarios/evaluations/latest')
  return data
}

export async function getLatestBenchmark(): Promise<BenchmarkReport | null> {
  const { data } = await client.get<BenchmarkReport | null>('/benchmark/latest')
  return data
}

export async function runBenchmark(rounds = 2): Promise<BenchmarkReport> {
  const { data } = await client.post<BenchmarkReport>('/benchmark/run', { rounds })
  return data
}

export async function getPatrolOverview(): Promise<PatrolOverview> {
  const { data } = await client.get<PatrolOverview>('/patrol/overview')
  return data
}

export async function listPatrolFindings(params: {
  status?: string
  severity?: string
  page?: number
  page_size?: number
} = {}): Promise<PagedResult<PatrolFinding>> {
  const { data } = await client.get<PagedResult<PatrolFinding>>('/findings', { params })
  return data
}

export async function listPatrolIncidents(params: {
  status?: string
  severity?: string
  page?: number
  page_size?: number
} = {}): Promise<PagedResult<PatrolIncident>> {
  const { data } = await client.get<PagedResult<PatrolIncident>>('/incidents', { params })
  return data
}

export async function getIncidentTimeline(incidentId: number): Promise<IncidentTimeline> {
  const { data } = await client.get<IncidentTimeline>(`/incidents/${incidentId}/timeline`)
  return data
}

export async function runPatrolPolicy(policyId: number): Promise<PatrolRunSummary> {
  const { data } = await client.post<PatrolRunSummary>(`/patrol/policies/${policyId}/run`)
  return data
}

export async function acknowledgePatrolFinding(findingId: number): Promise<PatrolFinding> {
  const { data } = await client.post<PatrolFinding>(`/findings/${findingId}/acknowledge`)
  return data
}

export async function closePatrolIncident(incidentId: number): Promise<PatrolIncident> {
  const { data } = await client.post<PatrolIncident>(`/incidents/${incidentId}/close`)
  return data
}

export async function listIncidentCollaborations(
  limit = 50,
): Promise<IncidentCollaborationSummary[]> {
  const { data } = await client.get<IncidentCollaborationSummary[]>('/collaboration/incidents', {
    params: { limit },
  })
  return data
}

export async function getIncidentCollaboration(
  collaborationId: number,
): Promise<IncidentCollaborationDetail> {
  const { data } = await client.get<IncidentCollaborationDetail>(
    `/collaboration/incidents/${collaborationId}`,
  )
  return data
}

export async function startPatrolIncidentCollaboration(
  incidentId: number,
): Promise<IncidentCollaborationDetail> {
  const { data } = await client.post<IncidentCollaborationDetail>(
    `/collaboration/patrol-incidents/${incidentId}`,
  )
  return data
}

export async function dispatchIncidentCollaboration(
  collaborationId: number,
): Promise<{ collaboration_id: number; event_id: string }> {
  const { data } = await client.post<{ collaboration_id: number; event_id: string }>(
    `/collaboration/incidents/${collaborationId}/agentteams/dispatch`,
  )
  return data
}

export async function getAgentTeamsStatus(): Promise<AgentTeamsStatus> {
  const { data } = await client.get<AgentTeamsStatus>('/collaboration/agentteams/status')
  return data
}

export async function getAgentTeamManifest(): Promise<AgentTeamManifest> {
  const { data } = await client.get<AgentTeamManifest>('/collaboration/team')
  return data
}

export async function verifyIncidentCollaborationAudit(
  collaborationId: number,
): Promise<IncidentCollaborationDetail['audit']> {
  const { data } = await client.get<IncidentCollaborationDetail['audit']>(
    `/collaboration/incidents/${collaborationId}/audit/verify`,
  )
  return data
}

export async function getFeishuChannelStatus(): Promise<FeishuChannelStatus> {
  const { data } = await client.get<FeishuChannelStatus>('/channels/feishu/status')
  return data
}

export async function retryFeishuDelivery(outboxId: number): Promise<void> {
  await client.post(`/channels/feishu/deliveries/${outboxId}/retry`)
}

export async function listOperators(): Promise<OperatorAccount[]> {
  const { data } = await client.get<OperatorAccount[]>('/operators')
  return data
}

export async function getOperatorContext(actor = 'local-admin'): Promise<OperatorContext> {
  const { data } = await client.get<OperatorContext>(`/operator-context/${encodeURIComponent(actor)}`)
  return data
}

export async function updateOperatorContext(
  payload: {
    expected_version: number
    summary_density: OperatorContext['explicit']['summary_density']
    evidence_view: OperatorContext['explicit']['evidence_view']
    notification_route: OperatorContext['explicit']['notification_route']
    service_focus: string[]
  },
  actor = 'local-admin',
): Promise<OperatorContext> {
  const { data } = await client.put<OperatorContext>(
    `/operator-context/${encodeURIComponent(actor)}`,
    payload,
  )
  return data
}

export async function forgetLearnedOperatorContext(
  reason: string,
  actor = 'local-admin',
): Promise<OperatorContext> {
  const { data } = await client.delete<OperatorContext>(
    `/operator-context/${encodeURIComponent(actor)}/learned-preferences`,
    { data: { reason } },
  )
  return data
}

export async function listFeishuIdentities(): Promise<FeishuIdentity[]> {
  const { data } = await client.get<FeishuIdentity[]>('/channels/feishu/identities')
  return data
}

export async function listPendingFeishuIdentities(): Promise<PendingFeishuIdentity[]> {
  const { data } = await client.get<PendingFeishuIdentity[]>('/channels/feishu/pending-identities')
  return data
}

export async function createFeishuIdentity(payload: {
  operator_id: number
  tenant_key: string
  open_id: string
}): Promise<FeishuIdentity> {
  const { data } = await client.post<FeishuIdentity>('/channels/feishu/identities', payload)
  return data
}

export async function setFeishuIdentityStatus(
  identityId: number,
  status: FeishuIdentity['status'],
): Promise<FeishuIdentity> {
  const { data } = await client.patch<FeishuIdentity>(`/channels/feishu/identities/${identityId}`, { status })
  return data
}

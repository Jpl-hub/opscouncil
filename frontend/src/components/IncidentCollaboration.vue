<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import {
  IconCheckCircle,
  IconExclamationCircle,
  IconLink,
  IconRefresh,
  IconSend,
} from '@arco-design/web-vue/es/icon'
import {
  dispatchIncidentCollaboration,
  getAgentTeamManifest,
  getAgentTeamsStatus,
  getIncidentCollaboration,
  listIncidentCollaborations,
  listPatrolIncidents,
  startPatrolIncidentCollaboration,
  verifyIncidentCollaborationAudit,
} from '../api'
import type {
  AgentTeamManifest,
  AgentTeamsStatus,
  CollaborationAuditEvent,
  CollaborationWorkItem,
  IncidentCollaborationDetail,
  IncidentCollaborationSummary,
  PatrolIncident,
} from '../types'

const emit = defineEmits<{
  (event: 'open-task', taskId: number): void
}>()

const collaborations = ref<IncidentCollaborationSummary[]>([])
const incidents = ref<PatrolIncident[]>([])
const selectedId = ref<number | null>(null)
const selectedIncidentId = ref<number | undefined>(undefined)
const detail = ref<IncidentCollaborationDetail | null>(null)
const agentTeamsStatus = ref<AgentTeamsStatus | null>(null)
const manifest = ref<AgentTeamManifest | null>(null)
const loading = ref(false)
const detailLoading = ref(false)
const starting = ref(false)
const dispatching = ref(false)
const verifying = ref(false)
const error = ref('')

const trackedIncidentIds = computed(() => new Set(collaborations.value.map((item) => item.incident_id)))
const availableIncidents = computed(() => incidents.value.filter((item) => (
  !trackedIncidentIds.value.has(item.id)
  && !['CLOSED', 'RESOLVED'].includes(item.status)
)))
const latestDispatch = computed(() => (
  [...(detail.value?.events ?? [])]
    .reverse()
    .find((item) => item.event_type === 'agentteams_dispatched') ?? null
))
const evidenceRefs = computed(() => {
  const refs = new Set<string>()
  const initial = detail.value?.shared_context?.initial_evidence_refs
  if (Array.isArray(initial)) {
    initial.forEach((item) => {
      if (typeof item === 'string' && item.trim()) refs.add(item.trim())
    })
  }
  detail.value?.work_items.forEach((item) => {
    item.evidence_refs.forEach((ref) => refs.add(ref))
  })
  return [...refs]
})
const teamOnline = computed(() => Boolean(agentTeamsStatus.value?.configured && agentTeamsStatus.value?.reachable))

onMounted(() => {
  void refreshAll()
})

async function refreshAll() {
  if (loading.value) return
  loading.value = true
  error.value = ''
  try {
    const [collaborationRows, incidentPage, runtimeStatus, teamManifest] = await Promise.all([
      listIncidentCollaborations(100),
      listPatrolIncidents({ page: 1, page_size: 100 }),
      getAgentTeamsStatus(),
      getAgentTeamManifest(),
    ])
    collaborations.value = collaborationRows
    incidents.value = incidentPage.items
    agentTeamsStatus.value = runtimeStatus
    manifest.value = teamManifest

    const requested = selectedId.value
    const next = collaborationRows.find((item) => item.id === requested)?.id
      ?? collaborationRows[0]?.id
      ?? null
    selectedId.value = next
    selectedIncidentId.value = availableIncidents.value[0]?.id
    if (next !== null) await loadDetail(next)
    else detail.value = null
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : '协作调查加载失败'
  } finally {
    loading.value = false
  }
}

async function loadDetail(collaborationId: number) {
  selectedId.value = collaborationId
  detailLoading.value = true
  error.value = ''
  try {
    detail.value = await getIncidentCollaboration(collaborationId)
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : '事件协作详情加载失败'
  } finally {
    detailLoading.value = false
  }
}

async function startSelectedIncident() {
  if (!selectedIncidentId.value || starting.value) return
  starting.value = true
  error.value = ''
  try {
    const created = await startPatrolIncidentCollaboration(selectedIncidentId.value)
    selectedId.value = created.id
    await refreshAll()
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : '事件接入协作流程失败'
  } finally {
    starting.value = false
  }
}

async function dispatchToTeam() {
  if (!detail.value || !teamOnline.value || dispatching.value) return
  dispatching.value = true
  error.value = ''
  try {
    await dispatchIncidentCollaboration(detail.value.id)
    await loadDetail(detail.value.id)
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : 'AgentTeams 派发失败'
  } finally {
    dispatching.value = false
  }
}

async function verifyAudit() {
  if (!detail.value || verifying.value) return
  verifying.value = true
  error.value = ''
  try {
    detail.value.audit = await verifyIncidentCollaborationAudit(detail.value.id)
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : '协作审计校验失败'
  } finally {
    verifying.value = false
  }
}

function collaborationStatusLabel(value: string) {
  return ({
    TRIAGING: '信号归并',
    INVESTIGATING: '根因调查',
    PLANNING: '处置规划',
    WAITING_EXECUTION: '等待执行',
    VERIFYING: '恢复验证',
    LEARNING: '经验沉淀',
    RESOLVED: '已闭环',
    NEEDS_OPERATOR: '需要人工',
    FAILED: '协作异常',
  } as Record<string, string>)[value] ?? value
}

function workLabel(value: CollaborationWorkItem['work_key']) {
  return ({
    triage: '归并信号',
    investigate: '调查根因',
    plan: '生成动作契约',
    execute: '策略控制执行',
    verify: '独立恢复验证',
    learn: '沉淀合格经验',
  } as Record<CollaborationWorkItem['work_key'], string>)[value]
}

function roleLabel(value: string) {
  return ({
    signal_correlator: '信号归并 Agent',
    rca_investigator: '因果调查 Agent',
    remediation_planner: '处置规划 Agent',
    policy_controller: '确定性策略控制器',
    recovery_verifier: '恢复验证 Agent',
    incident_commander: '事件指挥 Agent',
  } as Record<string, string>)[value] ?? value
}

function workStatusLabel(value: string) {
  return ({
    PENDING: '等待依赖',
    READY: '可领取',
    RUNNING: '执行中',
    SUCCEEDED: '已完成',
    FAILED: '失败',
    BLOCKED: '已阻断',
    CANCELLED: '已取消',
  } as Record<string, string>)[value] ?? value
}

function gateLabel(value?: string) {
  return ({ PENDING: '待形成证据', PASSED: '证据充分', FAILED: '证据不足', OVERRIDDEN: '人工复核' } as Record<string, string>)[value || ''] ?? '-'
}

function autonomyLabel(value?: string) {
  return ({
    UNDECIDED: '尚未判定',
    OBSERVE_ONLY: '仅观察',
    AUTO_REVERSIBLE: '可逆动作自动执行',
    HUMAN_GATED: '人工审批后执行',
    BLOCKED: '禁止执行',
  } as Record<string, string>)[value || ''] ?? '-'
}

function workResult(item: CollaborationWorkItem) {
  const output = item.output
  if (!output) {
    if (item.status === 'READY') return '依赖已满足，等待对应身份领取。'
    if (item.status === 'PENDING') return `依赖：${item.depends_on.map((key) => workLabel(key as CollaborationWorkItem['work_key'])).join('、')}`
    return item.status === 'RUNNING' ? '正在收集并核验证据。' : '尚无结果。'
  }
  const action = output.action
  const candidates = [
    output.summary,
    output.root_cause,
    output.incident_boundary,
    output.incident_summary,
    output.detail,
    action && typeof action === 'object' ? (action as Record<string, unknown>).rationale : null,
  ]
  const result = candidates.find((item) => typeof item === 'string' && item.trim())
  return typeof result === 'string' ? result : '结构化结果已写入共享事件上下文。'
}

function workEvidenceCount(item: CollaborationWorkItem) {
  const refs = new Set(item.evidence_refs)
  const inherited = item.input.evidence_refs
  if (Array.isArray(inherited)) {
    inherited.forEach((ref) => {
      if (typeof ref === 'string' && ref.trim()) refs.add(ref.trim())
    })
  }
  return refs.size
}

function actionTool() {
  const action = detail.value?.action_contract?.action
  if (action && typeof action === 'object') {
    const toolName = (action as Record<string, unknown>).tool_name
    if (typeof toolName === 'string' && toolName) return toolName
  }
  return '-'
}

function executionOutcome() {
  const outcome = detail.value?.execution?.outcome
  if (typeof outcome !== 'string') return '尚未执行'
  return ({ SUCCEEDED: '执行成功', FAILED: '执行失败', ROLLED_BACK: '已回滚' } as Record<string, string>)[outcome] ?? outcome
}

function runtimeLabel() {
  if (!agentTeamsStatus.value?.configured) return '未配置'
  return agentTeamsStatus.value.reachable ? '协作在线' : '连接异常'
}

function runtimeReason() {
  if (!agentTeamsStatus.value?.configured) return '部署端尚未配置 AgentTeams Matrix 连接。'
  if (agentTeamsStatus.value.reachable) return `${manifest.value?.identity_count ?? 0} 个隔离身份已编排`
  return 'Matrix 服务当前不可达，请检查协作运行时。'
}

function shortHash(value?: string | null) {
  if (!value) return '-'
  return value.length <= 18 ? value : `${value.slice(0, 8)}...${value.slice(-6)}`
}

function formatTime(value?: string | null) {
  if (!value) return '-'
  return new Date(value).toLocaleString('zh-CN', { hour12: false })
}

function severityLabel(value?: string) {
  return value === 'CRITICAL' ? '严重' : '关注'
}

function eventLabel(event: CollaborationAuditEvent) {
  return ({
    collaboration_started: '协作流程已建立',
    work_claimed: '工作项已领取',
    work_submitted: '结果已提交',
    evidence_gate_failed: '证据门未通过',
    execution_recorded: '执行回执已记录',
    agentteams_dispatched: '已派发 AgentTeams',
    agentteams_room_bound: '协作房间已绑定',
  } as Record<string, string>)[event.event_type] ?? event.event_type
}
</script>

<template>
  <section class="collaboration-workspace">
    <header class="collaboration-toolbar">
      <div class="runtime-state" :class="{ online: teamOnline }">
        <i></i>
        <span>AgentTeams</span>
        <strong>{{ runtimeLabel() }}</strong>
        <small>{{ runtimeReason() }}</small>
      </div>
      <div class="collaboration-actions">
        <a-select
          v-model="selectedIncidentId"
          size="small"
          placeholder="选择尚未接入的事件"
          :disabled="!availableIncidents.length || starting"
          :style="{ width: '230px' }"
        >
          <a-option v-for="incident in availableIncidents" :key="incident.id" :value="incident.id">
            #{{ incident.id }} · {{ incident.title }}
          </a-option>
        </a-select>
        <a-button
          size="small"
          :disabled="!selectedIncidentId"
          :loading="starting"
          @click="startSelectedIncident"
        >
          <template #icon><IconLink /></template>
          接入调查
        </a-button>
        <a-button size="small" :loading="loading" title="刷新协作状态" @click="refreshAll">
          <template #icon><IconRefresh /></template>
        </a-button>
      </div>
    </header>

    <div v-if="error" class="collaboration-error">
      <IconExclamationCircle />
      <span>{{ error }}</span>
    </div>

    <div v-if="!loading && !collaborations.length" class="collaboration-empty">
      <strong>当前没有协作调查</strong>
      <span v-if="availableIncidents.length">选择一个运行事件接入协作流程。</span>
      <span v-else>巡检发现异常并形成事件后，将自动建立协作调查。</span>
    </div>

    <div v-else class="collaboration-layout" :class="{ busy: detailLoading }">
      <aside class="incident-index">
        <header>
          <strong>调查队列</strong>
          <span>{{ collaborations.length }}</span>
        </header>
        <div class="incident-list">
          <button
            v-for="item in collaborations"
            :key="item.id"
            :class="{ active: item.id === selectedId }"
            @click="loadDetail(item.id)"
          >
            <span class="incident-index-line">
              <code>#{{ item.incident_id }}</code>
              <em :class="item.status.toLowerCase()">{{ collaborationStatusLabel(item.status) }}</em>
            </span>
            <strong>{{ incidents.find((incident) => incident.id === item.incident_id)?.title || `事件 ${item.incident_id}` }}</strong>
            <small>{{ formatTime(item.updated_at) }}</small>
          </button>
        </div>
      </aside>

      <main class="workflow-panel">
        <template v-if="detail">
          <header class="workflow-header">
            <div>
              <span class="severity-mark" :class="detail.incident?.severity.toLowerCase()">
                {{ severityLabel(detail.incident?.severity) }}
              </span>
              <div>
                <strong>{{ detail.incident?.title || `事件 ${detail.incident_id}` }}</strong>
                <p>{{ detail.incident?.host_key }} · {{ detail.incident?.summary }}</p>
              </div>
            </div>
            <div class="workflow-actions">
              <a-button
                v-if="detail.incident?.task_id"
                size="small"
                @click="emit('open-task', detail.incident.task_id)"
              >
                打开调查任务
              </a-button>
              <a-button
                type="primary"
                size="small"
                :disabled="!teamOnline"
                :loading="dispatching"
                @click="dispatchToTeam"
              >
                <template #icon><IconSend /></template>
                {{ latestDispatch ? '重新派发' : '派发团队' }}
              </a-button>
            </div>
          </header>

          <section class="workflow-chain" aria-label="事件协作工作流">
            <article
              v-for="(item, index) in detail.work_items"
              :key="item.id"
              :class="[item.status.toLowerCase(), { controller: item.role === 'policy_controller' }]"
            >
              <div class="step-axis">
                <i><IconCheckCircle v-if="item.status === 'SUCCEEDED'" /></i>
                <span v-if="index < detail.work_items.length - 1"></span>
              </div>
              <div class="step-body">
                <header>
                  <div>
                    <strong>{{ workLabel(item.work_key) }}</strong>
                    <span>{{ roleLabel(item.role) }}</span>
                  </div>
                  <em>{{ workStatusLabel(item.status) }}</em>
                </header>
                <p>{{ workResult(item) }}</p>
                <footer>
                  <span>证据 {{ workEvidenceCount(item) }}</span>
                  <span v-if="item.attempt_count">尝试 {{ item.attempt_count }}</span>
                  <span v-if="item.assigned_agent">{{ item.assigned_agent }}</span>
                  <code :title="item.skill_id">{{ item.skill_id }}</code>
                </footer>
              </div>
            </article>
          </section>
        </template>
        <div v-else class="panel-placeholder">请选择调查事件。</div>
      </main>

      <aside class="decision-panel">
        <template v-if="detail">
          <section class="decision-section">
            <header>
              <strong>当前边界</strong>
              <span>上下文 v{{ detail.context_version }}</span>
            </header>
            <dl>
              <div>
                <dt>证据门</dt>
                <dd :class="detail.evidence_gate_status.toLowerCase()">{{ gateLabel(detail.evidence_gate_status) }}</dd>
              </div>
              <div>
                <dt>自治范围</dt>
                <dd>{{ autonomyLabel(detail.autonomy_mode) }}</dd>
              </div>
              <div>
                <dt>动作工具</dt>
                <dd><code>{{ actionTool() }}</code></dd>
              </div>
              <div>
                <dt>执行状态</dt>
                <dd>{{ executionOutcome() }}</dd>
              </div>
              <div>
                <dt>契约哈希</dt>
                <dd><code :title="detail.action_contract_hash || ''">{{ shortHash(detail.action_contract_hash) }}</code></dd>
              </div>
            </dl>
          </section>

          <section class="decision-section evidence-section">
            <header>
              <strong>证据引用</strong>
              <span>{{ evidenceRefs.length }}</span>
            </header>
            <ul v-if="evidenceRefs.length">
              <li v-for="ref in evidenceRefs.slice(0, 8)" :key="ref" :title="ref">{{ ref }}</li>
            </ul>
            <p v-else>尚未形成可引用证据。</p>
          </section>

          <section class="decision-section audit-section">
            <header>
              <strong>协作审计</strong>
              <button :disabled="verifying" title="重新校验哈希链" @click="verifyAudit">
                <IconRefresh />
              </button>
            </header>
            <div class="audit-result" :class="{ valid: detail.audit.valid }">
              <IconCheckCircle v-if="detail.audit.valid" />
              <IconExclamationCircle v-else />
              <span>{{ detail.audit.valid ? '链路完整' : '校验失败' }}</span>
              <strong>{{ detail.audit.event_count }} 个事件</strong>
            </div>
            <code :title="detail.audit.head_hash || ''">{{ shortHash(detail.audit.head_hash) }}</code>
            <div v-if="detail.events.length" class="event-tail">
              <span>{{ eventLabel(detail.events[detail.events.length - 1]) }}</span>
              <small>{{ formatTime(detail.events[detail.events.length - 1].created_at) }}</small>
            </div>
          </section>

          <section class="decision-section team-section">
            <header>
              <strong>协作运行时</strong>
              <span>{{ manifest?.identity_count ?? 0 }} 个身份</span>
            </header>
            <p>{{ manifest?.leader ? `事件指挥：${manifest.leader}` : '等待团队清单' }}</p>
            <div class="matrix-receipt">
              <span>Matrix 回执</span>
              <code :title="latestDispatch?.source_event_id || ''">{{ shortHash(latestDispatch?.source_event_id) }}</code>
            </div>
          </section>
        </template>
      </aside>
    </div>
  </section>
</template>

<style scoped>
.collaboration-workspace {
  min-height: 0;
  height: 100%;
  display: grid;
  grid-template-rows: auto auto minmax(0, 1fr);
  background: #fff;
  border: 1px solid #d8dee8;
  overflow: hidden;
}

.collaboration-toolbar {
  min-height: 58px;
  padding: 10px 14px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  border-bottom: 1px solid #e3e7ed;
}

.runtime-state,
.collaboration-actions,
.workflow-header > div,
.workflow-actions,
.incident-index-line,
.decision-section header,
.audit-result,
.matrix-receipt {
  display: flex;
  align-items: center;
}

.runtime-state {
  min-width: 0;
  gap: 8px;
}

.runtime-state i {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #c53b3b;
  flex: 0 0 auto;
}

.runtime-state.online i { background: #309455; }
.runtime-state span { color: #586273; font-size: 13px; }
.runtime-state strong { color: #20252d; font-size: 14px; }
.runtime-state small {
  max-width: 340px;
  color: #778194;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.collaboration-actions { gap: 8px; }

.collaboration-error {
  padding: 8px 14px;
  display: flex;
  gap: 8px;
  align-items: center;
  color: #a52828;
  background: #fff5f5;
  border-bottom: 1px solid #efcaca;
  font-size: 13px;
}

.collaboration-layout {
  min-height: 0;
  display: grid;
  grid-template-columns: minmax(190px, 0.72fr) minmax(470px, 2.15fr) minmax(240px, 0.95fr);
  opacity: 1;
  transition: opacity 120ms ease;
}

.collaboration-layout.busy { opacity: .64; }

.incident-index,
.workflow-panel,
.decision-panel {
  min-width: 0;
  min-height: 0;
  overflow: hidden;
}

.incident-index,
.workflow-panel { border-right: 1px solid #e3e7ed; }

.incident-index {
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
  background: #f7f8fa;
}

.incident-index > header {
  padding: 13px 14px 9px;
  display: flex;
  justify-content: space-between;
  color: #2b313b;
}

.incident-index > header span {
  min-width: 24px;
  text-align: center;
  color: #667085;
  font-size: 12px;
}

.incident-list,
.workflow-chain,
.decision-panel {
  overflow: auto;
  scrollbar-width: thin;
  scrollbar-color: #bac2ce transparent;
}

.incident-list button {
  width: 100%;
  padding: 11px 13px;
  display: grid;
  gap: 6px;
  border: 0;
  border-top: 1px solid #e6e9ee;
  background: transparent;
  color: #20252d;
  text-align: left;
  cursor: pointer;
}

.incident-list button:hover { background: #f0f2f5; }
.incident-list button.active { background: #fff; box-shadow: inset 3px 0 #c53434; }
.incident-list button > strong {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 13px;
}
.incident-list button > small { color: #7a8495; font-size: 11px; }

.incident-index-line { justify-content: space-between; gap: 8px; }
.incident-index-line code { color: #697386; font-size: 11px; }
.incident-index-line em {
  color: #9b661c;
  font-size: 11px;
  font-style: normal;
}
.incident-index-line em.resolved { color: #277b46; }
.incident-index-line em.failed,
.incident-index-line em.needs_operator { color: #ae2d2d; }

.workflow-panel {
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
}

.workflow-header {
  width: 100%;
  max-width: 100%;
  min-width: 0;
  min-height: 78px;
  padding: 12px 16px;
  display: flex;
  justify-content: space-between;
  gap: 12px;
  border-bottom: 1px solid #e3e7ed;
}

.workflow-header > div:first-child { min-width: 0; gap: 10px; }
.workflow-header > div:first-child > div { min-width: 0; }
.workflow-header strong { font-size: 16px; color: #1f252d; }
.workflow-header p {
  margin: 4px 0 0;
  max-width: 660px;
  color: #687386;
  font-size: 12px;
  line-height: 1.5;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.severity-mark {
  min-width: 38px;
  height: 24px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  color: #9a5b13;
  background: #fff3df;
  border: 1px solid #e4be83;
  font-size: 11px;
}
.severity-mark.critical { color: #a52828; background: #fff0f0; border-color: #e8aaaa; }
.workflow-actions { align-self: center; flex: 0 0 auto; gap: 8px; }

.workflow-chain {
  width: 100%;
  max-width: 100%;
  min-width: 0;
  padding: 13px 16px 18px;
}
.workflow-chain article {
  display: grid;
  grid-template-columns: 30px minmax(0, 1fr);
  gap: 6px;
  min-height: 88px;
}

.step-axis {
  display: grid;
  grid-template-rows: 26px minmax(0, 1fr);
  justify-items: center;
}
.step-axis i {
  width: 22px;
  height: 22px;
  display: flex;
  align-items: center;
  justify-content: center;
  border: 2px solid #c7ced9;
  border-radius: 50%;
  background: #fff;
  color: #fff;
}
.step-axis span { width: 1px; height: 100%; background: #d8dde5; }
.workflow-chain article.ready .step-axis i,
.workflow-chain article.running .step-axis i { border-color: #c88b30; box-shadow: inset 0 0 0 5px #fff3df; }
.workflow-chain article.succeeded .step-axis i { border-color: #309455; background: #309455; }
.workflow-chain article.failed .step-axis i,
.workflow-chain article.blocked .step-axis i { border-color: #c33c3c; box-shadow: inset 0 0 0 5px #fff0f0; }

.step-body {
  min-width: 0;
  padding: 1px 0 13px;
  border-bottom: 1px solid #e9ecf1;
}
.step-body header,
.step-body header > div,
.step-body footer {
  display: flex;
  align-items: center;
}
.step-body header { justify-content: space-between; gap: 10px; }
.step-body header > div { min-width: 0; gap: 9px; }
.step-body header strong { font-size: 14px; color: #252b34; }
.step-body header span { color: #707b8c; font-size: 12px; }
.step-body header em { color: #6c7687; font-size: 11px; font-style: normal; }
.step-body p {
  margin: 7px 0;
  color: #4e5868;
  font-size: 12px;
  line-height: 1.55;
}
.step-body footer { gap: 10px; color: #7c8695; font-size: 11px; }
.step-body footer code {
  margin-left: auto;
  max-width: 144px;
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: #5e6878;
}
.workflow-chain article.controller .step-body { background: linear-gradient(90deg, rgba(246, 247, 249, .8), transparent 75%); }

.decision-panel { padding: 0 14px 16px; background: #fbfbfc; }
.decision-section { padding: 14px 0; border-bottom: 1px solid #e1e5eb; }
.decision-section:last-child { border-bottom: 0; }
.decision-section header { justify-content: space-between; gap: 8px; margin-bottom: 10px; }
.decision-section header strong { color: #2a3039; font-size: 13px; }
.decision-section header span { color: #7d8797; font-size: 11px; }
.decision-section header button {
  width: 25px;
  height: 25px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: 0;
  background: transparent;
  color: #667085;
  cursor: pointer;
}
.decision-section dl { margin: 0; }
.decision-section dl > div,
.matrix-receipt {
  min-height: 30px;
  justify-content: space-between;
  gap: 12px;
}
.decision-section dt { color: #778194; font-size: 11px; }
.decision-section dd {
  margin: 0;
  max-width: 150px;
  color: #2d343e;
  font-size: 12px;
  text-align: right;
  overflow-wrap: anywhere;
}
.decision-section dd.passed { color: #277b46; }
.decision-section dd.failed { color: #ae2d2d; }
.decision-section code { color: #525d6d; font-size: 11px; }
.evidence-section ul { margin: 0; padding: 0; list-style: none; display: grid; gap: 5px; }
.evidence-section li {
  padding: 4px 6px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  background: #f0f2f5;
  color: #535e6e;
  font: 11px/1.35 ui-monospace, SFMono-Regular, Consolas, monospace;
}
.evidence-section p,
.team-section p { margin: 0; color: #6d7787; font-size: 12px; line-height: 1.5; }
.audit-result { gap: 6px; color: #a52d2d; font-size: 12px; }
.audit-result.valid { color: #277b46; }
.audit-result strong { margin-left: auto; color: #5b6575; font-size: 11px; }
.audit-section > code { display: block; margin-top: 7px; }
.event-tail { margin-top: 9px; padding-top: 8px; display: grid; gap: 3px; border-top: 1px dashed #d8dde5; }
.event-tail span { color: #454f5e; font-size: 12px; }
.event-tail small { color: #8891a0; font-size: 10px; }
.matrix-receipt { margin-top: 8px; }
.matrix-receipt span { color: #778194; font-size: 11px; }

.collaboration-empty,
.panel-placeholder {
  min-height: 240px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 7px;
  color: #7b8493;
}
.collaboration-empty strong { color: #353c46; }

@media (max-width: 1280px) {
  .collaboration-layout { grid-template-columns: 180px minmax(430px, 1fr) 230px; }
  .runtime-state small { display: none; }
  .workflow-header { align-items: flex-start; }
  .workflow-actions { flex-direction: column; align-items: stretch; }
}

@media (max-width: 980px) {
  .collaboration-toolbar { align-items: flex-start; flex-direction: column; }
  .collaboration-actions { width: 100%; }
  .collaboration-actions :deep(.arco-select-view) { flex: 1; }
  .collaboration-layout { grid-template-columns: 160px minmax(420px, 1fr); }
  .decision-panel { display: none; }
}
</style>

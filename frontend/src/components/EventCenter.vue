<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { IconClose, IconEye, IconRefresh } from '@arco-design/web-vue/es/icon'
import { getIncidentTimeline } from '../api'
import { useTaskStore } from '../stores/tasks'
import type { IncidentTimeline, PatrolIncident, PendingFeishuIdentity } from '../types'

const emit = defineEmits<{
  (event: 'open-task', taskId: number): void
}>()

type EventTab = 'findings' | 'incidents' | 'approvals' | 'collaboration'

const props = withDefaults(defineProps<{
  initialTab?: EventTab
}>(), {
  initialTab: 'incidents',
})

const store = useTaskStore()
const activeTab = ref<EventTab>(props.initialTab)
const findingStatus = ref('')
const findingSeverity = ref('')
const incidentStatus = ref('')
const incidentSeverity = ref('')
const selectedPolicyId = ref<number | undefined>(undefined)
const selectedOperatorId = ref<number | undefined>(undefined)
const selectedPendingIdentity = ref('')
const timelineVisible = ref(false)
const timelineLoading = ref(false)
const selectedTimeline = ref<IncidentTimeline | null>(null)

const enabledPolicies = computed(() => store.patrolOverview?.policies.filter((item) => item.enabled) ?? [])
const activePolicyId = computed(() => selectedPolicyId.value ?? enabledPolicies.value[0]?.id ?? null)
const activeOperators = computed(() => store.operators.filter((item) => item.status === 'ACTIVE'))
const selectedPending = computed(() =>
  store.feishuPendingIdentities.find((item) => pendingIdentityKey(item) === selectedPendingIdentity.value),
)
const patrolTabActive = computed(() => activeTab.value === 'findings' || activeTab.value === 'incidents')
const highRiskApprovalCount = computed(() =>
  store.pendingApprovals.filter((item) => ['R3', 'R4'].includes(item.risk_level)).length,
)
const approvalTaskCount = computed(() => new Set(store.pendingApprovals.map((item) => item.task_id)).size)
const oldestApprovalTime = computed(() => {
  const oldest = store.pendingApprovals[store.pendingApprovals.length - 1]
  return oldest ? formatTime(oldest.created_at) : '-'
})

watch(
  () => props.initialTab,
  (value) => {
    activeTab.value = value
    if (value === 'approvals') void store.refreshPendingApprovals()
  },
)

function refresh(options: { findingPage?: number; incidentPage?: number } = {}) {
  if (activeTab.value === 'collaboration') return store.refreshFeishuChannel()
  if (activeTab.value === 'approvals') return store.refreshPendingApprovals()
  return store.refreshPatrolData({
    findingStatus: findingStatus.value,
    findingSeverity: findingSeverity.value,
    findingPage: options.findingPage ?? store.patrolFindings.page,
    incidentStatus: incidentStatus.value,
    incidentSeverity: incidentSeverity.value,
    incidentPage: options.incidentPage ?? store.patrolIncidents.page,
  })
}

function selectTab(tab: EventTab) {
  activeTab.value = tab
  if (tab === 'approvals') void store.refreshPendingApprovals()
}

async function bindIdentity() {
  if (!selectedOperatorId.value || !selectedPending.value) return
  try {
    await store.createFeishuIdentity({
      operator_id: selectedOperatorId.value,
      tenant_key: selectedPending.value.tenant_key,
      open_id: selectedPending.value.open_id,
    })
    selectedPendingIdentity.value = ''
  } catch {
    // Store exposes the actionable error in the shared workspace banner.
  }
}

function pendingIdentityKey(item: PendingFeishuIdentity) {
  return `${item.tenant_key}\u0000${item.open_id}`
}

function maskedOpenId(value: string) {
  return value.length <= 14 ? value : `${value.slice(0, 7)}...${value.slice(-5)}`
}

function runPatrol() {
  if (activePolicyId.value !== null) void store.runPatrolPolicy(activePolicyId.value)
}

function findingStatusLabel(value: string) {
  return ({ OPEN: '待处理', ACKNOWLEDGED: '已确认', RESOLVED: '已恢复' } as Record<string, string>)[value] ?? value
}

function incidentStatusLabel(value: string) {
  return ({ OPEN: '待调查', INVESTIGATING: '调查中', RESOLVED: '已恢复', CLOSED: '已关闭' } as Record<string, string>)[value] ?? value
}

function incidentLifecycleLabel(item: PatrolIncident) {
  if (['OPEN', 'INVESTIGATING'].includes(item.status) && item.healthy_streak > 0) {
    return `恢复确认 ${item.healthy_streak}/${item.recovery_target}`
  }
  return incidentStatusLabel(item.status)
}

function eventSummary(item: { signal_key: string; summary: string; status: string }) {
  if (
    item.signal_key === 'failed_service'
    && item.summary.trim().toLowerCase().startsWith('unknown ')
  ) {
    return item.status === 'RESOLVED'
      ? '历史采样未返回有效服务单元；事件已恢复，原始记录保留用于审计。'
      : '采样未返回有效服务单元，需先补充证据再形成服务故障结论。'
  }
  return item.summary
}

function runStatusLabel(value?: string) {
  return ({ RUNNING: '运行中', SUCCEEDED: '完成', FAILED: '异常' } as Record<string, string>)[value || ''] ?? '未运行'
}

function severityLabel(value: string) {
  return value === 'CRITICAL' ? '严重' : '关注'
}

function channelStatusLabel() {
  const status = store.feishuChannelStatus
  if (!status?.enabled) return '未启用'
  if (status.connected) return '协同在线'
  return ({
    LONG_CONNECTION_PENDING: '正在连接',
    BOT_CAPABILITY_UNAVAILABLE: '机器人未就绪',
    PROCESS_STOPPED: '通道已停止',
  } as Record<string, string>)[status.detail_code || ''] ?? '连接异常'
}

function channelDetailLabel() {
  const status = store.feishuChannelStatus
  if (!status?.enabled) return '未配置'
  if (status.connected) return '消息与审批就绪'
  if (status.detail_code === 'BOT_CAPABILITY_UNAVAILABLE') return '请启用并发布应用机器人'
  return '等待通道恢复'
}

function deliveryKindLabel(value: string) {
  return ({
    TASK_ACCEPTED: '任务受理',
    TASK_RESULT: '任务结果',
    INCIDENT: '巡检事件',
    INVESTIGATION: '调查结论',
    APPROVAL_REQUEST: '处置审批',
    EXECUTION: '处置进度',
    VERIFICATION: '独立验证',
    ROLLBACK: '回滚审批',
  } as Record<string, string>)[value] ?? value
}

function deliveryStatusLabel(value: string) {
  return ({ PENDING: '待投递', SENDING: '投递中', SENT: '已送达', FAILED: '失败' } as Record<string, string>)[value] ?? value
}

function deliveryResultLabel(value: string | null) {
  if (!value) return '-'
  return ({
    APPROVAL_TOKEN_REJECTED: '审批已结束',
    OUTBOX_PAYLOAD_INVALID: '消息结构异常',
    FEISHU_RATE_LIMIT: '平台限流',
    FEISHU_REQUEST_FAILED: '平台请求失败',
    FEISHU_SEND_FAILED: '投递失败',
    LEASE_EXPIRED: '投递租约过期',
  } as Record<string, string>)[value] ?? '投递失败'
}

function roleLabel(value: string) {
  return ({ VIEWER: '只读', OPERATOR: '运维人员', APPROVER: '审批人', ADMIN: '管理员' } as Record<string, string>)[value] ?? value
}

function proposalToolLabel(value: string) {
  return ({
    safe_log_rotate: '日志安全轮转',
    restore_log_backup: '日志备份恢复',
    restart_managed_service: '受控服务重启',
    restore_config_mode: '配置权限恢复',
  } as Record<string, string>)[value] ?? value
}

function taskStatusLabel(value: string) {
  return ({
    RECEIVED: '已接收',
    STATIC_REVIEW: '安全校验',
    PLAN: '规划中',
    PERCEIVE: '感知中',
    DRY_RUN: '方案预检',
    DYNAMIC_REVIEW: '动态校验',
    APPROVAL_REQUIRED: '等待审批',
    EXECUTE: '执行中',
    VERIFY: '核验中',
    SUMMARIZE: '汇总中',
    SEALED: '分析已封存',
    REJECTED: '已拒绝',
    BLOCKED: '已阻断',
    NEEDS_OPERATOR: '等待人工处理',
    FAILED: '任务失败',
    CANCELLED: '已取消',
    ROLLED_BACK: '已回滚',
  } as Record<string, string>)[value] ?? value
}

function formatMetric(metric: Record<string, unknown>) {
  const value = metric.metric
  return typeof value === 'string' || typeof value === 'number' ? String(value) : '-'
}

function formatTime(value?: string | null) {
  if (!value) return '-'
  return new Date(value).toLocaleString('zh-CN', { hour12: false })
}

async function openIncidentTimeline(item: PatrolIncident) {
  timelineVisible.value = true
  timelineLoading.value = true
  selectedTimeline.value = null
  try {
    selectedTimeline.value = await getIncidentTimeline(item.id)
  } catch (error) {
    store.error = error instanceof Error ? error.message : '事件时间线加载失败'
  } finally {
    timelineLoading.value = false
  }
}

function timelinePhaseLabel(value: string) {
  return ({
    DETECTION: '发现',
    INVESTIGATION: '调查',
    DECISION: '决策',
    CHANGE: '变更',
    VERIFICATION: '验证',
    RECOVERY: '恢复',
  } as Record<string, string>)[value] ?? value
}

function timelineVerificationLabel(value?: string) {
  return ({
    VERIFIED: '验证通过',
    READY: '待审批',
    APPROVED: '已批准',
    EXECUTING: '执行中',
    BLOCKED: '已阻断',
    FAILED: '执行失败',
    NEEDS_OPERATOR: '人工接管',
    REVOKED: '已撤销',
    NOT_REQUIRED: '无需变更',
  } as Record<string, string>)[value || ''] ?? '待确认'
}

function timelineConfidenceLabel(value?: string) {
  return ({ LOW: '较低', MEDIUM: '中等', HIGH: '较高' } as Record<string, string>)[value || ''] ?? '-'
}

function elapsedLabel(value: number | null) {
  if (value === null) return '-'
  if (value < 60) return `${value} 秒`
  const minutes = Math.floor(value / 60)
  const seconds = value % 60
  return seconds ? `${minutes} 分 ${seconds} 秒` : `${minutes} 分`
}
</script>

<template>
  <section class="event-center">
    <header class="event-toolbar">
      <nav aria-label="事件视图">
        <button :class="{ active: activeTab === 'incidents' }" @click="selectTab('incidents')">
          聚合事件
          <code>{{ store.patrolIncidents.total }}</code>
        </button>
        <button :class="{ active: activeTab === 'findings' }" @click="selectTab('findings')">
          运行发现
          <code>{{ store.patrolFindings.total }}</code>
        </button>
        <button :class="{ active: activeTab === 'approvals' }" @click="selectTab('approvals')">
          审批待办
          <code>{{ store.pendingApprovals.length }}</code>
        </button>
        <button
          data-testid="collaboration-tab"
          :class="{ active: activeTab === 'collaboration' }"
          @click="selectTab('collaboration')"
        >
          飞书协同
          <code>{{ store.feishuChannelStatus?.identity_count ?? 0 }}</code>
        </button>
      </nav>
      <div class="event-actions">
        <a-select
          v-if="patrolTabActive && enabledPolicies.length > 1"
          v-model="selectedPolicyId"
          size="small"
          :style="{ width: '150px' }"
          placeholder="巡检策略"
        >
          <a-option v-for="policy in enabledPolicies" :key="policy.id" :value="policy.id">
            {{ policy.name }}
          </a-option>
        </a-select>
        <a-button
          v-if="patrolTabActive"
          type="primary"
          size="small"
          :disabled="activePolicyId === null"
          :loading="store.patrolBusyKey === `policy:${activePolicyId}`"
          @click="runPatrol"
        >
          立即巡检
        </a-button>
        <a-button
          size="small"
          :loading="activeTab === 'collaboration' ? store.channelLoading : activeTab === 'approvals' ? false : store.patrolLoading"
          title="刷新当前视图"
          @click="refresh()"
        >
          <template #icon><IconRefresh /></template>
        </a-button>
      </div>
    </header>

    <section v-if="patrolTabActive" class="event-summary">
      <div>
        <span>待处理事件</span>
        <strong>{{ store.patrolOverview?.open_incident_count ?? 0 }}</strong>
      </div>
      <div>
        <span>原始发现</span>
        <strong>{{ store.patrolFindings.total }}</strong>
      </div>
      <div>
        <span>最近巡检</span>
        <strong>{{ runStatusLabel(store.patrolOverview?.latest_run?.status) }}</strong>
        <small>{{ formatTime(store.patrolOverview?.latest_run?.completed_at) }}</small>
      </div>
      <div>
        <span>采样节点</span>
        <strong>{{ store.patrolOverview?.latest_run?.host_key || '-' }}</strong>
        <small>{{ store.patrolOverview?.latest_run?.collection_status || '-' }}</small>
      </div>
    </section>

    <section v-else-if="activeTab === 'approvals'" class="event-summary approval-summary">
      <div>
        <span>待审批</span>
        <strong>{{ store.pendingApprovals.length }}</strong>
      </div>
      <div>
        <span>高风险</span>
        <strong>{{ highRiskApprovalCount }}</strong>
      </div>
      <div>
        <span>涉及任务</span>
        <strong>{{ approvalTaskCount }}</strong>
      </div>
      <div>
        <span>最早提交</span>
        <strong class="approval-oldest">{{ oldestApprovalTime }}</strong>
      </div>
    </section>

    <section v-else class="event-summary channel-summary" data-testid="channel-summary">
      <div>
        <span>通道状态</span>
        <strong class="channel-connection" :class="{ online: store.feishuChannelStatus?.connected }">
          <i></i>{{ channelStatusLabel() }}
        </strong>
        <small>{{ formatTime(store.feishuChannelStatus?.last_heartbeat_at) }}</small>
      </div>
      <div>
        <span>待投递</span>
        <strong>{{ (store.feishuChannelStatus?.outbox.pending ?? 0) + (store.feishuChannelStatus?.outbox.sending ?? 0) }}</strong>
        <small>失败 {{ store.feishuChannelStatus?.outbox.failed ?? 0 }}</small>
      </div>
      <div>
        <span>有效身份</span>
        <strong>{{ store.feishuChannelStatus?.identity_count ?? 0 }}</strong>
        <small>审批人 {{ store.feishuChannelStatus?.approver_count ?? 0 }}</small>
      </div>
      <div>
        <span>已送达</span>
        <strong>{{ store.feishuChannelStatus?.outbox.sent ?? 0 }}</strong>
        <small>{{ channelDetailLabel() }}</small>
      </div>
    </section>

    <div v-if="store.error" class="event-error">{{ store.error }}</div>

    <section v-if="activeTab === 'findings'" class="event-table-shell">
      <header class="event-filterbar">
        <strong>运行发现</strong>
        <div>
          <a-select v-model="findingStatus" size="small" :style="{ width: '112px' }" @change="refresh({ findingPage: 1 })">
            <a-option value="">全部状态</a-option>
            <a-option value="OPEN">待处理</a-option>
            <a-option value="ACKNOWLEDGED">已确认</a-option>
            <a-option value="RESOLVED">已恢复</a-option>
          </a-select>
          <a-select v-model="findingSeverity" size="small" :style="{ width: '104px' }" @change="refresh({ findingPage: 1 })">
            <a-option value="">全部等级</a-option>
            <a-option value="CRITICAL">严重</a-option>
            <a-option value="WARN">关注</a-option>
          </a-select>
        </div>
      </header>
      <div class="event-table finding-table">
        <div class="event-row head">
          <span>等级</span><span>发现</span><span>主机 / 指标</span><span>时间</span><span>次数</span><span>状态</span><span></span>
        </div>
        <div v-for="item in store.patrolFindings.items" :key="item.id" class="event-row">
          <span class="severity" :class="item.severity.toLowerCase()"><i></i>{{ severityLabel(item.severity) }}</span>
          <span class="event-subject" :title="eventSummary(item)"><strong>{{ item.title }}</strong><small>{{ eventSummary(item) }}</small></span>
          <span class="event-host"><strong>{{ item.host_key }}</strong><code>{{ formatMetric(item.metric) }}</code></span>
          <span class="event-time"><strong>{{ formatTime(item.last_observed_at) }}</strong><small>首次 {{ formatTime(item.first_observed_at) }}</small></span>
          <strong>{{ item.occurrence_count }}</strong>
          <span class="event-status" :class="item.status.toLowerCase()">{{ findingStatusLabel(item.status) }}</span>
          <a-button
            v-if="item.status === 'OPEN'"
            type="text"
            size="mini"
            :loading="store.patrolBusyKey === `finding:${item.id}`"
            @click="store.acknowledgePatrolFinding(item.id)"
          >确认</a-button>
          <span v-else></span>
        </div>
        <div v-if="!store.patrolFindings.items.length" class="event-empty">当前筛选条件下没有运行发现。</div>
      </div>
      <a-pagination
        v-if="store.patrolFindings.page_count > 1"
        size="small"
        :current="store.patrolFindings.page"
        :page-size="store.patrolFindings.page_size"
        :total="store.patrolFindings.total"
        @change="refresh({ findingPage: $event })"
      />
    </section>

    <section v-else-if="activeTab === 'incidents'" class="event-table-shell">
      <header class="event-filterbar">
        <strong>聚合事件</strong>
        <div>
          <a-select v-model="incidentStatus" size="small" :style="{ width: '112px' }" @change="refresh({ incidentPage: 1 })">
            <a-option value="">全部状态</a-option>
            <a-option value="OPEN">待调查</a-option>
            <a-option value="INVESTIGATING">调查中</a-option>
            <a-option value="RESOLVED">已恢复</a-option>
            <a-option value="CLOSED">已关闭</a-option>
          </a-select>
          <a-select v-model="incidentSeverity" size="small" :style="{ width: '104px' }" @change="refresh({ incidentPage: 1 })">
            <a-option value="">全部等级</a-option>
            <a-option value="CRITICAL">严重</a-option>
            <a-option value="WARN">关注</a-option>
          </a-select>
        </div>
      </header>
      <div class="event-table incident-table">
        <div class="event-row head">
          <span>等级</span><span>事件</span><span>主机</span><span>调查任务</span><span>更新时间</span><span>状态</span><span></span>
        </div>
        <div v-for="item in store.patrolIncidents.items" :key="item.id" class="event-row">
          <span class="severity" :class="item.severity.toLowerCase()"><i></i>{{ severityLabel(item.severity) }}</span>
          <button
            class="event-subject incident-subject"
            :title="`查看事件时间线：${eventSummary(item)}`"
            @click="openIncidentTimeline(item)"
          >
            <strong>{{ item.title }} <IconEye /></strong>
            <small>{{ eventSummary(item) }}</small>
          </button>
          <code>{{ item.host_key }}</code>
          <button v-if="item.task_id" class="task-link" @click="emit('open-task', item.task_id)">
            #{{ item.task_id }} · {{ taskStatusLabel(item.task_status || '-') }}
          </button>
          <span v-else>-</span>
          <span>{{ formatTime(item.updated_at) }}</span>
          <span
            class="event-status"
            :class="item.status.toLowerCase()"
            :title="item.last_healthy_at ? `最近健康采样：${formatTime(item.last_healthy_at)}` : ''"
          >{{ incidentLifecycleLabel(item) }}</span>
          <a-button
            v-if="!['CLOSED', 'RESOLVED'].includes(item.status)"
            type="text"
            size="mini"
            :disabled="Boolean(item.task_id && !['SEALED', 'REJECTED', 'BLOCKED', 'FAILED', 'NEEDS_OPERATOR', 'CANCELLED', 'ROLLED_BACK'].includes(item.task_status || ''))"
            :loading="store.patrolBusyKey === `incident:${item.id}`"
            @click="store.closePatrolIncident(item.id)"
          >关闭</a-button>
          <span v-else></span>
        </div>
        <div v-if="!store.patrolIncidents.items.length" class="event-empty">当前筛选条件下没有聚合事件。</div>
      </div>
      <a-pagination
        v-if="store.patrolIncidents.page_count > 1"
        size="small"
        :current="store.patrolIncidents.page"
        :page-size="store.patrolIncidents.page_size"
        :total="store.patrolIncidents.total"
        @change="refresh({ incidentPage: $event })"
      />
    </section>

    <section v-else-if="activeTab === 'approvals'" class="event-table-shell approval-shell">
      <header class="event-filterbar">
        <strong>审批待办</strong>
        <span>进入任务核对证据后决策</span>
      </header>
      <div class="event-table approval-table">
        <div class="event-row head">
          <span>风险</span><span>处置动作</span><span>任务请求</span><span>提交时间</span><span>任务状态</span><span></span>
        </div>
        <div v-for="item in store.pendingApprovals" :key="item.id" class="event-row">
          <code class="approval-risk" :class="item.risk_level.toLowerCase()">{{ item.risk_level }}</code>
          <span class="event-subject" :title="item.reason">
            <strong>{{ proposalToolLabel(item.tool_name) }}</strong>
            <small>{{ item.reason }}</small>
          </span>
          <span class="event-subject" :title="item.user_input">
            <strong>#{{ item.task_id }}</strong>
            <small>{{ item.user_input }}</small>
          </span>
          <span>{{ formatTime(item.created_at) }}</span>
          <span>{{ taskStatusLabel(item.task_status) }}</span>
          <a-button type="text" size="mini" @click="emit('open-task', item.task_id)">审阅</a-button>
        </div>
        <div v-if="!store.pendingApprovals.length" class="event-empty">当前没有待审批处置。</div>
      </div>
    </section>

    <section v-else class="event-table-shell channel-shell" data-testid="collaboration-workspace">
      <header class="event-filterbar">
        <strong>协同通道</strong>
        <span class="channel-state" :class="{ online: store.feishuChannelStatus?.connected }">
          <i></i>{{ channelStatusLabel() }}
        </span>
      </header>
      <div class="channel-workspace">
        <section class="channel-pane delivery-pane">
          <header class="channel-pane-title">
            <strong>近期投递</strong>
            <span>仅显示状态与错误分类</span>
          </header>
          <div class="delivery-table">
            <div class="delivery-row head">
              <span>类型</span><span>状态</span><span>尝试</span><span>更新时间</span><span>结果</span><span></span>
            </div>
            <div
              v-for="item in store.feishuChannelStatus?.recent_deliveries ?? []"
              :key="item.id"
              class="delivery-row"
            >
              <strong>{{ deliveryKindLabel(item.kind) }}</strong>
              <span class="delivery-status" :class="item.status.toLowerCase()">{{ deliveryStatusLabel(item.status) }}</span>
              <code>{{ item.attempt_count }}/{{ item.max_attempts }}</code>
              <span>{{ formatTime(item.updated_at) }}</span>
              <span>{{ deliveryResultLabel(item.last_error_code) }}</span>
              <a-button
                v-if="item.retry_allowed"
                type="text"
                size="mini"
                :loading="store.channelBusyKey === `delivery:${item.id}`"
                @click="store.retryFeishuDelivery(item.id)"
              >重试</a-button>
              <span v-else></span>
            </div>
            <div v-if="!store.feishuChannelStatus?.recent_deliveries.length" class="event-empty">
              暂无协同投递记录
            </div>
          </div>
        </section>

        <section class="channel-pane identity-pane">
          <header class="channel-pane-title">
            <strong>身份与权限</strong>
            <span>待绑定 {{ store.feishuPendingIdentities.length }} · 已绑定 {{ store.feishuIdentities.length }}</span>
          </header>
          <form class="channel-bind-form" @submit.prevent="bindIdentity">
            <div class="operator-field">
              <a-select
                v-model="selectedOperatorId"
                size="small"
                placeholder="选择运维人员"
              >
                <a-option v-for="operator in activeOperators" :key="operator.id" :value="operator.id">
                  {{ operator.display_name }} · {{ roleLabel(operator.role) }}
                </a-option>
              </a-select>
            </div>
            <div class="pending-identity-field">
              <a-select
                v-model="selectedPendingIdentity"
                size="small"
                placeholder="选择待绑定飞书用户"
                :disabled="!store.feishuPendingIdentities.length"
              >
                <a-option
                  v-for="identity in store.feishuPendingIdentities"
                  :key="pendingIdentityKey(identity)"
                  :value="pendingIdentityKey(identity)"
                >
                  {{ maskedOpenId(identity.open_id) }} · {{ identity.attempt_count }} 次 · {{ formatTime(identity.last_seen_at) }}
                </a-option>
              </a-select>
            </div>
            <a-button
              html-type="submit"
              type="primary"
              size="small"
              :disabled="!selectedOperatorId || !selectedPending"
              :loading="store.channelBusyKey === 'identity:create'"
            >确认绑定</a-button>
          </form>
          <div class="identity-list">
            <div v-for="identity in store.feishuIdentities" :key="identity.id" class="identity-row">
              <span class="identity-person">
                <strong>{{ identity.operator_display_name }}</strong>
                <small>{{ roleLabel(identity.operator_role) }} · {{ identity.tenant_key }}</small>
              </span>
              <code :title="identity.open_id">{{ identity.open_id }}</code>
              <span class="identity-state" :class="identity.status.toLowerCase()">
                {{ identity.status === 'ACTIVE' ? '有效' : '停用' }}
              </span>
              <a-button
                type="text"
                size="mini"
                :loading="store.channelBusyKey === `identity:${identity.id}`"
                @click="store.setFeishuIdentityStatus(identity.id, identity.status === 'ACTIVE' ? 'DISABLED' : 'ACTIVE')"
              >{{ identity.status === 'ACTIVE' ? '停用' : '启用' }}</a-button>
            </div>
            <div v-if="!store.feishuIdentities.length" class="event-empty">尚未绑定飞书身份</div>
          </div>
        </section>
      </div>
    </section>

    <div
      v-if="timelineVisible"
      class="trace-overlay event-timeline-overlay"
      @click.self="timelineVisible = false"
    >
      <aside class="trace-drawer event-timeline-dialog">
        <header class="trace-drawer-head">
          <div>
            <strong>事件时间线</strong>
            <span>从告警、调查、变更到验证的统一链路</span>
          </div>
          <button class="drawer-close" aria-label="关闭事件时间线" @click="timelineVisible = false">
            <IconClose />
          </button>
        </header>
        <div class="event-timeline-dialog-body">
          <div v-if="timelineLoading" class="timeline-loading">正在重建事件链路</div>
          <div v-else-if="selectedTimeline" class="incident-timeline">
        <header class="timeline-incident-head">
          <span class="severity" :class="selectedTimeline.incident.severity.toLowerCase()">
            <i></i>{{ severityLabel(selectedTimeline.incident.severity) }}
          </span>
          <strong>{{ selectedTimeline.incident.title }}</strong>
          <code>{{ selectedTimeline.incident.host_key }}</code>
        </header>
        <div class="timeline-correlation">
          <div>
            <span>根因</span>
            <strong>{{ selectedTimeline.correlation.root_cause?.title || '证据仍在收集' }}</strong>
            <small v-if="selectedTimeline.correlation.root_cause">
              {{ timelineConfidenceLabel(selectedTimeline.correlation.root_cause.confidence) }}
              · {{ selectedTimeline.correlation.root_cause.score }}
            </small>
          </div>
          <div>
            <span>实际变更</span>
            <strong>{{ selectedTimeline.correlation.change_count }}</strong>
            <small>方案 {{ selectedTimeline.correlation.proposal_count }}</small>
          </div>
          <div>
            <span>结果</span>
            <strong>{{ timelineVerificationLabel(selectedTimeline.correlation.verification_status) }}</strong>
            <small>{{ elapsedLabel(selectedTimeline.correlation.time_to_verified_seconds) }}</small>
          </div>
        </div>
        <ol class="timeline-list">
          <li
            v-for="item in selectedTimeline.events"
            :key="item.key"
            :class="item.phase.toLowerCase()"
          >
            <i aria-hidden="true"></i>
            <div class="timeline-event" :title="item.references.join(' · ')">
              <header>
                <span>{{ timelinePhaseLabel(item.phase) }}</span>
                <time>{{ formatTime(item.occurred_at) }}</time>
              </header>
              <strong>{{ item.title }}</strong>
              <p>{{ item.summary }}</p>
            </div>
          </li>
        </ol>
          </div>
          <div v-else class="timeline-loading">未取得事件时间线</div>
        </div>
      </aside>
    </div>
  </section>
</template>

<style scoped>
.event-center {
  min-height: 0;
  height: 100%;
  display: grid;
  grid-template-rows: auto auto auto minmax(0, 1fr);
  gap: 12px;
  padding: 12px 14px;
  overflow: hidden;
}

.event-toolbar,
.event-filterbar,
.event-summary,
.event-toolbar nav,
.event-actions,
.event-filterbar > div {
  display: flex;
  align-items: center;
}

.event-toolbar {
  justify-content: space-between;
  min-width: 0;
}

.event-toolbar nav {
  gap: 4px;
}

.event-toolbar nav button {
  height: 32px;
  padding: 0 12px;
  border: 0;
  border-bottom: 2px solid transparent;
  background: transparent;
  color: #667085;
  cursor: pointer;
}

.event-toolbar nav button.active {
  border-bottom-color: #c33232;
  color: #202631;
  font-weight: 700;
}

.event-toolbar nav code {
  margin-left: 5px;
  color: #98a2b3;
}

.event-actions,
.event-filterbar > div {
  gap: 8px;
}

.event-summary {
  min-height: 64px;
  border-top: 1px solid #e2e6ec;
  border-bottom: 1px solid #e2e6ec;
}

.event-summary > div {
  min-width: 0;
  flex: 1;
  display: grid;
  grid-template-columns: auto 1fr;
  align-items: center;
  column-gap: 10px;
  padding: 0 18px;
  border-right: 1px solid #edf0f4;
}

.event-summary > div:last-child {
  border-right: 0;
}

.event-summary span,
.event-summary small {
  color: #7a8494;
  font-size: 12px;
}

.event-summary strong {
  min-width: 0;
  overflow: hidden;
  color: #242b36;
  font-size: 17px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.approval-oldest {
  font-size: 13px !important;
}

.event-summary small {
  grid-column: 2;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.event-error {
  min-height: 30px;
  padding: 6px 10px;
  border-left: 3px solid #c33232;
  background: #fff5f5;
  color: #a32929;
  font-size: 12px;
}

.event-table-shell {
  min-height: 0;
  display: grid;
  grid-template-rows: auto minmax(0, 1fr) auto;
  border: 1px solid #dfe4eb;
  background: #fff;
  overflow: hidden;
}

.event-filterbar {
  justify-content: space-between;
  min-height: 48px;
  padding: 0 12px;
  border-bottom: 1px solid #e4e8ee;
}

.event-filterbar > strong {
  color: #28313f;
  font-size: 14px;
}

.event-table {
  min-height: 0;
  overflow: auto;
  scrollbar-gutter: stable;
}

.event-row {
  min-width: 960px;
  min-height: 56px;
  display: grid;
  align-items: center;
  gap: 12px;
  padding: 6px 12px;
  border-bottom: 1px solid #edf0f4;
  color: #3c4655;
  font-size: 12px;
}

.finding-table .event-row {
  grid-template-columns: 64px minmax(230px, 1.6fr) minmax(130px, .8fr) minmax(175px, 1fr) 46px 74px 52px;
}

.incident-table .event-row {
  grid-template-columns: 64px minmax(230px, 1.6fr) 120px 135px 165px 96px 52px;
}

.approval-table .event-row {
  grid-template-columns: 56px minmax(190px, 1fr) minmax(220px, 1.35fr) 160px 92px 50px;
}

.approval-risk {
  width: 38px;
  justify-content: center;
  font-weight: 700;
}

.approval-risk.r3,
.approval-risk.r4 {
  background: #fff0f0;
  color: #b72f2f;
}

.approval-shell .event-filterbar > span {
  color: #7a8494;
  font-size: 12px;
}

.event-row.head {
  min-height: 36px;
  position: sticky;
  top: 0;
  z-index: 1;
  padding-top: 0;
  padding-bottom: 0;
  background: #f7f8fa;
  color: #7a8494;
  font-weight: 650;
}

.event-row > *,
.event-subject,
.event-host,
.event-time {
  min-width: 0;
}

.event-subject,
.event-host,
.event-time {
  display: grid;
  gap: 3px;
}

.incident-subject {
  width: 100%;
  padding: 0;
  border: 0;
  background: transparent;
  text-align: left;
  cursor: pointer;
}

.incident-subject:hover strong {
  color: #a32929;
}

.incident-subject strong {
  display: flex;
  align-items: center;
  gap: 6px;
}

.incident-subject svg {
  flex: 0 0 auto;
  color: #98a2b3;
  font-size: 13px;
}

.event-subject strong,
.event-subject small,
.event-host strong,
.event-host code,
.event-time strong,
.event-time small {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.event-subject strong,
.event-host strong,
.event-time strong {
  color: #28313f;
  font-size: 13px;
}

.event-subject small,
.event-time small {
  color: #8a94a3;
  font-size: 11px;
}

.severity {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.severity i {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: #d69a36;
}

.severity.critical {
  color: #a32929;
}

.severity.critical i {
  background: #c33232;
}

.event-status {
  width: fit-content;
  padding: 2px 7px;
  border: 1px solid #d9dee6;
  border-radius: 3px;
  color: #657083;
}

.event-status.open,
.event-status.investigating {
  border-color: #efc988;
  background: #fff9ee;
  color: #8a5b16;
}

.event-status.resolved,
.event-status.closed {
  border-color: #b9d9c1;
  background: #f3faf4;
  color: #2f7740;
}

.task-link {
  width: fit-content;
  max-width: 100%;
  padding: 0;
  border: 0;
  background: none;
  color: #2d5fbf;
  cursor: pointer;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.timeline-loading {
  min-height: 320px;
  display: grid;
  place-items: center;
  color: #7a8494;
}

.event-timeline-dialog {
  width: min(820px, calc(100vw - 68px));
  height: min(700px, calc(100vh - 68px));
  grid-template-rows: 62px minmax(0, 1fr);
}

.event-timeline-dialog-body {
  min-height: 0;
  padding: 18px 24px 24px;
  overflow: auto;
  background: #fff;
}

.incident-timeline {
  min-width: 0;
}

.timeline-incident-head {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  align-items: center;
  gap: 7px 12px;
  padding: 2px 0 16px;
  border-bottom: 1px solid #e2e6ec;
}

.timeline-incident-head > strong {
  min-width: 0;
  overflow: hidden;
  color: #202631;
  font-size: 17px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.timeline-incident-head > code {
  grid-column: 2;
  width: fit-content;
  max-width: 100%;
  overflow: hidden;
  color: #667085;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.timeline-correlation {
  display: grid;
  grid-template-columns: minmax(0, 1.5fr) 96px 120px;
  min-height: 76px;
  border-bottom: 1px solid #e2e6ec;
}

.timeline-correlation > div {
  min-width: 0;
  display: grid;
  align-content: center;
  gap: 3px;
  padding: 10px 14px;
  border-right: 1px solid #edf0f4;
}

.timeline-correlation > div:first-child {
  padding-left: 0;
}

.timeline-correlation > div:last-child {
  border-right: 0;
}

.timeline-correlation span,
.timeline-correlation small {
  color: #7a8494;
  font-size: 11px;
}

.timeline-correlation strong {
  min-width: 0;
  overflow: hidden;
  color: #303846;
  font-size: 14px;
  line-height: 1.4;
}

.timeline-correlation > div:first-child strong {
  display: -webkit-box;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
}

.timeline-list {
  margin: 0;
  padding: 18px 0 8px;
  list-style: none;
}

.timeline-list > li {
  position: relative;
  min-height: 82px;
  display: grid;
  grid-template-columns: 15px minmax(0, 1fr);
  gap: 12px;
}

.timeline-list > li::before {
  content: "";
  position: absolute;
  top: 14px;
  bottom: -4px;
  left: 5px;
  width: 1px;
  background: #dfe4eb;
}

.timeline-list > li:last-child::before {
  display: none;
}

.timeline-list > li > i {
  width: 11px;
  height: 11px;
  margin-top: 3px;
  border: 2px solid #fff;
  border-radius: 50%;
  background: #7a8494;
  box-shadow: 0 0 0 1px #aeb6c2;
}

.timeline-list > li.change > i {
  background: #c33232;
  box-shadow: 0 0 0 1px #c33232;
}

.timeline-list > li.verification > i,
.timeline-list > li.recovery > i {
  background: #3f8f51;
  box-shadow: 0 0 0 1px #3f8f51;
}

.timeline-event {
  min-width: 0;
  padding: 0 0 16px;
}

.timeline-event header {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 5px;
}

.timeline-event header span {
  color: #a32929;
  font-size: 11px;
  font-weight: 700;
}

.timeline-event time {
  color: #8a94a3;
  font-size: 11px;
}

.timeline-event > strong {
  display: block;
  color: #303846;
  font-size: 14px;
}

.timeline-event p {
  margin: 4px 0 5px;
  color: #5e6878;
  font-size: 12px;
  line-height: 1.55;
}

.channel-connection,
.channel-state {
  display: inline-flex;
  align-items: center;
  gap: 7px;
}

.channel-connection i,
.channel-state i {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: #c33232;
}

.channel-connection.online i,
.channel-state.online i {
  background: #37984c;
}

.channel-shell {
  grid-template-rows: auto minmax(0, 1fr);
}

.channel-state {
  color: #8a3a32;
  font-size: 12px;
}

.channel-state.online {
  color: #2f7740;
}

.channel-workspace {
  min-height: 0;
  display: grid;
  grid-template-columns: minmax(0, 1.25fr) minmax(340px, .75fr);
  overflow: hidden;
}

.channel-pane {
  min-width: 0;
  min-height: 0;
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
  overflow: hidden;
}

.delivery-pane {
  border-right: 1px solid #e2e6ec;
}

.identity-pane {
  grid-template-rows: auto auto minmax(0, 1fr);
}

.channel-pane-title {
  min-height: 42px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 0 12px;
  border-bottom: 1px solid #edf0f4;
}

.channel-pane-title strong {
  color: #303846;
  font-size: 13px;
}

.channel-pane-title span {
  color: #8a94a3;
  font-size: 11px;
}

.delivery-table,
.identity-list {
  min-height: 0;
  overflow: auto;
  scrollbar-gutter: stable;
}

.delivery-row {
  min-width: 600px;
  min-height: 48px;
  display: grid;
  grid-template-columns: minmax(88px, 1fr) 68px 48px minmax(132px, 1.2fr) minmax(88px, .8fr) 42px;
  align-items: center;
  gap: 10px;
  padding: 6px 12px;
  border-bottom: 1px solid #edf0f4;
  color: #586273;
  font-size: 12px;
}

.delivery-row.head {
  min-height: 34px;
  position: sticky;
  top: 0;
  z-index: 1;
  background: #f7f8fa;
  color: #7a8494;
}

.delivery-row > * {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.delivery-row strong {
  color: #303846;
}

.delivery-status {
  width: fit-content;
  padding: 2px 6px;
  border: 1px solid #d9dee6;
  border-radius: 3px;
}

.delivery-status.sent {
  border-color: #b9d9c1;
  color: #2f7740;
}

.delivery-status.pending,
.delivery-status.sending {
  border-color: #efc988;
  color: #8a5b16;
}

.delivery-status.failed {
  border-color: #edb5b5;
  color: #a32929;
}

.channel-bind-form {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 8px;
  padding: 10px 12px;
  border-bottom: 1px solid #edf0f4;
}

.operator-field {
  grid-column: 1 / -1;
  min-width: 0;
}

.operator-field :deep(.arco-select),
.pending-identity-field :deep(.arco-select) {
  width: 100%;
}

.pending-identity-field {
  min-width: 0;
}

.identity-row {
  min-height: 58px;
  display: grid;
  grid-template-columns: minmax(118px, 1.1fr) minmax(100px, 1fr) 46px 42px;
  align-items: center;
  gap: 8px;
  padding: 7px 12px;
  border-bottom: 1px solid #edf0f4;
  color: #5e6878;
  font-size: 12px;
}

.identity-row > * {
  min-width: 0;
}

.identity-person {
  display: grid;
  gap: 2px;
}

.identity-person strong,
.identity-person small,
.identity-row code {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.identity-person strong {
  color: #303846;
}

.identity-person small {
  color: #8a94a3;
  font-size: 11px;
}

.identity-state {
  color: #8a3a32;
}

.identity-state.active {
  color: #2f7740;
}

.event-empty {
  min-height: 160px;
  display: grid;
  place-items: center;
  color: #8993a2;
}

:deep(.arco-pagination) {
  justify-content: flex-end;
  min-height: 42px;
  padding: 7px 10px;
  border-top: 1px solid #edf0f4;
}

@media (max-width: 1100px) {
  .event-summary > div {
    padding: 0 10px;
  }

  .channel-workspace {
    grid-template-columns: minmax(0, 1fr) 330px;
  }
}

@media (max-width: 900px) {
  .channel-workspace {
    grid-template-columns: 1fr;
    grid-template-rows: minmax(210px, 1fr) minmax(250px, 1fr);
  }

  .delivery-pane {
    border-right: 0;
    border-bottom: 1px solid #e2e6ec;
  }
}
</style>

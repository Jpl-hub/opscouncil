<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import {
  IconClose,
  IconDelete,
  IconEdit,
  IconHistory,
  IconPlus,
  IconRefresh,
  IconSearch,
} from '@arco-design/web-vue/es/icon'
import {
  createServiceExpectation,
  getServiceReconciliation,
  listServiceExpectationHistory,
  retireServiceExpectation,
} from '../api'
import type {
  ServiceExpectationRecord,
  ServiceReconciliationItem,
  ServiceReconciliationReport,
} from '../types'

const props = defineProps<{
  hostKey: string
}>()
const emit = defineEmits<{
  investigate: [prompt: string]
}>()

const activeHost = computed(() => (
  /^(?:\*|[A-Za-z0-9_.:-]+)$/.test(props.hostKey)
  && props.hostKey !== '-'
    ? props.hostKey
    : ''
))
const report = ref<ServiceReconciliationReport | null>(null)
const rows = computed(() => report.value?.items ?? [])
const records = computed(() => rows.value.map((item) => item.expectation))
const history = ref<ServiceExpectationRecord[]>([])
const loading = ref(false)
const saving = ref(false)
const error = ref('')
const editorOpen = ref(false)
const retireOpen = ref(false)
const historyOpen = ref(false)
const editingRecord = ref<ServiceExpectationRecord | null>(null)
const selectedRecord = ref<ServiceExpectationRecord | null>(null)
const form = ref(blankForm())
const retirement = ref({ reason: '', source_ref: '', approved_by: 'admin' })

const criticalCount = computed(() => records.value.filter((item) => item.criticality === 'CRITICAL').length)
const unmanagedListeners = computed(() => report.value?.unmanaged_listeners ?? [])
const formReady = computed(() => (
  form.value.host_key.trim().length > 0
  && form.value.unit_name.trim().endsWith('.service')
  && form.value.service_owner.trim().length > 0
  && form.value.rationale.trim().length >= 5
  && form.value.source_ref.trim().length > 0
  && form.value.approved_by.trim().length > 0
  && (
    form.value.expected_active_state === 'active'
    || form.value.listener_expectations.length === 0
  )
  && form.value.listener_expectations.every((item, index, rows) => (
    Number.isInteger(item.port)
    && item.port >= 1
    && item.port <= 65535
    && rows.findIndex((row) => (
      row.protocol === item.protocol && row.port === item.port
    )) === index
  ))
))
const retirementReady = computed(() => (
  retirement.value.reason.trim().length >= 5
  && retirement.value.source_ref.trim().length > 0
  && retirement.value.approved_by.trim().length > 0
))

watch(
  activeHost,
  (hostKey) => {
    if (hostKey) void refresh()
    else report.value = null
  },
  { immediate: true },
)

function blankForm() {
  return {
    host_key: activeHost.value,
    unit_name: '',
    expected_active_state: 'active' as 'active' | 'inactive',
    service_owner: '',
    criticality: 'HIGH' as ServiceExpectationRecord['criticality'],
    environment: 'PRODUCTION' as ServiceExpectationRecord['environment'],
    listener_expectations: [] as ServiceExpectationRecord['listener_expectations'],
    rationale: '',
    source_ref: '',
    approved_by: 'admin',
    expires_at: '',
  }
}

async function refresh() {
  if (!activeHost.value) return
  loading.value = true
  error.value = ''
  try {
    report.value = await getServiceReconciliation(activeHost.value)
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : '服务目录加载失败'
  } finally {
    loading.value = false
  }
}

function openCreate() {
  if (!activeHost.value) return
  editingRecord.value = null
  form.value = blankForm()
  editorOpen.value = true
}

function openEdit(record: ServiceExpectationRecord) {
  editingRecord.value = record
  form.value = {
    host_key: record.host_key,
    unit_name: record.unit_name,
    expected_active_state: record.expected_active_state,
    service_owner: record.service_owner,
    criticality: record.criticality,
    environment: record.environment,
    listener_expectations: record.listener_expectations.map((item) => ({ ...item })),
    rationale: record.rationale,
    source_ref: record.source_ref,
    approved_by: 'admin',
    expires_at: record.expires_at ? toLocalDateTime(record.expires_at) : '',
  }
  editorOpen.value = true
}

async function save() {
  if (!formReady.value || saving.value) return
  saving.value = true
  error.value = ''
  try {
    await createServiceExpectation({
      ...form.value,
      host_key: form.value.host_key.trim(),
      unit_name: form.value.unit_name.trim(),
      service_owner: form.value.service_owner.trim(),
      rationale: form.value.rationale.trim(),
      source_ref: form.value.source_ref.trim(),
      approved_by: form.value.approved_by.trim(),
      listener_expectations: (
        form.value.expected_active_state === 'active'
          ? form.value.listener_expectations
          : []
      ),
      expires_at: form.value.expires_at ? new Date(form.value.expires_at).toISOString() : null,
    })
    editorOpen.value = false
    await refresh()
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : '服务目录保存失败'
  } finally {
    saving.value = false
  }
}

function openRetire(record: ServiceExpectationRecord) {
  selectedRecord.value = record
  retirement.value = { reason: '', source_ref: '', approved_by: 'admin' }
  retireOpen.value = true
}

async function retire() {
  if (!selectedRecord.value || !retirementReady.value || saving.value) return
  saving.value = true
  error.value = ''
  try {
    await retireServiceExpectation({
      host_key: selectedRecord.value.host_key,
      unit_name: selectedRecord.value.unit_name,
      reason: retirement.value.reason.trim(),
      source_ref: retirement.value.source_ref.trim(),
      approved_by: retirement.value.approved_by.trim(),
    })
    retireOpen.value = false
    await refresh()
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : '服务目录停用失败'
  } finally {
    saving.value = false
  }
}

async function openHistory(record: ServiceExpectationRecord) {
  selectedRecord.value = record
  history.value = []
  historyOpen.value = true
  error.value = ''
  try {
    history.value = await listServiceExpectationHistory(record.host_key, record.unit_name)
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : '版本记录加载失败'
  }
}

function stateLabel(value: string) {
  return value === 'active' ? '应运行' : '应停止'
}

function actualStateLabel(value: string | null | undefined) {
  return {
    active: '运行中',
    inactive: '已停止',
    failed: '启动失败',
    activating: '启动中',
    deactivating: '停止中',
    reloading: '重载中',
  }[value || ''] || '状态未知'
}

function complianceLabel(value: ServiceReconciliationItem['compliance']) {
  return {
    IN_SYNC: '一致',
    DRIFT: '偏离',
    UNKNOWN: '待核验',
  }[value]
}

function investigate(item: ServiceReconciliationItem) {
  const record = item.expectation
  const actual = item.runtime?.active_state || 'unknown'
  const network = item.network_exposure
  const networkRequest = network.status === 'DRIFT'
    ? `同时核对网络开放偏离：${network.reason}`
    : '同时核对登记端口、监听进程归属和实际开放范围。'
  emit('investigate', [
    `调查 ${record.unit_name} 当前 ${actual} 与服务目录期望 ${record.expected_active_state} 是否一致，`,
    `${networkRequest}`,
    '基于 systemd、ss、进程归属和经批准服务目录给出证据化结论及安全处置建议。',
  ].join(''))
}

function investigateUnmanaged() {
  const targets = unmanagedListeners.value
    .slice(0, 8)
    .map((item) => `${item.protocol.toUpperCase()}/${item.port}(${item.process || '归属未知'})`)
    .join('、')
  emit(
    'investigate',
    `调查当前未纳入服务目录的监听端口：${targets}。核对进程、用户、systemd 单元、开放范围和业务必要性，不自动关闭端口。`,
  )
}

function addListenerExpectation() {
  if (form.value.expected_active_state !== 'active') return
  const used = new Set(
    form.value.listener_expectations.map((item) => `${item.protocol}:${item.port}`),
  )
  let port = 8080
  while (used.has(`tcp:${port}`) && port < 65535) port += 1
  form.value.listener_expectations.push({
    protocol: 'tcp',
    port,
    allowed_scope: 'private',
    required: true,
  })
}

function removeListenerExpectation(index: number) {
  form.value.listener_expectations.splice(index, 1)
}

function criticalityLabel(value: ServiceExpectationRecord['criticality']) {
  return { CRITICAL: '核心', HIGH: '重要', MEDIUM: '一般', LOW: '低' }[value]
}

function environmentLabel(value: ServiceExpectationRecord['environment']) {
  return { PRODUCTION: '生产', STAGING: '预发', TEST: '测试', DEVELOPMENT: '开发' }[value]
}

function exposureStatusLabel(item: ServiceReconciliationItem) {
  const count = item.network_exposure.checks.length
  return {
    IN_SYNC: `${count} 个端口一致`,
    DRIFT: '网络开放偏离',
    UNKNOWN: '监听归属待核',
    NOT_DECLARED: '未登记端口',
  }[item.network_exposure.status]
}

function toLocalDateTime(value: string) {
  const date = new Date(value)
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000)
  return local.toISOString().slice(0, 16)
}

function formatDateTime(value: string) {
  return new Intl.DateTimeFormat('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).format(new Date(value))
}
</script>

<template>
  <section class="service-catalog-workspace">
    <header class="catalog-toolbar">
      <div>
        <strong>服务目录</strong>
        <span>{{ activeHost || '等待主机信息' }}</span>
      </div>
      <div class="catalog-toolbar-meta">
        <span>{{ report?.summary.total_count ?? 0 }} 项</span>
        <span v-if="report?.summary.drift_count" class="catalog-drift-count">
          {{ report.summary.drift_count }} 项偏离
        </span>
        <span v-if="report?.summary.network_drift_count" class="catalog-drift-count">
          {{ report.summary.network_drift_count }} 项网络偏离
        </span>
        <span v-if="report?.summary.unmanaged_listener_count">
          {{ report.summary.unmanaged_listener_count }} 个监听未纳管
        </span>
        <span v-if="report?.summary.in_sync_count">
          {{ report.summary.in_sync_count }} 项一致
        </span>
        <span v-if="criticalCount">{{ criticalCount }} 项核心</span>
        <button class="icon-button" title="刷新服务目录" :disabled="loading" @click="refresh">
          <IconRefresh />
        </button>
        <button class="primary-button" :disabled="!activeHost" @click="openCreate">
          <IconPlus />
          登记服务
        </button>
      </div>
    </header>

    <div v-if="error" class="catalog-error">{{ error }}</div>

    <div class="catalog-table-wrap">
      <table v-if="records.length" class="catalog-table">
        <thead>
          <tr>
            <th>服务单元</th>
            <th>运行状态</th>
            <th>责任方</th>
            <th>级别 / 环境</th>
            <th>依据</th>
            <th aria-label="操作"></th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="item in rows"
            :key="item.expectation.id"
            :class="`catalog-row-${item.compliance.toLowerCase()}`"
          >
            <td>
              <strong :title="item.expectation.unit_name">{{ item.expectation.unit_name }}</strong>
              <small>
                {{ item.expectation.host_key === '*' ? '全部主机' : item.expectation.host_key }}
                · v{{ item.expectation.version }}
              </small>
            </td>
            <td>
              <span class="compliance-mark" :class="item.compliance.toLowerCase()" :title="item.reason">
                <i></i>{{ complianceLabel(item.compliance) }}
              </span>
              <small :title="item.reason">
                {{ actualStateLabel(item.runtime?.active_state) }}
                → {{ stateLabel(item.expectation.expected_active_state) }}
              </small>
              <span
                class="exposure-mark"
                :class="item.network_exposure.status.toLowerCase()"
                :title="item.network_exposure.reason"
              >
                {{ exposureStatusLabel(item) }}
              </span>
            </td>
            <td>
              <strong :title="item.expectation.service_owner">{{ item.expectation.service_owner }}</strong>
              <small :title="item.expectation.rationale">{{ item.expectation.rationale }}</small>
            </td>
            <td>
              <span>{{ criticalityLabel(item.expectation.criticality) }}</span>
              <small>{{ environmentLabel(item.expectation.environment) }}</small>
            </td>
            <td>
              <code :title="item.expectation.source_ref">{{ item.expectation.source_ref }}</code>
              <small>
                {{ item.expectation.approved_by }} · {{ formatDateTime(item.expectation.effective_from) }}
              </small>
            </td>
            <td>
              <div class="row-actions">
                <button
                  v-if="item.compliance === 'DRIFT'"
                  class="investigate"
                  title="调查运行偏离"
                  @click="investigate(item)"
                ><IconSearch /></button>
                <button title="追加新版本" @click="openEdit(item.expectation)"><IconEdit /></button>
                <button title="查看版本记录" @click="openHistory(item.expectation)"><IconHistory /></button>
                <button
                  class="danger"
                  title="停用目录记录"
                  @click="openRetire(item.expectation)"
                ><IconDelete /></button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
      <div v-else class="catalog-empty">
        <strong>{{ loading ? '正在读取服务目录' : '此主机尚未登记服务' }}</strong>
        <button v-if="!loading" @click="openCreate">登记第一项服务</button>
      </div>
    </div>

    <div v-if="unmanagedListeners.length" class="unmanaged-listener-strip">
      <strong>未纳管监听 {{ unmanagedListeners.length }}</strong>
      <span :title="unmanagedListeners.map((item) => item.local_address).join('、')">
        {{
          unmanagedListeners
            .slice(0, 4)
            .map((item) => `${item.protocol.toUpperCase()}/${item.port} · ${item.process || '归属未知'}`)
            .join('　')
        }}
      </span>
      <button title="调查未纳管监听" @click="investigateUnmanaged">
        <IconSearch />
        调查
      </button>
    </div>

    <div v-if="editorOpen" class="catalog-modal-mask" @click.self="editorOpen = false">
      <section class="catalog-modal" role="dialog" aria-modal="true" aria-label="登记服务">
        <header>
          <strong>{{ editingRecord ? '追加服务版本' : '登记服务' }}</strong>
          <button class="icon-button" title="关闭" @click="editorOpen = false"><IconClose /></button>
        </header>
        <form class="catalog-form" @submit.prevent="save">
          <label>
            <span>主机</span>
            <input v-model="form.host_key" :disabled="Boolean(editingRecord)" maxlength="256" />
          </label>
          <label>
            <span>systemd 单元</span>
            <input v-model="form.unit_name" :disabled="Boolean(editingRecord)" placeholder="checkout-api.service" maxlength="256" />
          </label>
          <label>
            <span>期望状态</span>
            <select v-model="form.expected_active_state">
              <option value="active">应运行</option>
              <option value="inactive">应停止</option>
            </select>
          </label>
          <label>
            <span>责任方</span>
            <input v-model="form.service_owner" placeholder="平台运维组" maxlength="256" />
          </label>
          <label>
            <span>重要级别</span>
            <select v-model="form.criticality">
              <option value="CRITICAL">核心</option>
              <option value="HIGH">重要</option>
              <option value="MEDIUM">一般</option>
              <option value="LOW">低</option>
            </select>
          </label>
          <label>
            <span>环境</span>
            <select v-model="form.environment">
              <option value="PRODUCTION">生产</option>
              <option value="STAGING">预发</option>
              <option value="TEST">测试</option>
              <option value="DEVELOPMENT">开发</option>
            </select>
          </label>
          <label>
            <span>批准人</span>
            <input v-model="form.approved_by" maxlength="128" />
          </label>
          <label>
            <span>有效期至</span>
            <input v-model="form.expires_at" type="datetime-local" />
          </label>
          <label class="full-row">
            <span>依据编号或链接</span>
            <input v-model="form.source_ref" placeholder="CMDB-SVC-1042 / 变更单链接" maxlength="1000" />
          </label>
          <section class="listener-editor full-row">
            <header>
              <span>网络开放</span>
              <button
                type="button"
                :disabled="form.expected_active_state !== 'active' || form.listener_expectations.length >= 20"
                @click="addListenerExpectation"
              >
                <IconPlus />
                登记端口
              </button>
            </header>
            <div
              v-for="(listener, index) in form.listener_expectations"
              :key="`${listener.protocol}-${index}`"
              class="listener-editor-row"
            >
              <select v-model="listener.protocol" aria-label="协议">
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
              </select>
              <input v-model.number="listener.port" type="number" min="1" max="65535" aria-label="端口" />
              <select v-model="listener.allowed_scope" aria-label="最大开放范围">
                <option value="loopback">仅本机</option>
                <option value="link_local">链路本地</option>
                <option value="private">内网</option>
                <option value="public">公网地址</option>
                <option value="wildcard">任意地址</option>
              </select>
              <label class="listener-required">
                <input v-model="listener.required" type="checkbox" />
                <span>必须监听</span>
              </label>
              <button type="button" title="移除此端口" @click="removeListenerExpectation(index)">
                <IconDelete />
              </button>
            </div>
            <div v-if="!form.listener_expectations.length" class="listener-editor-empty">
              {{ form.expected_active_state === 'active' ? '未登记网络端口' : '停止状态不保留监听要求' }}
            </div>
          </section>
          <label class="full-row">
            <span>登记原因</span>
            <textarea v-model="form.rationale" rows="3" maxlength="2000"></textarea>
          </label>
        </form>
        <footer>
          <button @click="editorOpen = false">取消</button>
          <button class="primary-button" :disabled="!formReady || saving" @click="save">
            {{ saving ? '保存中' : '保存并生成新版本' }}
          </button>
        </footer>
      </section>
    </div>

    <div v-if="retireOpen && selectedRecord" class="catalog-modal-mask" @click.self="retireOpen = false">
      <section class="catalog-modal compact" role="dialog" aria-modal="true" aria-label="停用服务记录">
        <header>
          <strong>停用 {{ selectedRecord.unit_name }}</strong>
          <button class="icon-button" title="关闭" @click="retireOpen = false"><IconClose /></button>
        </header>
        <form class="catalog-form single" @submit.prevent="retire">
          <label>
            <span>停用原因</span>
            <textarea v-model="retirement.reason" rows="3" maxlength="2000"></textarea>
          </label>
          <label>
            <span>依据编号或链接</span>
            <input v-model="retirement.source_ref" maxlength="1000" />
          </label>
          <label>
            <span>批准人</span>
            <input v-model="retirement.approved_by" maxlength="128" />
          </label>
        </form>
        <footer>
          <button @click="retireOpen = false">取消</button>
          <button class="danger-button" :disabled="!retirementReady || saving" @click="retire">确认停用</button>
        </footer>
      </section>
    </div>

    <div v-if="historyOpen && selectedRecord" class="catalog-modal-mask" @click.self="historyOpen = false">
      <section class="catalog-modal history" role="dialog" aria-modal="true" aria-label="服务版本记录">
        <header>
          <div>
            <strong>{{ selectedRecord.unit_name }}</strong>
            <span>{{ selectedRecord.host_key }}</span>
          </div>
          <button class="icon-button" title="关闭" @click="historyOpen = false"><IconClose /></button>
        </header>
        <div class="history-list">
          <article v-for="item in history" :key="item.id">
            <code>v{{ item.version }}</code>
            <div>
              <strong>{{ item.record_status === 'ACTIVE' ? stateLabel(item.expected_active_state) : '已停用' }}</strong>
              <span>
                {{ item.service_owner }} · {{ item.source_ref }}
                · {{ item.listener_expectations.length }} 个登记端口
              </span>
            </div>
            <small>{{ item.approved_by }} · {{ formatDateTime(item.created_at) }}</small>
          </article>
          <div v-if="!history.length" class="catalog-empty">正在读取版本记录</div>
        </div>
      </section>
    </div>
  </section>
</template>

<style scoped>
.service-catalog-workspace {
  grid-column: 1;
  grid-row: 1 / -1;
  min-width: 0;
  min-height: 0;
  display: grid;
  grid-template-rows: auto auto minmax(0, 1fr) auto;
  gap: 8px;
  color: #dceafa;
}

.catalog-toolbar {
  min-width: 0;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 8px 12px;
  border-bottom: 1px solid rgba(72, 161, 216, 0.24);
  background: rgba(6, 18, 31, 0.66);
}

.catalog-toolbar > div,
.catalog-toolbar-meta {
  min-width: 0;
  display: flex;
  align-items: center;
  gap: 10px;
}

.catalog-toolbar strong {
  color: #f1f7ff;
  font-size: 16px;
}

.catalog-toolbar span {
  overflow: hidden;
  color: #90a7c0;
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.catalog-toolbar .catalog-drift-count {
  color: #ff999f;
}

button {
  height: 30px;
  padding: 0 12px;
  border: 1px solid rgba(116, 151, 185, 0.36);
  border-radius: 5px;
  background: rgba(14, 31, 48, 0.9);
  color: #cbd9e8;
  font-size: 12px;
  cursor: pointer;
}

button:hover:not(:disabled) {
  border-color: rgba(125, 211, 252, 0.56);
  color: #fff;
}

button:disabled {
  cursor: not-allowed;
  opacity: 0.5;
}

.icon-button {
  width: 30px;
  padding: 0;
  display: inline-grid;
  place-items: center;
}

.primary-button,
.danger-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  border-color: #2563eb;
  background: #2563eb;
  color: #fff;
}

.danger-button {
  border-color: #b9363e;
  background: #a92f36;
}

.catalog-error {
  grid-row: 2;
  padding: 7px 12px;
  border: 1px solid rgba(248, 113, 113, 0.34);
  background: rgba(127, 29, 29, 0.28);
  color: #ffb4b8;
  font-size: 12px;
}

.catalog-table-wrap {
  grid-row: 3;
  min-width: 0;
  min-height: 0;
  overflow: auto;
  border: 1px solid rgba(72, 161, 216, 0.22);
  background: rgba(6, 18, 31, 0.72);
}

.catalog-table {
  width: 100%;
  border-collapse: collapse;
  table-layout: fixed;
}

.catalog-table th,
.catalog-table td {
  min-width: 0;
  padding: 10px 12px;
  border-bottom: 1px solid rgba(91, 128, 160, 0.18);
  text-align: left;
  vertical-align: middle;
}

.catalog-table th {
  position: sticky;
  top: 0;
  z-index: 1;
  background: #0b1a29;
  color: #8198b1;
  font-size: 11px;
  font-weight: 600;
}

.catalog-table th:nth-child(1) { width: 22%; }
.catalog-table th:nth-child(2) { width: 15%; }
.catalog-table th:nth-child(3) { width: 19%; }
.catalog-table th:nth-child(4) { width: 11%; }
.catalog-table th:nth-child(5) { width: 19%; }
.catalog-table th:nth-child(6) { width: 14%; }

.catalog-table td > strong,
.catalog-table td > small,
.catalog-table td > code,
.catalog-table td > span {
  min-width: 0;
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.catalog-table td > strong {
  color: #eaf4ff;
  font-size: 12px;
}

.catalog-table td > small {
  margin-top: 4px;
  color: #7f96ad;
  font-size: 10px;
}

.exposure-mark {
  margin-top: 5px;
  color: #8299b1;
  font-size: 10px;
}

.exposure-mark.in_sync {
  color: #86c99b;
}

.exposure-mark.drift {
  color: #ff989d;
}

.exposure-mark.unknown {
  color: #e8bf72;
}

.catalog-table td > code {
  color: #9bc8e8;
  font-family: 'Times New Roman', monospace;
  font-size: 11px;
}

.compliance-mark {
  display: inline-flex !important;
  align-items: center;
  gap: 6px;
  color: #b8c8d9;
  font-size: 12px;
}

.compliance-mark i {
  width: 7px;
  height: 7px;
  flex: 0 0 auto;
  border-radius: 50%;
  background: #60a5fa;
}

.compliance-mark.in_sync {
  color: #9ed7ae;
}

.compliance-mark.in_sync i {
  background: #42b463;
}

.compliance-mark.drift {
  color: #ffaaa7;
}

.compliance-mark.drift i {
  background: #ef5552;
}

.compliance-mark.unknown i {
  background: #94a3b8;
}

.row-actions {
  display: flex;
  justify-content: flex-end;
  gap: 5px;
}

.row-actions button {
  width: 25px;
  height: 25px;
  padding: 0;
  display: inline-grid;
  place-items: center;
  font-size: 13px;
}

.row-actions .investigate {
  border-color: rgba(248, 113, 113, 0.5);
  color: #ffb0b4;
}

.row-actions .danger {
  color: #ff9ea4;
}

.catalog-empty {
  min-height: 220px;
  display: grid;
  place-content: center;
  justify-items: center;
  gap: 12px;
  color: #8fa4bd;
  font-size: 13px;
}

.unmanaged-listener-strip {
  grid-row: 4;
  min-width: 0;
  min-height: 38px;
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  align-items: center;
  gap: 12px;
  padding: 4px 10px 4px 12px;
  border: 1px solid rgba(232, 191, 114, 0.28);
  background: rgba(83, 59, 22, 0.24);
}

.unmanaged-listener-strip strong {
  color: #f0cf91;
  font-size: 12px;
}

.unmanaged-listener-strip span {
  min-width: 0;
  overflow: hidden;
  color: #9eb0c2;
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.unmanaged-listener-strip button,
.listener-editor header button {
  display: inline-flex;
  align-items: center;
  gap: 5px;
}

.catalog-modal-mask {
  position: fixed;
  inset: 0;
  z-index: 80;
  display: grid;
  place-items: center;
  padding: 24px;
  background: rgba(2, 8, 15, 0.72);
}

.catalog-modal {
  width: min(760px, 94vw);
  max-height: calc(100vh - 48px);
  display: grid;
  grid-template-rows: auto minmax(0, 1fr) auto;
  overflow: hidden;
  border: 1px solid #2f506d;
  border-radius: 6px;
  background: #0d1a27;
  box-shadow: 0 18px 60px rgba(0, 0, 0, 0.45);
}

.catalog-modal.compact {
  width: min(520px, 94vw);
}

.catalog-modal > header,
.catalog-modal > footer {
  min-width: 0;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 12px 16px;
  border-bottom: 1px solid rgba(91, 128, 160, 0.24);
}

.catalog-modal > header > div {
  min-width: 0;
  display: grid;
  gap: 2px;
}

.catalog-modal > header span {
  color: #8299b1;
  font-size: 11px;
}

.catalog-modal > footer {
  justify-content: flex-end;
  border-top: 1px solid rgba(91, 128, 160, 0.24);
  border-bottom: 0;
}

.catalog-form {
  min-height: 0;
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px 16px;
  padding: 16px;
  overflow: auto;
}

.catalog-form.single {
  grid-template-columns: minmax(0, 1fr);
}

.catalog-form label {
  min-width: 0;
  display: grid;
  gap: 6px;
}

.catalog-form label.full-row {
  grid-column: 1 / -1;
}

.catalog-form .listener-editor {
  min-width: 0;
  grid-column: 1 / -1;
  display: grid;
  gap: 7px;
}

.listener-editor > header {
  min-width: 0;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.listener-editor > header > span {
  color: #9bb0c6;
  font-size: 11px;
}

.listener-editor-row {
  min-width: 0;
  display: grid;
  grid-template-columns: 82px 110px minmax(130px, 1fr) 94px 34px;
  align-items: center;
  gap: 7px;
}

.catalog-form .listener-editor-row .listener-required {
  display: flex;
  align-items: center;
  gap: 6px;
  color: #aab9c8;
  font-size: 11px;
  white-space: nowrap;
}

.catalog-form .listener-editor-row .listener-required input {
  width: 14px;
  height: 14px;
  margin: 0;
}

.listener-editor-row > button {
  width: 34px;
  padding: 0;
  display: inline-grid;
  place-items: center;
  color: #ff9ea4;
}

.listener-editor-empty {
  height: 34px;
  display: flex;
  align-items: center;
  padding: 0 9px;
  border: 1px dashed rgba(91, 128, 160, 0.32);
  color: #7890a8;
  font-size: 11px;
}

.catalog-form label > span {
  color: #9bb0c6;
  font-size: 11px;
}

.catalog-form input,
.catalog-form select,
.catalog-form textarea {
  width: 100%;
  min-width: 0;
  box-sizing: border-box;
  border: 1px solid #314a61;
  border-radius: 5px;
  outline: 0;
  background: #08131f;
  color: #e5f0fb;
  font: inherit;
  font-size: 12px;
}

.catalog-form input,
.catalog-form select {
  height: 34px;
  padding: 0 9px;
}

.catalog-form textarea {
  min-height: 74px;
  padding: 9px;
  resize: vertical;
}

.catalog-form input:focus,
.catalog-form select:focus,
.catalog-form textarea:focus {
  border-color: #3b82f6;
}

.catalog-form input:disabled {
  color: #8398ad;
  background: #101c28;
}

.history-list {
  min-height: 160px;
  max-height: min(460px, 70vh);
  overflow: auto;
}

.history-list article {
  min-width: 0;
  display: grid;
  grid-template-columns: 54px minmax(0, 1fr) auto;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  border-bottom: 1px solid rgba(91, 128, 160, 0.18);
}

.history-list article > div {
  min-width: 0;
  display: grid;
  gap: 3px;
}

.history-list code,
.history-list strong,
.history-list span,
.history-list small {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.history-list code {
  color: #8ccdf2;
}

.history-list span,
.history-list small {
  color: #8097ae;
  font-size: 11px;
}

@media (max-width: 900px) {
  .catalog-table {
    min-width: 900px;
  }

  .catalog-form {
    grid-template-columns: minmax(0, 1fr);
  }

  .catalog-form label.full-row {
    grid-column: auto;
  }

  .catalog-form .listener-editor {
    grid-column: auto;
  }

  .listener-editor-row {
    grid-template-columns: 72px 96px minmax(120px, 1fr) 88px 34px;
  }
}
</style>

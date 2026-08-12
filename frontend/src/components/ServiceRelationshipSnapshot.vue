<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { GraphChart } from 'echarts/charts'
import { TooltipComponent } from 'echarts/components'
import { init, use, type EChartsCoreOption } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'

use([GraphChart, TooltipComponent, CanvasRenderer])

type RelationshipNode = {
  id: string
  kind?: string
  label?: string
  pid?: number
  port?: number
  address?: string
  protocol?: string
  user?: string
  unit?: string
  systemd_unit?: string
  exposure_scope?: string
  scope?: string
  active_state?: string
  sub_state?: string
}

type RelationshipEdge = {
  source: string
  target: string
  relation: string
  observation_count?: number
  sample_count?: number
  evidence_ref?: string
}

type EvidenceGap = {
  code?: string
  count?: number
  reason?: string
}

type ChangeImpact = {
  status?: string
  action?: string
  coverage?: string
  propagated_unit_count?: number
  possible_client_count?: number
  predicted_units?: Array<{
    unit?: string
    role?: string
    certainty?: string
    mechanism?: string
  }>
}

const props = defineProps<{
  snapshot: Record<string, unknown>
}>()

const emit = defineEmits<{
  requestImpact: [unit: string]
  requestInvestigation: [request: string]
}>()

const chartHost = ref<HTMLDivElement | null>(null)
const viewMode = ref<'graph' | 'table'>('graph')
const selectedNodeId = ref('')
let chart: ReturnType<typeof init> | null = null
let resizeObserver: ResizeObserver | null = null

const nodes = computed<RelationshipNode[]>(() => (
  Array.isArray(props.snapshot.nodes)
    ? props.snapshot.nodes.filter((item): item is RelationshipNode => Boolean(item && typeof item === 'object' && 'id' in item))
    : []
))
const edges = computed<RelationshipEdge[]>(() => (
  Array.isArray(props.snapshot.edges)
    ? props.snapshot.edges.filter((item): item is RelationshipEdge => Boolean(item && typeof item === 'object' && 'source' in item && 'target' in item))
    : []
))
const evidenceGaps = computed<EvidenceGap[]>(() => (
  Array.isArray(props.snapshot.evidence_gaps)
    ? props.snapshot.evidence_gaps.filter((item): item is EvidenceGap => Boolean(item && typeof item === 'object'))
    : []
))
const changeImpact = computed<ChangeImpact | null>(() => {
  const value = props.snapshot.change_impact
  return value && typeof value === 'object' ? value as ChangeImpact : null
})
const nodeById = computed(() => new Map(nodes.value.map((node) => [node.id, node])))
const nodeLabels = computed(() => new Map(
  nodes.value.map((node) => [
    node.id,
    node.kind === 'process' && typeof node.pid === 'number'
      ? `${node.label || node.id} · PID ${node.pid}`
      : node.label || node.id,
  ]),
))
const focusPorts = computed(() => (
  Array.isArray(props.snapshot.focus_ports)
    ? props.snapshot.focus_ports.filter((port): port is number => typeof port === 'number')
    : []
))
const focusProcessIds = computed(() => (
  Array.isArray(props.snapshot.focus_process_ids)
    ? props.snapshot.focus_process_ids.filter((pid): pid is number => typeof pid === 'number')
    : []
))
const selectedNode = computed(() => nodeById.value.get(selectedNodeId.value) || null)
const selectedRelations = computed(() => (
  edges.value.filter((edge) => edge.source === selectedNodeId.value || edge.target === selectedNodeId.value)
))
const selectedUnit = computed(() => {
  const node = selectedNode.value
  if (!node) return ''
  if (node.kind === 'service') return node.unit || node.label || ''
  return node.systemd_unit || ''
})
const investigationRequest = computed(() => {
  const node = selectedNode.value
  if (!node) return ''
  if (node.kind === 'process' && typeof node.pid === 'number') {
    return (
      `继续核查 PID ${node.pid}（${node.label || '目标进程'}）的运行状态、资源占用和文件句柄，`
      + '只采集证据，不执行系统变更。'
    )
  }
  if (node.kind === 'listener' && typeof node.port === 'number') {
    const protocol = String(node.protocol || 'tcp').toUpperCase()
    return (
      `检查 ${protocol} 端口 ${node.port} 的监听进程、暴露范围和当前连接，`
      + '只采集证据，不执行系统变更。'
    )
  }
  if (node.kind === 'service' && selectedUnit.value) {
    return (
      `继续核查 ${selectedUnit.value} 的当前状态、近期日志和运行依赖，`
      + '只采集证据，不执行系统变更。'
    )
  }
  return ''
})
const snapshotCount = computed(() => (
  typeof props.snapshot.snapshot_count === 'number'
    ? Math.max(1, props.snapshot.snapshot_count)
    : 1
))
const captureWindowText = computed(() => {
  const first = formatCaptureTime(props.snapshot.captured_at_first)
  const last = formatCaptureTime(props.snapshot.captured_at)
  if (!first && !last) return '当次观测'
  if (!first || first === last) return last || first
  return `${first}—${last}`
})

function formatCaptureTime(value: unknown): string {
  if (typeof value !== 'string') return ''
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return ''
  return new Intl.DateTimeFormat('zh-CN', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date)
}
const metrics = computed(() => [
  { label: '进程', value: numberValue('process_count') },
  { label: '监听', value: numberValue('listener_count') },
  { label: '调用', value: numberValue('connection_relation_count') },
  { label: '关系', value: numberValue('edge_count') },
])
const coverageLabel = computed(() => (
  evidenceGaps.value.length ? `${evidenceGaps.value.length} 项证据缺口` : '关系归属完整'
))

onMounted(() => {
  resizeObserver = new ResizeObserver(() => chart?.resize())
  if (chartHost.value) resizeObserver.observe(chartHost.value)
  renderGraph()
})

onUnmounted(() => {
  resizeObserver?.disconnect()
  chart?.dispose()
  chart = null
})

watch(
  [nodes, edges, viewMode],
  () => {
    ensureSelection()
    if (viewMode.value === 'graph') void nextTick(renderGraph)
  },
  { deep: true, immediate: true },
)

function ensureSelection() {
  if (selectedNodeId.value && nodeById.value.has(selectedNodeId.value)) return
  const focusPid = focusProcessIds.value[0]
  const focusNode = typeof focusPid === 'number'
    ? nodes.value.find((node) => node.id === `process:${focusPid}`)
    : null
  selectedNodeId.value = focusNode?.id || nodes.value[0]?.id || ''
}

function renderGraph() {
  if (!chartHost.value || viewMode.value !== 'graph') return
  if (!chart) {
    chart = init(chartHost.value, undefined, { renderer: 'canvas' })
    chart.on('click', (params) => {
      const data = params.data
      const nodeId = data && typeof data === 'object' && 'id' in data
        ? String(data.id || '')
        : ''
      if (params.dataType === 'node' && nodeId) {
        selectedNodeId.value = nodeId
        renderGraph()
      }
    })
  }

  const option: EChartsCoreOption = {
    animationDurationUpdate: 260,
    tooltip: {
      confine: true,
      formatter: (params: unknown) => graphTooltip(params),
    },
    series: [
      {
        type: 'graph',
        layout: 'force',
        roam: true,
        draggable: true,
        data: nodes.value.map((node) => ({
          id: node.id,
          name: graphNodeLabel(node),
          symbolSize: nodeSize(node),
          itemStyle: {
            color: nodeColor(node),
            borderColor: node.id === selectedNodeId.value ? '#bf2f32' : '#ffffff',
            borderWidth: node.id === selectedNodeId.value ? 3 : 1.5,
            shadowBlur: node.id === selectedNodeId.value ? 8 : 0,
            shadowColor: 'rgba(191, 47, 50, 0.2)',
          },
          label: {
            show: true,
            position: 'bottom',
            distance: 6,
            color: '#3c4655',
            fontSize: 11,
          },
          value: node.id,
        })),
        links: edges.value.map((edge) => ({
          source: edge.source,
          target: edge.target,
          value: edge.relation,
          lineStyle: {
            color: edgeColor(edge.relation),
            width: (
              (edge.relation === 'CONNECTS_TO' ? 2.4 : 1.4)
              + Math.min(1.2, Math.max(0, (edge.sample_count || 1) - 1) * 0.35)
            ),
            type: ['BEFORE', 'AFTER', 'WANTS'].includes(edge.relation) ? 'dashed' : 'solid',
            opacity: edge.source === selectedNodeId.value || edge.target === selectedNodeId.value ? 0.95 : 0.5,
            curveness: 0.08,
          },
        })),
        force: {
          repulsion: 260,
          edgeLength: [90, 150],
          gravity: 0.08,
        },
        emphasis: {
          focus: 'adjacency',
          lineStyle: { width: 3, opacity: 1 },
        },
        edgeSymbol: ['none', 'arrow'],
        edgeSymbolSize: 7,
      },
    ],
  }
  chart.setOption(option, true)
}

function graphTooltip(value: unknown): string {
  if (!value || typeof value !== 'object') return ''
  const params = value as {
    dataType?: string
    data?: { id?: string; source?: string; target?: string; value?: string }
  }
  if (params.dataType === 'edge' && params.data) {
    return `${nodeLabel(params.data.source || '')}<br>${relationLabel(params.data.value || '')}<br>${nodeLabel(params.data.target || '')}`
  }
  const node = params.data?.id ? nodeById.value.get(params.data.id) : null
  if (!node) return ''
  return `${kindLabel(node.kind)} · ${nodeLabel(node.id)}`
}

function graphNodeLabel(node: RelationshipNode): string {
  const raw = node.label || node.id
  if (node.kind === 'listener' && typeof node.port === 'number') return `:${node.port}`
  return raw.length > 18 ? `${raw.slice(0, 16)}…` : raw
}

function nodeSize(node: RelationshipNode): number {
  if (node.kind === 'service') return 56
  if (node.kind === 'process') return 48
  if (node.kind === 'listener') return 34
  return 32
}

function nodeColor(node: RelationshipNode): string {
  if (node.kind === 'service') return '#313a48'
  if (node.kind === 'process') return '#bf3437'
  if (node.kind === 'listener') return '#438b5a'
  if (node.kind === 'remote_endpoint') return node.scope === 'external' ? '#c37b1d' : '#68788d'
  return '#768293'
}

function edgeColor(relation: string): string {
  if (relation === 'CONNECTS_TO') return '#b52f32'
  if (['PART_OF', 'PROPAGATES_STOP_TO', 'BINDS_TO', 'REQUIRES'].includes(relation)) return '#b47724'
  if (relation === 'LISTENS_ON') return '#4f8b61'
  return '#77859a'
}

function numberValue(key: string): number {
  const value = props.snapshot[key]
  return typeof value === 'number' && Number.isFinite(value) ? value : 0
}

function nodeLabel(id: string): string {
  return nodeLabels.value.get(id) || id
}

function kindLabel(kind?: string): string {
  return {
    service: '服务单元',
    process: '进程',
    listener: '监听端口',
    remote_endpoint: '远端端点',
  }[kind || ''] || '运行对象'
}

function relationLabel(relation: string): string {
  return {
    RUNS_PROCESS: '运行进程',
    LISTENS_ON: '监听',
    CONNECTS_TO: '调用',
    REQUIRES: '强依赖',
    WANTS: '弱依赖',
    BINDS_TO: '绑定',
    PART_OF: '随目标启停',
    PROPAGATES_STOP_TO: '停止传播',
    PROPAGATES_RELOAD_TO: '重载传播',
    TRIGGERS: '触发',
    BEFORE: '先于',
    AFTER: '后于',
  }[relation] || relation
}

function observationLabel(edge: RelationshipEdge): string {
  const count = typeof edge.observation_count === 'number' ? edge.observation_count : 1
  const samples = typeof edge.sample_count === 'number' ? edge.sample_count : 1
  const sampleLabel = samples > 1 ? `${samples} 次取证` : ''
  if (edge.relation === 'CONNECTS_TO') {
    return [sampleLabel, `${count} 条连接`].filter(Boolean).join(' / ')
  }
  const source = ['RUNS_PROCESS', 'LISTENS_ON'].includes(edge.relation) ? '实时观测' : 'systemd'
  return [sampleLabel, source].filter(Boolean).join(' / ')
}

function relationPeer(edge: RelationshipEdge): string {
  const peer = edge.source === selectedNodeId.value ? edge.target : edge.source
  return nodeLabel(peer)
}

function relationDirection(edge: RelationshipEdge): string {
  return edge.source === selectedNodeId.value ? '指向' : '来自'
}

function nodeDetail(node: RelationshipNode): Array<{ label: string; value: string }> {
  const rows = [
    { label: '类型', value: kindLabel(node.kind) },
    { label: '进程号', value: typeof node.pid === 'number' ? String(node.pid) : '' },
    { label: '运行用户', value: node.user || '' },
    { label: '服务归属', value: node.unit || node.systemd_unit || '' },
    { label: '监听地址', value: node.address || '' },
    { label: '暴露范围', value: node.exposure_scope || node.scope || '' },
    { label: '运行状态', value: [node.active_state, node.sub_state].filter(Boolean).join(' / ') },
  ]
  return rows.filter((row) => row.value)
}

function impactStatusLabel(): string {
  const status = changeImpact.value?.status
  if (status === 'ASSESSED') return '证据完整'
  if (status === 'PARTIAL') return '部分证据'
  if (status === 'UNKNOWN') return '无法确认'
  return '仅观测'
}

function impactUnitLabel(): string {
  const units = changeImpact.value?.predicted_units
    ?.filter((item) => item.role !== 'TARGET' && item.unit)
    .map((item) => item.unit as string) || []
  if (!units.length) return '未发现传播单元'
  return units.slice(0, 3).join('、') + (units.length > 3 ? ` 等 ${units.length} 个` : '')
}
</script>

<template>
  <section class="relationship-snapshot">
    <header class="relationship-head">
      <div class="relationship-title">
        <span>运行关系</span>
        <strong>{{ coverageLabel }}</strong>
        <small>
          {{ captureWindowText }} · {{ snapshotCount }} 次取证
          <template v-if="focusPorts.length"> · 端口 {{ focusPorts.join('、') }}</template>
        </small>
      </div>
      <dl class="relationship-metrics">
        <div v-for="metric in metrics" :key="metric.label">
          <dt>{{ metric.label }}</dt>
          <dd>{{ metric.value }}</dd>
        </div>
      </dl>
      <div class="relationship-switch" aria-label="关系视图">
        <button :class="{ active: viewMode === 'graph' }" @click="viewMode = 'graph'">关系图</button>
        <button :class="{ active: viewMode === 'table' }" @click="viewMode = 'table'">清单</button>
      </div>
    </header>

    <div
      v-if="changeImpact && changeImpact.action && changeImpact.action !== 'observe'"
      class="relationship-impact"
      :class="changeImpact.status?.toLowerCase()"
    >
      <strong>{{ changeImpact.action === 'restart' ? '重启影响预演' : '变更影响预演' }}</strong>
      <span>{{ impactStatusLabel() }}</span>
      <span>传播 {{ changeImpact.propagated_unit_count || 0 }}</span>
      <span>连接方 {{ changeImpact.possible_client_count || 0 }}</span>
      <em :title="impactUnitLabel()">{{ impactUnitLabel() }}</em>
    </div>

    <div v-show="viewMode === 'graph'" class="relationship-graph-workspace">
      <div ref="chartHost" class="relationship-chart" aria-label="实际运行关系图"></div>
      <aside class="relationship-inspector">
        <template v-if="selectedNode">
          <span>{{ kindLabel(selectedNode.kind) }}</span>
          <strong :title="nodeLabel(selectedNode.id)">{{ nodeLabel(selectedNode.id) }}</strong>
          <dl>
            <div v-for="row in nodeDetail(selectedNode)" :key="row.label">
              <dt>{{ row.label }}</dt>
              <dd :title="row.value">{{ row.value }}</dd>
            </div>
          </dl>
          <div class="selected-relations">
            <span>直接关系 {{ selectedRelations.length }}</span>
            <button
              v-for="edge in selectedRelations.slice(0, 5)"
              :key="`${edge.source}-${edge.relation}-${edge.target}`"
              @click="selectedNodeId = edge.source === selectedNodeId ? edge.target : edge.source; renderGraph()"
            >
              <small>{{ relationDirection(edge) }} · {{ relationLabel(edge.relation) }}</small>
              <strong :title="relationPeer(edge)">{{ relationPeer(edge) }}</strong>
            </button>
          </div>
          <div
            v-if="investigationRequest || selectedUnit"
            class="relationship-actions"
          >
            <button
              v-if="investigationRequest"
              @click="emit('requestInvestigation', investigationRequest)"
            >
              继续核查
            </button>
            <button
              v-if="selectedUnit"
              class="impact-request"
              @click="emit('requestImpact', selectedUnit)"
            >
              预演重启影响
            </button>
          </div>
        </template>
        <span v-else>当前范围没有可归属节点</span>
      </aside>
    </div>

    <div v-if="viewMode === 'table'" class="relationship-table">
      <div class="relationship-row heading">
        <span>来源</span>
        <span>关系</span>
        <span>目标</span>
        <span>依据</span>
      </div>
      <button
        v-for="edge in edges"
        :key="`${edge.source}-${edge.relation}-${edge.target}`"
        class="relationship-row"
        @click="selectedNodeId = edge.source; viewMode = 'graph'"
      >
        <strong :title="nodeLabel(edge.source)">{{ nodeLabel(edge.source) }}</strong>
        <span>{{ relationLabel(edge.relation) }}</span>
        <strong :title="nodeLabel(edge.target)">{{ nodeLabel(edge.target) }}</strong>
        <code :title="edge.evidence_ref">{{ observationLabel(edge) }}</code>
      </button>
      <div v-if="!edges.length" class="relationship-empty">当前范围未观测到可归属连接</div>
    </div>

    <footer v-if="evidenceGaps.length" class="relationship-gaps">
      <strong>证据缺口</strong>
      <span>{{ evidenceGaps.map((gap) => gap.reason || gap.code).filter(Boolean).join('；') }}</span>
    </footer>
  </section>
</template>

<style scoped>
.relationship-snapshot {
  height: 100%;
  min-height: 0;
  display: grid;
  grid-template-rows: auto auto minmax(0, 1fr) auto;
  overflow: hidden;
  border: 1px solid #d8dee8;
  border-radius: 6px;
  background: #fff;
}

.relationship-head {
  min-width: 0;
  min-height: 60px;
  display: grid;
  grid-template-columns: minmax(180px, 1fr) auto auto;
  align-items: center;
  gap: 18px;
  padding: 8px 12px;
  border-bottom: 1px solid #e4e8ee;
}

.relationship-title {
  min-width: 0;
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  align-items: baseline;
  gap: 2px 10px;
}

.relationship-title span {
  color: #7a8495;
  font-size: 11px;
}

.relationship-title strong {
  min-width: 0;
  overflow: hidden;
  color: #202633;
  font-size: 15px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.relationship-title small {
  grid-column: 1 / -1;
  color: #7b8594;
  font-size: 11px;
}

.relationship-metrics {
  display: flex;
  align-items: center;
  gap: 16px;
  margin: 0;
}

.relationship-metrics > div {
  display: flex;
  align-items: baseline;
  gap: 4px;
}

.relationship-metrics dt,
.relationship-metrics dd {
  margin: 0;
}

.relationship-metrics dt {
  color: #7a8495;
  font-size: 11px;
}

.relationship-metrics dd {
  color: #202633;
  font-size: 15px;
  font-weight: 700;
}

.relationship-switch {
  display: grid;
  grid-template-columns: 1fr 1fr;
  padding: 2px;
  border: 1px solid #d8dee8;
  border-radius: 4px;
  background: #f3f5f7;
}

.relationship-switch button {
  height: 27px;
  padding: 0 10px;
  border: 0;
  border-radius: 3px;
  background: transparent;
  color: #667085;
  cursor: pointer;
  font-size: 12px;
}

.relationship-switch button.active {
  background: #fff;
  color: #252c37;
  box-shadow: 0 1px 3px rgba(31, 39, 51, 0.12);
  font-weight: 650;
}

.relationship-impact {
  grid-row: 2;
  min-width: 0;
  display: grid;
  grid-template-columns: auto auto auto auto minmax(0, 1fr);
  align-items: center;
  gap: 12px;
  padding: 8px 12px;
  border-bottom: 1px solid #e8ebf0;
  background: #fbf8f2;
  color: #505b6b;
  font-size: 12px;
}

.relationship-impact strong {
  color: #202633;
  font-size: 13px;
}

.relationship-impact > span:first-of-type {
  color: #277842;
  font-weight: 700;
}

.relationship-impact.partial > span:first-of-type,
.relationship-impact.unknown > span:first-of-type {
  color: #a66313;
}

.relationship-impact em {
  min-width: 0;
  overflow: hidden;
  color: #6c7788;
  font-style: normal;
  text-align: right;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.relationship-graph-workspace {
  grid-row: 3;
  min-height: 0;
  display: grid;
  grid-template-columns: minmax(0, 1fr) 220px;
  overflow: hidden;
}

.relationship-chart {
  width: 100%;
  min-height: 310px;
  background:
    linear-gradient(#f1f3f6 1px, transparent 1px),
    linear-gradient(90deg, #f1f3f6 1px, transparent 1px);
  background-size: 28px 28px;
}

.relationship-inspector {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 14px 12px;
  overflow: auto;
  border-left: 1px solid #e2e6ec;
  background: #fafbfc;
}

.relationship-inspector > span {
  color: #7a8495;
  font-size: 11px;
}

.relationship-inspector > strong {
  overflow: hidden;
  color: #252c37;
  font-size: 15px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.relationship-inspector > dl {
  display: grid;
  gap: 0;
  margin: 5px 0 8px;
  border-top: 1px solid #e2e6ec;
}

.relationship-inspector > dl div {
  min-width: 0;
  display: grid;
  grid-template-columns: 60px minmax(0, 1fr);
  gap: 8px;
  padding: 6px 0;
  border-bottom: 1px solid #e8ebef;
}

.relationship-inspector dt,
.relationship-inspector dd {
  min-width: 0;
  margin: 0;
  font-size: 11px;
}

.relationship-inspector dt {
  color: #7a8495;
}

.relationship-inspector dd {
  overflow: hidden;
  color: #384251;
  text-align: right;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.selected-relations {
  min-width: 0;
  display: grid;
}

.selected-relations > span {
  margin-bottom: 4px;
  color: #7a8495;
  font-size: 11px;
}

.selected-relations button {
  min-width: 0;
  display: grid;
  gap: 2px;
  padding: 7px 0;
  border: 0;
  border-bottom: 1px solid #e5e8ed;
  background: transparent;
  cursor: pointer;
  text-align: left;
}

.selected-relations button:hover strong {
  color: #b42d30;
}

.selected-relations small {
  color: #7a8495;
  font-size: 10px;
}

.selected-relations strong {
  overflow: hidden;
  color: #384251;
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.relationship-actions {
  width: 100%;
  display: grid;
  gap: 6px;
  min-height: 32px;
  margin-top: auto;
}

.relationship-actions button {
  width: 100%;
  min-height: 32px;
  border: 1px solid #d3d9e2;
  border-radius: 4px;
  background: #fff;
  color: #4a5668;
  cursor: pointer;
  font-size: 12px;
}

.relationship-actions button:hover {
  border-color: #b8c1cd;
  background: #f7f8fa;
}

.relationship-actions .impact-request {
  border: 1px solid #bd3437;
  color: #ae292d;
}

.relationship-actions .impact-request:hover {
  border-color: #bd3437;
  background: #fff4f4;
}

.relationship-table {
  grid-row: 3;
  min-height: 0;
  overflow: auto;
  scrollbar-gutter: stable;
}

.relationship-row {
  width: 100%;
  min-width: 640px;
  display: grid;
  grid-template-columns: minmax(160px, 1fr) 110px minmax(180px, 1fr) 92px;
  align-items: center;
  gap: 12px;
  padding: 8px 12px;
  border: 0;
  border-bottom: 1px solid #edf0f4;
  background: #fff;
  color: inherit;
  cursor: pointer;
  text-align: left;
}

.relationship-row:hover {
  background: #fafbfc;
}

.relationship-row.heading {
  position: sticky;
  top: 0;
  z-index: 1;
  background: #f6f7f9;
  color: #7a8495;
  cursor: default;
  font-size: 11px;
}

.relationship-row strong {
  min-width: 0;
  overflow: hidden;
  color: #303743;
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.relationship-row span,
.relationship-row code {
  color: #5f6b7b;
  font-size: 11px;
}

.relationship-row code {
  border: 0;
  background: transparent;
  text-align: right;
}

.relationship-empty {
  padding: 18px 12px;
  color: #6c7788;
  font-size: 13px;
}

.relationship-gaps {
  grid-row: 4;
  min-width: 0;
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  gap: 10px;
  padding: 8px 12px;
  border-top: 1px solid #eadfc9;
  background: #fffaf1;
  color: #6d4f20;
  font-size: 11px;
}

.relationship-gaps span {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

@media (max-width: 900px) {
  .relationship-head {
    grid-template-columns: minmax(0, 1fr) auto;
  }

  .relationship-metrics {
    grid-column: 1 / -1;
    grid-row: 2;
  }

  .relationship-graph-workspace {
    grid-template-columns: minmax(0, 1fr);
  }

  .relationship-inspector {
    display: none;
  }
}
</style>

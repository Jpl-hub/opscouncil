<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import type { InvestigationPackage } from '../types'

type DecisionGraph = InvestigationPackage['decision_graph']
type EvidenceAssurance = InvestigationPackage['evidence_assurance']
type GraphNode = DecisionGraph['nodes'][number]
type GraphEdge = DecisionGraph['edges'][number]
type EdgeFilter = 'ALL' | 'SUPPORTS' | 'REFUTES'

const props = defineProps<{
  graph?: DecisionGraph | null
  assurance?: EvidenceAssurance | null
  compact?: boolean
  defaultScope?: 'CORE' | 'ALL'
}>()

const showAll = ref(props.defaultScope === 'ALL')
const edgeFilter = ref<EdgeFilter>('ALL')
const selectedNodeId = ref('')

const laneOrder: GraphNode['kind'][] = [
  'REQUEST',
  'EVIDENCE',
  'HYPOTHESIS',
  'ACTION',
  'VERIFICATION',
]
const defaultLaneLabels: Record<GraphNode['kind'], string> = {
  REQUEST: '任务',
  EVIDENCE: '实时证据',
  HYPOTHESIS: '候选根因',
  ACTION: '处置',
  VERIFICATION: '核验',
}
const laneLimits: Record<GraphNode['kind'], number> = {
  REQUEST: 1,
  EVIDENCE: 6,
  HYPOTHESIS: 3,
  ACTION: 2,
  VERIFICATION: 1,
}
const laneX: Record<GraphNode['kind'], number> = {
  REQUEST: 18,
  EVIDENCE: 236,
  HYPOTHESIS: 454,
  ACTION: 672,
  VERIFICATION: 890,
}
const nodeWidth = 178
const nodeHeight = 68
const nodeGap = 18

const availableNodes = computed(() => props.graph?.nodes || [])
const hasEvidenceSummary = computed(() =>
  availableNodes.value.some((node) => node.id === 'hypothesis:evidence_summary'),
)
function laneLabel(kind: GraphNode['kind']) {
  if (kind === 'HYPOTHESIS' && hasEvidenceSummary.value) return '研判结论'
  return defaultLaneLabels[kind]
}
const primaryClaimEvidenceIds = computed(() => {
  const claim = props.assurance?.claims[0]
  return new Set([
    ...(claim?.supporting_evidence_ids || []),
    ...(claim?.refuting_evidence_ids || []),
  ].map((id) => `evidence:${id}`))
})
const evidenceRepresentatives = computed(() => {
  const result = new Map<string, string>()
  if (showAll.value) return result
  const evidenceNodes = availableNodes.value
    .filter((node) => node.kind === 'EVIDENCE')
    .sort((left, right) => {
      const leftPriority = primaryClaimEvidenceIds.value.has(left.id) ? 0 : 1
      const rightPriority = primaryClaimEvidenceIds.value.has(right.id) ? 0 : 1
      return leftPriority - rightPriority
    })
  const representativeBySource = new Map<string, string>()
  for (const node of evidenceNodes) {
    const sourceKey = String(node.metadata.source_key || node.id)
    const representative = representativeBySource.get(sourceKey)
    if (representative) {
      result.set(node.id, representative)
      continue
    }
    representativeBySource.set(sourceKey, node.id)
    result.set(node.id, node.id)
  }
  return result
})
const visibleNodes = computed(() => {
  const grouped = new Map<GraphNode['kind'], GraphNode[]>()
  for (const kind of laneOrder) grouped.set(kind, [])
  for (const node of availableNodes.value) grouped.get(node.kind)?.push(node)

  const nodes: GraphNode[] = []
  for (const kind of laneOrder) {
    let lane = grouped.get(kind) || []
    if (!showAll.value && kind === 'EVIDENCE') {
      const sourceCounts = new Map<string, number>()
      for (const item of lane) {
        const sourceKey = String(item.metadata.source_key || item.id)
        sourceCounts.set(sourceKey, (sourceCounts.get(sourceKey) || 0) + 1)
      }
      lane = lane
        .filter((item) => evidenceRepresentatives.value.get(item.id) === item.id)
        .sort((left, right) => {
          const leftPriority = primaryClaimEvidenceIds.value.has(left.id) ? 0 : 1
          const rightPriority = primaryClaimEvidenceIds.value.has(right.id) ? 0 : 1
          return leftPriority - rightPriority
        })
        .map((item) => {
          const sourceKey = String(item.metadata.source_key || item.id)
          const count = sourceCounts.get(sourceKey) || 1
          return count > 1
            ? {
                ...item,
                label: `${item.label} · ${count} 项`,
                metadata: { ...item.metadata, observation_count: count },
              }
            : item
        })
    }
    nodes.push(...(showAll.value ? lane : lane.slice(0, laneLimits[kind])))
  }
  return nodes
})
const nodePositions = computed(() => {
  const grouped = new Map<GraphNode['kind'], GraphNode[]>()
  for (const kind of laneOrder) grouped.set(kind, [])
  for (const node of visibleNodes.value) grouped.get(node.kind)?.push(node)
  const positions = new Map<string, { x: number; y: number }>()
  for (const kind of laneOrder) {
    const lane = grouped.get(kind) || []
    lane.forEach((node, index) => {
      positions.set(node.id, {
        x: laneX[kind],
        y: 54 + index * (nodeHeight + nodeGap),
      })
    })
  }
  return positions
})
const canvasHeight = computed(() => {
  const counts = laneOrder.map(
    (kind) => visibleNodes.value.filter((node) => node.kind === kind).length,
  )
  return Math.max(280, Math.max(...counts, 1) * (nodeHeight + nodeGap) + 56)
})
const visibleNodeIds = computed(() => new Set(visibleNodes.value.map((node) => node.id)))
const visibleEdges = computed(() => {
  const result: GraphEdge[] = []
  const seen = new Set<string>()
  for (const edge of props.graph?.edges || []) {
    const source = evidenceRepresentatives.value.get(edge.source) || edge.source
    const target = evidenceRepresentatives.value.get(edge.target) || edge.target
    if (!visibleNodeIds.value.has(source) || !visibleNodeIds.value.has(target)) continue
    if (edgeFilter.value !== 'ALL' && edge.relation !== edgeFilter.value) continue
    const key = `${source}:${target}:${edge.relation}`
    if (seen.has(key)) continue
    seen.add(key)
    result.push({ ...edge, id: key, source, target })
  }
  return result
})
const hiddenNodeCount = computed(() =>
  Math.max(0, availableNodes.value.length - visibleNodes.value.length),
)
const selectedNode = computed(() =>
  visibleNodes.value.find((node) => node.id === selectedNodeId.value)
  || visibleNodes.value.find((node) => node.kind === 'HYPOTHESIS')
  || visibleNodes.value[0]
  || null,
)

watch(
  () => props.graph,
  () => {
    selectedNodeId.value = ''
    showAll.value = props.defaultScope === 'ALL'
    edgeFilter.value = 'ALL'
  },
)

watch(
  () => props.defaultScope,
  (scope) => {
    showAll.value = scope === 'ALL'
  },
)

function nodePosition(nodeId: string) {
  return nodePositions.value.get(nodeId) || { x: 0, y: 0 }
}

function edgePath(edge: GraphEdge) {
  const source = nodePosition(edge.source)
  const target = nodePosition(edge.target)
  const startX = source.x + nodeWidth
  const startY = source.y + nodeHeight / 2
  const endX = target.x
  const endY = target.y + nodeHeight / 2
  const bend = Math.max(34, (endX - startX) * 0.45)
  return `M ${startX} ${startY} C ${startX + bend} ${startY}, ${endX - bend} ${endY}, ${endX} ${endY}`
}

function edgeLabelPosition(edge: GraphEdge) {
  const source = nodePosition(edge.source)
  const target = nodePosition(edge.target)
  return {
    x: (source.x + nodeWidth + target.x) / 2,
    y: (source.y + target.y + nodeHeight) / 2 - 5,
  }
}

function selectNode(node: GraphNode) {
  selectedNodeId.value = node.id
}

function statusText(node: GraphNode) {
  const map: Record<string, string> = {
    CORROBORATED: '交叉核验',
    SINGLE_SOURCE: '单一来源',
    CONFLICTED: '证据冲突',
    UNSUPPORTED: '证据不足',
    QUARANTINED: '已隔离',
    OK: '采集正常',
    SEALED: '已封存',
    PENDING_APPROVAL: '待审批',
    EXECUTED: '已执行',
    VERIFIED: '已核验',
    NOT_REQUIRED: '无需处置',
  }
  return map[node.status] || node.status
}

function nodeTone(node: GraphNode) {
  if (['CONFLICTED', 'BLOCKED', 'FAILED', 'ERROR', 'QUARANTINED'].includes(node.status)) return 'danger'
  if (['SINGLE_SOURCE', 'UNSUPPORTED', 'PENDING_APPROVAL', 'NEEDS_OPERATOR'].includes(node.status)) {
    return 'notice'
  }
  if (['CORROBORATED', 'OK', 'SEALED', 'EXECUTED', 'VERIFIED'].includes(node.status)) {
    return 'safe'
  }
  return 'neutral'
}

function selectedMetadata() {
  if (!selectedNode.value) return []
  return Object.entries(selectedNode.value.metadata || {})
    .filter(([, value]) => value !== null && value !== undefined && value !== '')
    .slice(0, 4)
    .map(([key, value]) => ({
      key: metadataLabel(key),
      value: Array.isArray(value) ? value.join('，') : String(value),
    }))
}

function metadataLabel(key: string) {
  const labels: Record<string, string> = {
    intent: '意图',
    source_type: '来源类型',
    source_key: '证据源',
    trust_level: '可信级别',
    observed_at: '采集时间',
    confidence: '置信级别',
    confidence_score: '置信分',
    evidence_gap: '证据缺口',
    risk_level: '风险',
    requires_approval: '审批',
    observation_count: '观测数量',
  }
  return labels[key] || key
}
</script>

<template>
  <section class="decision-graph" :class="{ compact }">
    <header class="graph-toolbar">
      <div>
        <strong>任务证据图谱</strong>
        <span v-if="graph">
          {{ graph.summary.evidence_count }} 条证据 ·
          {{ graph.summary.hypothesis_count }} 个{{ hasEvidenceSummary ? '研判结论' : '候选根因' }}
        </span>
      </div>
      <div class="graph-controls">
        <div class="segmented" aria-label="证据关系筛选">
          <button :class="{ active: edgeFilter === 'ALL' }" @click="edgeFilter = 'ALL'">全部</button>
          <button :class="{ active: edgeFilter === 'SUPPORTS' }" @click="edgeFilter = 'SUPPORTS'">支持</button>
          <button :class="{ active: edgeFilter === 'REFUTES' }" @click="edgeFilter = 'REFUTES'">反证</button>
        </div>
        <button
          v-if="hiddenNodeCount || showAll"
          class="scope-button"
          @click="showAll = !showAll"
        >
          {{ showAll ? '核心路径' : `全部节点 +${hiddenNodeCount}` }}
        </button>
      </div>
    </header>

    <div v-if="!graph?.nodes.length" class="graph-empty">
      当前任务尚未形成证据图谱。
    </div>
    <div v-else class="graph-layout">
      <div class="graph-canvas">
        <svg
          :viewBox="`0 0 1086 ${canvasHeight}`"
          role="img"
          :aria-label="`请求、证据、${hasEvidenceSummary ? '研判结论' : '候选根因'}、处置与核验关系图`"
        >
          <defs>
            <marker id="graph-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
              <path d="M0,0 L8,4 L0,8 Z" />
            </marker>
            <marker id="graph-arrow-negative" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
              <path d="M0,0 L8,4 L0,8 Z" />
            </marker>
          </defs>

          <text
            v-for="kind in laneOrder"
            :key="`lane:${kind}`"
            :x="laneX[kind]"
            y="26"
            class="lane-label"
          >
            {{ laneLabel(kind) }}
          </text>

          <g v-for="edge in visibleEdges" :key="edge.id" class="graph-edge" :class="edge.polarity">
            <path
              :d="edgePath(edge)"
              :marker-end="edge.polarity === 'negative' ? 'url(#graph-arrow-negative)' : 'url(#graph-arrow)'"
            />
            <text
              :x="edgeLabelPosition(edge).x"
              :y="edgeLabelPosition(edge).y"
              text-anchor="middle"
            >
              {{ edge.label }}
            </text>
          </g>

          <g
            v-for="node in visibleNodes"
            :key="node.id"
            class="graph-node"
            :class="[nodeTone(node), { selected: selectedNode?.id === node.id }]"
            :transform="`translate(${nodePosition(node.id).x}, ${nodePosition(node.id).y})`"
            role="button"
            tabindex="0"
            @click="selectNode(node)"
            @keydown.enter="selectNode(node)"
          >
            <rect :width="nodeWidth" :height="nodeHeight" rx="4" />
            <foreignObject x="12" y="9" :width="nodeWidth - 24" :height="nodeHeight - 16">
              <div class="node-copy">
                <strong>{{ node.label }}</strong>
                <span>{{ statusText(node) }}</span>
              </div>
            </foreignObject>
          </g>
        </svg>
      </div>

      <aside v-if="selectedNode" class="node-inspector">
        <div class="node-inspector-head">
          <span>{{ laneLabel(selectedNode.kind) }}</span>
          <code :class="nodeTone(selectedNode)">{{ statusText(selectedNode) }}</code>
        </div>
        <strong>{{ selectedNode.label }}</strong>
        <p>{{ selectedNode.summary || '该节点暂无补充摘要。' }}</p>
        <dl v-if="selectedMetadata().length">
          <div v-for="item in selectedMetadata()" :key="item.key">
            <dt>{{ item.key }}</dt>
            <dd :title="item.value">{{ item.value }}</dd>
          </div>
        </dl>
        <small v-if="selectedNode.source_ref" :title="selectedNode.source_ref">
          {{ selectedNode.source_ref }}
        </small>
      </aside>
    </div>

    <footer v-if="assurance" class="assurance-strip" :class="assurance.status.toLowerCase()">
      <strong>{{ assurance.status_label }}</strong>
      <span>{{ assurance.independent_source_count }} 类独立来源</span>
      <span>{{ assurance.support_count }} 条支持</span>
      <span v-if="assurance.refutation_count">{{ assurance.refutation_count }} 条反证</span>
      <p v-if="assurance.claims[0]?.evidence_gap">{{ assurance.claims[0].evidence_gap }}</p>
    </footer>
  </section>
</template>

<style scoped>
.decision-graph {
  min-width: 0;
  height: 100%;
  display: grid;
  grid-template-rows: auto minmax(0, 1fr) auto;
  background: #fff;
}

.graph-toolbar {
  min-height: 52px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 8px 14px;
  border-bottom: 1px solid #dfe4ec;
}

.graph-toolbar > div:first-child {
  min-width: 0;
  display: flex;
  align-items: baseline;
  gap: 12px;
}

.graph-toolbar strong {
  color: #202631;
  font-size: 16px;
}

.graph-toolbar span {
  color: #778195;
  font-size: 12px;
}

.graph-controls,
.segmented {
  display: flex;
  align-items: center;
}

.graph-controls {
  gap: 8px;
}

.segmented {
  padding: 2px;
  background: #f1f3f6;
  border-radius: 4px;
}

.segmented button,
.scope-button {
  height: 28px;
  border: 0;
  color: #586376;
  background: transparent;
  cursor: pointer;
  font-size: 12px;
}

.segmented button {
  min-width: 44px;
}

.segmented button.active {
  color: #1f2632;
  background: #fff;
  box-shadow: 0 1px 3px rgb(31 38 50 / 12%);
}

.scope-button {
  padding: 0 9px;
  border: 1px solid #d7dde6;
  background: #fff;
}

.graph-layout {
  min-height: 0;
  display: grid;
  grid-template-columns: minmax(0, 1fr) 246px;
}

.graph-canvas {
  min-width: 0;
  min-height: 0;
  overflow: auto;
  background:
    linear-gradient(#f6f8fa 1px, transparent 1px),
    linear-gradient(90deg, #f6f8fa 1px, transparent 1px);
  background-size: 28px 28px;
}

.graph-canvas svg {
  display: block;
  width: 100%;
  min-width: 780px;
  height: auto;
  min-height: 100%;
}

.lane-label {
  fill: #7b8494;
  font-size: 12px;
  font-weight: 600;
}

.graph-edge path {
  fill: none;
  stroke: #aeb7c5;
  stroke-width: 1.4;
  marker-end: url(#graph-arrow);
}

.graph-edge text {
  fill: #818a99;
  font-size: 10px;
}

.graph-edge.positive path {
  stroke: #4d9d61;
}

.graph-edge.negative path {
  stroke: #c33b3b;
  stroke-dasharray: 5 4;
}

#graph-arrow path {
  fill: #6f7b8d;
}

#graph-arrow-negative path {
  fill: #c33b3b;
}

.graph-node {
  cursor: pointer;
  outline: none;
}

.graph-node rect {
  fill: #fff;
  stroke: #cad2dd;
  stroke-width: 1.2;
}

.graph-node.safe rect {
  stroke: #70ad7e;
}

.graph-node.notice rect {
  stroke: #d79a45;
}

.graph-node.danger rect {
  stroke: #c84141;
}

.graph-node.selected rect {
  stroke-width: 2.4;
  filter: drop-shadow(0 2px 4px rgb(31 38 50 / 12%));
}

.node-copy {
  width: 100%;
  height: 100%;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  gap: 5px;
  color: #242a35;
  font-family: inherit;
}

.node-copy strong {
  overflow: hidden;
  font-size: 13px;
  line-height: 18px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.node-copy span {
  color: #778195;
  font-size: 11px;
}

.node-inspector {
  min-width: 0;
  overflow: auto;
  padding: 14px;
  border-left: 1px solid #dfe4ec;
  background: #fafbfc;
}

.node-inspector-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 12px;
}

.node-inspector-head span {
  color: #788295;
  font-size: 12px;
}

.node-inspector-head code {
  padding: 2px 6px;
  color: #596375;
  background: #edf0f4;
  font-family: inherit;
  font-size: 11px;
}

.node-inspector-head code.safe {
  color: #28753c;
  background: #edf8ef;
}

.node-inspector-head code.notice {
  color: #8b5d18;
  background: #fff6e8;
}

.node-inspector-head code.danger {
  color: #a72d2d;
  background: #fff0f0;
}

.node-inspector > strong {
  display: block;
  color: #202631;
  font-size: 15px;
  line-height: 22px;
}

.node-inspector > p {
  margin: 10px 0 14px;
  color: #4e596a;
  font-size: 13px;
  line-height: 20px;
}

.node-inspector dl {
  margin: 0;
}

.node-inspector dl div {
  display: grid;
  grid-template-columns: 64px minmax(0, 1fr);
  gap: 8px;
  padding: 7px 0;
  border-top: 1px solid #e6e9ee;
}

.node-inspector dt,
.node-inspector dd {
  min-width: 0;
  margin: 0;
  font-size: 12px;
}

.node-inspector dt {
  color: #8a93a2;
}

.node-inspector dd {
  overflow: hidden;
  color: #3c4554;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.node-inspector > small {
  display: block;
  overflow: hidden;
  margin-top: 14px;
  color: #929aa8;
  font-size: 10px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.assurance-strip {
  min-height: 38px;
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 7px 14px;
  border-top: 1px solid #dfe4ec;
  color: #596375;
  font-size: 12px;
}

.assurance-strip strong {
  color: #26303d;
}

.assurance-strip p {
  min-width: 0;
  overflow: hidden;
  margin: 0 0 0 auto;
  color: #778195;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.assurance-strip.corroborated {
  box-shadow: inset 3px 0 #3b944f;
}

.assurance-strip.single_source,
.assurance-strip.unsupported {
  box-shadow: inset 3px 0 #ce8a2d;
}

.assurance-strip.conflicted {
  box-shadow: inset 3px 0 #bd3535;
}

.graph-empty {
  display: grid;
  place-items: center;
  color: #818b9a;
  font-size: 13px;
}

.decision-graph.compact .node-inspector {
  display: none;
}

.decision-graph.compact .graph-layout {
  grid-template-columns: minmax(0, 1fr);
}

@media (max-width: 1160px) {
  .graph-layout {
    grid-template-columns: minmax(0, 1fr);
  }

  .node-inspector {
    display: none;
  }
}
</style>

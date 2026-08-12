<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import {
  IconCheck,
  IconDelete,
  IconEdit,
  IconRefresh,
  IconSearch,
  IconUpload,
} from '@arco-design/web-vue/es/icon'
import { useTaskStore } from '../stores/tasks'
import type { AgentSkill, OperationalMemory, OperationalMemoryStatus } from '../types'

const props = withDefaults(defineProps<{
  initialSection?: 'qa' | 'documents' | 'memories' | 'capabilities'
}>(), {
  initialSection: 'qa',
})

const emit = defineEmits<{
  (event: 'open-task', taskId: number): void
}>()

const store = useTaskStore()
const activeSection = ref<'qa' | 'documents' | 'memories' | 'capabilities'>(props.initialSection)
const knowledgeQuery = ref('')
const importMode = ref<'file' | 'text'>('file')
const selectedFile = ref<File | null>(null)
const fileInput = ref<HTMLInputElement | null>(null)
const uploadForm = ref({ title: '', source_type: 'manual', trust_level: 'internal' })
const textForm = ref({
  title: '',
  source_type: 'runbook',
  source_uri: '',
  trust_level: 'internal',
  content: '',
})
const memoryQuery = ref('')
const memoryHostScope = ref('')
const memoryStatus = ref<'' | OperationalMemoryStatus>('')
const memorySearchApplied = ref(false)
const selectedMemoryId = ref<number | null>(null)
const editingMemoryId = ref<number | null>(null)
const correctionForm = ref({ title: '', host_scope: '', service_scope: '', root_cause: '', resolution: '' })
const forgetModalOpen = ref(false)
const forgetReason = ref('')
const relationResolution = ref<{
  relationId: number
  decision: 'KEEP_EXISTING' | 'SUPERSEDE_EXISTING'
} | null>(null)
const relationReason = ref('')
const selectedCapabilityId = ref<string | null>(null)
const knowledgePrompts = [
  '服务重启前需要检查什么？',
  '关键配置漂移如何处置？',
  '日志空间不足时如何安全处理？',
]

const aiConfigured = computed(() => Boolean(store.aiStatus?.configured))
const indexReady = computed(() => Boolean(store.knowledgeIndexStatus?.ready))
const indexedText = computed(() => {
  const index = store.knowledgeIndexStatus
  if (!index) return '-'
  return `${index.indexed_chunk_count}/${index.chunk_count}`
})
const lexicalText = computed(() => {
  const index = store.knowledgeIndexStatus
  if (!index) return '-'
  return `${index.lexical_chunk_count}/${index.chunk_count}`
})
const textReady = computed(() => (
  aiConfigured.value
  && textForm.value.title.trim().length > 0
  && textForm.value.content.trim().length >= 20
))
const uploadReady = computed(() => aiConfigured.value && Boolean(selectedFile.value))
const currentHost = computed(() => {
  const hostname = store.livePosture?.snapshot.hostname
  return typeof hostname === 'string' ? hostname : ''
})
const memoryEvaluation = computed(() => store.operationalMemoryEvaluation)
const memoryEvaluationTone = computed(() => {
  if (!memoryEvaluation.value) return 'idle'
  if (memoryEvaluation.value.overall_status === 'ok') return 'ok'
  if (memoryEvaluation.value.overall_status === 'failed') return 'failed'
  return 'idle'
})

const visibleMemories = computed(() => {
  let rows: OperationalMemory[]
  if (memorySearchApplied.value) {
    const byId = new Map(store.operationalMemories.map((item) => [item.id, item]))
    rows = store.operationalMemoryHits
      .map((hit) => byId.get(hit.document_id))
      .filter((item): item is OperationalMemory => Boolean(item))
  } else {
    rows = store.operationalMemories
  }
  if (memoryStatus.value) rows = rows.filter((item) => item.status === memoryStatus.value)
  return rows
})
const selectedMemory = computed(() => (
  store.operationalMemories.find((item) => item.id === selectedMemoryId.value)
  ?? visibleMemories.value[0]
  ?? null
))
const selectedMemoryScore = computed(() => (
  store.operationalMemoryHits.find((hit) => hit.document_id === selectedMemory.value?.id)?.retrieval.rerank_score
  ?? null
))
const memoryRelations = computed(() => store.operationalMemoryRelations)
const pendingMemoryRelations = computed(() => (
  memoryRelations.value.filter((relation) => relation.status === 'PENDING')
))
const selectedCapability = computed<AgentSkill | null>(() => (
  store.agentSkills.find((item) => item.id === selectedCapabilityId.value)
  ?? store.agentSkills.find((item) => item.tools.length > 0)
  ?? store.agentSkills[0]
  ?? null
))
const catalogHash = computed(() => store.agentSkills[0]?.catalog_hash || '')

watch(
  currentHost,
  (hostname) => {
    if (!memoryHostScope.value && hostname) memoryHostScope.value = hostname
  },
  { immediate: true },
)

watch(
  selectedMemoryId,
  (memoryId) => {
    if (memoryId === null) {
      store.operationalMemoryRelations = []
      return
    }
    void store.refreshOperationalMemoryRelations(memoryId)
  },
  { immediate: true },
)

watch(
  () => props.initialSection,
  (section) => {
    activeSection.value = section
  },
)

watch(
  () => store.operationalMemories.map((item) => item.id),
  (ids) => {
    if (selectedMemoryId.value === null || !ids.includes(selectedMemoryId.value)) {
      selectedMemoryId.value = ids[0] ?? null
    }
  },
  { immediate: true },
)

watch(
  () => store.agentSkills.map((item) => item.id),
  (ids) => {
    if (selectedCapabilityId.value === null || !ids.includes(selectedCapabilityId.value)) {
      selectedCapabilityId.value = store.agentSkills.find((item) => item.tools.length > 0)?.id ?? ids[0] ?? null
    }
  },
  { immediate: true },
)

async function runKnowledgeSearch() {
  await store.searchKnowledge(knowledgeQuery.value)
}

async function runSuggestedKnowledgeSearch(prompt: string) {
  knowledgeQuery.value = prompt
  await runKnowledgeSearch()
}

function chooseFile() {
  fileInput.value?.click()
}

function onFileChange(event: Event) {
  const input = event.target as HTMLInputElement
  selectedFile.value = input.files?.[0] ?? null
}

async function uploadDocument() {
  if (!selectedFile.value || !uploadReady.value) return
  await store.uploadKnowledgeDocument({
    file: selectedFile.value,
    title: uploadForm.value.title.trim() || undefined,
    source_type: uploadForm.value.source_type,
    trust_level: uploadForm.value.trust_level,
  })
  if (store.error) return
  selectedFile.value = null
  uploadForm.value.title = ''
  if (fileInput.value) fileInput.value.value = ''
}

async function submitTextDocument() {
  if (!textReady.value) return
  await store.submitKnowledgeDocument({
    title: textForm.value.title.trim(),
    source_type: textForm.value.source_type,
    source_uri: textForm.value.source_uri.trim() || '本地录入',
    trust_level: textForm.value.trust_level,
    content: textForm.value.content.trim(),
  })
  if (store.error) return
  textForm.value = {
    title: '',
    source_type: 'runbook',
    source_uri: '',
    trust_level: 'internal',
    content: '',
  }
}

async function searchMemories() {
  memorySearchApplied.value = Boolean(memoryQuery.value.trim())
  await store.searchOperationalMemories(memoryQuery.value, memoryHostScope.value)
  selectedMemoryId.value = visibleMemories.value[0]?.id ?? null
}

function clearMemorySearch() {
  memoryQuery.value = ''
  memoryHostScope.value = ''
  memorySearchApplied.value = false
  store.operationalMemoryHits = []
  selectedMemoryId.value = visibleMemories.value[0]?.id ?? null
}

function beginCorrection(memory: OperationalMemory) {
  editingMemoryId.value = memory.id
  correctionForm.value = {
    title: memory.title,
    host_scope: memory.host_scope,
    service_scope: memory.service_scope,
    root_cause: memory.root_cause,
    resolution: memory.resolution,
  }
}

async function saveCorrection() {
  if (editingMemoryId.value === null) return
  const saved = await store.correctOperationalMemory(editingMemoryId.value, {
    title: correctionForm.value.title.trim() || undefined,
    host_scope: correctionForm.value.host_scope.trim() || '*',
    service_scope: correctionForm.value.service_scope.trim() || '*',
    root_cause: correctionForm.value.root_cause.trim(),
    resolution: correctionForm.value.resolution.trim(),
  })
  if (!saved) return
  editingMemoryId.value = null
  selectedMemoryId.value = store.operationalMemories[0]?.id ?? null
}

async function confirmMemory(memoryId: number) {
  await store.confirmOperationalMemory(memoryId)
  selectedMemoryId.value = memoryId
}

async function qualifyMemory(memoryId: number) {
  await store.qualifyOperationalMemory(memoryId)
  selectedMemoryId.value = memoryId
}

async function deactivateMemory(memoryId: number) {
  await store.deactivateOperationalMemory(memoryId)
  selectedMemoryId.value = memoryId
}

function openForgetMemory() {
  forgetReason.value = ''
  forgetModalOpen.value = true
}

async function submitForgetMemory() {
  if (!selectedMemory.value || forgetReason.value.trim().length < 10) return
  const forgotten = await store.forgetOperationalMemory(
    selectedMemory.value.id,
    forgetReason.value.trim(),
  )
  if (forgotten) {
    forgetModalOpen.value = false
    forgetReason.value = ''
  }
}

function openRelationResolution(
  relationId: number,
  decision: 'KEEP_EXISTING' | 'SUPERSEDE_EXISTING',
) {
  relationResolution.value = { relationId, decision }
  relationReason.value = ''
}

async function submitRelationResolution() {
  if (
    !selectedMemory.value
    || !relationResolution.value
    || relationReason.value.trim().length < 10
  ) return
  const resolved = await store.resolveOperationalMemoryRelation(
    relationResolution.value.relationId,
    relationResolution.value.decision,
    relationReason.value.trim(),
    selectedMemory.value.id,
  )
  if (resolved) {
    relationResolution.value = null
    relationReason.value = ''
  }
}

async function deleteMemory(memoryId: number) {
  await store.deleteOperationalMemory(memoryId)
  selectedMemoryId.value = visibleMemories.value[0]?.id ?? null
}

function memoryStatusLabel(status: OperationalMemoryStatus) {
  return ({
    DRAFT: '待确认',
    CONFLICTED: '待核对',
    CONFIRMED: '已确认',
    CORRECTED: '已修订',
    INACTIVE: '已停用',
    FORGOTTEN: '已移出',
  } as Record<OperationalMemoryStatus, string>)[status]
}

function memoryQualificationLabel(memory: OperationalMemory) {
  if (memory.status !== 'CONFIRMED') return memoryStatusLabel(memory.status)
  return ({
    PENDING: '待验证',
    QUALIFIED: '已启用',
    FAILED: '未准入',
  } as const)[memory.qualification_status]
}

function memoryListStatusClass(memory: OperationalMemory) {
  if (memory.status !== 'CONFIRMED') return memory.status.toLowerCase()
  return memory.qualification_status.toLowerCase()
}

function memoryEvaluationStatus() {
  const report = memoryEvaluation.value
  if (!report) return '尚未验证'
  if (report.overall_status === 'ok') return `${report.summary.passed_count}/${report.summary.case_count} 通过`
  if (report.overall_status === 'failed') return `${report.summary.passed_count}/${report.summary.case_count} 通过`
  return '需要确认记忆'
}

function memoryEvaluationRate(value: number | null | undefined) {
  return typeof value === 'number' ? `${Math.round(value * 100)}%` : '-'
}

function memoryRelationLabel(value: string) {
  return ({
    SUPPORTS: '相互印证',
    DUPLICATES: '内容重复',
    CONFLICTS: '结论冲突',
    SUPERSEDES: '版本取代',
  } as Record<string, string>)[value] ?? value
}

function memoryRelationStatusLabel(value: string) {
  return ({
    PENDING: '待处理',
    RESOLVED: '已处理',
    DISMISSED: '已关闭',
  } as Record<string, string>)[value] ?? value
}

function relatedMemoryTitle(memoryId: number) {
  return store.operationalMemories.find((memory) => memory.id === memoryId)?.title
    ?? `经验 #${memoryId}`
}

function sourceLabel(value: string) {
  return ({
    runbook: '处置规范',
    incident_review: '故障复盘',
    policy: '安全制度',
    manual: '运维手册',
    builtin: '内置规范',
  } as Record<string, string>)[value] ?? value
}

function trustLabel(value: string) {
  return ({ verified: '已验证', internal: '内部', draft: '草稿', operator_confirmed: '人工确认' } as Record<string, string>)[value] ?? value
}

function retrievalText(score: number) {
  return `相关度 ${Math.round(score * 100)}%`
}

function controlNodeLabel(value: string) {
  return ({
    STATIC_REVIEW: '静态审查',
    PLAN_POLICY: '计划校验',
    INVESTIGATION: '证据调查',
    APPROVAL: '人工审批',
    EXECUTION: '受限执行',
    VERIFICATION: '结果核验',
    AUDIT: '审计封存',
  } as Record<string, string>)[value] ?? value
}

function formatTime(value: string | null | undefined) {
  if (!value) return '-'
  return new Date(value).toLocaleString('zh-CN', { hour12: false })
}

function shortHash(value: string) {
  if (!value) return '-'
  return value.length > 14 ? `${value.slice(0, 7)}...${value.slice(-7)}` : value
}
</script>

<template>
  <section class="module-table knowledge-workspace">
    <header class="knowledge-nav">
      <nav aria-label="知识工作区">
        <button :class="{ active: activeSection === 'qa' }" @click="activeSection = 'qa'">知识问答</button>
        <button :class="{ active: activeSection === 'documents' }" @click="activeSection = 'documents'">资料管理</button>
        <button :class="{ active: activeSection === 'memories' }" @click="activeSection = 'memories'">运维经验</button>
        <button :class="{ active: activeSection === 'capabilities' }" @click="activeSection = 'capabilities'">能力目录</button>
      </nav>
      <div class="knowledge-index-state">
        <span :class="{ ready: indexReady }">{{ indexReady ? '索引正常' : '索引待处理' }}</span>
        <code>语义索引 {{ indexedText }}</code>
        <code>关键词索引 {{ lexicalText }}</code>
      </div>
    </header>

    <section v-if="activeSection === 'qa'" class="knowledge-pane qa-pane">
      <div class="qa-query">
        <a-input
          v-model="knowledgeQuery"
          placeholder="询问运维规范或安全处置边界..."
          @press-enter="runKnowledgeSearch"
        />
        <a-button type="primary" :disabled="!knowledgeQuery.trim()" :loading="store.knowledgeSearching" @click="runKnowledgeSearch">
          <template #icon><IconSearch /></template>
          检索
        </a-button>
      </div>
      <div class="qa-result-grid">
        <article class="qa-answer">
          <header>
            <strong>回答</strong>
            <span :title="store.knowledgeAnswer?.model || ''">
              {{ store.knowledgeAnswer ? '模型辅助归纳' : '等待检索' }}
            </span>
          </header>
          <div v-if="store.knowledgeAnswer" class="qa-answer-body">
            <p>{{ store.knowledgeAnswer.answer }}</p>
            <div v-if="store.knowledgeAnswer.next_actions.length" class="qa-actions">
              <button
                v-for="action in store.knowledgeAnswer.next_actions"
                :key="action"
                @click="knowledgeQuery = action"
              >
                {{ action }}
              </button>
            </div>
          </div>
          <div v-else class="knowledge-empty qa-empty">
            <template v-if="store.knowledgeDocuments.length">
              <span>常用查询</span>
              <div class="qa-suggestions">
                <button
                  v-for="prompt in knowledgePrompts"
                  :key="prompt"
                  @click="runSuggestedKnowledgeSearch(prompt)"
                >
                  {{ prompt }}
                </button>
              </div>
            </template>
            <button v-else class="qa-import-link" @click="activeSection = 'documents'">导入运维资料</button>
          </div>
        </article>
        <aside class="qa-citations">
          <header>
            <strong>依据</strong>
            <span>{{ store.knowledgeHits.length }} 条</span>
          </header>
          <div v-if="store.knowledgeHits.length" class="citation-list">
            <article v-for="hit in store.knowledgeHits" :key="`${hit.source_kind}-${hit.chunk_id}`">
              <div class="memory-editor-actions">
                <strong>{{ hit.title }}</strong>
                <span>{{ retrievalText(hit.retrieval.rerank_score) }}</span>
              </div>
              <p>{{ hit.content }}</p>
              <footer>
                <span>{{ trustLabel(hit.trust_level) }}</span>
                <code>词法 {{ hit.retrieval.lexical_rank ?? '-' }} · 向量 {{ hit.retrieval.vector_rank ?? '-' }}</code>
              </footer>
            </article>
          </div>
          <div v-else class="knowledge-empty">暂无检索依据</div>
        </aside>
      </div>
    </section>

    <section v-else-if="activeSection === 'documents'" class="knowledge-pane document-pane">
      <aside class="document-import">
        <header class="subnav">
          <button :class="{ active: importMode === 'file' }" @click="importMode = 'file'">文件</button>
          <button :class="{ active: importMode === 'text' }" @click="importMode = 'text'">文本</button>
        </header>
        <div v-if="importMode === 'file'" class="document-form file-form">
          <input
            ref="fileInput"
            class="hidden-file-input"
            type="file"
            accept=".pdf,.docx,.txt,.md,.markdown,.log,.conf,.cfg,.ini,.service,.json,.yaml,.yml,.csv"
            @change="onFileChange"
          />
          <button class="file-select" type="button" @click="chooseFile">
            <IconUpload />
            <span>{{ selectedFile?.name || '选择运维资料' }}</span>
          </button>
          <a-input v-model="uploadForm.title" placeholder="标题（可选）" />
          <a-select v-model="uploadForm.source_type">
            <a-option value="runbook">处置规范</a-option>
            <a-option value="incident_review">故障复盘</a-option>
            <a-option value="policy">安全制度</a-option>
            <a-option value="manual">运维手册</a-option>
          </a-select>
          <a-select v-model="uploadForm.trust_level">
            <a-option value="internal">企业内部</a-option>
            <a-option value="verified">已验证</a-option>
            <a-option value="draft">草稿</a-option>
          </a-select>
          <a-button type="primary" :disabled="!uploadReady" :loading="store.knowledgeSubmitting" @click="uploadDocument">
            上传并索引
          </a-button>
        </div>
        <div v-else class="document-form text-form">
          <a-input v-model="textForm.title" placeholder="资料标题" />
          <div class="document-form-row">
            <a-select v-model="textForm.source_type">
              <a-option value="runbook">处置规范</a-option>
              <a-option value="incident_review">故障复盘</a-option>
              <a-option value="policy">安全制度</a-option>
              <a-option value="manual">运维手册</a-option>
            </a-select>
            <a-select v-model="textForm.trust_level">
              <a-option value="internal">企业内部</a-option>
              <a-option value="verified">已验证</a-option>
              <a-option value="draft">草稿</a-option>
            </a-select>
          </div>
          <a-input v-model="textForm.source_uri" placeholder="来源" />
          <a-textarea v-model="textForm.content" placeholder="粘贴正文..." />
          <a-button type="primary" :disabled="!textReady" :loading="store.knowledgeSubmitting" @click="submitTextDocument">
            保存并索引
          </a-button>
        </div>
      </aside>
      <section class="document-register">
        <header class="register-toolbar">
          <div>
            <strong>资料台账</strong>
            <span>{{ store.knowledgeDocuments.length }} 份</span>
          </div>
          <div>
            <a-button size="small" :loading="store.knowledgeSeeding" @click="store.seedBuiltinKnowledge()">导入规范</a-button>
            <a-button
              size="small"
              aria-label="重建知识索引"
              :disabled="!store.knowledgeDocuments.length"
              :loading="store.knowledgeReindexing"
              @click="store.rebuildKnowledgeIndex()"
            >
              <template #icon><IconRefresh /></template>
              重建索引
            </a-button>
          </div>
        </header>
        <div class="document-table">
          <div class="document-row head">
            <span>资料</span><span>类型</span><span>可信度</span><span>版本</span><span>片段</span><span>操作</span>
          </div>
          <div v-for="doc in store.knowledgeDocuments" :key="doc.id" class="document-row">
            <span><strong>{{ doc.title }}</strong><small>{{ doc.source_uri }}</small></span>
            <span>{{ sourceLabel(doc.source_type) }}</span>
            <span>{{ trustLabel(doc.trust_level) }}</span>
            <code>v{{ doc.version }}</code>
            <span>{{ doc.chunk_count ?? 0 }}</span>
            <a-popconfirm content="删除后同步移除索引，确认删除？" @ok="store.deleteKnowledgeDocument(doc.id)">
              <a-button size="mini" status="danger" title="删除资料">
                <template #icon><IconDelete /></template>
              </a-button>
            </a-popconfirm>
          </div>
          <div v-if="!store.knowledgeDocuments.length" class="knowledge-empty">暂无资料</div>
        </div>
      </section>
    </section>

    <section v-else-if="activeSection === 'memories'" class="knowledge-pane memory-pane">
      <div class="memory-toolbar">
        <a-input v-model="memoryQuery" placeholder="检索已准入的处置经验..." @press-enter="searchMemories" />
        <a-input v-model="memoryHostScope" placeholder="主机范围（可选）" @press-enter="searchMemories" />
        <a-select v-model="memoryStatus" placeholder="全部状态">
          <a-option value="">全部状态</a-option>
          <a-option value="DRAFT">待确认</a-option>
          <a-option value="CONFLICTED">待核对</a-option>
          <a-option value="CONFIRMED">已确认</a-option>
          <a-option value="CORRECTED">已修订</a-option>
          <a-option value="INACTIVE">已停用</a-option>
          <a-option value="FORGOTTEN">已移出</a-option>
        </a-select>
        <a-button
          type="primary"
          aria-label="检索运维经验"
          title="检索运维经验"
          :loading="store.operationalMemorySearching"
          @click="searchMemories"
        >
          <template #icon><IconSearch /></template>
        </a-button>
        <a-button v-if="memorySearchApplied" title="清除检索" @click="clearMemorySearch">
          <template #icon><IconRefresh /></template>
        </a-button>
      </div>
      <div class="memory-validation" :class="memoryEvaluationTone">
        <div class="memory-validation-status">
          <i aria-hidden="true"></i>
          <span>记忆边界验证</span>
          <strong>{{ memoryEvaluationStatus() }}</strong>
        </div>
        <dl>
          <div>
            <dt>召回命中</dt>
            <dd>{{ memoryEvaluationRate(memoryEvaluation?.summary.top1_recall_rate) }}</dd>
          </div>
          <div>
            <dt>主机隔离</dt>
            <dd>{{ memoryEvaluationRate(memoryEvaluation?.summary.scope_isolation_rate) }}</dd>
          </div>
          <div>
            <dt>状态隔离</dt>
            <dd>{{ memoryEvaluationRate(memoryEvaluation?.summary.state_exclusion_rate) }}</dd>
          </div>
          <div>
            <dt>内容完整</dt>
            <dd>{{ memoryEvaluationRate(memoryEvaluation?.summary.content_integrity_rate) }}</dd>
          </div>
        </dl>
        <a-button
          size="small"
          :loading="store.operationalMemoryEvaluationRunning"
          @click="store.runOperationalMemoryEvaluation"
        >
          运行验证
        </a-button>
      </div>
      <div class="memory-grid">
        <aside class="memory-list">
          <button
            v-for="memory in visibleMemories"
            :key="memory.id"
            :class="{ active: selectedMemory?.id === memory.id }"
            @click="selectedMemoryId = memory.id"
          >
            <span>
              <strong>{{ memory.title }}</strong>
              <small>{{ memory.host_scope }} · {{ memory.service_scope }}</small>
            </span>
            <em :class="memoryListStatusClass(memory)">{{ memoryQualificationLabel(memory) }}</em>
          </button>
          <div v-if="!visibleMemories.length" class="knowledge-empty">没有匹配的运维经验</div>
        </aside>
        <article v-if="selectedMemory" class="memory-detail">
          <header>
            <div>
              <strong>{{ selectedMemory.title }}</strong>
              <span>
                v{{ selectedMemory.version }} · {{ memoryQualificationLabel(selectedMemory) }} ·
                {{ selectedMemoryScore === null ? '台账记录' : retrievalText(selectedMemoryScore) }}
              </span>
            </div>
            <div class="memory-actions">
              <a-button size="small" @click="emit('open-task', selectedMemory.source_task_id)">源任务</a-button>
              <a-button
                v-if="selectedMemory.status === 'DRAFT'"
                size="small"
                type="primary"
                :loading="store.operationalMemoryBusyKey === `confirm:${selectedMemory.id}`"
                @click="confirmMemory(selectedMemory.id)"
              >
                <template #icon><IconCheck /></template>
                确认
              </a-button>
              <a-button
                v-if="selectedMemory.status === 'CONFIRMED' && selectedMemory.qualification_status !== 'QUALIFIED'"
                size="small"
                type="primary"
                :loading="store.operationalMemoryBusyKey === `qualify:${selectedMemory.id}`"
                @click="qualifyMemory(selectedMemory.id)"
              >
                准入验证
              </a-button>
              <a-button
                v-if="selectedMemory.status === 'CONFIRMED'"
                size="small"
                aria-label="修订运维经验"
                @click="beginCorrection(selectedMemory)"
              >
                <template #icon><IconEdit /></template>
                修订
              </a-button>
              <a-popconfirm
                v-if="selectedMemory.status === 'CONFIRMED'"
                content="停用后不再参与检索，确认停用？"
                @ok="deactivateMemory(selectedMemory.id)"
              >
                <a-button size="small">停用</a-button>
              </a-popconfirm>
              <a-popconfirm
                v-if="selectedMemory.status === 'DRAFT'"
                content="确认删除该版本？"
                @ok="deleteMemory(selectedMemory.id)"
              >
                <a-button size="small" status="danger" title="删除经验">
                  <template #icon><IconDelete /></template>
                </a-button>
              </a-popconfirm>
              <a-button
                v-if="['CONFIRMED', 'CONFLICTED', 'INACTIVE'].includes(selectedMemory.status)"
                size="small"
                status="danger"
                :loading="store.operationalMemoryBusyKey === `forget:${selectedMemory.id}`"
                @click="openForgetMemory"
              >
                移出经验库
              </a-button>
            </div>
          </header>
          <template v-if="editingMemoryId === selectedMemory.id">
            <div class="memory-editor">
              <label><span>标题</span><a-input v-model="correctionForm.title" /></label>
              <div class="memory-editor-scopes">
                <label><span>主机范围</span><a-input v-model="correctionForm.host_scope" /></label>
                <label><span>服务范围</span><a-input v-model="correctionForm.service_scope" /></label>
              </div>
              <label><span>根因</span><a-textarea v-model="correctionForm.root_cause" /></label>
              <label><span>处置经验</span><a-textarea v-model="correctionForm.resolution" /></label>
              <div>
                <a-button @click="editingMemoryId = null">取消</a-button>
                <a-button
                  type="primary"
                  :disabled="!correctionForm.root_cause.trim() || correctionForm.resolution.trim().length < 10"
                  :loading="store.operationalMemoryBusyKey === `correct:${selectedMemory.id}`"
                  @click="saveCorrection"
                >
                  保存新版本
                </a-button>
              </div>
            </div>
          </template>
          <template v-else>
            <dl class="memory-facts">
              <div><dt>主机</dt><dd>{{ selectedMemory.host_scope }}</dd></div>
              <div><dt>服务</dt><dd>{{ selectedMemory.service_scope }}</dd></div>
              <div><dt>可信度</dt><dd>{{ selectedMemory.confidence_score }}</dd></div>
              <div><dt>证据</dt><dd>{{ selectedMemory.evidence_refs.length }} 项</dd></div>
              <div>
                <dt>内容校验</dt>
                <dd :class="{ 'memory-integrity-failed': selectedMemory.integrity_status === 'FAILED' }">
                  {{ selectedMemory.integrity_status === 'VERIFIED' ? '通过' : '异常' }}
                </dd>
              </div>
              <div><dt>引用次数</dt><dd>{{ selectedMemory.retrieval_count }} 次</dd></div>
              <div><dt>有效反馈</dt><dd>{{ selectedMemory.helpful_count }} 次</dd></div>
              <div><dt>准入状态</dt><dd>{{ memoryQualificationLabel(selectedMemory) }}</dd></div>
              <div><dt>有效期</dt><dd>{{ selectedMemory.valid_until ? formatTime(selectedMemory.valid_until) : '持续有效' }}</dd></div>
            </dl>
            <section v-if="selectedMemory.status === 'CONFLICTED'" class="memory-conflict-section">
              <div class="memory-section-heading">
                <span>待核对关系</span>
                <strong>{{ pendingMemoryRelations.length }} 项</strong>
              </div>
              <div v-if="pendingMemoryRelations.length" class="memory-relation-list">
                <article v-for="relation in pendingMemoryRelations" :key="relation.id">
                  <div>
                    <strong>{{ memoryRelationLabel(relation.relation) }}</strong>
                    <span>{{ relatedMemoryTitle(relation.target_memory_id) }}</span>
                  </div>
                  <p>{{ relation.reason }}</p>
                  <footer>
                    <span>匹配 {{ relation.confidence_score }}%</span>
                    <div>
                      <a-button
                        size="mini"
                        @click="openRelationResolution(relation.id, 'KEEP_EXISTING')"
                      >
                        保留现有
                      </a-button>
                      <a-button
                        size="mini"
                        type="primary"
                        @click="openRelationResolution(relation.id, 'SUPERSEDE_EXISTING')"
                      >
                        采用此版本
                      </a-button>
                    </div>
                  </footer>
                </article>
              </div>
              <div v-else class="knowledge-empty">关系状态正在刷新</div>
            </section>
            <section>
              <span>根因</span>
              <p>{{ selectedMemory.root_cause }}</p>
            </section>
            <section>
              <span>处置经验</span>
              <p>{{ selectedMemory.resolution }}</p>
            </section>
            <section v-if="memoryRelations.length && selectedMemory.status !== 'CONFLICTED'" class="memory-relation-ledger">
              <div class="memory-section-heading">
                <span>关系记录</span>
                <strong>{{ memoryRelations.length }} 项</strong>
              </div>
              <div v-for="relation in memoryRelations" :key="relation.id" class="memory-relation-row">
                <span>{{ memoryRelationLabel(relation.relation) }}</span>
                <span>{{ relatedMemoryTitle(
                  relation.source_memory_id === selectedMemory.id
                    ? relation.target_memory_id
                    : relation.source_memory_id
                ) }}</span>
                <em>{{ memoryRelationStatusLabel(relation.status) }}</em>
              </div>
            </section>
            <section v-if="selectedMemory.status === 'FORGOTTEN'" class="memory-forgotten">
              <span>停用记录</span>
              <p>{{ selectedMemory.forget_reason }}</p>
            </section>
            <footer>
              <span>来源：任务 #{{ selectedMemory.source_task_id }} · {{ selectedMemory.created_by }}</span>
              <span v-if="selectedMemory.confirmed_by">确认：{{ selectedMemory.confirmed_by }} · {{ formatTime(selectedMemory.confirmed_at) }}</span>
              <span v-else>创建：{{ formatTime(selectedMemory.created_at) }}</span>
            </footer>
          </template>
        </article>
        <div v-else class="knowledge-empty">请选择一条运维经验</div>
      </div>
    </section>

    <section v-else class="knowledge-pane capability-pane">
      <aside class="capability-list">
        <button
          v-for="capability in store.agentSkills"
          :key="capability.id"
          :class="{ active: selectedCapability?.id === capability.id }"
          @click="selectedCapabilityId = capability.id"
        >
          <span><strong>{{ capability.name }}</strong><small>{{ capability.tools.length }} 个工具</small></span>
          <code>v{{ capability.version }}</code>
        </button>
      </aside>
      <article v-if="selectedCapability" class="capability-detail">
        <header>
          <div>
            <strong>{{ selectedCapability.name }}</strong>
            <span>{{ selectedCapability.output_contract }}</span>
          </div>
          <code>目录 {{ selectedCapability.catalog_version }} · {{ shortHash(catalogHash) }}</code>
        </header>
        <div class="control-flow">
          <template v-for="(node, index) in selectedCapability.control_nodes" :key="node">
            <span>{{ controlNodeLabel(node) }}</span>
            <i v-if="index < selectedCapability.control_nodes.length - 1">›</i>
          </template>
        </div>
        <section class="capability-tool-table">
          <div class="capability-tool-row head"><span>工具</span><span>最低版本</span><span>用途</span></div>
          <div v-for="tool in selectedCapability.tools" :key="tool.name" class="capability-tool-row">
            <code :title="tool.name">{{ tool.name }}</code><span>v{{ tool.min_version }}</span><span>{{ tool.purpose }}</span>
          </div>
          <div v-if="!selectedCapability.tools.length" class="knowledge-empty">该能力不访问主机工具</div>
        </section>
        <footer class="capability-gates">
          <span v-for="gate in selectedCapability.safety_gates" :key="gate">{{ gate }}</span>
        </footer>
      </article>
    </section>
    <a-modal
      v-model:visible="forgetModalOpen"
      title="移出经验库"
      :width="480"
      :footer="false"
    >
      <div class="memory-governance-modal">
        <p>{{ selectedMemory?.title }}</p>
        <a-textarea
          v-model="forgetReason"
          placeholder="填写停用这条经验的具体原因..."
          :max-length="1000"
          show-word-limit
        />
        <div>
          <a-button @click="forgetModalOpen = false">取消</a-button>
          <a-button
            type="primary"
            status="danger"
            :disabled="forgetReason.trim().length < 10"
            :loading="Boolean(selectedMemory && store.operationalMemoryBusyKey === `forget:${selectedMemory.id}`)"
            @click="submitForgetMemory"
          >
            确认移出
          </a-button>
        </div>
      </div>
    </a-modal>
    <a-modal
      :visible="Boolean(relationResolution)"
      :title="relationResolution?.decision === 'SUPERSEDE_EXISTING' ? '采用新经验' : '保留现有经验'"
      :width="480"
      :footer="false"
      @cancel="relationResolution = null"
    >
      <div class="memory-governance-modal">
        <p>处理依据将写入审计链，提交后立即更新这条经验的使用范围。</p>
        <a-textarea
          v-model="relationReason"
          placeholder="填写证据差异或适用条件..."
          :max-length="1000"
          show-word-limit
        />
        <div>
          <a-button @click="relationResolution = null">取消</a-button>
          <a-button
            type="primary"
            :disabled="relationReason.trim().length < 10"
            :loading="Boolean(relationResolution && store.operationalMemoryBusyKey === `resolve:${relationResolution.relationId}`)"
            @click="submitRelationResolution"
          >
            提交处理结果
          </a-button>
        </div>
      </div>
    </a-modal>
  </section>
</template>

<style scoped>
.knowledge-workspace {
  min-width: 0;
  min-height: 0;
  height: 100%;
  display: grid;
  grid-template-rows: 48px minmax(0, 1fr);
  padding: 0;
  overflow: hidden;
  border: 1px solid var(--border);
  background: #fff;
}

.knowledge-nav,
.knowledge-nav nav,
.knowledge-index-state,
.register-toolbar,
.register-toolbar > div,
.memory-detail > header,
.memory-actions,
.capability-detail > header,
.qa-answer > header,
.qa-citations > header {
  display: flex;
  align-items: center;
}

.knowledge-nav {
  justify-content: space-between;
  gap: 16px;
  padding: 0 14px;
  border-bottom: 1px solid var(--border);
  background: #fafbfc;
}

.knowledge-nav nav {
  align-self: stretch;
  gap: 22px;
}

.knowledge-nav nav button,
.subnav button {
  position: relative;
  height: 100%;
  padding: 0 2px;
  border: 0;
  background: transparent;
  color: #667085;
}

.knowledge-nav nav button.active,
.subnav button.active {
  color: #202633;
  font-weight: 700;
}

.knowledge-nav nav button.active::after,
.subnav button.active::after {
  content: '';
  position: absolute;
  right: 0;
  bottom: -1px;
  left: 0;
  height: 2px;
  background: var(--red);
}

.knowledge-index-state {
  gap: 8px;
  color: #667085;
  font-size: 12px;
}

.knowledge-index-state > span::before {
  content: '';
  display: inline-block;
  width: 7px;
  height: 7px;
  margin-right: 6px;
  border-radius: 50%;
  background: #d46b08;
}

.knowledge-index-state > span.ready::before {
  background: #16a34a;
}

.knowledge-pane {
  min-width: 0;
  min-height: 0;
  overflow: hidden;
}

.qa-pane {
  display: grid;
  grid-template-rows: 52px minmax(0, 1fr);
}

.qa-query,
.memory-toolbar {
  display: grid;
  align-items: center;
  gap: 8px;
  padding: 9px 12px;
  border-bottom: 1px solid var(--border-soft);
}

.qa-query {
  grid-template-columns: minmax(0, 1fr) auto;
}

.qa-result-grid {
  min-height: 0;
  display: grid;
  grid-template-columns: minmax(0, 1.35fr) minmax(330px, .65fr);
}

.qa-answer,
.qa-citations {
  min-width: 0;
  min-height: 0;
  display: grid;
  grid-template-rows: 42px minmax(0, 1fr);
  overflow: hidden;
}

.qa-citations {
  border-left: 1px solid var(--border);
}

.qa-answer > header,
.qa-citations > header {
  justify-content: space-between;
  padding: 0 14px;
  border-bottom: 1px solid var(--border-soft);
}

.qa-answer > header span,
.qa-citations > header span,
.memory-detail header span,
.capability-detail header span {
  color: #667085;
  font-size: 12px;
}

.qa-answer-body {
  min-height: 0;
  overflow: auto;
  padding: 18px;
}

.qa-answer-body p,
.memory-detail section p {
  color: #26313f;
  font-size: 14px;
  line-height: 1.7;
  white-space: pre-wrap;
}

.qa-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 18px;
}

.qa-actions button {
  padding: 5px 9px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: #f7f8fa;
  color: #475569;
  font-size: 12px;
}

.citation-list,
.document-table,
.memory-list,
.capability-list,
.capability-tool-table {
  min-height: 0;
  overflow: auto;
}

.citation-list article {
  padding: 12px 14px;
  border-bottom: 1px solid var(--border-soft);
}

.citation-list article > div,
.citation-list footer {
  display: flex;
  justify-content: space-between;
  gap: 10px;
}

.citation-list article > div span,
.citation-list footer span,
.citation-list footer code {
  flex: 0 0 auto;
  color: #667085;
  font-size: 11px;
}

.citation-list p {
  display: -webkit-box;
  margin: 7px 0;
  overflow: hidden;
  color: #475569;
  font-size: 12px;
  line-height: 1.5;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 3;
}

.knowledge-empty {
  min-height: 0;
  display: grid;
  place-items: center;
  padding: 18px;
  color: #8a94a3;
  font-size: 13px;
}

.qa-empty {
  align-content: center;
  gap: 14px;
}

.qa-empty > span {
  color: #667085;
  font-weight: 650;
}

.qa-suggestions {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 8px;
}

.qa-suggestions button,
.qa-import-link {
  padding: 7px 11px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: #fff;
  color: #344054;
  cursor: pointer;
}

.qa-suggestions button:hover,
.qa-import-link:hover {
  border-color: #b72f2f;
  color: #a32929;
}

.document-pane {
  display: grid;
  grid-template-columns: minmax(290px, 340px) minmax(0, 1fr);
}

.document-import {
  min-height: 0;
  display: grid;
  grid-template-rows: 42px minmax(0, 1fr);
  border-right: 1px solid var(--border);
  background: #fafbfc;
}

.subnav {
  display: flex;
  align-items: stretch;
  gap: 18px;
  padding: 0 14px;
  border-bottom: 1px solid var(--border-soft);
}

.document-form {
  min-height: 0;
  display: grid;
  align-content: start;
  gap: 10px;
  overflow: auto;
  padding: 14px;
}

.text-form {
  grid-template-rows: auto auto auto minmax(140px, 1fr) auto;
  align-content: stretch;
}

.text-form :deep(.arco-textarea-wrapper),
.text-form :deep(textarea) {
  height: 100%;
  min-height: 0;
  resize: none;
}

.document-form-row {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px;
}

.file-select {
  min-width: 0;
  height: 46px;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 0 11px;
  overflow: hidden;
  border: 1px dashed #aeb8c7;
  border-radius: 5px;
  background: #fff;
  color: #475569;
}

.file-select span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.hidden-file-input {
  display: none;
}

.document-register {
  min-width: 0;
  min-height: 0;
  display: grid;
  grid-template-rows: 46px minmax(0, 1fr);
}

.register-toolbar {
  justify-content: space-between;
  padding: 0 12px;
  border-bottom: 1px solid var(--border-soft);
}

.register-toolbar > div {
  gap: 8px;
}

.register-toolbar span {
  color: #667085;
  font-size: 12px;
}

.document-row {
  min-width: 720px;
  min-height: 48px;
  display: grid;
  grid-template-columns: minmax(220px, 1.5fr) 88px 72px 64px 54px 46px;
  align-items: center;
  gap: 10px;
  padding: 7px 12px;
  border-bottom: 1px solid var(--border-soft);
  color: #475569;
  font-size: 12px;
}

.document-row.head {
  min-height: 36px;
  position: sticky;
  top: 0;
  z-index: 1;
  background: #f7f8fa;
  color: #667085;
}

.document-row > span:first-child {
  min-width: 0;
  display: grid;
}

.document-row strong,
.document-row small {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.document-row strong {
  color: #26313f;
  font-size: 13px;
}

.document-row small {
  color: #8a94a3;
}

.memory-pane {
  display: grid;
  grid-template-rows: 52px 46px minmax(0, 1fr);
}

.memory-toolbar {
  grid-template-columns: minmax(240px, 1fr) minmax(160px, .45fr) 120px auto auto;
}

.memory-validation {
  min-width: 0;
  display: grid;
  grid-template-columns: minmax(190px, auto) minmax(360px, 1fr) auto;
  align-items: center;
  gap: 18px;
  padding: 0 12px;
  border-bottom: 1px solid var(--border-soft);
  background: #fbfcfd;
}

.memory-validation-status {
  min-width: 0;
  display: flex;
  align-items: center;
  gap: 7px;
  white-space: nowrap;
}

.memory-validation-status i {
  width: 8px;
  height: 8px;
  flex: 0 0 auto;
  border-radius: 50%;
  background: #98a2b3;
}

.memory-validation.ok .memory-validation-status i {
  background: #16a34a;
}

.memory-validation.failed .memory-validation-status i {
  background: #c33535;
}

.memory-validation-status span {
  color: #344054;
  font-size: 12px;
  font-weight: 650;
}

.memory-validation-status strong {
  color: #667085;
  font-size: 11px;
  font-weight: 500;
}

.memory-validation dl {
  min-width: 0;
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: clamp(18px, 3vw, 48px);
  margin: 0;
}

.memory-validation dl > div {
  display: flex;
  align-items: baseline;
  gap: 6px;
  white-space: nowrap;
}

.memory-validation dt {
  color: #7a8493;
  font-size: 11px;
}

.memory-validation dd {
  margin: 0;
  color: #26313f;
  font-size: 12px;
  font-weight: 650;
}

.memory-validation dd small {
  margin-left: 1px;
  color: #7a8493;
  font-size: 10px;
  font-weight: 400;
}

.memory-grid,
.capability-pane {
  min-height: 0;
  display: grid;
  grid-template-columns: minmax(300px, .72fr) minmax(0, 1.28fr);
}

.memory-list,
.capability-list {
  border-right: 1px solid var(--border);
}

.memory-list > button,
.capability-list > button {
  width: 100%;
  min-width: 0;
  min-height: 58px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 9px 12px;
  border: 0;
  border-bottom: 1px solid var(--border-soft);
  background: #fff;
  text-align: left;
}

.memory-list > button:hover,
.memory-list > button.active,
.capability-list > button:hover,
.capability-list > button.active {
  background: #f7f9fc;
}

.memory-list > button.active,
.capability-list > button.active {
  box-shadow: inset 3px 0 0 var(--red);
}

.memory-list button > span,
.capability-list button > span {
  min-width: 0;
  display: grid;
  gap: 3px;
}

.memory-list strong,
.memory-list small,
.capability-list strong,
.capability-list small {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.memory-list small,
.capability-list small {
  color: #7a8493;
  font-size: 11px;
}

.memory-list em {
  flex: 0 0 auto;
  padding: 2px 6px;
  border-radius: 4px;
  background: #eef1f5;
  color: #667085;
  font-size: 11px;
  font-style: normal;
}

.memory-list em.qualified {
  background: #edf8f0;
  color: #15803d;
}

.memory-list em.draft,
.memory-list em.pending {
  background: #fff7e8;
  color: #b45309;
}

.memory-list em.conflicted,
.memory-list em.failed {
  background: #fff1f0;
  color: #b42318;
}

.memory-list em.forgotten,
.memory-list em.inactive,
.memory-list em.corrected {
  background: #f2f4f7;
  color: #667085;
}

.memory-detail,
.capability-detail {
  min-width: 0;
  min-height: 0;
  overflow: auto;
  padding: 16px 18px;
}

.memory-detail > header,
.capability-detail > header {
  justify-content: space-between;
  gap: 14px;
  padding-bottom: 13px;
  border-bottom: 1px solid var(--border-soft);
}

.memory-detail header > div:first-child,
.capability-detail header > div:first-child {
  min-width: 0;
  display: grid;
  gap: 3px;
}

.memory-detail header strong,
.capability-detail header strong {
  font-size: 16px;
}

.memory-actions {
  flex: 0 0 auto;
  gap: 6px;
}

.memory-facts {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  margin: 14px 0;
  border: 1px solid var(--border-soft);
}

.memory-facts > div {
  min-width: 0;
  padding: 9px 11px;
  border-right: 1px solid var(--border-soft);
}

.memory-facts > div:last-child {
  border-right: 0;
}

.memory-facts > div:nth-child(4n) {
  border-right: 0;
}

.memory-facts > div:nth-child(n + 5) {
  border-top: 1px solid var(--border-soft);
}

.memory-facts dt,
.memory-detail section > span {
  color: #7a8493;
  font-size: 11px;
}

.memory-facts dd {
  margin: 2px 0 0;
  overflow: hidden;
  color: #26313f;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.memory-detail section {
  padding: 12px 0;
  border-bottom: 1px solid var(--border-soft);
}

.memory-section-heading,
.memory-relation-list article > div,
.memory-relation-list article > footer,
.memory-governance-modal > div {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}

.memory-section-heading strong {
  color: #475569;
  font-size: 12px;
}

.memory-relation-list {
  margin-top: 8px;
  border-top: 1px solid var(--border-soft);
}

.memory-relation-list article {
  padding: 10px 0;
  border-bottom: 1px solid var(--border-soft);
}

.memory-relation-list article:last-child {
  padding-bottom: 0;
  border-bottom: 0;
}

.memory-relation-list article > div strong {
  color: #b42318;
  font-size: 12px;
}

.memory-relation-list article > div span,
.memory-relation-list article > footer > span {
  color: #667085;
  font-size: 11px;
}

.memory-relation-list article p {
  margin: 7px 0;
  color: #475569;
  font-size: 12px;
  line-height: 1.55;
}

.memory-relation-list article footer > div {
  display: flex;
  gap: 6px;
}

.memory-relation-ledger {
  display: grid;
  gap: 0;
}

.memory-relation-row {
  min-width: 0;
  display: grid;
  grid-template-columns: 90px minmax(0, 1fr) 60px;
  gap: 10px;
  padding: 8px 0;
  border-top: 1px solid var(--border-soft);
  color: #475569;
  font-size: 12px;
}

.memory-relation-row span:nth-child(2) {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.memory-relation-row em {
  color: #667085;
  font-style: normal;
  text-align: right;
}

.memory-forgotten p {
  color: #667085 !important;
}

.memory-governance-modal {
  display: grid;
  gap: 14px;
}

.memory-governance-modal > p {
  margin: 0;
  color: #475569;
  line-height: 1.6;
}

.memory-governance-modal :deep(textarea) {
  min-height: 110px;
  resize: vertical;
}

.memory-detail > footer {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  padding-top: 12px;
  color: #7a8493;
  font-size: 11px;
}

.memory-editor {
  display: grid;
  gap: 10px;
  padding-top: 14px;
}

.memory-editor label {
  display: grid;
  gap: 5px;
  color: #667085;
  font-size: 12px;
}

.memory-editor label :deep(textarea) {
  min-height: 86px;
  resize: vertical;
}

.memory-editor-scopes {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
}

.memory-editor-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
}

.capability-pane {
  grid-template-columns: minmax(260px, .6fr) minmax(0, 1.4fr);
}

.capability-detail {
  display: grid;
  grid-template-rows: auto auto minmax(0, 1fr) auto;
  gap: 14px;
  overflow: hidden;
}

.control-flow {
  min-width: 0;
  display: flex;
  align-items: center;
  gap: 7px;
  overflow-x: auto;
}

.control-flow span {
  flex: 0 0 auto;
  padding: 5px 8px;
  border: 1px solid #cfd8e6;
  border-radius: 4px;
  color: #475569;
  font-size: 12px;
}

.control-flow i {
  color: #98a2b3;
  font-style: normal;
}

.capability-tool-row {
  min-width: 620px;
  min-height: 42px;
  display: grid;
  grid-template-columns: minmax(210px, .58fr) 84px minmax(240px, 1.42fr);
  align-items: center;
  gap: 10px;
  padding: 6px 10px;
  border-bottom: 1px solid var(--border-soft);
  color: #475569;
  font-size: 12px;
}

.capability-tool-row > * {
  min-width: 0;
}

.capability-tool-row > code {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.capability-tool-row.head {
  min-height: 34px;
  position: sticky;
  top: 0;
  background: #f7f8fa;
  color: #667085;
}

.capability-gates {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.capability-gates span {
  padding: 4px 7px;
  border-radius: 4px;
  background: #fff7e8;
  color: #9a5805;
  font-size: 11px;
}

@media (max-width: 1380px) {
  .knowledge-index-state code:last-child {
    display: none;
  }

  .document-pane {
    grid-template-columns: 300px minmax(0, 1fr);
  }

  .memory-toolbar {
    grid-template-columns: minmax(220px, 1fr) 150px 112px auto auto;
  }

  .memory-validation {
    gap: 12px;
  }

  .memory-validation dl {
    gap: 18px;
  }

  .memory-grid {
    grid-template-columns: 310px minmax(0, 1fr);
  }
}
</style>

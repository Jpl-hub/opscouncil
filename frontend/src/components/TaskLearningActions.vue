<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { IconCheck, IconClose, IconEdit } from '@arco-design/web-vue/es/icon'
import { useTaskStore } from '../stores/tasks'
import type { OperatorFeedbackVerdict } from '../types'

defineProps<{
  compact?: boolean
}>()

const emit = defineEmits<{
  (event: 'open-memories'): void
}>()

const store = useTaskStore()
const feedbackDialogOpen = ref(false)
const feedbackVerdict = ref<Exclude<OperatorFeedbackVerdict, 'HELPFUL'>>('INCOMPLETE')
const feedbackCorrection = ref('')
const memoryDialogOpen = ref(false)
const memoryForm = ref({ title: '', host_scope: '', service_scope: '*', resolution: '' })

const task = computed(() => store.activeTask)
const latestFeedback = computed(() => store.taskFeedback[0] ?? null)
const taskMemories = computed(() => (
  task.value
    ? store.operationalMemories.filter((item) => item.source_task_id === task.value?.id)
    : []
))
const activeMemory = computed(() => (
  taskMemories.value.find((item) => item.status === 'CONFIRMED')
  ?? taskMemories.value.find((item) => item.status === 'DRAFT')
  ?? taskMemories.value[0]
  ?? null
))
const canReview = computed(() => Boolean(
  task.value
  && ['SEALED', 'REJECTED', 'BLOCKED', 'FAILED', 'NEEDS_OPERATOR', 'ROLLED_BACK'].includes(task.value.status),
))
const canCreateMemory = computed(() => Boolean(
  task.value?.status === 'SEALED'
  && store.investigation?.investigation_runtime?.status === 'CONCLUDED'
  && store.investigation?.diagnosis.status === 'model_assisted'
  && store.investigation?.hypotheses.some((item) => item.status === 'SUPPORTED')
  && !activeMemory.value,
))
const feedbackLabel = computed(() => {
  if (!latestFeedback.value) return '未评价'
  return ({ HELPFUL: '有帮助', INCOMPLETE: '信息不全', INCORRECT: '结论有误' } as Record<string, string>)[latestFeedback.value.verdict]
    ?? latestFeedback.value.verdict
})
const memoryStatusLabel = computed(() => {
  const status = activeMemory.value?.status
  return ({ DRAFT: '经验待确认', CONFIRMED: '经验已确认', CORRECTED: '经验已修订', INACTIVE: '经验已停用' } as Record<string, string>)[status || '']
    ?? '查看经验'
})

watch(
  () => task.value?.id,
  () => {
    feedbackDialogOpen.value = false
    memoryDialogOpen.value = false
    feedbackCorrection.value = ''
  },
)

async function markHelpful() {
  if (!task.value) return
  await store.recordTaskFeedback(task.value.id, 'HELPFUL', '', activeMemory.value?.id)
}

function openFeedback(verdict: Exclude<OperatorFeedbackVerdict, 'HELPFUL'>) {
  feedbackVerdict.value = verdict
  feedbackCorrection.value = ''
  feedbackDialogOpen.value = true
}

async function submitFeedback() {
  if (!task.value) return
  const feedback = await store.recordTaskFeedback(
    task.value.id,
    feedbackVerdict.value,
    feedbackCorrection.value,
    activeMemory.value?.id,
  )
  if (feedback) feedbackDialogOpen.value = false
}

function openMemoryDraft() {
  const diagnosis = store.investigation?.diagnosis
  const hypothesis = store.investigation?.hypotheses.find((item) => item.status === 'SUPPORTED')
  const recommended = diagnosis?.recommended_actions
    .map((item) => `${item.title}：${item.rationale}`)
    .join('；')
  memoryForm.value = {
    title: hypothesis?.title || '',
    host_scope: '',
    service_scope: '*',
    resolution: recommended || diagnosis?.conclusion || task.value?.summary || '',
  }
  memoryDialogOpen.value = true
}

async function createMemoryDraft() {
  if (!task.value) return
  const memory = await store.createOperationalMemoryFromTask(task.value.id, {
    title: memoryForm.value.title.trim() || undefined,
    host_scope: memoryForm.value.host_scope.trim() || undefined,
    service_scope: memoryForm.value.service_scope.trim() || '*',
    resolution: memoryForm.value.resolution.trim(),
  })
  if (memory) memoryDialogOpen.value = false
}
</script>

<template>
  <div v-if="canReview" class="task-learning-bar" :class="{ compact }">
    <div class="learning-state">
      <span>本次结论</span>
      <strong>{{ feedbackLabel }}</strong>
    </div>
    <div class="learning-actions">
      <button :disabled="store.taskFeedbackSubmitting" @click="markHelpful">
        <IconCheck />
        有帮助
      </button>
      <button :disabled="store.taskFeedbackSubmitting" @click="openFeedback('INCOMPLETE')">信息不全</button>
      <button :disabled="store.taskFeedbackSubmitting" @click="openFeedback('INCORRECT')">结论有误</button>
      <i aria-hidden="true"></i>
      <button v-if="activeMemory" class="memory-link" @click="emit('open-memories')">{{ memoryStatusLabel }}</button>
      <button v-else-if="canCreateMemory" class="memory-create" @click="openMemoryDraft">
        <IconEdit />
        沉淀经验
      </button>
    </div>
  </div>

  <Teleport to="body">
    <div v-if="feedbackDialogOpen" class="learning-overlay" @click.self="feedbackDialogOpen = false">
      <section class="learning-dialog feedback-dialog">
        <header>
          <div>
            <strong>{{ feedbackVerdict === 'INCORRECT' ? '纠正本次结论' : '补充缺失信息' }}</strong>
            <span>反馈将写入当前任务审计链</span>
          </div>
          <button title="关闭" @click="feedbackDialogOpen = false"><IconClose /></button>
        </header>
        <a-textarea
          v-model="feedbackCorrection"
          :placeholder="feedbackVerdict === 'INCORRECT' ? '填写正确结论或关键证据...' : '填写仍需补充的证据或信息...'"
        />
        <footer>
          <a-button @click="feedbackDialogOpen = false">取消</a-button>
          <a-button
            type="primary"
            :disabled="feedbackVerdict === 'INCORRECT' && !feedbackCorrection.trim()"
            :loading="store.taskFeedbackSubmitting"
            @click="submitFeedback"
          >
            提交反馈
          </a-button>
        </footer>
      </section>
    </div>

    <div v-if="memoryDialogOpen" class="learning-overlay" @click.self="memoryDialogOpen = false">
      <section class="learning-dialog memory-dialog">
        <header>
          <div>
            <strong>沉淀运维经验</strong>
            <span>保存后需人工确认才会进入检索</span>
          </div>
          <button title="关闭" @click="memoryDialogOpen = false"><IconClose /></button>
        </header>
        <div class="memory-form-grid">
          <label><span>标题</span><a-input v-model="memoryForm.title" /></label>
          <label><span>主机范围</span><a-input v-model="memoryForm.host_scope" placeholder="留空使用任务主机" /></label>
          <label><span>服务范围</span><a-input v-model="memoryForm.service_scope" /></label>
          <label class="resolution-field">
            <span>处置经验</span>
            <a-textarea v-model="memoryForm.resolution" />
          </label>
        </div>
        <footer>
          <a-button @click="memoryDialogOpen = false">取消</a-button>
          <a-button
            type="primary"
            :disabled="memoryForm.resolution.trim().length < 10"
            :loading="store.operationalMemoryBusyKey === `create:${task?.id}`"
            @click="createMemoryDraft"
          >
            保存草稿
          </a-button>
        </footer>
      </section>
    </div>
  </Teleport>
</template>

<style scoped>
.task-learning-bar {
  min-width: 0;
  min-height: 42px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 7px 10px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: #fafbfc;
}

.learning-state,
.learning-actions {
  display: flex;
  align-items: center;
}

.learning-state {
  flex: 0 0 auto;
  gap: 7px;
}

.learning-state span {
  color: #667085;
  font-size: 12px;
}

.learning-state strong {
  color: #26313f;
  font-size: 13px;
}

.learning-actions {
  min-width: 0;
  justify-content: flex-end;
  gap: 4px;
}

.learning-actions button {
  height: 28px;
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 0 8px;
  border: 1px solid transparent;
  border-radius: 4px;
  background: transparent;
  color: #475569;
  font-size: 12px;
}

.learning-actions button:hover {
  border-color: #cfd8e6;
  background: #fff;
}

.learning-actions button:disabled {
  cursor: wait;
  opacity: .55;
}

.learning-actions i {
  width: 1px;
  height: 18px;
  margin: 0 4px;
  background: var(--border);
}

.learning-actions .memory-create {
  border-color: #d5a34a;
  background: #fffaf0;
  color: #915d08;
}

.learning-actions .memory-link {
  color: #15803d;
}

.task-learning-bar.compact {
  min-height: 0;
  display: grid;
  gap: 8px;
  padding: 0;
  border: 0;
  background: transparent;
}

.task-learning-bar.compact .learning-state {
  justify-content: space-between;
}

.task-learning-bar.compact .learning-actions {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 5px;
}

.task-learning-bar.compact .learning-actions button {
  min-width: 0;
  justify-content: center;
  padding: 0 5px;
  border-color: #d8dee7;
  background: #fff;
}

.task-learning-bar.compact .learning-actions i {
  display: none;
}

.task-learning-bar.compact .learning-actions .memory-link,
.task-learning-bar.compact .learning-actions .memory-create {
  grid-column: 1 / -1;
}

.learning-overlay {
  position: fixed;
  z-index: 2200;
  inset: 0;
  display: grid;
  place-items: center;
  padding: 24px;
  background: rgba(16, 24, 40, .42);
}

.learning-dialog {
  width: min(640px, calc(100vw - 48px));
  max-height: calc(100vh - 64px);
  display: grid;
  gap: 14px;
  overflow: auto;
  padding: 18px;
  border-radius: 7px;
  background: #fff;
  box-shadow: 0 18px 60px rgba(16, 24, 40, .24);
}

.learning-dialog > header,
.learning-dialog > footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.learning-dialog > header > div {
  display: grid;
  gap: 3px;
}

.learning-dialog > header strong {
  color: #202633;
  font-size: 16px;
}

.learning-dialog > header span,
.memory-form-grid label > span {
  color: #667085;
  font-size: 12px;
}

.learning-dialog > header > button {
  width: 30px;
  height: 30px;
  display: grid;
  place-items: center;
  border: 0;
  border-radius: 4px;
  background: #f1f3f6;
  color: #475569;
}

.learning-dialog > footer {
  justify-content: flex-end;
  padding-top: 4px;
}

.feedback-dialog :deep(textarea) {
  min-height: 130px;
  resize: vertical;
}

.memory-form-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
}

.memory-form-grid label {
  min-width: 0;
  display: grid;
  gap: 5px;
}

.resolution-field {
  grid-column: 1 / -1;
}

.resolution-field :deep(textarea) {
  min-height: 140px;
  resize: vertical;
}
</style>

import { taskEventStreamUrl } from './api'
import type { TaskStreamEvent } from './types'

export interface TaskEventStreamHandlers {
  onEvent: (event: TaskStreamEvent) => void
  onDisconnect: () => void
}

export class TaskEventStreamClient {
  private source: EventSource | null = null
  private taskId: number | null = null

  open(taskId: number, handlers: TaskEventStreamHandlers) {
    if (this.source && this.taskId === taskId) return
    this.close()
    const source = new EventSource(taskEventStreamUrl(taskId))
    this.source = source
    this.taskId = taskId
    source.addEventListener('task_event', (rawEvent) => {
      if (this.source !== source) return
      try {
        handlers.onEvent(JSON.parse((rawEvent as MessageEvent<string>).data) as TaskStreamEvent)
      } catch {
        handlers.onDisconnect()
      }
    })
    source.onerror = () => {
      if (this.source === source) handlers.onDisconnect()
    }
  }

  close() {
    this.source?.close()
    this.source = null
    this.taskId = null
  }
}

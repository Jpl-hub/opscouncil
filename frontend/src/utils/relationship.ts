type JsonRecord = Record<string, unknown>

export function mergeRelationshipSnapshots(
  snapshots: JsonRecord[],
): JsonRecord | null {
  if (!snapshots.length) return null

  const nodes = new Map<string, JsonRecord>()
  const edges = new Map<string, JsonRecord>()
  const gaps = new Map<string, JsonRecord>()
  const focusPorts = new Set<number>()
  const focusUnits = new Set<string>()
  const focusProcessIds = new Set<number>()
  const focusUnitProcessIds = new Set<number>()
  const capturedTimes: string[] = []
  let changeImpact: JsonRecord | null = null
  let maxUnattributedSockets = 0

  for (const snapshot of snapshots) {
    const capturedAt = stringValue(snapshot.captured_at)
    if (capturedAt && !Number.isNaN(Date.parse(capturedAt))) {
      capturedTimes.push(capturedAt)
    }
    const sampledEdges = new Set<string>()
    for (const node of records(snapshot.nodes)) {
      const id = stringValue(node.id)
      if (id) nodes.set(id, { ...nodes.get(id), ...node })
    }
    for (const edge of records(snapshot.edges)) {
      const source = stringValue(edge.source)
      const target = stringValue(edge.target)
      const relation = stringValue(edge.relation)
      if (!source || !target || !relation) continue
      const key = `${source}\u0000${relation}\u0000${target}`
      const previous = edges.get(key)
      const firstInSnapshot = !sampledEdges.has(key)
      sampledEdges.add(key)
      edges.set(key, {
        ...previous,
        ...edge,
        observation_count: Math.max(
          numberValue(previous?.observation_count, 0),
          numberValue(edge.observation_count, 1),
        ),
        sample_count: numberValue(previous?.sample_count, 0) + (firstInSnapshot ? 1 : 0),
        first_observed_at: stringValue(previous?.first_observed_at) || capturedAt,
        last_observed_at: capturedAt || stringValue(previous?.last_observed_at),
      })
    }
    for (const gap of records(snapshot.evidence_gaps)) {
      const key = `${stringValue(gap.code)}\u0000${stringValue(gap.reason)}`
      gaps.set(key, {
        ...gaps.get(key),
        ...gap,
        count: Math.max(
          numberValue(gaps.get(key)?.count, 0),
          numberValue(gap.count, 1),
        ),
      })
    }
    addNumbers(focusPorts, snapshot.focus_ports)
    addStrings(focusUnits, snapshot.focus_units)
    addNumbers(focusProcessIds, snapshot.focus_process_ids)
    addNumbers(focusUnitProcessIds, snapshot.focus_unit_process_ids)
    maxUnattributedSockets = Math.max(
      maxUnattributedSockets,
      numberValue(snapshot.unattributed_socket_count, 0),
    )

    const candidateImpact = record(snapshot.change_impact)
    if (
      candidateImpact
      && (
        !changeImpact
        || stringValue(candidateImpact.action) !== 'observe'
      )
    ) {
      changeImpact = candidateImpact
    }
  }

  const nodeRows = [...nodes.values()].sort((left, right) => (
    `${stringValue(left.kind)}:${stringValue(left.id)}`
      .localeCompare(`${stringValue(right.kind)}:${stringValue(right.id)}`, 'zh-CN')
  ))
  const edgeRows = [...edges.values()].sort((left, right) => (
    `${stringValue(left.relation)}:${stringValue(left.source)}:${stringValue(left.target)}`
      .localeCompare(
        `${stringValue(right.relation)}:${stringValue(right.source)}:${stringValue(right.target)}`,
        'zh-CN',
      )
  ))
  const kindCount = (kind: string) => nodeRows.filter((node) => node.kind === kind).length
  const latest = snapshots[snapshots.length - 1]
  capturedTimes.sort((left, right) => Date.parse(left) - Date.parse(right))

  return {
    ...latest,
    snapshot_count: snapshots.length,
    captured_at_first: capturedTimes[0] || stringValue(latest.captured_at),
    captured_at: capturedTimes[capturedTimes.length - 1] || stringValue(latest.captured_at),
    focus_ports: [...focusPorts].sort((left, right) => left - right),
    focus_units: [...focusUnits].sort(),
    focus_process_ids: [...focusProcessIds].sort((left, right) => left - right),
    focus_unit_process_ids: [...focusUnitProcessIds].sort((left, right) => left - right),
    nodes: nodeRows,
    edges: edgeRows,
    node_count: nodeRows.length,
    edge_count: edgeRows.length,
    service_count: kindCount('service'),
    process_count: kindCount('process'),
    listener_count: kindCount('listener'),
    connection_relation_count: edgeRows.filter((edge) => edge.relation === 'CONNECTS_TO').length,
    external_endpoint_count: nodeRows.filter(
      (node) => node.kind === 'remote_endpoint' && node.scope === 'external',
    ).length,
    unattributed_socket_count: maxUnattributedSockets,
    evidence_gaps: [...gaps.values()],
    change_impact: changeImpact,
  }
}

function records(value: unknown): JsonRecord[] {
  return Array.isArray(value)
    ? value.filter((item): item is JsonRecord => Boolean(item && typeof item === 'object'))
    : []
}

function record(value: unknown): JsonRecord | null {
  return value && typeof value === 'object' ? value as JsonRecord : null
}

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function numberValue(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback
}

function addNumbers(target: Set<number>, value: unknown) {
  if (!Array.isArray(value)) return
  for (const item of value) {
    if (typeof item === 'number' && Number.isFinite(item)) target.add(item)
  }
}

function addStrings(target: Set<string>, value: unknown) {
  if (!Array.isArray(value)) return
  for (const item of value) {
    if (typeof item === 'string' && item) target.add(item)
  }
}

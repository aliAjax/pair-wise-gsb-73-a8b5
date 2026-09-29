import type {
  BaselineComparison,
  BaselineEntityCategory,
  BaselineEntityChange,
  BaselineMigrationStatus,
  BaselinePayload,
  ReviewDecision,
  ReviewScopeItem,
  Threat,
  ThreatModelState,
  VersionSnapshot,
} from '@/models/domain'

const clone = <T>(value: T): T => structuredClone(value)

/** 从当前模型抽取需要冻结的内容（不包含意见、版本历史、审计）。 */
export const freezeBaseline = (state: ThreatModelState): BaselinePayload => ({
  boundary: clone(state.boundary),
  zones: clone(state.zones),
  components: clone(state.components),
  dependencies: clone(state.dependencies),
  flows: clone(state.flows),
  controls: clone(state.controls),
  evidence: clone(state.evidence),
  threats: clone(state.threats),
  attackPaths: clone(state.attackPaths),
  risks: clone(state.risks),
  mitigations: clone(state.mitigations),
})

/** 冻结时刻把全部三方意见一并归档（按引用复制即可，意见对象之后不再原地修改）。 */
export const freezeDecisions = (state: ThreatModelState): ReviewDecision[] => clone(state.decisions)

/** 会签流程会原地改这两个字段，比对内容时必须剔除，否则每次会签都算“模型变更”。 */
const NON_CONTENT_KEYS = new Set(['reviewStatus', 'revision'])

const stableStringify = (value: unknown): string => {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([key]) => !NON_CONTENT_KEYS.has(key))
      .sort(([a], [b]) => a.localeCompare(b))
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${stableStringify(item)}`).join(',')}}`
  }
  return JSON.stringify(value)
}

interface NamedEntity {
  id: string
  name?: string
}

type EntityCollectionKey = Exclude<BaselineEntityCategory, 'boundary'>

const COLLECTIONS: { category: EntityCollectionKey; key: keyof BaselinePayload }[] = [
  { category: 'zone', key: 'zones' },
  { category: 'component', key: 'components' },
  { category: 'dependency', key: 'dependencies' },
  { category: 'flow', key: 'flows' },
  { category: 'control', key: 'controls' },
  { category: 'evidence', key: 'evidence' },
  { category: 'threat', key: 'threats' },
  { category: 'attackPath', key: 'attackPaths' },
  { category: 'risk', key: 'risks' },
  { category: 'mitigation', key: 'mitigations' },
]

export const baselineStatus = (snapshot: VersionSnapshot): BaselineMigrationStatus =>
  snapshot.baselineStatus ?? 'legacy_pending'

export const isFrozen = (snapshot: VersionSnapshot): boolean =>
  baselineStatus(snapshot) === 'frozen'

/** 旧版记录（平台里只存了对象编号）第一次使用时按当前模型尽力补成新结构。 */
export const reconstructLegacyBaseline = (
  snapshot: VersionSnapshot,
  state: ThreatModelState,
): { baseline: BaselinePayload; decisions: ReviewDecision[] } => {
  const current = freezeBaseline(state)
  const keepByIds = <T extends NamedEntity>(items: T[], ids: string[]): T[] => {
    const allowed = new Set(ids)
    return items.filter((item) => allowed.has(item.id))
  }

  // 旧记录留有编号清单的集合：只取回当时存在的对象；已删除对象当前模型里找不回来，
  // 内容级差异拿不到，因此状态会标记为 legacy_partial。
  current.components = keepByIds(current.components, snapshot.componentIds)
  current.flows = keepByIds(current.flows, snapshot.flowIds)
  current.controls = keepByIds(current.controls, snapshot.controlIds)
  current.risks = keepByIds(current.risks, snapshot.riskIds)
  current.threats = keepByIds(current.threats, snapshot.threatIds)
  // 旧版本没有边界/信任区/依赖/证据/攻击路径/缓解任务的编号清单，只能整体保留当前值。
  // 旧版意见按其 revision 归档到该版本：意见本身不可变，回滚时只增补不覆盖。
  const decisions = state.decisions.filter((decision) => decision.revision <= snapshot.revision)

  return { baseline: current, decisions }
}

const FIELD_LABELS: Record<string, string> = {
  name: '名称',
  title: '标题',
  description: '描述',
  owner: '负责人',
  status: '状态',
  severity: '严重级别',
  category: '威胁分类',
  code: '编号',
  likelihood: '可能性',
  impact: '影响程度',
  type: '类型',
  zoneId: '信任区',
  componentId: '所属组件',
  sourceId: '来源',
  targetId: '目标',
  protocol: '协议',
  dataClass: '数据分级',
  crossesTrustBoundary: '跨信任边界',
  criticality: '重要级别',
  vendor: '供应商',
  purpose: '用途',
  controlIds: '关联控制',
  riskIds: '关联风险',
  componentIds: '关联组件',
  flowIds: '关联数据流',
  attackPathIds: '攻击路径',
  externalDependencyIds: '外部依赖',
  evidenceIds: '证据',
  controlId: '所属控制',
  threatId: '所属威胁',
  dueAt: '截止时间',
  action: '处置方向',
  detail: '处置细节',
  reference: '证据引用',
  expiresAt: '到期时间',
  collectedAt: '采集时间',
  valid: '证据有效性',
  kind: '类型',
  entryPoint: '入口',
  target: '目标',
  steps: '攻击步骤',
  inScope: '建模范围',
  outOfScope: '排除范围',
  level: '信任级别',
  acceptanceExpiresAt: '接受有效期',
  acceptanceCondition: '接受条件',
}

const fieldLabel = (key: string): string => FIELD_LABELS[key] ?? key

const changedFields = (before: unknown, after: unknown): string[] => {
  if (!before || !after || typeof before !== 'object' || typeof after !== 'object') return []
  const keys = new Set([...Object.keys(before), ...Object.keys(after)])
  return [...keys]
    .filter((key) => !NON_CONTENT_KEYS.has(key))
    .filter((key) => stableStringify((before as Record<string, unknown>)[key]) !==
      stableStringify((after as Record<string, unknown>)[key]))
    .map(fieldLabel)
}

const entityName = (entity: unknown): string | undefined => {
  if (!entity || typeof entity !== 'object') return undefined
  const record = entity as Record<string, unknown>
  if (typeof record.name === 'string') return record.name
  if (typeof record.title === 'string') return record.title
  if (typeof record.code === 'string') {
    return typeof record.title === 'string' ? `${record.code} ${record.title}` : record.code
  }
  return undefined
}

const CATEGORY_LABEL: Record<BaselineEntityCategory, string> = {
  boundary: '系统边界',
  zone: '信任区',
  component: '组件',
  dependency: '外部依赖',
  flow: '数据流',
  control: '控制',
  evidence: '控制证据',
  threat: '威胁',
  attackPath: '攻击路径',
  risk: '风险',
  mitigation: '缓解任务',
}

export const categoryLabel = (category: BaselineEntityCategory): string =>
  CATEGORY_LABEL[category]

/** 在基线中解析对象名称（对象已被删除时回退编号）。 */
export const resolveBaselineName = (
  baseline: BaselinePayload | null | undefined,
  category: BaselineEntityCategory,
  id: string,
): string | undefined => {
  if (!baseline) return undefined
  if (category === 'boundary') {
    return baseline.boundary.id === id ? baseline.boundary.name : undefined
  }
  const mapping = {
    zone: baseline.zones,
    component: baseline.components,
    dependency: baseline.dependencies,
    flow: baseline.flows,
    control: baseline.controls,
    evidence: baseline.evidence,
    threat: baseline.threats,
    attackPath: baseline.attackPaths,
    risk: baseline.risks,
    mitigation: baseline.mitigations,
  } as const
  const found = mapping[category]?.find((item) => item.id === id)
  return found ? entityName(found) : undefined
}

const diffCollection = (
  category: BaselineEntityCategory,
  beforeItems: NamedEntity[],
  afterItems: NamedEntity[],
  changes: BaselineEntityChange[],
): void => {
  const beforeMap = new Map(beforeItems.map((item) => [item.id, item]))
  const afterMap = new Map(afterItems.map((item) => [item.id, item]))

  afterItems.forEach((item) => {
    const previous = beforeMap.get(item.id)
    if (!previous) {
      changes.push({ category, id: item.id, changeType: 'added', name: entityName(item) })
      return
    }
    const fields = changedFields(previous, item)
    if (fields.length) {
      changes.push({
        category,
        id: item.id,
        changeType: 'modified',
        fields,
        name: entityName(item) ?? entityName(previous),
      })
    }
  })

  beforeItems.forEach((item) => {
    if (!afterMap.has(item.id)) {
      changes.push({ category, id: item.id, changeType: 'removed', name: entityName(item) })
    }
  })
}

const REF_FIELDS = {
  componentIds: '关联组件',
  flowIds: '关联数据流',
  controlIds: '关联控制',
  riskIds: '关联风险',
  attackPathIds: '攻击路径',
  externalDependencyIds: '外部依赖',
} as const

const addedOrRemoved = (
  before: string[] | undefined,
  after: string[] | undefined,
): { added: string[]; removed: string[] } => {
  const beforeSet = new Set(before ?? [])
  const afterSet = new Set(after ?? [])
  return {
    added: (after ?? []).filter((id) => !beforeSet.has(id)),
    removed: (before ?? []).filter((id) => !afterSet.has(id)),
  }
}

const buildReviewScope = (
  from: BaselinePayload,
  to: BaselinePayload,
  changes: BaselineEntityChange[],
): ReviewScopeItem[] => {
  const scope = new Map<string, Set<string>>()
  const note = (threatId: string, reason: string): void => {
    const reasons = scope.get(threatId) ?? new Set<string>()
    reasons.add(reason)
    scope.set(threatId, reasons)
  }
  const nameIn = (
    baseline: BaselinePayload,
    category: BaselineEntityCategory,
    id: string,
  ): string => resolveBaselineName(baseline, category, id) ?? id

  to.threats.forEach((threat) => {
    const previous = from.threats.find((item) => item.id === threat.id)
    if (!previous) {
      note(threat.id, '威胁为新增条目，需要完整会签')
      return
    }
    // 引用类字段变化会在下面逐条给出具体原因，这里只概括非引用字段，避免重复。
    const refFieldLabels: string[] = Object.values(REF_FIELDS)
    const fields = changedFields(previous, threat).filter(
      (label) => !refFieldLabels.includes(label),
    )
    if (fields.length) note(threat.id, `威胁内容变化：${fields.join('、')}`)

    ;(Object.keys(REF_FIELDS) as (keyof typeof REF_FIELDS)[]).forEach((field) => {
      const delta = addedOrRemoved(
        previous[field] as string[] | undefined,
        threat[field] as string[] | undefined,
      )
      delta.added.forEach((id) => {
        const category = field === 'externalDependencyIds' ? 'dependency'
          : field === 'controlIds' ? 'control'
            : field === 'riskIds' ? 'risk'
              : field === 'attackPathIds' ? 'attackPath'
                : field === 'flowIds' ? 'flow'
                  : 'component'
        note(threat.id, `${REF_FIELDS[field]}新增：${nameIn(to, category, id)}`)
      })
      delta.removed.forEach((id) => {
        const category = field === 'externalDependencyIds' ? 'dependency'
          : field === 'controlIds' ? 'control'
            : field === 'riskIds' ? 'risk'
              : field === 'attackPathIds' ? 'attackPath'
                : field === 'flowIds' ? 'flow'
                  : 'component'
        note(threat.id, `${REF_FIELDS[field]}移除：${nameIn(from, category, id)}`)
      })
    })
  })

  const relatedThreats = (
    category: BaselineEntityCategory,
    id: string,
  ): Threat[] => {
    if (category === 'component') return to.threats.filter((item) => item.componentIds.includes(id))
    if (category === 'flow') return to.threats.filter((item) => item.flowIds.includes(id))
    if (category === 'control') return to.threats.filter((item) => item.controlIds.includes(id))
    if (category === 'risk') return to.threats.filter((item) => item.riskIds.includes(id))
    if (category === 'attackPath') {
      return to.threats.filter((item) => item.attackPathIds.includes(id))
    }
    if (category === 'dependency') {
      return to.threats.filter((item) => item.externalDependencyIds.includes(id))
    }
    if (category === 'evidence') {
      const controlIds = new Set(
        to.controls.filter((control) => control.evidenceIds.includes(id)).map((control) => control.id),
      )
      return to.threats.filter((item) => item.controlIds.some((controlId) => controlIds.has(controlId)))
    }
    if (category === 'mitigation') {
      const task = to.mitigations.find((item) => item.id === id)
      return task ? to.threats.filter((item) => item.id === task.threatId) : []
    }
    return []
  }

  changes
    .filter((change) => change.changeType !== 'added' || change.category === 'evidence' || change.category === 'mitigation')
    .forEach((change) => {
      const baseline = change.changeType === 'removed' ? from : to
      const targetName = nameIn(baseline, change.category, change.id)
      const label = CATEGORY_LABEL[change.category]
      if (change.category === 'boundary' || change.category === 'zone') {
        const detail = change.fields?.length ? `（${change.fields.join('、')}）` : ''
        const affected = change.category === 'zone'
          ? to.threats.filter((threat) =>
              threat.componentIds.some((componentId) => {
                const zoneId =
                  to.components.find((component) => component.id === componentId)?.zoneId
                return zoneId === change.id
              }))
          : to.threats
        affected.forEach((threat) => note(threat.id, `${label}「${targetName}」发生变化${detail}`))
        return
      }

      relatedThreats(change.category, change.id).forEach((threat) => {
        if (change.changeType === 'added') {
          note(threat.id, `新增${label}「${targetName}」与该威胁相关`)
        } else if (change.changeType === 'removed') {
          note(threat.id, `${label}「${targetName}」已删除`)
        } else {
          note(
            threat.id,
            `关联${label}「${targetName}」发生变化：${change.fields?.join('、') ?? '内容'}`,
          )
        }
      })
    })

  // 被删除威胁本身不再需要会签，但仍给出原因记录，便于审计核对。
  from.threats
    .filter((threat) => !to.threats.some((item) => item.id === threat.id))
    .forEach((threat) => note(threat.id, '威胁已删除，无需重新会签'))

  return to.threats
    .map((threat) => ({ threatId: threat.id, reasons: [...(scope.get(threat.id) ?? [])] }))
    .filter((item) => item.reasons.length > 0)
}

/** 两个完整冻结基线的内容级比对。 */
export const compareFullBaselines = (
  from: BaselinePayload,
  to: BaselinePayload,
): Omit<BaselineComparison, 'legacyFallback' | 'incomplete'> => {
  const changes: BaselineEntityChange[] = []

  if (stableStringify(from.boundary) !== stableStringify(to.boundary)) {
    changes.push({
      category: 'boundary',
      id: to.boundary.id,
      changeType: 'modified',
      fields: changedFields(from.boundary, to.boundary),
      name: to.boundary.name,
    })
  }

  COLLECTIONS.forEach(({ category, key }) => {
    diffCollection(
      category,
      from[key] as NamedEntity[],
      to[key] as NamedEntity[],
      changes,
    )
  })

  const reviewScope = buildReviewScope(from, to, changes)
  const removedThreatIds = new Set(
    from.threats.filter((threat) => !to.threats.some((item) => item.id === threat.id))
      .map((threat) => threat.id),
  )

  return {
    changes,
    reviewScope,
    reviewThreatIds: reviewScope
      .map((item) => item.threatId)
      .filter((id) => !removedThreatIds.has(id)),
  }
}

/** 没有内容基线时退化为旧版编号比对，范围只引用目标版本登记的 affectedThreatIds。 */
const compareLegacy = (from: VersionSnapshot, to: VersionSnapshot): BaselineComparison => {
  const changes: BaselineEntityChange[] = []
  const collect = (
    category: BaselineEntityCategory,
    before: string[],
    after: string[],
  ): void => {
    const beforeSet = new Set(before)
    const afterSet = new Set(after)
    after
      .filter((id) => !beforeSet.has(id))
      .forEach((id) => changes.push({ category, id, changeType: 'added' }))
    before
      .filter((id) => !afterSet.has(id))
      .forEach((id) => changes.push({ category, id, changeType: 'removed' }))
  }
  collect('component', from.componentIds, to.componentIds)
  collect('flow', from.flowIds, to.flowIds)
  collect('control', from.controlIds, to.controlIds)
  collect('risk', from.riskIds, to.riskIds)
  collect('threat', from.threatIds, to.threatIds)

  const partial = baselineStatus(from) === 'legacy_partial' ||
    baselineStatus(to) === 'legacy_partial'

  return {
    changes,
    reviewScope: to.affectedThreatIds.map((threatId) => ({
      threatId,
      reasons: [partial
        ? '基线为旧记录补档结果，重审范围仅按登记值参考'
        : '旧版基线无内容留档，重审范围沿用版本登记值'],
    })),
    reviewThreatIds: to.affectedThreatIds,
    legacyFallback: true,
    incomplete: true,
  }
}

/**
 * 用前后两个基线算出变更内容与需要重审的范围。
 * 任一版本尚未补成新结构时自动退化为编号比对并标记 incomplete。
 */
export const compareBaselines = (
  from: VersionSnapshot,
  to: VersionSnapshot,
): BaselineComparison => {
  if (from.baseline && to.baseline) {
    return { ...compareFullBaselines(from.baseline, to.baseline), legacyFallback: false, incomplete: false }
  }
  return compareLegacy(from, to)
}

/** 建版本时基于当前生效基线预演重审范围（用于创建对话框预选）。 */
export const previewReviewScope = (
  state: ThreatModelState,
  activeBaseline: VersionSnapshot | null,
): BaselineComparison => {
  const candidate: VersionSnapshot = {
    id: 'preview',
    revision: state.currentRevision + 1,
    label: '',
    createdAt: '',
    author: '',
    notes: '',
    threatIds: [],
    componentIds: [],
    flowIds: [],
    controlIds: [],
    riskIds: [],
    affectedThreatIds: [],
    baseline: freezeBaseline(state),
    decisions: freezeDecisions(state),
    baselineStatus: 'frozen',
  }
  if (activeBaseline?.baseline) {
    return {
      ...compareFullBaselines(activeBaseline.baseline, candidate.baseline as BaselinePayload),
      legacyFallback: false,
      incomplete: false,
    }
  }
  // 首个冻结基线之前：旧编号基线只能给不出内容范围，全部威胁视为首版会签。
  if (activeBaseline) {
    return compareLegacy(activeBaseline, candidate)
  }
  return {
    changes: [],
    reviewScope: state.threats.map((threat) => ({
      threatId: threat.id,
      reasons: ['首次冻结基线，全部威胁纳入首版会签'],
    })),
    reviewThreatIds: state.threats.map((threat) => threat.id),
    legacyFallback: false,
    incomplete: false,
  }
}

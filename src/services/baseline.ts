import type {
  BaselineMigrationStep,
  ThreatModelState,
  VersionBaseline,
  VersionDifference,
  VersionEntityChange,
  VersionFieldChange,
  VersionSnapshot,
} from '@/models/domain'

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T

export const BASELINE_MIGRATION_STEPS: BaselineMigrationStep[] = [
  'threats',
  'components',
  'flows',
  'controls',
  'risks',
  'decisions',
]

export const freezeBaseline = (state: ThreatModelState): VersionBaseline => ({
  threats: clone(state.threats),
  components: clone(state.components),
  flows: clone(state.flows),
  controls: clone(state.controls),
  risks: clone(state.risks),
  decisions: clone(state.decisions),
})

const emptyBaseline = (): VersionBaseline => ({
  threats: [],
  components: [],
  flows: [],
  controls: [],
  risks: [],
  decisions: [],
})

const captureByIds = <T extends { id: string }>(
  ids: string[],
  source: T[],
  label: string,
): T[] => {
  const available = new Map(source.map((item) => [item.id, item]))
  const missing = ids.filter((id) => !available.has(id))
  if (missing.length > 0) {
    throw new Error(`${label} ${missing.join('、')} 在当前模型中不存在，无法补全基线`)
  }
  return ids.map((id) => clone(available.get(id) as T))
}

const runMigrationStep = (
  step: BaselineMigrationStep,
  snapshot: VersionSnapshot,
  state: ThreatModelState,
  draft: VersionBaseline,
): void => {
  if (step === 'threats') draft.threats = captureByIds(snapshot.threatIds, state.threats, '威胁')
  if (step === 'components')
    draft.components = captureByIds(snapshot.componentIds, state.components, '组件')
  if (step === 'flows') draft.flows = captureByIds(snapshot.flowIds, state.flows, '数据流')
  if (step === 'controls')
    draft.controls = captureByIds(snapshot.controlIds, state.controls, '控制')
  if (step === 'risks') draft.risks = captureByIds(snapshot.riskIds, state.risks, '风险')
  if (step === 'decisions')
    draft.decisions = clone(
      state.decisions.filter((decision) => decision.revision === snapshot.revision),
    )
}

export const migrateSnapshotBaseline = (
  snapshot: VersionSnapshot,
  state: ThreatModelState,
): VersionSnapshot => {
  if (snapshot.baseline) return snapshot

  const migration = snapshot.migration ?? {
    status: 'pending' as const,
    completedSteps: [] as BaselineMigrationStep[],
    updatedAt: '',
  }
  const draft = snapshot.draftBaseline ?? emptyBaseline()

  try {
    BASELINE_MIGRATION_STEPS.forEach((step) => {
      if (migration.completedSteps.includes(step)) return
      runMigrationStep(step, snapshot, state, draft)
      migration.completedSteps.push(step)
    })
    snapshot.baseline = draft
    delete snapshot.draftBaseline
    migration.status = 'done'
    migration.error = undefined
    migration.note = '旧版本记录已补全为完整基线，内容按当前模型状态重建'
  } catch (error) {
    snapshot.draftBaseline = draft
    migration.status = 'failed'
    migration.error = error instanceof Error ? error.message : String(error)
  }

  migration.updatedAt = new Date().toISOString()
  snapshot.migration = migration
  return snapshot
}

const FIELD_LABELS: Record<string, string> = {
  code: '编号',
  name: '名称',
  title: '标题',
  description: '描述',
  owner: '负责人',
  status: '状态',
  severity: '严重度',
  category: '分类',
  type: '类型',
  criticality: '关键等级',
  level: '信任等级',
  protocol: '协议',
  dataClass: '数据密级',
  likelihood: '可能性',
  impact: '影响度',
  vendor: '供应商',
  purpose: '用途',
  zoneId: '所属信任区',
  sourceId: '来源组件',
  targetId: '目标组件',
  componentId: '关联组件',
  componentIds: '关联组件',
  flowIds: '关联数据流',
  controlIds: '关联控制',
  riskIds: '关联风险',
  externalDependencyIds: '关联外部依赖',
  attackPathIds: '关联攻击路径',
  evidenceIds: '关联证据',
  crossesTrustBoundary: '跨信任边界',
  acceptanceExpiresAt: '接受到期日',
  acceptanceCondition: '接受条件',
  inScope: '建模范围',
  outOfScope: '排除范围',
}

const EXCLUDED_FIELDS = new Set(['id', 'revision', 'reviewStatus'])

const formatValue = (value: unknown): string => {
  if (value === undefined || value === null || value === '') return '（空）'
  if (Array.isArray(value)) return value.length > 0 ? value.join('、') : '（空）'
  return String(value)
}

const diffFields = (
  before: Record<string, unknown>,
  after: Record<string, unknown>,
): VersionFieldChange[] => {
  const keys = [...new Set([...Object.keys(before), ...Object.keys(after)])].filter(
    (key) => !EXCLUDED_FIELDS.has(key),
  )
  return keys
    .filter((key) => JSON.stringify(before[key]) !== JSON.stringify(after[key]))
    .map((key) => ({
      field: FIELD_LABELS[key] ?? key,
      before: formatValue(before[key]),
      after: formatValue(after[key]),
    }))
}

interface CollectionDiff {
  added: string[]
  removed: string[]
  changedIds: string[]
  details: VersionEntityChange[]
}

const diffCollections = <T extends { id: string }>(
  category: string,
  before: T[],
  after: T[],
  name: (item: T) => string,
): CollectionDiff => {
  const beforeMap = new Map(before.map((item) => [item.id, item]))
  const afterMap = new Map(after.map((item) => [item.id, item]))
  const added = after.filter((item) => !beforeMap.has(item.id)).map((item) => item.id)
  const removed = before.filter((item) => !afterMap.has(item.id)).map((item) => item.id)
  const details: VersionEntityChange[] = []
  after.forEach((afterItem) => {
    const beforeItem = beforeMap.get(afterItem.id)
    if (!beforeItem) return
    const fields = diffFields(
      beforeItem as Record<string, unknown>,
      afterItem as Record<string, unknown>,
    )
    if (fields.length > 0) {
      details.push({ category, id: afterItem.id, name: name(afterItem), fields })
    }
  })
  return {
    added,
    removed,
    changedIds: details.map((detail) => detail.id),
    details,
  }
}

const changedIdSet = <T extends { id: string }>(before: T[], after: T[]): Set<string> => {
  const diff = diffCollections('', before, after, () => '')
  return new Set([...diff.added, ...diff.removed, ...diff.changedIds])
}

export const computeAffectedThreats = (
  from: VersionBaseline,
  to: VersionBaseline,
): string[] => {
  const changedComponents = changedIdSet(from.components, to.components)
  const changedFlows = changedIdSet(from.flows, to.flows)
  const changedControls = changedIdSet(from.controls, to.controls)
  const changedRisks = changedIdSet(from.risks, to.risks)
  const threatDiff = diffCollections('威胁', from.threats, to.threats, () => '')

  const affected = new Set<string>([...threatDiff.added, ...threatDiff.changedIds])
  to.threats.forEach((threat) => {
    const touched =
      threat.componentIds.some((id) => changedComponents.has(id)) ||
      threat.flowIds.some((id) => changedFlows.has(id)) ||
      threat.controlIds.some((id) => changedControls.has(id)) ||
      threat.riskIds.some((id) => changedRisks.has(id))
    if (touched) affected.add(threat.id)
  })
  return [...affected]
}

export const diffBaselines = (from: VersionBaseline, to: VersionBaseline): VersionDifference => {
  const threats = diffCollections('威胁', from.threats, to.threats, (item) => `${item.code} ${item.title}`)
  const components = diffCollections('组件', from.components, to.components, (item) => item.name)
  const flows = diffCollections('数据流', from.flows, to.flows, (item) => item.name)
  const controls = diffCollections('控制', from.controls, to.controls, (item) => item.name)
  const risks = diffCollections('风险', from.risks, to.risks, (item) => `${item.code} ${item.title}`)
  const collections = [threats, components, flows, controls, risks]

  const toChanges = (ids: string[], category: string) => ids.map((id) => ({ category, id }))

  const changedDetails = collections.flatMap((collection) => collection.details)
  return {
    added: [
      ...toChanges(threats.added, '威胁'),
      ...toChanges(components.added, '组件'),
      ...toChanges(flows.added, '数据流'),
      ...toChanges(controls.added, '控制'),
      ...toChanges(risks.added, '风险'),
    ],
    removed: [
      ...toChanges(threats.removed, '威胁'),
      ...toChanges(components.removed, '组件'),
      ...toChanges(flows.removed, '数据流'),
      ...toChanges(controls.removed, '控制'),
      ...toChanges(risks.removed, '风险'),
    ],
    changed: changedDetails.map(
      (detail) =>
        `${detail.category} ${detail.name}：${detail.fields
          .map((field) => `${field.field} ${field.before} → ${field.after}`)
          .join('；')}`,
    ),
    changedDetails,
    affectedThreatIds: computeAffectedThreats(from, to),
  }
}

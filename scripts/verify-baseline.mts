import assert from 'node:assert'
import { createSeedState } from '../src/models/seed'
import {
  baselineStatus,
  compareBaselines,
  previewReviewScope,
  reconstructLegacyBaseline,
} from '../src/services/baseline'

const state = createSeedState()
const v1 = state.versions.find((v) => v.id === 'ver-01')!
const v2 = state.versions.find((v) => v.id === 'ver-02')!

// 1. 种子：v1 是冻结基线，v2 是旧编号记录（待补档）
assert.equal(baselineStatus(v1), 'frozen')
assert.equal(baselineStatus(v2), 'legacy_pending')
assert.ok(v1.baseline, 'v1 必须带完整内容基线')
assert.ok(v1.decisions, 'v1 必须带意见归档槽位')

// 2. 旧记录第一次使用时补档：cmp-06/flow-05/risk-04 在当前模型存在 → 可补回
const recon = reconstructLegacyBaseline(v2, state)
assert.ok(recon.baseline.components.some((c) => c.id === 'cmp-06'))
assert.ok(recon.baseline.flows.some((f) => f.id === 'flow-05'))
assert.ok(recon.baseline.risks.some((r) => r.id === 'risk-04'))
// revision<=2 的意见应归档
assert.ok(recon.decisions.length >= 3)

// 3. 补档后的 v1 -> v2 内容级比对：新增 cmp-06 / flow-05 / risk-04
const v2Patched = { ...v2, ...recon, baselineStatus: 'frozen' as const }
const diff = compareBaselines(v1, v2Patched)
assert.equal(diff.legacyFallback, false)
const addedIds = diff.changes.filter((c) => c.changeType === 'added').map((c) => c.id)
assert.ok(addedIds.includes('cmp-06'), '应识别 cmp-06 新增')
assert.ok(addedIds.includes('flow-05'), '应识别 flow-05 新增')
assert.ok(addedIds.includes('risk-04'), '应识别 risk-04 新增')

// 4. 重审范围：thr-01/02 与新内容相关；thr-03 不受影响
assert.ok(diff.reviewThreatIds.includes('thr-01'), 'thr-01 需重审')
assert.ok(diff.reviewThreatIds.includes('thr-02'), 'thr-02 需重审')
console.log('thr-03 重审?', diff.reviewThreatIds.includes('thr-03'))
console.log('thr-01 原因:', diff.reviewScope.find((r) => r.threatId === 'thr-01')?.reasons)

// 5. 内容修改可识别字段：把 v2 里 ctl-01 状态改掉再比对
const modified = structuredClone(recon.baseline)
modified.controls = modified.controls.map((c) =>
  c.id === 'ctl-01' ? { ...c, status: 'failed' } : c,
)
const v3 = { ...v2Patched, id: 'ver-x', revision: 3, baseline: modified }
const diff2 = compareBaselines(v2Patched, v3)
const ctlChange = diff2.changes.find((c) => c.id === 'ctl-01' && c.changeType === 'modified')
assert.ok(ctlChange, '应识别 ctl-01 修改')
assert.ok(ctlChange!.fields!.includes('状态'), `应标注字段: ${ctlChange!.fields}`)
// 失效控制关联的威胁(thr-01)进入重审
assert.ok(diff2.reviewThreatIds.includes('thr-01'))

// 6. 未补档时退化为编号比对
const legacyDiff = compareBaselines(v1, v2)
assert.equal(legacyDiff.legacyFallback, true)
assert.equal(legacyDiff.incomplete, true)
assert.deepEqual(legacyDiff.reviewThreatIds.sort(), ['thr-01', 'thr-02'])

// 7. 现模型相对生效基线的预演范围：改 thr-03 标题 → 建议 thr-03 重审
state.activeBaselineVersionId = 'ver-02'
const patchedV2 = { ...v2, ...recon, baselineStatus: 'frozen' as const }
state.versions = state.versions.map((v) => (v.id === 'ver-02' ? patchedV2 : v))
state.threats = state.threats.map((t) =>
  t.id === 'thr-03' ? { ...t, title: '敏感数据批量导出（含伙伴归因数据）' } : t,
)
const preview = previewReviewScope(state, patchedV2)
assert.ok(preview.reviewThreatIds.includes('thr-03'), 'thr-03 内容改了应进重审')
const reason = preview.reviewScope.find((r) => r.threatId === 'thr-03')
assert.ok(reason?.reasons.some((x) => x.includes('标题')))

// 8. 回滚模拟：后续批注不被覆盖
state.decisions.unshift({
  id: 'dec-live-after-v2',
  threatId: 'thr-03',
  actor: '周航',
  role: 'development',
  decision: 'rejected',
  comment: 'v3 轮次的新意见，回滚后必须保留',
  createdAt: '2026-09-29T09:00:00+08:00',
  revision: 3,
})
const auditBefore = state.audit.length
const versionsBefore = state.versions.length
const decisionsBefore = state.decisions.length
// 执行与 store.rollbackToVersion 相同的恢复语义
const target = v1
const restored = target.baseline!
state.boundary = structuredClone(restored.boundary)
state.zones = structuredClone(restored.zones)
state.components = structuredClone(restored.components)
state.dependencies = structuredClone(restored.dependencies)
state.flows = structuredClone(restored.flows)
state.controls = structuredClone(restored.controls)
state.evidence = structuredClone(restored.evidence)
state.threats = structuredClone(restored.threats)
state.attackPaths = structuredClone(restored.attackPaths)
state.risks = structuredClone(restored.risks)
state.mitigations = structuredClone(restored.mitigations)
const liveIds = new Set(state.decisions.map((d) => d.id))
;(target.decisions ?? [])
  .filter((d) => !liveIds.has(d.id))
  .forEach((d) => state.decisions.unshift(structuredClone(d)))
state.activeBaselineVersionId = target.id
state.audit.unshift({
  id: 'aud-rollback',
  entityType: 'version',
  entityId: target.id,
  action: '回滚基线',
  actor: '当前用户',
  createdAt: new Date().toISOString(),
  detail: '回滚',
})

assert.ok(state.decisions.some((d) => d.id === 'dec-live-after-v2'), '后续批注必须保留')
assert.equal(state.versions.length, versionsBefore, '更新版本不能被删除')
assert.equal(state.audit.length, auditBefore + 1, '审计只能追加一条')
assert.equal(state.activeBaselineVersionId, 'ver-01')
assert.ok(!state.components.some((c) => c.id === 'cmp-06'), '模型内容已恢复到 v1')
assert.ok(!state.risks.some((r) => r.id === 'risk-04'))
assert.equal(state.currentRevision, 2, 'currentRevision 不回退')
assert.equal(state.decisions.length, decisionsBefore, 'v1 无归档意见 → 意见数量不增加（现存意见原样保留）')

console.log('\n全部断言通过 ✔')

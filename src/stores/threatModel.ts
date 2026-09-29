import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import type {
  ActorRole,
  AuditEvent,
  BaselineComparison,
  DecisionType,
  Threat,
  ThreatModelState,
  VersionSnapshot,
} from '@/models/domain'
import { createId, loadState, resetState, saveState } from '@/services/repository'
import {
  baselineStatus,
  compareBaselines,
  freezeBaseline,
  freezeDecisions,
  previewReviewScope,
  reconstructLegacyBaseline,
} from '@/services/baseline'
import {
  dashboardMetrics,
  decisionsForThreat,
  getValidationIssues,
  reviewProgress,
} from '@/services/selectors'

type CollectionKey =
  | 'zones'
  | 'components'
  | 'dependencies'
  | 'flows'
  | 'controls'
  | 'evidence'
  | 'threats'
  | 'attackPaths'
  | 'risks'
  | 'mitigations'
  | 'decisions'

interface IdentifiedEntity {
  id: string
}

export const useThreatModelStore = defineStore('threat-model', () => {
  const data = ref<ThreatModelState>(loadState())
  const lastSavedAt = ref(new Date().toISOString())

  const metrics = computed(() => dashboardMetrics(data.value))
  const issues = computed(() => getValidationIssues(data.value))
  const pendingReviews = computed(() =>
    data.value.threats.filter((threat) => threat.reviewStatus === 'in_review'),
  )
  // 当前生效基线：优先按指向找到冻结版本；历史数据没有指向时退化为最新版本。
  const activeBaseline = computed<VersionSnapshot | null>(
    () =>
      data.value.versions.find(
        (version) => version.id === data.value.activeBaselineVersionId,
      ) ??
      data.value.versions[0] ??
      null,
  )

  const persist = (): void => {
    saveState(data.value)
    lastSavedAt.value = new Date().toISOString()
  }

  const appendAudit = (
    entityType: string,
    entityId: string,
    action: string,
    detail: string,
  ): void => {
    const event: AuditEvent = {
      id: createId('aud'),
      entityType,
      entityId,
      action,
      actor: '当前用户',
      createdAt: new Date().toISOString(),
      detail,
    }
    data.value.audit.unshift(event)
  }

  const saveEntity = (collection: CollectionKey, item: IdentifiedEntity): void => {
    const target = data.value[collection] as unknown as IdentifiedEntity[]
    const index = target.findIndex((entry) => entry.id === item.id)
    if (index >= 0) {
      target[index] = item
    } else {
      target.unshift(item)
    }
    const label = 'name' in item && typeof item.name === 'string' ? item.name : item.id
    appendAudit(collection, item.id, index >= 0 ? '更新' : '新增', `${label} 已保存`)
    persist()
  }

  const removeEntity = (collection: CollectionKey, id: string): void => {
    const target = data.value[collection] as unknown as IdentifiedEntity[]
    const index = target.findIndex((entry) => entry.id === id)
    if (index < 0) return
    target.splice(index, 1)
    appendAudit(collection, id, '删除', '记录已从当前版本移除')
    persist()
  }

  const updateBoundary = (boundary: ThreatModelState['boundary']): void => {
    data.value.boundary = boundary
    appendAudit('boundary', boundary.id, '更新', `${boundary.name} 的系统边界已更新`)
    persist()
  }

  const saveThreat = (threat: Threat): void => {
    saveEntity('threats', threat)
  }

  /**
   * 冻结新版本：模型内容与三方会签意见一起留档；重审范围基于当前生效基线
   * 与现模型的内容比对自动算出，调用方可以在此基础上增删，但不允许为空。
   */
  const createVersion = (
    label: string,
    notes: string,
    affectedThreatIds?: string[],
  ): VersionSnapshot => {
    const previous = activeBaseline.value
    const scopeIds =
      affectedThreatIds && affectedThreatIds.length > 0
        ? affectedThreatIds
        : previewReviewScope(data.value, previous).reviewThreatIds

    const revision = data.value.currentRevision + 1
    const snapshot: VersionSnapshot = {
      id: createId('ver'),
      revision,
      label,
      createdAt: new Date().toISOString(),
      author: '当前用户',
      notes,
      // 旧编号字段同步保留，旧版界面与降级比对仍可读。
      threatIds: data.value.threats.map((threat) => threat.id),
      componentIds: data.value.components.map((component) => component.id),
      flowIds: data.value.flows.map((flow) => flow.id),
      controlIds: data.value.controls.map((control) => control.id),
      riskIds: data.value.risks.map((risk) => risk.id),
      affectedThreatIds: scopeIds,
      // 新结构：冻结时刻的完整模型内容 + 三方意见留档。
      baseline: freezeBaseline(data.value),
      decisions: freezeDecisions(data.value),
      baselineStatus: 'frozen',
    }
    data.value.currentRevision = revision
    data.value.versions.unshift(snapshot)
    data.value.activeBaselineVersionId = snapshot.id
    data.value.threats = data.value.threats.map((threat) => {
      if (!scopeIds.includes(threat.id)) {
        return { ...threat, revision }
      }
      return { ...threat, revision, reviewStatus: 'in_review' as const }
    })
    appendAudit(
      'version',
      snapshot.id,
      '创建版本',
      `${label} 已冻结模型基线与会签意见，${scopeIds.length} 条威胁进入重新审核`,
    )
    persist()
    return snapshot
  }

  /**
   * 把一条旧版编号记录补成新结构。单条独立处理、独立落盘：
   * 中途失败只标记该条 failed 并保留错误信息，其余记录与下次重试不受影响。
   */
  const migrateVersion = (versionId: string): { ok: boolean; error?: string } => {
    const index = data.value.versions.findIndex((version) => version.id === versionId)
    if (index < 0) return { ok: false, error: '版本不存在' }
    const snapshot = data.value.versions[index]
    if (baselineStatus(snapshot) === 'frozen') return { ok: true }

    try {
      const reconstructed = reconstructLegacyBaseline(snapshot, data.value)
      const baseline = reconstructed.baseline
      const stillMissing =
        snapshot.threatIds.some((id) => !baseline.threats.some((item) => item.id === id)) ||
        snapshot.componentIds.some((id) => !baseline.components.some((item) => item.id === id)) ||
        snapshot.flowIds.some((id) => !baseline.flows.some((item) => item.id === id)) ||
        snapshot.controlIds.some((id) => !baseline.controls.some((item) => item.id === id)) ||
        snapshot.riskIds.some((id) => !baseline.risks.some((item) => item.id === id))
      data.value.versions[index] = {
        ...snapshot,
        ...reconstructed,
        baselineStatus: stillMissing ? 'legacy_partial' : 'frozen',
        migratedAt: new Date().toISOString(),
        migrationError: undefined,
      }
      persist()
      return { ok: true }
    } catch (error) {
      data.value.versions[index] = {
        ...snapshot,
        baselineStatus: 'failed',
        migrationError: error instanceof Error ? error.message : String(error),
      }
      persist()
      return { ok: false, error: data.value.versions[index].migrationError }
    }
  }

  /** 首次进入版本页时逐条补档；任意一条失败都可以中断，已成功的条目不回滚。 */
  const migrateLegacyVersions = (): { succeeded: number; failed: number } => {
    let succeeded = 0
    let failed = 0
    const pendingIds = data.value.versions
      .filter((version) => baselineStatus(version) !== 'frozen')
      .map((version) => version.id)
    pendingIds.forEach((versionId) => {
      const result = migrateVersion(versionId)
      if (result.ok) succeeded += 1
      else failed += 1
    })
    if (succeeded > 0 || failed > 0) {
      appendAudit(
        'version',
        'legacy-baseline-migration',
        '旧基线补档',
        `旧版本记录补成新结构：成功 ${succeeded} 条${failed > 0 ? `，失败 ${failed} 条（可重试）` : ''}`,
      )
      persist()
    }
    return { succeeded, failed }
  }

  /** 创建新版本对话框预选：给出当前生效基线到现模型的重审范围。 */
  const previewScope = (): BaselineComparison =>
    previewReviewScope(data.value, activeBaseline.value)

  const compareVersion = (fromId: string, toId: string): BaselineComparison | null => {
    const from = data.value.versions.find((version) => version.id === fromId)
    const to = data.value.versions.find((version) => version.id === toId)
    if (!from || !to) return null
    return compareBaselines(from, to)
  }

  /**
   * 回滚到选中版本：只恢复该基线冻结的建模对象与其归档意见，
   * 不删除任何更新版本、不改写后续批注（意见只增补不覆盖）、不动既有审计轨迹，
   * 仅追加一条回滚审计并把生效基线指向切到选中版本。
   */
  const rollbackToVersion = (versionId: string): { ok: boolean; error?: string } => {
    const snapshot = data.value.versions.find((version) => version.id === versionId)
    if (!snapshot) return { ok: false, error: '版本不存在' }
    if (!snapshot.baseline) return { ok: false, error: '该版本尚未补成新结构，请先补档' }

    const restored = snapshot.baseline
    data.value.boundary = structuredClone(restored.boundary)
    data.value.zones = structuredClone(restored.zones)
    data.value.components = structuredClone(restored.components)
    data.value.dependencies = structuredClone(restored.dependencies)
    data.value.flows = structuredClone(restored.flows)
    data.value.controls = structuredClone(restored.controls)
    data.value.evidence = structuredClone(restored.evidence)
    data.value.threats = structuredClone(restored.threats)
    data.value.attackPaths = structuredClone(restored.attackPaths)
    data.value.risks = structuredClone(restored.risks)
    data.value.mitigations = structuredClone(restored.mitigations)

    // 归档意见只增补：现存意见（后续批注）一律保留，已不存在的旧意见按原 id 补回。
    const liveDecisionIds = new Set(data.value.decisions.map((decision) => decision.id))
    const archived = (snapshot.decisions ?? []).filter(
      (decision) => !liveDecisionIds.has(decision.id),
    )
    if (archived.length > 0) data.value.decisions.unshift(...structuredClone(archived))

    data.value.activeBaselineVersionId = snapshot.id
    // currentRevision 不回退：下次建版仍单调递增，避免撞掉进行中的会签轮次。
    appendAudit(
      'version',
      snapshot.id,
      '回滚基线',
      `建模内容已恢复到 ${snapshot.label}；后续批注与审计记录均保留，更新版本未被删除`,
    )
    persist()
    return { ok: true }
  }

  const submitDecision = (
    threatId: string,
    role: ActorRole,
    decision: DecisionType,
    actor: string,
    comment: string,
  ): void => {
    const threat = data.value.threats.find((item) => item.id === threatId)
    if (!threat) return
    data.value.decisions = data.value.decisions.filter(
      (item) => !(item.threatId === threatId && item.role === role && item.revision === threat.revision),
    )
    data.value.decisions.unshift({
      id: createId('dec'),
      threatId,
      role,
      actor,
      decision,
      comment,
      createdAt: new Date().toISOString(),
      revision: threat.revision,
    })

    const currentDecisions = decisionsForThreat(data.value.decisions, threatId, threat.revision)
    const requiredRoles: ActorRole[] = ['development', 'security', 'business']
    const allSubmitted = requiredRoles.every((requiredRole) =>
      currentDecisions.some((item) => item.role === requiredRole),
    )
    if (currentDecisions.some((item) => item.decision === 'rejected')) {
      threat.reviewStatus = 'rejected'
    } else if (
      allSubmitted &&
      currentDecisions.every((item) => item.decision === 'approved')
    ) {
      threat.reviewStatus = 'approved'
    } else {
      threat.reviewStatus = 'in_review'
    }

    const decisionLabel: Record<DecisionType, string> = {
      accept: '接受',
      degrade: '降级',
      evidence_required: '要求补证',
      approved: '会签通过',
      rejected: '驳回',
    }
    appendAudit(
      'threat',
      threatId,
      decisionLabel[decision],
      `${actor}（${role}）提交会签意见`,
    )
    persist()
  }

  const updateMitigationStatus = (
    taskId: string,
    status: ThreatModelState['mitigations'][number]['status'],
  ): void => {
    const task = data.value.mitigations.find((item) => item.id === taskId)
    if (!task) return
    task.status = status
    appendAudit('mitigation', task.id, '更新状态', `${task.title} 更新为 ${status}`)
    persist()
  }

  const acceptRisk = (riskId: string, expiresAt: string, condition: string): void => {
    const risk = data.value.risks.find((item) => item.id === riskId)
    if (!risk) return
    risk.status = 'accepted'
    risk.acceptanceExpiresAt = expiresAt
    risk.acceptanceCondition = condition
    appendAudit('risk', risk.id, '接受风险', `接受有效至 ${expiresAt}：${condition}`)
    persist()
  }

  const closeRisk = (riskId: string): void => {
    const risk = data.value.risks.find((item) => item.id === riskId)
    if (!risk) return
    risk.status = 'closed'
    appendAudit('risk', risk.id, '关闭风险', '风险已关闭并从开放风险中移除')
    persist()
  }

  const resetDemo = (): void => {
    data.value = resetState()
    lastSavedAt.value = new Date().toISOString()
  }

  const exportReport = (): string => {
    const lines = [
      `# ${data.value.boundary.name} 威胁建模报告`,
      '',
      `生成时间：${new Date().toISOString()}`,
      `当前版本：v1.${data.value.currentRevision}`,
      `建模范围：${data.value.boundary.inScope}`,
      `排除范围：${data.value.boundary.outOfScope}`,
      '',
      '## 风险摘要',
      `- 资产与组件：${data.value.components.length}`,
      `- 威胁：${data.value.threats.length}`,
      `- 开放关键威胁：${metrics.value.critical}`,
      `- 威胁覆盖率：${metrics.value.coverage}%`,
      `- 待处理校验问题：${issues.value.length}`,
      '',
      '## 威胁清单',
      ...data.value.threats.map(
        (threat) =>
          `- ${threat.code} [${threat.severity}/${threat.reviewStatus}] ${threat.title}：${threat.description}`,
      ),
      '',
      '## 风险接受',
      ...data.value.risks
        .filter((risk) => risk.status === 'accepted')
        .map(
          (risk) =>
            `- ${risk.code} ${risk.title}，有效至 ${risk.acceptanceExpiresAt ?? '未设置'}，条件：${risk.acceptanceCondition ?? '未填写'}`,
        ),
      '',
      '## 校验问题',
      ...issues.value.map((issue) => `- [${issue.severity}] ${issue.title}：${issue.detail}`),
      '',
      '## 会签记录',
      ...data.value.decisions.map(
        (decision) =>
          `- ${decision.createdAt} ${decision.actor}（${decision.role}）${decision.decision}：${decision.comment}`,
      ),
    ]
    return lines.join('\n')
  }

  return {
    data,
    lastSavedAt,
    metrics,
    issues,
    pendingReviews,
    activeBaseline,
    saveEntity,
    removeEntity,
    updateBoundary,
    saveThreat,
    createVersion,
    migrateVersion,
    migrateLegacyVersions,
    previewScope,
    compareVersion,
    rollbackToVersion,
    submitDecision,
    updateMitigationStatus,
    acceptRisk,
    closeRisk,
    resetDemo,
    exportReport,
    reviewProgress,
  }
})

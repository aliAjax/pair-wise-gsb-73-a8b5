import { computed, ref, toRaw } from 'vue'
import { defineStore } from 'pinia'
import type {
  ActorRole,
  AuditEvent,
  DecisionType,
  Threat,
  ThreatModelState,
  VersionSnapshot,
} from '@/models/domain'
import {
  BASELINE_MIGRATION_STEPS,
  computeAffectedThreats,
  freezeBaseline,
  migrateSnapshotBaseline,
} from '@/services/baseline'
import { createId, loadState, resetState, saveState } from '@/services/repository'
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

  const ensureVersionBaseline = (versionId: string): VersionSnapshot | null => {
    const snapshot = data.value.versions.find((version) => version.id === versionId)
    if (!snapshot || snapshot.baseline) return snapshot ?? null
    migrateSnapshotBaseline(snapshot, data.value)
    if (snapshot.baseline) {
      appendAudit(
        'version',
        snapshot.id,
        '基线升级',
        `${snapshot.label} 已补全为完整基线（模型内容与三方意见留档）`,
      )
    } else {
      appendAudit(
        'version',
        snapshot.id,
        '基线升级中断',
        `${snapshot.label} 升级未完成：${snapshot.migration?.error ?? '未知原因'}，可从断点继续`,
      )
    }
    persist()
    return snapshot
  }

  const previewAffectedThreats = (): string[] => {
    const previous = data.value.versions[0]
    if (!previous) return data.value.threats.map((threat) => threat.id)
    ensureVersionBaseline(previous.id)
    if (!previous.baseline) return data.value.threats.map((threat) => threat.id)
    return computeAffectedThreats(previous.baseline, freezeBaseline(data.value))
  }

  const createVersion = (
    label: string,
    notes: string,
    manualAffectedThreatIds: string[] = [],
  ): VersionSnapshot => {
    const revision = data.value.currentRevision + 1
    const previous = data.value.versions[0]
    if (previous) ensureVersionBaseline(previous.id)
    const baseline = freezeBaseline(data.value)
    const autoAffected = previous?.baseline
      ? computeAffectedThreats(previous.baseline, baseline)
      : data.value.threats.map((threat) => threat.id)
    const affectedThreatIds = [...new Set([...autoAffected, ...manualAffectedThreatIds])]
    const snapshot: VersionSnapshot = {
      id: createId('ver'),
      revision,
      label,
      createdAt: new Date().toISOString(),
      author: '当前用户',
      notes,
      threatIds: data.value.threats.map((threat) => threat.id),
      componentIds: data.value.components.map((component) => component.id),
      flowIds: data.value.flows.map((flow) => flow.id),
      controlIds: data.value.controls.map((control) => control.id),
      riskIds: data.value.risks.map((risk) => risk.id),
      affectedThreatIds,
      baseline,
      migration: {
        status: 'done',
        completedSteps: [...BASELINE_MIGRATION_STEPS],
        updatedAt: new Date().toISOString(),
      },
    }
    data.value.currentRevision = revision
    data.value.versions.unshift(snapshot)
    data.value.threats = data.value.threats.map((threat) => {
      if (!affectedThreatIds.includes(threat.id)) {
        return threat
      }
      return { ...threat, revision, reviewStatus: 'in_review' }
    })
    appendAudit(
      'version',
      snapshot.id,
      '创建版本',
      `${label} 已创建并冻结基线，${affectedThreatIds.length} 条威胁进入重新审核，未受影响威胁的会签保持不变`,
    )
    persist()
    return snapshot
  }

  const rollbackToVersion = (versionId: string): VersionSnapshot | null => {
    const snapshot = ensureVersionBaseline(versionId)
    if (!snapshot?.baseline) return null
    const baseline = snapshot.baseline
    const affectedThreatIds = computeAffectedThreats(freezeBaseline(data.value), baseline)
    const currentThreats = new Map(data.value.threats.map((threat) => [threat.id, threat]))

    data.value.threats = baseline.threats.map((frozen) => {
      const restored = structuredClone(toRaw(frozen))
      const current = currentThreats.get(frozen.id)
      if (current) {
        restored.revision = current.revision
      }
      if (affectedThreatIds.includes(frozen.id)) {
        restored.reviewStatus = 'in_review'
      } else if (current) {
        restored.reviewStatus = current.reviewStatus
      }
      return restored
    })
    data.value.components = baseline.components.map((item) => structuredClone(toRaw(item)))
    data.value.flows = baseline.flows.map((item) => structuredClone(toRaw(item)))
    data.value.controls = baseline.controls.map((item) => structuredClone(toRaw(item)))
    data.value.risks = baseline.risks.map((item) => structuredClone(toRaw(item)))
    appendAudit(
      'version',
      snapshot.id,
      '回滚版本',
      `模型内容已恢复至 ${snapshot.label}，${affectedThreatIds.length} 条威胁需重新审核；既有会签批注与审计轨迹保持不变`,
    )
    persist()
    return snapshot
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
    saveEntity,
    removeEntity,
    updateBoundary,
    saveThreat,
    createVersion,
    rollbackToVersion,
    ensureVersionBaseline,
    previewAffectedThreats,
    submitDecision,
    updateMitigationStatus,
    acceptRisk,
    closeRisk,
    resetDemo,
    exportReport,
    reviewProgress,
  }
})

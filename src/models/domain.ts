export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type ReviewStatus = 'draft' | 'in_review' | 'approved' | 'rejected'
export type ThreatStatus = 'open' | 'mitigating' | 'mitigated' | 'accepted'
export type ControlStatus = 'effective' | 'degraded' | 'failed' | 'planned'
export type ActorRole = 'development' | 'security' | 'business'
export type DecisionType = 'accept' | 'degrade' | 'evidence_required' | 'approved' | 'rejected'

export interface SystemBoundary {
  id: string
  name: string
  description: string
  owner: string
  inScope: string
  outOfScope: string
}

export interface TrustZone {
  id: string
  name: string
  level: 'internet' | 'dmz' | 'internal' | 'restricted'
  description: string
}

export interface ArchitectureComponent {
  id: string
  name: string
  type: 'service' | 'asset' | 'data_store' | 'gateway' | 'client'
  zoneId: string
  criticality: Severity
  owner: string
  description: string
}

export interface ExternalDependency {
  id: string
  name: string
  vendor: string
  purpose: string
  dataClass: 'public' | 'internal' | 'confidential' | 'restricted'
  owner: string
  status: 'active' | 'review_due' | 'retired'
}

export interface DataFlow {
  id: string
  name: string
  sourceId: string
  targetId: string
  protocol: string
  dataClass: 'public' | 'internal' | 'confidential' | 'restricted'
  crossesTrustBoundary: boolean
  description: string
}

export interface ControlEvidence {
  id: string
  controlId: string
  title: string
  kind: 'test' | 'config' | 'ticket' | 'scan' | 'attestation'
  reference: string
  collectedAt: string
  expiresAt: string
  owner: string
  valid: boolean
}

export interface SecurityControl {
  id: string
  name: string
  type: 'preventive' | 'detective' | 'corrective'
  status: ControlStatus
  owner: string
  componentId: string
  description: string
  evidenceIds: string[]
}

export interface AttackPath {
  id: string
  name: string
  entryPoint: string
  target: string
  steps: string[]
  likelihood: 1 | 2 | 3 | 4 | 5
}

export interface Risk {
  id: string
  code: string
  title: string
  likelihood: 1 | 2 | 3 | 4 | 5
  impact: 1 | 2 | 3 | 4 | 5
  status: 'open' | 'mitigating' | 'accepted' | 'closed'
  owner: string
  acceptanceExpiresAt?: string
  acceptanceCondition?: string
}

export interface Threat {
  id: string
  code: string
  title: string
  category: 'spoofing' | 'tampering' | 'repudiation' | 'information_disclosure' | 'denial_of_service' | 'elevation'
  description: string
  severity: Severity
  status: ThreatStatus
  componentIds: string[]
  flowIds: string[]
  externalDependencyIds: string[]
  attackPathIds: string[]
  controlIds: string[]
  riskIds: string[]
  reviewStatus: ReviewStatus
  revision: number
}

export interface MitigationTask {
  id: string
  threatId: string
  title: string
  owner: string
  dueAt: string
  status: 'todo' | 'in_progress' | 'verifying' | 'done'
  action: 'restrict' | 'monitor' | 'encrypt' | 'isolate' | 'allow_with_condition'
  detail: string
  evidenceIds: string[]
  conflictGroup?: string
}

export interface ReviewDecision {
  id: string
  threatId: string
  actor: string
  role: ActorRole
  decision: DecisionType
  comment: string
  createdAt: string
  revision: number
}

/**
 * 基线冻结时完整留档的模型内容。
 * 与 ThreatModelState 分离：只包含建模对象，不含会签意见（意见单独留档）、
 * 版本历史与审计轨迹（这些记录在任何回滚中都不允许被改写）。
 */
export interface BaselinePayload {
  boundary: SystemBoundary
  zones: TrustZone[]
  components: ArchitectureComponent[]
  dependencies: ExternalDependency[]
  flows: DataFlow[]
  controls: SecurityControl[]
  evidence: ControlEvidence[]
  threats: Threat[]
  attackPaths: AttackPath[]
  risks: Risk[]
  mitigations: MitigationTask[]
}

/**
 * - frozen：新结构，建版本时已把模型内容与三方意见完整冻结
 * - legacy_pending：旧版记录（只有编号），等待第一次使用时补档
 * - legacy_partial：旧版记录已按当前模型尽力补档，跨版本比对只能得到不完整结果
 * - failed：上次补档中途失败，记录保持原样，可随时重试
 */
export type BaselineMigrationStatus =
  | 'frozen'
  | 'legacy_pending'
  | 'legacy_partial'
  | 'failed'

export interface VersionSnapshot {
  id: string
  revision: number
  label: string
  createdAt: string
  author: string
  notes: string
  /** 旧结构保留字段：编号清单，旧记录兼容与降级比对仍会使用。 */
  threatIds: string[]
  componentIds: string[]
  flowIds: string[]
  controlIds: string[]
  riskIds: string[]
  affectedThreatIds: string[]
  /** 新结构：冻结时刻的完整模型内容；旧记录补档成功后才有值。 */
  baseline?: BaselinePayload | null
  /** 冻结时刻归档的三方会签意见，回滚时只增补、不覆盖任何现存意见。 */
  decisions?: ReviewDecision[]
  /** 留档结构状态；历史 localStorage 中没有该字段的记录按 legacy_pending 处理。 */
  baselineStatus?: BaselineMigrationStatus
  migratedAt?: string
  migrationError?: string
}

export interface AuditEvent {
  id: string
  entityType: string
  entityId: string
  action: string
  actor: string
  createdAt: string
  detail: string
}

export interface ThreatModelState {
  boundary: SystemBoundary
  zones: TrustZone[]
  components: ArchitectureComponent[]
  dependencies: ExternalDependency[]
  flows: DataFlow[]
  controls: SecurityControl[]
  evidence: ControlEvidence[]
  threats: Threat[]
  attackPaths: AttackPath[]
  risks: Risk[]
  mitigations: MitigationTask[]
  decisions: ReviewDecision[]
  versions: VersionSnapshot[]
  audit: AuditEvent[]
  currentRevision: number
  /** 当前生效基线指向的版本；回滚只改这个指向，不删除任何更新版本。 */
  activeBaselineVersionId?: string
}

export interface ValidationIssue {
  id: string
  kind: 'uncovered_component' | 'control_failed' | 'risk_acceptance_expired' | 'mitigation_conflict' | 'missing_evidence'
  severity: Severity
  title: string
  detail: string
  entityId: string
}

export type BaselineEntityCategory =
  | 'boundary'
  | 'zone'
  | 'component'
  | 'dependency'
  | 'flow'
  | 'control'
  | 'evidence'
  | 'threat'
  | 'attackPath'
  | 'risk'
  | 'mitigation'

export interface BaselineEntityChange {
  category: BaselineEntityCategory
  id: string
  changeType: 'added' | 'removed' | 'modified'
  /** 修改类差异对应的变化字段（新增/删除为空）。 */
  fields?: string[]
  /** 冻结基线中解析出的对象名称，避免对象删除后无法展示。 */
  name?: string
}

export interface ReviewScopeItem {
  threatId: string
  /** 该条威胁需要重审的具体原因，来自前后基线的内容级比对。 */
  reasons: string[]
}

export interface BaselineComparison {
  changes: BaselineEntityChange[]
  reviewScope: ReviewScopeItem[]
  reviewThreatIds: string[]
  /** 参与比对的版本没有内容基线，退化为编号比对。 */
  legacyFallback: boolean
  /** 结果不完整（补档基线或编号比对），范围仅作参考。 */
  incomplete: boolean
}

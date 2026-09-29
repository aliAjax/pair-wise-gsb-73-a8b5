<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import MultiSelect from 'primevue/multiselect'
import Textarea from 'primevue/textarea'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import PageHeader from '@/components/PageHeader.vue'
import type {
  BaselineEntityChange,
  ReviewScopeItem,
  VersionSnapshot,
} from '@/models/domain'
import { baselineStatus, categoryLabel, resolveBaselineName } from '@/services/baseline'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()
const toast = useToast()
const confirm = useConfirm()

// 版本按 revision 倒序：建版时 unshift 到表头，比较基准应是更早的版本。
const versions = computed(() =>
  [...store.data.versions].sort((a, b) => b.revision - a.revision),
)
const fromVersionId = ref(versions.value[1]?.id ?? versions.value[0]?.id ?? '')
const toVersionId = ref(versions.value[0]?.id ?? '')
const createVisible = ref(false)
const createForm = reactive({
  label: '',
  notes: '',
  affectedThreatIds: [] as string[],
})
const suggestedScope = ref<ReviewScopeItem[]>([])

const fromVersion = computed(
  () => store.data.versions.find((version) => version.id === fromVersionId.value) ?? null,
)
const toVersion = computed(
  () => store.data.versions.find((version) => version.id === toVersionId.value) ?? null,
)
const difference = computed(() =>
  fromVersion.value && toVersion.value
    ? store.compareVersion(fromVersion.value.id, toVersion.value.id)
    : null,
)

const statusMeta: Record<string, { label: string; className: string }> = {
  frozen: { label: '已冻结', className: 'status-frozen' },
  legacy_pending: { label: '待补档', className: 'status-pending' },
  legacy_partial: { label: '部分补档', className: 'status-partial' },
  failed: { label: '补档失败', className: 'status-failed' },
}

const changeGroups = computed(() => {
  const changes = difference.value?.changes ?? []
  return {
    added: changes.filter((change) => change.changeType === 'added'),
    removed: changes.filter((change) => change.changeType === 'removed'),
    modified: changes.filter((change) => change.changeType === 'modified'),
  }
})

const currentName = (category: BaselineEntityChange['category'], id: string): string | undefined => {
  const collections = {
    boundary: [store.data.boundary],
    zone: store.data.zones,
    component: store.data.components,
    dependency: store.data.dependencies,
    flow: store.data.flows,
    control: store.data.controls,
    evidence: store.data.evidence,
    threat: store.data.threats,
    attackPath: store.data.attackPaths,
    risk: store.data.risks,
    mitigation: store.data.mitigations,
  } as const
  const item = collections[category].find((entry) => entry.id === id)
  if (!item) return undefined
  return 'name' in item ? item.name : 'title' in item ? item.title : id
}

const changeText = (change: BaselineEntityChange): string => {
  const name =
    change.name ??
    resolveBaselineName(toVersion.value?.baseline, change.category, change.id) ??
    resolveBaselineName(fromVersion.value?.baseline, change.category, change.id) ??
    currentName(change.category, change.id) ??
    change.id
  const fields = change.fields?.length ? `（${change.fields.join('、')}）` : ''
  return `${categoryLabel(change.category)}：${name}${fields}`
}

const scopeThreatTitle = (threatId: string): string => {
  const threat = store.data.threats.find((item) => item.id === threatId)
  return threat ? `${threat.code} ${threat.title}` : threatId
}

const runMigration = (versionIds: string[], silent = false): void => {
  let failed = 0
  versionIds.forEach((versionId) => {
    const result = store.migrateVersion(versionId)
    if (!result.ok) failed += 1
  })
  if (silent) return
  if (failed > 0) {
    toast.add({
      severity: 'warn',
      summary: '部分旧基线补档失败',
      detail: `${failed} 条记录补档未完成，可在版本历史中重试，不影响其他记录`,
      life: 3500,
    })
  } else if (versionIds.length > 0) {
    toast.add({ severity: 'success', summary: '旧基线补档完成', detail: '旧版本已补齐内容留档', life: 2500 })
  }
}

// 第一次进入版本页：把旧编号记录逐条补成新结构，失败的保留状态可继续。
onMounted(() => {
  const { succeeded, failed } = store.migrateLegacyVersions()
  if (failed > 0) {
    toast.add({
      severity: 'warn',
      summary: '部分旧基线补档失败',
      detail: `${failed} 条记录补档未完成，可在版本历史中重试，不影响其他记录`,
      life: 3500,
    })
  } else if (succeeded > 0) {
    toast.add({ severity: 'success', summary: '旧基线补档完成', detail: '旧版本已补齐内容留档', life: 2500 })
  }
})

// 比较时若选中的记录还没补成新结构，先按需补档；失败则自动退化为编号比对。
watch([fromVersionId, toVersionId], () => {
  const legacyIds = [fromVersionId.value, toVersionId.value].filter((id) => {
    const version = store.data.versions.find((item) => item.id === id)
    return version && baselineStatus(version) !== 'frozen'
  })
  if (legacyIds.length) runMigration(legacyIds, true)
})

const openCreate = (): void => {
  const preview = store.previewScope()
  suggestedScope.value = preview.reviewScope
  createForm.label = `v1.${store.data.currentRevision + 1} 变更评审`
  createForm.notes = ''
  createForm.affectedThreatIds = [...preview.reviewThreatIds]
  createVisible.value = true
}

const createVersion = (): void => {
  if (!createForm.label.trim() || !createForm.notes.trim()) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '版本名称和变更说明不能为空', life: 3000 })
    return
  }
  if (createForm.affectedThreatIds.length === 0) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '至少保留一条需要重审的威胁', life: 3000 })
    return
  }
  const snapshot = store.createVersion(
    createForm.label,
    createForm.notes,
    createForm.affectedThreatIds,
  )
  fromVersionId.value = toVersionId.value
  toVersionId.value = snapshot.id
  createVisible.value = false
  toast.add({ severity: 'success', summary: '基线已冻结', detail: '模型内容与三方意见已一并留档', life: 3000 })
}

const rollback = (snapshot: VersionSnapshot): void => {
  confirm.require({
    header: '回滚到选中基线',
    message: `将把建模内容恢复到「${snapshot.label}」。仅恢复该版本冻结的模型对象与其归档意见；更新版本不会被删除，之后新增的批注与审计记录全部保留，审计仅追加一条回滚记录。是否继续？`,
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: '确认回滚',
    rejectLabel: '取消',
    accept: () => {
      const result = store.rollbackToVersion(snapshot.id)
      if (!result.ok) {
        toast.add({ severity: 'error', summary: '无法回滚', detail: result.error ?? '回滚失败', life: 3500 })
        return
      }
      fromVersionId.value = snapshot.id
      toVersionId.value = versions.value[0]?.id ?? snapshot.id
      toast.add({
        severity: 'success',
        summary: '基线已回滚',
        detail: `${snapshot.label} 成为生效基线，批注与后续审计未被改写`,
        life: 3500,
      })
    },
  })
}

const approvalLabel = (snapshot: VersionSnapshot): string =>
  `${snapshot.affectedThreatIds.filter((id) => {
    const threat = store.data.threats.find((item) => item.id === id)
    return threat?.reviewStatus === 'approved'
  }).length}/${snapshot.affectedThreatIds.length}`
</script>

<template>
  <div class="page">
    <PageHeader
      eyebrow="审计与基线"
      title="基线冻结与升级"
      description="建版本时冻结完整模型内容与三方意见，按前后基线内容级比对确定重审范围；回滚只恢复选中版本。"
    />

    <section class="panel">
      <div class="panel-header">
        <h2 class="panel-title">基线比较</h2>
        <Button label="冻结新版本" icon="pi pi-snowflake" @click="openCreate" />
      </div>
      <div class="compare-toolbar">
        <div class="version-select">
          <span>基准版本</span>
          <select v-model="fromVersionId">
            <option v-for="version in versions" :key="version.id" :value="version.id">
              {{ version.label }}
            </option>
          </select>
        </div>
        <i class="pi pi-arrow-right"></i>
        <div class="version-select">
          <span>目标版本</span>
          <select v-model="toVersionId">
            <option v-for="version in versions" :key="version.id" :value="version.id">
              {{ version.label }}
            </option>
          </select>
        </div>
      </div>

      <div v-if="difference?.incomplete" class="legacy-banner">
        <i class="pi pi-info-circle"></i>
        <span>参与比较的版本为旧编号记录补档结果，以下差异与重审范围仅按编号/登记值推断，内容级变化不完整。</span>
      </div>

      <div class="diff-columns diff-padding">
        <div class="diff-block added-block">
          <h4>新增项（{{ changeGroups.added.length }}）</h4>
          <ul v-if="changeGroups.added.length">
            <li v-for="change in changeGroups.added" :key="`${change.category}-${change.id}`">
              {{ changeText(change) }}
            </li>
          </ul>
          <span v-else class="muted">无新增项</span>
        </div>
        <div class="diff-block removed-block">
          <h4>移除项（{{ changeGroups.removed.length }}）</h4>
          <ul v-if="changeGroups.removed.length">
            <li v-for="change in changeGroups.removed" :key="`${change.category}-${change.id}`">
              {{ changeText(change) }}
            </li>
          </ul>
          <span v-else class="muted">无移除项</span>
        </div>
        <div class="diff-block modified-block">
          <h4>内容修改（{{ changeGroups.modified.length }}）</h4>
          <ul v-if="changeGroups.modified.length">
            <li v-for="change in changeGroups.modified" :key="`${change.category}-${change.id}`">
              {{ changeText(change) }}
            </li>
          </ul>
          <span v-else class="muted">无内容修改</span>
        </div>
      </div>

      <div class="changed-list">
        <div class="scope-head">
          <h4>需要重新会签的范围</h4>
          <span class="muted">{{ difference?.reviewThreatIds.length ?? 0 }} 条威胁</span>
        </div>
        <ul v-if="difference?.reviewScope.length" class="scope-list">
          <li v-for="item in difference.reviewScope" :key="item.threatId">
            <strong>{{ scopeThreatTitle(item.threatId) }}</strong>
            <span v-for="reason in item.reasons" :key="reason" class="scope-reason">
              <i class="pi pi-arrow-right"></i>{{ reason }}
            </span>
          </li>
        </ul>
        <span v-else class="muted">两个基线内容一致，无需重新会签。</span>
      </div>
    </section>

    <div class="versions-grid">
      <section class="panel">
        <div class="panel-header">
          <h2 class="panel-title">版本历史</h2>
        </div>
        <DataTable :value="versions" dataKey="id" size="small" stripedRows>
          <Column header="版本" style="width: 170px">
            <template #body="{ data }">
              <strong>{{ data.label }}</strong>
              <div class="mono">r{{ data.revision }}</div>
              <span v-if="store.data.activeBaselineVersionId === data.id" class="active-badge">生效中</span>
            </template>
          </Column>
          <Column header="留档状态" style="width: 110px">
            <template #body="{ data }">
              <span class="freeze-status" :class="statusMeta[baselineStatus(data)].className">
                {{ statusMeta[baselineStatus(data)].label }}
              </span>
              <Button
                v-if="baselineStatus(data) !== 'frozen'"
                link
                severity="secondary"
                icon="pi pi-refresh"
                style="margin-left: 4px"
                @click="runMigration([data.id])"
              />
            </template>
          </Column>
          <Column header="创建时间" style="width: 120px">
            <template #body="{ data }">
              {{ new Date(data.createdAt).toLocaleDateString('zh-CN') }}
            </template>
          </Column>
          <Column header="受影响" style="width: 70px">
            <template #body="{ data }">{{ data.affectedThreatIds.length }} 条</template>
          </Column>
          <Column header="通过" style="width: 70px">
            <template #body="{ data }">{{ approvalLabel(data) }}</template>
          </Column>
          <Column field="notes" header="说明" />
          <Column header="操作" style="width: 110px">
            <template #body="{ data }">
              <Button
                size="small"
                outlined
                severity="warn"
                label="回滚"
                :disabled="!data.baseline"
                @click="rollback(data)"
              />
            </template>
          </Column>
        </DataTable>
      </section>

      <section class="panel audit-panel">
        <div class="panel-header">
          <h2 class="panel-title">审计轨迹</h2>
          <span class="muted">{{ store.data.audit.length }} 条</span>
        </div>
        <div class="audit-list">
          <article v-for="event in store.data.audit.slice(0, 12)" :key="event.id" class="audit-item">
            <i class="pi pi-circle-fill"></i>
            <div>
              <strong>{{ event.action }}</strong>
              <p>{{ event.detail }}</p>
              <span>{{ event.actor }} · {{ new Date(event.createdAt).toLocaleString('zh-CN') }}</span>
            </div>
          </article>
        </div>
      </section>
    </div>

    <Dialog v-model:visible="createVisible" header="冻结变更基线" modal :style="{ width: '760px' }">
      <div class="editor-form">
        <div class="field field-wide">
          <label>版本名称</label>
          <InputText v-model="createForm.label" />
        </div>
        <div class="field field-wide">
          <label>变更说明</label>
          <Textarea
            v-model="createForm.notes"
            rows="3"
            placeholder="说明架构、控制或风险发生的变更"
          />
        </div>
        <div class="field field-wide">
          <label>需要重审的威胁（已按基线差异预选，可调整）</label>
          <MultiSelect
            v-model="createForm.affectedThreatIds"
            :options="store.data.threats"
            option-label="title"
            option-value="id"
            display="chip"
            filter
            placeholder="只选择需要重新会签的威胁"
          />
          <div class="scope-preview">
            <template v-if="suggestedScope.length">
              <small class="muted">系统根据当前生效基线到现模型的内容比对，建议重审：</small>
              <ul>
                <li v-for="item in suggestedScope" :key="item.threatId">
                  <strong>{{ scopeThreatTitle(item.threatId) }}</strong>
                  <span v-for="reason in item.reasons" :key="reason">· {{ reason }}</span>
                </li>
              </ul>
            </template>
            <small v-else class="muted">与当前生效基线无内容差异；首个基线会把全部威胁纳入首版会签。</small>
          </div>
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="createVisible = false" />
        <Button label="冻结基线" icon="pi pi-snowflake" @click="createVersion" />
      </template>
    </Dialog>
  </div>
</template>

<style scoped>
.compare-toolbar {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 40px minmax(0, 1fr);
  align-items: end;
  gap: 10px;
  padding: 16px;
}

.compare-toolbar > i {
  display: grid;
  place-items: center;
  height: 38px;
  color: #6c7689;
}

.version-select {
  display: grid;
  gap: 6px;
}

.version-select span {
  color: #697489;
  font-size: 12px;
  font-weight: 600;
}

.version-select select {
  width: 100%;
  min-height: 39px;
  padding: 0 10px;
  border: 1px solid #ccd3dc;
  border-radius: 5px;
  color: #273247;
  background: #fff;
}

.legacy-banner {
  display: flex;
  gap: 9px;
  align-items: flex-start;
  margin: 0 16px 12px;
  padding: 10px 12px;
  border: 1px solid #e0c08a;
  border-radius: 6px;
  background: #fdf6e8;
  color: #805b16;
  font-size: 12px;
  line-height: 1.5;
}

.diff-padding {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
  padding: 0 16px 16px;
}

.added-block {
  border-left: 3px solid #2f8f69;
}

.removed-block {
  border-left: 3px solid #c64b39;
}

.modified-block {
  border-left: 3px solid #4c78a8;
}

.diff-block {
  padding: 10px 12px;
  background: #fafbfc;
  border-radius: 0 5px 5px 0;
}

.diff-block h4 {
  margin: 0 0 8px;
  font-size: 13px;
}

.diff-block ul {
  display: grid;
  gap: 5px;
  margin: 0;
  padding-left: 0;
  list-style: none;
}

.diff-block li {
  color: #46536a;
  font-size: 12px;
  line-height: 1.45;
}

.changed-list {
  padding: 0 16px 18px;
}

.scope-head {
  display: flex;
  align-items: baseline;
  gap: 10px;
}

.changed-list h4 {
  margin: 0 0 10px;
  font-size: 14px;
}

.scope-list {
  display: grid;
  gap: 10px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.scope-list > li {
  display: grid;
  gap: 4px;
  padding: 10px 12px;
  border: 1px solid #e4e9f0;
  border-radius: 6px;
  background: #fbfcfe;
}

.scope-list strong {
  font-size: 12px;
  color: #273247;
}

.scope-reason {
  display: flex;
  gap: 7px;
  color: #5d6a80;
  font-size: 11px;
}

.scope-reason i {
  margin-top: 3px;
  color: #4c78a8;
  font-size: 9px;
}

.freeze-status {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 11px;
  line-height: 1.6;
  white-space: nowrap;
}

.status-frozen {
  color: #1f6b4d;
  background: #e3f4ec;
}

.status-pending {
  color: #8a6116;
  background: #fdf0d5;
}

.status-partial {
  color: #8a4a16;
  background: #fbe6d2;
}

.status-failed {
  color: #a3392b;
  background: #fbe3df;
}

.active-badge {
  display: inline-block;
  margin-top: 3px;
  padding: 1px 7px;
  border-radius: 4px;
  color: #355e8f;
  background: #e8f0f9;
  font-size: 10px;
}

.scope-preview {
  margin-top: 8px;
  max-height: 180px;
  overflow: auto;
}

.scope-preview ul {
  margin: 6px 0 0;
  padding-left: 0;
  list-style: none;
}

.scope-preview li {
  display: grid;
  gap: 2px;
  padding: 6px 0;
  border-bottom: 1px dashed #e7ebf1;
  font-size: 11px;
}

.scope-preview li span {
  color: #738096;
}

.versions-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.45fr) minmax(320px, 0.55fr);
  gap: 16px;
  align-items: start;
}

.audit-list {
  padding: 8px 16px 14px;
}

.audit-item {
  position: relative;
  display: grid;
  grid-template-columns: 12px 1fr;
  gap: 10px;
  padding: 11px 0;
}

.audit-item::after {
  position: absolute;
  top: 28px;
  bottom: -10px;
  left: 4px;
  width: 1px;
  background: #dce2e9;
  content: "";
}

.audit-item:last-child::after {
  display: none;
}

.audit-item > i {
  margin-top: 5px;
  color: #5b83ad;
  font-size: 7px;
}

.audit-item strong {
  font-size: 12px;
}

.audit-item p {
  margin: 4px 0;
  color: #5f6a7e;
  font-size: 11px;
  line-height: 1.45;
}

.audit-item span {
  color: #8992a1;
  font-size: 10px;
}
</style>

<script setup lang="ts">
import { computed, reactive, ref, watchEffect } from 'vue'
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import MultiSelect from 'primevue/multiselect'
import Textarea from 'primevue/textarea'
import { useToast } from 'primevue/usetoast'
import PageHeader from '@/components/PageHeader.vue'
import type { VersionChange, VersionSnapshot } from '@/models/domain'
import { compareSnapshots } from '@/services/selectors'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()
const toast = useToast()
const fromVersionId = ref(store.data.versions[1]?.id ?? store.data.versions[0]?.id ?? '')
const toVersionId = ref(store.data.versions[0]?.id ?? '')
const createVisible = ref(false)
const autoAffectedIds = ref<string[]>([])
const createForm = reactive({
  label: '',
  notes: '',
  extraThreatIds: [] as string[],
})

watchEffect(() => {
  if (fromVersionId.value) store.ensureVersionBaseline(fromVersionId.value)
  if (toVersionId.value) store.ensureVersionBaseline(toVersionId.value)
})

const fromVersion = computed(
  () => store.data.versions.find((version) => version.id === fromVersionId.value) ?? null,
)
const toVersion = computed(
  () => store.data.versions.find((version) => version.id === toVersionId.value) ?? null,
)
const difference = computed(() =>
  fromVersion.value && toVersion.value
    ? compareSnapshots(fromVersion.value, toVersion.value)
    : { added: [], removed: [], changed: [], changedDetails: [], affectedThreatIds: [] },
)
const reReviewThreats = computed(() =>
  difference.value.affectedThreatIds
    .map((id) => store.data.threats.find((threat) => threat.id === id))
    .filter((threat): threat is NonNullable<typeof threat> => Boolean(threat)),
)

const entityName = (change: VersionChange): string => {
  if (change.category === '组件') {
    const item = store.data.components.find((entry) => entry.id === change.id)
    return item ? `${item.name} (${item.id})` : change.id
  }
  if (change.category === '数据流') {
    const item = store.data.flows.find((entry) => entry.id === change.id)
    return item ? `${item.name} (${item.id})` : change.id
  }
  if (change.category === '威胁') {
    const item = store.data.threats.find((entry) => entry.id === change.id)
    return item ? `${item.code} ${item.title} (${item.id})` : change.id
  }
  if (change.category === '控制') {
    const item = store.data.controls.find((entry) => entry.id === change.id)
    return item ? `${item.name} (${item.id})` : change.id
  }
  if (change.category === '风险') {
    const item = store.data.risks.find((entry) => entry.id === change.id)
    return item ? `${item.code} ${item.title} (${item.id})` : change.id
  }
  return change.id
}

const openCreate = (): void => {
  createForm.label = `v1.${store.data.currentRevision + 1} 变更评审`
  createForm.notes = ''
  createForm.extraThreatIds = []
  autoAffectedIds.value = store.previewAffectedThreats()
  createVisible.value = true
}

const autoAffectedNames = computed(() =>
  autoAffectedIds.value
    .map((id) => store.data.threats.find((threat) => threat.id === id))
    .filter((threat): threat is NonNullable<typeof threat> => Boolean(threat)),
)

const createVersion = (): void => {
  if (!createForm.label.trim() || !createForm.notes.trim()) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '版本名称和变更说明不能为空', life: 3000 })
    return
  }
  const snapshot = store.createVersion(createForm.label, createForm.notes, createForm.extraThreatIds)
  fromVersionId.value = toVersionId.value
  toVersionId.value = snapshot.id
  createVisible.value = false
  toast.add({
    severity: 'success',
    summary: '版本已创建',
    detail: `基线已冻结，${snapshot.affectedThreatIds.length} 条威胁进入重新审核`,
    life: 3000,
  })
}

const retryMigration = (snapshot: VersionSnapshot): void => {
  const result = store.ensureVersionBaseline(snapshot.id)
  if (result?.baseline) {
    toast.add({ severity: 'success', summary: '升级完成', detail: `${snapshot.label} 已补全为完整基线`, life: 3000 })
  } else {
    toast.add({
      severity: 'warn',
      summary: '升级仍未完成',
      detail: result?.migration?.error ?? '未知原因',
      life: 4000,
    })
  }
}

const rollback = (snapshot: VersionSnapshot): void => {
  const confirmed = window.confirm(
    `确认将模型内容回滚至「${snapshot.label}」？\n会签批注与审计轨迹不会被改写。`,
  )
  if (!confirmed) return
  const result = store.rollbackToVersion(snapshot.id)
  if (!result) {
    toast.add({ severity: 'error', summary: '回滚失败', detail: '该版本基线尚未升级完成', life: 3000 })
    return
  }
  toast.add({
    severity: 'success',
    summary: '已回滚',
    detail: `模型内容已恢复至 ${snapshot.label}，批注与审计保持不变`,
    life: 3000,
  })
}

const baselineLabel = (snapshot: VersionSnapshot): string => {
  if (snapshot.baseline) return '已冻结'
  if (snapshot.migration?.status === 'failed') return '升级中断'
  return '待升级'
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
      title="版本差异"
      description="比较模型基线，识别组件、数据流、控制与风险变化，并限定重新审核的威胁范围。"
    />

    <section class="panel">
      <div class="panel-header">
        <h2 class="panel-title">版本比较</h2>
        <Button label="创建新版本" icon="pi pi-plus" @click="openCreate" />
      </div>
      <div class="compare-toolbar">
        <div class="version-select">
          <span>基准版本</span>
          <select v-model="fromVersionId">
            <option v-for="version in store.data.versions" :key="version.id" :value="version.id">
              {{ version.label }}
            </option>
          </select>
        </div>
        <i class="pi pi-arrow-right"></i>
        <div class="version-select">
          <span>目标版本</span>
          <select v-model="toVersionId">
            <option v-for="version in store.data.versions" :key="version.id" :value="version.id">
              {{ version.label }}
            </option>
          </select>
        </div>
      </div>
      <div class="diff-columns diff-padding">
        <div class="diff-block added-block">
          <h4>新增项</h4>
          <ul v-if="difference.added.length">
            <li v-for="change in difference.added" :key="`${change.category}-${change.id}`">
              <span>{{ change.category }}</span> {{ entityName(change) }}
            </li>
          </ul>
          <span v-else class="muted">无新增项</span>
        </div>
        <div class="diff-block removed-block">
          <h4>移除项</h4>
          <ul v-if="difference.removed.length">
            <li v-for="change in difference.removed" :key="`${change.category}-${change.id}`">
              <span>{{ change.category }}</span> {{ entityName(change) }}
            </li>
          </ul>
          <span v-else class="muted">无移除项</span>
        </div>
      </div>
      <div class="changed-list">
        <h4>内容变更明细</h4>
        <template v-if="difference.changedDetails.length">
          <div v-for="entry in difference.changedDetails" :key="`${entry.category}-${entry.id}`" class="changed-item">
            <i class="pi pi-arrow-right"></i>
            <div>
              <strong>{{ entry.category }} · {{ entry.name }}</strong>
              <p v-for="field in entry.fields" :key="field.field">
                {{ field.field }}：<span class="field-before">{{ field.before }}</span>
                → <span class="field-after">{{ field.after }}</span>
              </p>
            </div>
          </div>
        </template>
        <template v-else-if="difference.changed.length">
          <div v-for="item in difference.changed" :key="item" class="changed-item">
            <i class="pi pi-arrow-right"></i>
            <span>{{ item }}</span>
          </div>
        </template>
        <span v-else class="muted">两个基线的模型内容一致</span>
      </div>
      <div v-if="difference.affectedThreatIds.length" class="rereview-list">
        <h4>需重新会签的威胁（{{ difference.affectedThreatIds.length }}）</h4>
        <div class="rereview-chips">
          <span v-for="threat in reReviewThreats" :key="threat.id" class="rereview-chip">
            {{ threat.code }} {{ threat.title }}
          </span>
        </div>
      </div>
    </section>

    <div class="versions-grid">
      <section class="panel">
        <div class="panel-header">
          <h2 class="panel-title">版本历史</h2>
        </div>
        <DataTable :value="store.data.versions" dataKey="id" size="small" stripedRows>
          <Column header="版本" style="width: 180px">
            <template #body="{ data }">
              <strong>{{ data.label }}</strong>
              <div class="mono">r{{ data.revision }}</div>
            </template>
          </Column>
          <Column header="创建时间" style="width: 155px">
            <template #body="{ data }">
              {{ new Date(data.createdAt).toLocaleDateString('zh-CN') }}
            </template>
          </Column>
          <Column field="author" header="创建人" style="width: 90px" />
          <Column header="受影响" style="width: 80px">
            <template #body="{ data }">{{ data.affectedThreatIds.length }} 条</template>
          </Column>
          <Column header="通过" style="width: 80px">
            <template #body="{ data }">{{ approvalLabel(data) }}</template>
          </Column>
          <Column header="基线" style="width: 130px">
            <template #body="{ data }">
              <span :class="['baseline-tag', { 'baseline-failed': data.migration?.status === 'failed' }]">
                {{ baselineLabel(data) }}
              </span>
              <Button
                v-if="!data.baseline"
                label="继续升级"
                text
                size="small"
                @click="retryMigration(data)"
              />
            </template>
          </Column>
          <Column header="操作" style="width: 90px">
            <template #body="{ data }">
              <Button
                label="回滚"
                icon="pi pi-undo"
                text
                size="small"
                :disabled="!data.baseline"
                @click="rollback(data)"
              />
            </template>
          </Column>
          <Column field="notes" header="说明" />
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

    <Dialog v-model:visible="createVisible" header="创建变更版本" modal :style="{ width: '720px' }">
      <div class="editor-form">
        <div class="field field-wide">
          <label>版本名称</label>
          <InputText v-model="createForm.label" />
        </div>
        <div class="field field-wide">
          <label>变更说明</label>
          <Textarea
            v-model="createForm.notes"
            rows="4"
            placeholder="说明架构、控制或风险发生的变更"
          />
        </div>
        <div class="field field-wide">
          <label>自动算出的重审范围</label>
          <div class="auto-affected">
            <span v-for="threat in autoAffectedNames" :key="threat.id" class="rereview-chip">
              {{ threat.code }} {{ threat.title }}
            </span>
            <span v-if="autoAffectedNames.length === 0" class="muted">
              与上一基线相比无内容变化，无需重审
            </span>
          </div>
          <small class="muted">由前后两个基线的内容差异自动计算，随版本一起冻结留档。</small>
        </div>
        <div class="field field-wide">
          <label>手动补充受影响威胁</label>
          <MultiSelect
            v-model="createForm.extraThreatIds"
            :options="store.data.threats"
            option-label="title"
            option-value="id"
            display="chip"
            filter
            placeholder="在自动范围之外补充需要重审的威胁"
          />
          <small class="muted">未进入重审范围的威胁保持当前会签状态，进行中的会签不会被冲掉。</small>
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="createVisible = false" />
        <Button label="创建版本" icon="pi pi-check" @click="createVersion" />
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

.diff-padding {
  padding: 0 16px 16px;
}

.added-block {
  border-left: 3px solid #2f8f69;
}

.removed-block {
  border-left: 3px solid #c64b39;
}

.diff-block li span {
  display: inline-block;
  min-width: 55px;
  margin-right: 7px;
  color: #748094;
  font-size: 11px;
}

.changed-list {
  padding: 0 16px 18px;
}

.changed-list h4 {
  margin: 0 0 10px;
  font-size: 14px;
}

.changed-item {
  display: flex;
  gap: 9px;
  padding: 6px 0;
  color: #515e73;
  font-size: 12px;
}

.changed-item strong {
  display: block;
  margin-bottom: 3px;
  color: #39445a;
  font-size: 12px;
}

.changed-item p {
  margin: 2px 0;
  color: #5f6a7e;
  font-size: 12px;
}

.field-before {
  color: #a8543f;
}

.field-after {
  color: #2f7d5b;
  font-weight: 600;
}

.rereview-list {
  padding: 0 16px 18px;
}

.rereview-list h4 {
  margin: 0 0 10px;
  font-size: 14px;
}

.rereview-chips,
.auto-affected {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.rereview-chip {
  padding: 3px 10px;
  border: 1px solid #d7c49a;
  border-radius: 999px;
  background: #faf3e3;
  color: #7a5b1d;
  font-size: 11px;
}

.baseline-tag {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  background: #e8f0e9;
  color: #2f7d5b;
  font-size: 11px;
}

.baseline-tag.baseline-failed {
  background: #f7e6e1;
  color: #b0452f;
}

.changed-item i {
  color: #4c78a8;
  font-size: 10px;
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

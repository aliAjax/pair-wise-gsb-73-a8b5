# SCAPEX 安全威胁建模与缓解措施会签平台

基于 Vue 3、PrimeVue、Pinia、Vue Router、Apollo Client、GraphQL、Vite 与 TypeScript 的独立前端工程。项目不依赖真实后端，GraphQL 查询通过自定义 `ApolloLink` 映射到浏览器 `localStorage` 中的本地仓库。

## 功能

- 系统边界、信任区、组件资产、外部依赖与数据流建模
- 由当前模型状态实时渲染的数据流图
- 威胁、攻击路径、控制、风险与组件/数据流关联
- 未覆盖组件、控制失效、证据缺失、风险接受过期与缓解冲突检查
- 5 x 5 风险矩阵、风险接受条件与有效期
- 开发、安全、业务三方逐项会签
- 版本基线冻结：建版本时把模型内容与三方会签意见一起留档
- 基线级差异：字段级内容对比，自动算出需要重新会签的威胁范围
- 旧版本记录首次使用时自动补全为新基线结构，中断后可从断点继续
- 版本回滚只恢复选中版本的模型内容，会签批注与审计轨迹不被改写
- 控制证据有效期管理、审计轨迹与 Markdown 报告导出
- 全部修改自动持久化到 `localStorage`

## 运行

```bash
npm install
npm run dev
```

默认开发地址为 `http://localhost:18473`。

## 构建

```bash
npm run build
```

## GraphQL

`src/graphql/client.ts` 使用 Apollo Client 的自定义 `ApolloLink`。当前注册以下真实查询操作：

- `DashboardMetrics`
- `ThreatIndex`
- `ControlHealth`

工作台指标通过 Apollo Client 查询，其余业务状态由 Pinia 管理并持久化。

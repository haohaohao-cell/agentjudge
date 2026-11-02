## 这个 PR 做了什么

<!-- 一句话说明，并链接相关 issue -->

## 变更类型

- [ ] 修复缺陷
- [ ] 新增检测能力（规则/守卫/合约）
- [ ] 重构/性能
- [ ] 文档
- [ ] CI/构建

## 自测清单

- [ ] `python -m unittest discover -s tests -v` 全部通过
- [ ] `python -m agentjudge eval` 无场景回归，FPR 未明显上升
- [ ] 新增规则已在 `policies/default.toml` 中写明 `explain` 与 `tags`
- [ ] 涉及检测逻辑的改动补了对应测试
- [ ] 更新了相关文档（README/docs）

## 风险与兼容性

<!-- 是否改变裁决口径？是否需要迁移策略/审计库？默认行为是否变化？ -->

## 备注

<!-- 截图、性能数据、威胁模型考虑等 -->

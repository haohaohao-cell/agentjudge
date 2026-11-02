# 贡献指南

## 环境

- Python 3.11+，**零运行时依赖**
- Windows / Linux / macOS 均可；CI 覆盖 3.11–3.13 × Ubuntu/Windows

```bash
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[dev]"         # dev 仅含 pytest/ruff，可选
```

## 常用命令

```bash
python -m unittest discover -s tests -v      # 全量测试（不依赖 pytest）
python -m agentjudge doctor                  # 环境自检
python -m agentjudge eval                    # 场景 + 语料回归
python -m agentjudge demo                    # 演示
PYTHONPATH=src python -m agentjudge serve    # 工作台
```

> 测试与运行期文件写在仓库内的 `var/`（已被 .gitignore 忽略），不使用系统临时目录，
> 因此在受限沙箱里也能跑。

## 代码约定

- 类型注解尽量完整；公共函数写 docstring（中文），标识符用英文；
- 新守卫实现 `Guard.check(ctx) -> list[Finding]`，**不要**在守卫里做聚合决策；
- 任何「不知道」都返回 fail-closed，禁止静默放行；
- 规则必须有 `explain` 与 `tags`，严重度与动作要匹配（`critical` 通常配 `deny`）；
- 不要引入新的运行时依赖；确需依赖请先在 issue 讨论。

## 提 PR 前

1. 加测试：守卫/链/引擎逻辑改动必须有对应用例；
2. 跑 `python -m unittest discover -s tests -v` 与
   `python -m agentjudge eval --baseline datasets/baseline.json --check`；
3. **行为变化要显式更新基线**：如果确实要新增拦截、调整阈值或改场景，运行
   `python -m agentjudge eval --write-baseline datasets/baseline.json`，
   并在 PR 里说明 `datasets/baseline.json` 的 diff 为什么合理；
4. 更新文档（README / docs/*）。

> CI 会在 `--check` 失败时红灯，常见原因：新规则误伤了良性语料（新增 `blocked_ids`）、
> 某个红队场景从通过变失败、ASR 上升。不要直接改基线来"骗过"CI——先看 diff 里
> 多出来的是不是你想拦的。

## 新增红队场景

见 [docs/evaluation.md](docs/evaluation.md#5-如何新增场景)。最有价值的场景是
「单步合规、组合危险」的多轮链条。

## 提交信息

采用 Conventional Commits：

```
feat(guard): 增加云元数据接口检测
fix(audit): 修复尾锚删除后仍判通过的问题
docs: 补充 MCP 接入示例
```

## 安全

发现漏洞请走 [SECURITY.md](SECURITY.md) 的私密渠道，不要在 issue 中公开。

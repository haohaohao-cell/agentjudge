# 技能言行体检与合约

目标：**上架/装载前**回答一个问题——「这个技能真的只做它说的事吗？」

## 1. 能力维度

| 键 | 中文 | 声明关键词（示例） | 实测来源 |
| --- | --- | --- | --- |
| `fs_read` | 读取文件 | 读取/查看/载入 + 文件 | `open()`, `Path.read_text`, `fs.readFile` |
| `fs_write` | 写入文件 | 写入/保存/修改/追加 + 文件 | `open(mode="w")`, `.write()`, `fs.writeFile` |
| `shell` | 执行命令 | 执行/运行 + 命令/脚本 | `subprocess`, `os.system`, `exec/eval` |
| `network` | 网络访问 | 联网/请求/下载/上传 | `requests`, `urllib`, `socket`, `curl` |
| `email` | 外发消息 | 邮件/通知/消息 | `smtplib`, webhook 字符串 |
| `env` | 读取环境/凭据 | 环境变量/密钥/凭据 | `os.environ`, `.ssh/`, `.aws/` |
| `memory` | 长期记忆 | 记忆/知识库 | 记忆写入调用 |
| `persistence` | 持久化/常驻 | 开机/常驻/定时 | `crontab`, `systemd`, `nohup` |

## 2. 声明解析（言）

- 读取 `SKILL.md` / `README.md` 与 `skill.json` 的 `description`；
- 按行匹配上述关键词；
- 行内出现否定词（`不/不会/无需/never/without`）→ 记为**否定声明**；
- 否定声明与正向声明冲突时，以正向为准。

刻意保守：只认显式表述。模糊描述会让能力被算作「未声明」，从而收紧而不是放宽。

## 3. 行为实测（行）

只做**静态分析**，不执行被检代码：

- Python：AST 遍历 import / call / 字符串常量，识别模块与函数调用；
- Shell：正则匹配命令与重定向；
- JS/TS：正则匹配 `fetch`、`child_process`、`fs.*`；
- 同时扫描高危字面量：私钥路径、`base64`、`eval/exec`、`rm -rf`。

每个证据保留 `file:line` 与代码片段，便于人工复核。

## 4. 差异分类

| 结论 | 含义 | 处理 |
| --- | --- | --- |
| `match` | 声明且实测 | 正常 |
| `undeclared` | 实测有、声明无 | 按能力危险度扣分，高危直接隔离 |
| `contradicted` | 声明明确否认、实测却有 | 最严重，直接隔离 |
| `unmet` | 声明有、实测没找到 | 仅提示（可能声明过宽） |

未声明能力扣分：`shell/network/email/env/persistence = 35`，`fs_write = 12`，`fs_read/memory = 3`。
高危字面量（私钥路径、编码混淆、动态执行、破坏性操作）额外扣分。

## 5. 信任评级

| 评级 | 条件（满足其一） | 运行时行为 |
| --- | --- | --- |
| `quarantined` | 存在高危未声明/相反声明、高危字面量，或评分 < 55 | 直接拒绝 |
| `conditional` | 评分 < 88 或存在任意未声明能力 | 只允许已声明能力，越界转人工 |
| `trusted` | 言行一致且无高危字面量 | 正常放行 |

## 6. 合约生成

```bash
agentjudge skill inspect examples/skills/note-taker --write-contract
```

生成 `contracts/skills/note-taker.toml`，包含 `status`、`capabilities`、`declared`、
`observed`、`fingerprint`（文件内容 + 声明集合的 SHA-256）与生成时间。

`capabilities` 取「声明能力」；若声明为空则退化为实测能力（此时 status 必然是
`conditional`/`quarantined`，实际不会放宽）。

合约可以进 Git，随技能版本走 code review；指纹变化即提示重新体检。

## 7. 运行时如何生效

调用带 `meta["skill"] = "note-taker"` 时，`ContractGuard` 会：

1. `quarantined` → `CT-SKILL-001` 拒绝；
2. `conditional` 且本次调用类别不在 `capabilities` → `CT-SKILL-002` 转人工；
3. 其余继续走路径/主机/脚本等常规合约检查。

## 8. 局限

- 静态分析看不到动态导入、字符串拼接出的模块名、运行时下载的载荷；
- 只覆盖 Python/Shell/JS，其他语言仅做字面量扫描；
- 声明解析是关键词启发式，可能漏掉「间接能力」描述；
- 因此 `conditional` 的价值在于**运行时兜底**：即使静态分析漏了，越界调用也会被拦。

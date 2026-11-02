"""能力主张解析：从 SKILL.md / skill.json 的“自然语言声明”里抽取能力。

这一步刻意做得保守：只认显式的能力表述，宁可漏判（漏判只会让体检更严格地
把能力算作“未声明”），也不把模糊措辞当成授权。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# 能力键 -> (中文名, 声明关键词正则)
CAPABILITIES: dict[str, tuple[str, str]] = {
    "fs_read": ("读取文件", r"(?:读|读取|载入|查看|扫描)[\s\S]{0,24}?(?:文件|目录|文档|配置|笔记)|\b(?:read|open|load|parse|scan)[a-z]*\b[\s\S]{0,16}\b(?:file|files|directory|config|notes?|document)\b"),
    "fs_write": ("写入文件", r"(?:写|写入|保存|修改|编辑|创建|追加|删除)[\s\S]{0,24}?(?:文件|目录|文档|笔记|配置)|\b(?:write|save|edit|modify|create|append|delete)[a-z]*\b[\s\S]{0,16}\b(?:file|files|notes?|document|record)\b"),
    "shell": ("执行命令", r"(?:执行|运行|调用)[\s\S]{0,12}?(?:命令|脚本|shell|程序|子进程)|\b(?:run|execute|invoke|spawn)[a-z]*\b[\s\S]{0,12}\b(?:command|commands|script|shell|subprocess|binary)\b|\bbash\b|\bshell\b|\bsubprocess\b"),
    "network": ("网络访问", r"(?:网络|联网|线上|远程|外网|接口|请求|下载|上传|抓取)[\s\S]{0,16}?(?:访问|请求|调用|接口|服务|网页|地址)?|\b(?:http|https|api|web|network|fetch|download|upload|request|remote)\b"),
    "email": ("外发消息", r"(?:邮件|邮箱|通知|消息|告警)[\s\S]{0,12}?(?:发送|推送|外发|通知)?|\b(?:email|mail|smtp|notification|webhook|message)\b"),
    "env": ("读取环境/凭据", r"(?:环境变量|凭据|凭证|密钥|令牌|密码|账号)[\s\S]{0,12}?(?:读取|使用|访问|获取)?|\b(?:env(?:ironment)?\s+variables?|credentials?|secrets?|tokens?|api[ _-]?keys?)\b"),
    "memory": ("长期记忆", r"(?:记忆|长期记忆|知识库|向量库)[\s\S]{0,12}?(?:写入|读取|存取|保存)?|\b(?:memory|remember|recall|vector\s+store)\b"),
    "persistence": ("持久化/常驻", r"(?:开机|自启|常驻|后台|定时|守护进程|计划任务)[\s\S]{0,12}?(?:运行|执行|任务|进程|启动)?|\b(?:daemon|persistent|autostart|startup|cron|scheduled\s+task|background)\b"),
}

# 未声明却实际具备的能力，按危险度赋权
UNDECLARED_SEVERITY: dict[str, str] = {
    "shell": "high",
    "network": "high",
    "email": "high",
    "env": "high",
    "persistence": "high",
    "fs_write": "medium",
    "fs_read": "low",
    "memory": "low",
}

NEGATION_RE = re.compile(
    r"(?:不|不会|禁止|无需|不需要|绝不|从不)[\s\S]{0,4}?"
    r"(?:读取|写入|执行|运行|访问|联网|连接|发送|外发|使用|修改|删除|调用)"
    r"|\b(?:no|never|without|does\s+not|do\s+not|doesn't|don't)\b[\s\S]{0,18}?"
    r"\b(?:read|write|execute|run|access|network|send|modify|delete|call)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class Claim:
    capability: str
    phrase: str
    negated: bool
    location: str

    def to_dict(self) -> dict[str, object]:
        return {
            "capability": self.capability,
            "phrase": self.phrase,
            "negated": self.negated,
            "location": self.location,
        }


def capability_label(key: str) -> str:
    return CAPABILITIES.get(key, (key, ""))[0]


def parse_claims(text: str, *, location: str = "SKILL.md") -> list[Claim]:
    """按行抽取能力主张；同一行内出现否定词则标记为否定声明。"""
    claims: list[Claim] = []
    if not text:
        return claims
    for raw_line in text.splitlines():
        line = raw_line.strip(" \t-*#>")
        if len(line) < 4:
            continue
        negated = bool(NEGATION_RE.search(line))
        for key, (_label, pattern) in CAPABILITIES.items():
            if re.search(pattern, line, re.IGNORECASE):
                claims.append(
                    Claim(capability=key, phrase=line[:160], negated=negated, location=location)
                )
    # 去重：同一能力保留前 5 条
    seen: dict[str, int] = {}
    unique: list[Claim] = []
    for claim in claims:
        count = seen.get(claim.capability, 0)
        if count >= 5:
            continue
        seen[claim.capability] = count + 1
        unique.append(claim)
    return unique


def declared_capabilities(claims: list[Claim]) -> set[str]:
    """只有“正向声明”才算声明过；被否定的能力不算。"""
    return {c.capability for c in claims if not c.negated}


def denied_capabilities(claims: list[Claim]) -> set[str]:
    positive = declared_capabilities(claims)
    negated = {c.capability for c in claims if c.negated}
    return negated - positive


__all__ = [
    "CAPABILITIES",
    "UNDECLARED_SEVERITY",
    "Claim",
    "parse_claims",
    "declared_capabilities",
    "denied_capabilities",
    "capability_label",
]

"""规则引擎守卫（Rules Guard）。

把安全团队熟悉的“正则 + 严重度”规则，应用在结构化的调用目标上
（命令、路径、URL、参数、内容），而不是盲目扫全部文本。
"""

from __future__ import annotations

import re
from typing import Any

from ..policy import Policy, RuleConfig
from ..taxonomy import command_hosts
from ..types import Action, Finding, Severity, ToolCall
from ..utils import host_matches, is_private_host, mask_secrets, strip_zero_width, truncate, url_host
from .base import Guard, GuardContext, finding

MAX_FINDINGS = 25


def texts_for_targets(call: ToolCall, targets: list[str]) -> list[tuple[str, str]]:
    blobs = call.text_blobs()
    out: list[tuple[str, str]] = []
    for target in targets:
        if target in {"all", "*"}:
            out.extend(blobs.items())
        elif target == "arg.*":
            out.extend((k, v) for k, v in blobs.items() if k.startswith("arg."))
        elif target in blobs:
            out.append((target, blobs[target]))
    seen: set[tuple[str, str]] = set()
    unique: list[tuple[str, str]] = []
    for name, text in out:
        if not text:
            continue
        key = (name, text)
        if key in seen:
            continue
        seen.add(key)
        unique.append((name, text))
    return unique


def _hosts_allowed(call: ToolCall, policy: Policy) -> bool:
    hosts = [h for h in command_hosts(call.command) if h]
    if call.url:
        host = url_host(call.url)
        if host:
            hosts.append(host)
    if not hosts:
        return False
    return all(
        host_matches(h, policy.network.allow_hosts) or is_private_host(h) or host_matches(h, policy.network.internal_hosts)
        for h in hosts
    )


class RulesGuard(Guard):
    name = "rules"
    description = "确定性正则规则引擎"

    def check(self, ctx: GuardContext) -> list[Finding]:
        return self.evaluate(ctx.policy, ctx.call)

    # -- 可复用的静态评估（结果侧复核也走这里） ---------------------------
    @staticmethod
    def evaluate(policy: Policy, call: ToolCall) -> list[Finding]:
        findings: list[Finding] = []
        seen_rules: set[str] = set()
        for rule in policy.enabled_rules():
            if rule.id in seen_rules:
                continue
            if rule.unless_host_allowed and _hosts_allowed(call, policy):
                continue
            hit = _match_rule(rule, call)
            if not hit:
                continue
            field, text, match = hit
            seen_rules.add(rule.id)
            findings.append(
                finding(
                    "rules",
                    rule.id,
                    rule.title,
                    severity=rule.severity,
                    action=rule.action,
                    explain=rule.explain or f"命中规则 {rule.id}",
                    evidence={
                        "field": field,
                        "match": mask_secrets(truncate(match, 200)),
                        "pattern": rule.pattern,
                        "text": mask_secrets(truncate(text, 260)),
                    },
                    tags=rule.tags,
                )
            )
            if len(findings) >= MAX_FINDINGS:
                break
        return findings

    @staticmethod
    def scan_content(policy: Policy, text: str) -> list[Finding]:
        """只对“内容”维度做规则扫描（读取结果复核）。"""
        if not text:
            return []
        synthetic = ToolCall(tool="content.scan", args={}, content=text)
        findings: list[Finding] = []
        for rule in policy.enabled_rules():
            if not ({"content", "all", "*"} & set(rule.targets)):
                continue
            hit = _match_rule(rule, synthetic)
            if not hit:
                continue
            field, matched_text, match = hit
            findings.append(
                finding(
                    "rules",
                    rule.id,
                    rule.title,
                    severity=rule.severity,
                    action=rule.action,
                    explain=rule.explain or f"命中规则 {rule.id}",
                    evidence={
                        "field": field,
                        "match": mask_secrets(truncate(match, 200)),
                        "preview": mask_secrets(truncate(matched_text, 260)),
                    },
                    tags=rule.tags,
                )
            )
        return findings


def _match_rule(rule: RuleConfig, call: ToolCall) -> tuple[str, str, str] | None:
    """返回 (字段, 文本, 命中片段)。同时匹配原文与去零宽的归一化视图。"""
    for field, text in texts_for_targets(call, rule.targets):
        match = rule.regex.search(text)
        if match:
            return field, text, match.group(0)
        cleaned = strip_zero_width(text)
        if cleaned != text:
            match = rule.regex.search(cleaned)
            if match:
                return field, cleaned, match.group(0)
    return None


def rule_matches(rule: RuleConfig, text: str) -> re.Match[str] | None:
    """测试辅助：在任意文本上试匹配。"""
    return rule.regex.search(text)


def explain_rule(rule: RuleConfig) -> dict[str, Any]:
    return {
        "id": rule.id,
        "title": rule.title,
        "severity": rule.severity.value,
        "action": rule.action.value,
        "targets": rule.targets,
        "pattern": rule.pattern,
        "explain": rule.explain,
    }


__all__ = ["RulesGuard", "texts_for_targets", "rule_matches", "explain_rule", "Action", "Severity"]

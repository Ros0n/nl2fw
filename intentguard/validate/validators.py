from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable, List

from ..ir.models import Action, IRPolicy


@dataclass(frozen=True)
class ValidationIssue:
    severity: str  # "error" | "warning"
    code: str
    message: str


class ValidationError(Exception):
    def __init__(self, issues: List[ValidationIssue]):
        super().__init__("IntentGuard validation failed")
        self.issues = issues


def validate_policy(policy: IRPolicy, *, default_deny_required: bool = True) -> List[ValidationIssue]:
    issues: List[ValidationIssue] = []

    if default_deny_required and policy.default_policy != Action.deny:
        issues.append(
            ValidationIssue(
                severity="error",
                code="default_deny_required",
                message="Default policy must be deny (DROP) for this prototype.",
            )
        )

    if not policy.rules:
        issues.append(
            ValidationIssue(severity="error", code="empty_policy", message="No rules provided.")
        )
        return issues

    for r in policy.rules:
        if not r.match.source_cidrs or not r.match.destination_cidrs:
            issues.append(
                ValidationIssue(
                    severity="error",
                    code="empty_match",
                    message=f"{r.rule_id}: source/destination CIDRs must be non-empty.",
                )
            )
        if r.match.protocol == "icmp" and r.match.ports:
            issues.append(
                ValidationIssue(
                    severity="error",
                    code="icmp_with_ports",
                    message=f"{r.rule_id}: ICMP must not specify ports.",
                )
            )
        for p in r.match.ports:
            if p < 1 or p > 65535:
                issues.append(
                    ValidationIssue(
                        severity="error",
                        code="invalid_port",
                        message=f"{r.rule_id}: invalid port {p}.",
                    )
                )

    return issues


def raise_on_errors(issues: List[ValidationIssue]) -> None:
    errs = [i for i in issues if i.severity == "error"]
    if errs:
        raise ValidationError(issues)


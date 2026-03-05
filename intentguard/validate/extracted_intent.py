from __future__ import annotations

import re
from typing import List

from ..context.models import ContextIndex
from ..llm.extraction_models import ExtractedIntent
from .validators import ValidationIssue


_IP_LIKE = re.compile(r"(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$")


def validate_extracted_intent(extracted: ExtractedIntent, ctx: ContextIndex) -> List[ValidationIssue]:
    issues: List[ValidationIssue] = []

    # Enforce "LLM never invents IPs"
    for field, values in [
        ("sources", extracted.sources),
        ("destinations", extracted.destinations),
        ("services", extracted.services),
    ]:
        for v in values:
            if _IP_LIKE.fullmatch(v.strip()):
                issues.append(
                    ValidationIssue(
                        severity="error",
                        code="llm_ip_literal",
                        message=f"LLM output must not contain IP/CIDR literals ({field}: {v}).",
                    )
                )

    # Unknown references
    known_entities = set(ctx.zones.keys()) | set(ctx.objects.keys()) | {ctx.firewall.name}
    for v in extracted.sources:
        if v.strip() not in known_entities:
            issues.append(
                ValidationIssue(
                    severity="error",
                    code="unknown_source",
                    message=f"Unknown source reference: {v}",
                )
            )
    for v in extracted.destinations:
        if v.strip() not in known_entities:
            issues.append(
                ValidationIssue(
                    severity="error",
                    code="unknown_destination",
                    message=f"Unknown destination reference: {v}",
                )
            )
    for v in extracted.services:
        if v.strip() not in ctx.services:
            issues.append(
                ValidationIssue(
                    severity="error",
                    code="unknown_service",
                    message=f"Unknown service reference: {v}",
                )
            )

    if extracted.action is None:
        issues.append(
            ValidationIssue(
                severity="error",
                code="missing_action",
                message="Missing action (allow/deny/reject).",
            )
        )

    # Empty rule rejection (semantic)
    if not extracted.sources or not extracted.destinations or not extracted.services:
        issues.append(
            ValidationIssue(
                severity="error",
                code="empty_rule",
                message="sources, destinations, and services must be non-empty.",
            )
        )

    return issues


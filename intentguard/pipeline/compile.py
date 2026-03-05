from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..context.models import ContextIndex
from ..generator.iptables import IptablesProgram, generate_iptables
from ..ir.models import IRPolicy
from ..llm.gemini_extractor import extract_intent
from ..llm.extraction_models import ExtractedIntent
from ..validate.extracted_intent import validate_extracted_intent
from ..validate.json_schema import load_schema, validate_json
from ..validate.validators import ValidationIssue, raise_on_errors, validate_policy
from .ir_builder import ResolutionError, build_ir_policy


@dataclass(frozen=True)
class CompileResult:
    extracted: Dict[str, Any]
    ir: IRPolicy
    validation: List[ValidationIssue]
    iptables: IptablesProgram


def compile_intentguard(
    *,
    nl_policy: str,
    ctx: ContextIndex,
    gemini_model: str = "gemini-2.5-flash",
    extracted_override: Optional[ExtractedIntent] = None,
) -> CompileResult:
    extracted = extracted_override or extract_intent(
        nl_policy=nl_policy, context_index=ctx.to_llm_index(), model=gemini_model
    )

    # JSON Schema validation (explicit requirement)
    schemas_dir = Path(__file__).resolve().parents[1] / "schemas"
    extraction_schema = load_schema(schemas_dir / "intent_extraction.schema.json")
    extraction_errors = validate_json(extracted.model_dump(), extraction_schema)
    pre_schema_issues = [
        ValidationIssue(severity="error", code="schema_violation", message=m)
        for m in extraction_errors
    ]
    raise_on_errors(pre_schema_issues)

    pre_issues = validate_extracted_intent(extracted, ctx)
    raise_on_errors(pre_issues)

    ir = build_ir_policy(extracted=extracted, ctx=ctx)

    ir_schema = load_schema(schemas_dir / "ir_policy.schema.json")
    ir_errors = validate_json(ir.model_dump(), ir_schema)
    ir_schema_issues = [
        ValidationIssue(severity="error", code="schema_violation", message=m) for m in ir_errors
    ]
    raise_on_errors(ir_schema_issues)

    issues = validate_policy(ir, default_deny_required=True)
    raise_on_errors(issues)

    # Rules-only output by default (no flush/default policies/conntrack baseline).
    program = generate_iptables(ir, include_baseline=False, include_established_related=False)

    return CompileResult(
        extracted=extracted.model_dump(),
        ir=ir,
        validation=pre_schema_issues + pre_issues + ir_schema_issues + issues,
        iptables=program,
    )


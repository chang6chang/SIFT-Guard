"""Pure-function R1-R6 promotion rule engine.

The orchestrator calls `promote()` for each DRAFT finding once per
iteration with the correlations referencing that finding. The function
chooses one of six rules, applied in order — the first whose
preconditions hold wins. No I/O, no side effects: the same inputs
always produce the same `PromotionDecision`.

Rules (CLAUDE.md confidence methodology, restated against the
substrate's correlation types):

  R1 — disputed: any contradicts correlation with severity in
       {material, fundamental} → DRAFT/DISPUTED. Disputes outrank
       corroboration: a fundamental contradiction means we cannot
       confirm even if other evidence supports the finding.

  R2 — demote on weakening: F.confidence == HIGH and any weakens
       correlation present → CONFIRMED/MEDIUM. We commit to the
       finding (CONFIRMED) but back off the confidence one notch.
       Only HIGH gets demoted; MEDIUM and LOW already have room.

  R3 — strong corroboration: any corroborates correlation with
       strength == strong → CONFIRMED/HIGH. The flagship promotion.

  R4 — moderate corroboration: any corroborates correlation with
       strength == moderate → CONFIRMED/max(F.confidence, MEDIUM).
       We confirm but pin the confidence to at least MEDIUM.

  R5 — quiet stabilization: iterations_so_far >= 2 and no
       correlations on F → CONFIRMED at F.confidence. After the
       second iteration with nothing new said about F, treat the
       silence as agreement and commit.

  R6 — default: stay DRAFT at F.confidence. The orchestrator skips
       writing an `update_finding` for R6 outcomes (no-op).

Confidence ordering for R4's max(): LOW < MEDIUM < HIGH. DISPUTED is
*not* in this order — it is only ever an output of R1, never an
input the rules reason against. If a finding is currently DISPUTED
(set by a prior R1) and a new corroboration arrives, R3/R4 still
fire and override the DISPUTED state.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from server.schemas import (
    ContradictsCorrelation,
    CorroboratesCorrelation,
    DraftFinding,
    FindingUpdate,
    RequestFollowupCorrelation,
    StrengthensCorrelation,
    WeakensCorrelation,
)

_AnyCorrelation = (
    CorroboratesCorrelation
    | ContradictsCorrelation
    | StrengthensCorrelation
    | WeakensCorrelation
    | RequestFollowupCorrelation
)


@dataclass(frozen=True)
class PromotionDecision:
    """Output of `promote()`. The orchestrator translates a non-R6
    decision into an `update_finding` MCP call. R6 decisions are
    skipped (no-op promotions don't earn an audit-chain entry).
    """

    finding_id: str
    new_state: Literal["DRAFT", "CONFIRMED"]
    new_confidence: Literal["LOW", "MEDIUM", "HIGH", "DISPUTED"]
    promotion_rule: Literal["R1", "R2", "R3", "R4", "R5", "R6"]
    driving_correlation_ids: list[str]


_CONF_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


def _conf_max(a: str, b: str) -> str:
    """Return the higher of two confidence levels per LOW<MEDIUM<HIGH.

    DISPUTED is not in the order — if either input is DISPUTED, fall
    back to the *non-DISPUTED* side (or MEDIUM if both are DISPUTED).
    R4 calls this to pin to at least MEDIUM, so DISPUTED → MEDIUM
    matches the rule's spirit.
    """
    if a == "DISPUTED" and b == "DISPUTED":
        return "MEDIUM"
    if a == "DISPUTED":
        return b
    if b == "DISPUTED":
        return a
    return a if _CONF_ORDER[a] >= _CONF_ORDER[b] else b


def _current_confidence(finding: DraftFinding | FindingUpdate) -> str:
    """The confidence to reason against — `confidence` for a DRAFT
    record, `new_confidence` for an UPDATE record."""
    if isinstance(finding, FindingUpdate):
        return finding.new_confidence
    return finding.confidence


def promote(
    finding: DraftFinding | FindingUpdate,
    correlations_for_finding: list[_AnyCorrelation],
    iterations_so_far: int,
) -> PromotionDecision:
    """Apply R1-R6 in order against the given finding + its
    correlations. Returns the matching rule's decision. Pure: no I/O.

    `correlations_for_finding` should already be filtered to
    correlations that name `finding.finding_id` in the relevant field
    (target_finding_id, target_finding_ids, finding_a_id/finding_b_id,
    or related_finding_ids). This function does not re-filter.

    `iterations_so_far` is the orchestrator's count of completed
    iterations *before* the current one — used by R5's "two
    iterations of silence" rule.
    """
    fid = finding.finding_id
    f_conf = _current_confidence(finding)

    # R1 — material or fundamental contradiction wins outright.
    contradicts_serious = [
        c
        for c in correlations_for_finding
        if isinstance(c, ContradictsCorrelation) and c.severity in ("material", "fundamental")
    ]
    if contradicts_serious:
        return PromotionDecision(
            finding_id=fid,
            new_state="DRAFT",
            new_confidence="DISPUTED",
            promotion_rule="R1",
            driving_correlation_ids=[c.correlation_id for c in contradicts_serious],
        )

    # R2 — HIGH demoted by weakens. Only HIGH gets the demotion treatment.
    if f_conf == "HIGH":
        weakens_list = [c for c in correlations_for_finding if isinstance(c, WeakensCorrelation)]
        if weakens_list:
            return PromotionDecision(
                finding_id=fid,
                new_state="CONFIRMED",
                new_confidence="MEDIUM",
                promotion_rule="R2",
                driving_correlation_ids=[c.correlation_id for c in weakens_list],
            )

    # R3 — strong corroboration → CONFIRMED/HIGH.
    strong_corroborates = [
        c
        for c in correlations_for_finding
        if isinstance(c, CorroboratesCorrelation) and c.strength == "strong"
    ]
    if strong_corroborates:
        return PromotionDecision(
            finding_id=fid,
            new_state="CONFIRMED",
            new_confidence="HIGH",
            promotion_rule="R3",
            driving_correlation_ids=[c.correlation_id for c in strong_corroborates],
        )

    # R4 — moderate corroboration → CONFIRMED/max(F.confidence, MEDIUM).
    moderate_corroborates = [
        c
        for c in correlations_for_finding
        if isinstance(c, CorroboratesCorrelation) and c.strength == "moderate"
    ]
    if moderate_corroborates:
        return PromotionDecision(
            finding_id=fid,
            new_state="CONFIRMED",
            new_confidence=_conf_max(f_conf, "MEDIUM"),
            promotion_rule="R4",
            driving_correlation_ids=[c.correlation_id for c in moderate_corroborates],
        )

    # R5 — quiet stabilization. After two completed iterations with no
    # correlations referencing F (and therefore no pending followup
    # against F either, since followup is itself a correlation type),
    # commit at the existing confidence.
    if iterations_so_far >= 2 and not correlations_for_finding:
        # F.confidence may be DISPUTED only if a prior R1 set it; in
        # that case there must have been a contradicts correlation
        # *previously*, and "no correlations now" means the dispute
        # is no longer being asserted. Confirming at DISPUTED is
        # nonsense — fall back to MEDIUM as a neutral commit value.
        commit_conf = "MEDIUM" if f_conf == "DISPUTED" else f_conf
        return PromotionDecision(
            finding_id=fid,
            new_state="CONFIRMED",
            new_confidence=commit_conf,
            promotion_rule="R5",
            driving_correlation_ids=[],
        )

    # R6 — default: no change. The orchestrator skips writing an
    # update for R6 outcomes (idempotent no-op).
    return PromotionDecision(
        finding_id=fid,
        new_state="DRAFT",
        new_confidence="DISPUTED" if f_conf == "DISPUTED" else f_conf,
        promotion_rule="R6",
        driving_correlation_ids=[],
    )


__all__ = ["PromotionDecision", "promote"]

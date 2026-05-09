"""Pure-function tests for orchestrator.promotion.promote().

R1-R6 are evaluated in order. Each test isolates one rule's
preconditions and asserts the rule fires with the expected output
state/confidence/driving_correlation_ids. Edge cases live alongside
the happy path for each rule. No I/O — `promote()` takes
DraftFinding/FindingUpdate + correlation list + iter count and
returns a PromotionDecision.
"""

from __future__ import annotations

from datetime import datetime, timezone


from orchestrator.promotion import PromotionDecision, promote
from server.schemas import (
    ContradictsCorrelation,
    CorroboratesCorrelation,
    DraftFinding,
    EvidenceRef,
    FindingUpdate,
    RequestFollowupCorrelation,
    StrengthensCorrelation,
    WeakensCorrelation,
)


_NOW = datetime(2026, 5, 7, 12, 0, 0, tzinfo=timezone.utc)
EVID = "550e8400-e29b-41d4-a716-446655440000"
FID = "11111111-1111-4111-8111-111111111111"
FID_OTHER = "22222222-2222-4222-8222-222222222222"
CID_1 = "33333333-3333-4333-8333-333333333333"
CID_2 = "44444444-4444-4444-8444-444444444444"
CID_3 = "55555555-5555-4555-8555-555555555555"


def _ref() -> EvidenceRef:
    return EvidenceRef(source_tool="vol_pslist", audit_line=1, detail="x")


def _draft(confidence: str = "MEDIUM") -> DraftFinding:
    return DraftFinding(
        finding_id=FID,
        evidence_id=EVID,
        analyst="process_analyst",
        state="DRAFT",
        category="process_hidden",
        severity="medium",
        confidence=confidence,
        title="Synthetic draft for promotion tests",
        description=(
            "A synthetic DraftFinding the promotion-rule unit tests "
            "construct in-memory. The confidence parameter drives the "
            "test scenario. No I/O occurs in these tests."
        ),
        evidence_refs=[_ref()],
        created_at=_NOW,
        tool_invocations=["vol_pslist:1"],
    )


def _update(new_state: str, new_confidence: str) -> FindingUpdate:
    """A FindingUpdate as if a prior iteration's orchestrator
    promoted the finding. Used for tests that assert promote() reads
    the latest record's confidence."""
    return FindingUpdate(
        update_id=CID_1,  # uuid value reused as a valid uuid4 string
        finding_id=FID,
        iteration_number=1,
        previous_state="DRAFT",
        new_state=new_state,
        previous_confidence="MEDIUM",
        new_confidence=new_confidence,
        promotion_rule="R3",
        driving_correlation_ids=[CID_2],
        created_at=_NOW,
        audit_line=10,
        orchestrator_version="orchestrator-v0.1",
    )


def _corroborates(strength: str, cid: str = CID_1) -> CorroboratesCorrelation:
    return CorroboratesCorrelation(
        correlation_id=cid,
        case_id="case-rocba",
        iteration_number=0,
        created_at=_NOW,
        audit_line=5,
        evidence_refs=[_ref()],
        hypothesis=(
            "Two analyst findings agree on the same target. Synthetic "
            "fixture for promotion-rule tests."
        ),
        target_finding_ids=[FID],
        strength=strength,
    )


def _contradicts(severity: str, cid: str = CID_1) -> ContradictsCorrelation:
    return ContradictsCorrelation(
        correlation_id=cid,
        case_id="case-rocba",
        iteration_number=0,
        created_at=_NOW,
        audit_line=5,
        evidence_refs=[_ref()],
        hypothesis=(
            "Two findings make incompatible claims about the same "
            "underlying artifact. Synthetic fixture for tests."
        ),
        finding_a_id=FID,
        finding_b_id=FID_OTHER,
        severity=severity,
        resolvable_by_followup=False,
    )


def _weakens(cid: str = CID_1) -> WeakensCorrelation:
    return WeakensCorrelation(
        correlation_id=cid,
        case_id="case-rocba",
        iteration_number=0,
        created_at=_NOW,
        audit_line=5,
        evidence_refs=[_ref()],
        hypothesis=(
            "A new observation suggests a benign explanation for the "
            "finding. Synthetic fixture for promotion tests."
        ),
        target_finding_id=FID,
    )


def _strengthens(cid: str = CID_1) -> StrengthensCorrelation:
    return StrengthensCorrelation(
        correlation_id=cid,
        case_id="case-rocba",
        iteration_number=0,
        created_at=_NOW,
        audit_line=5,
        evidence_refs=[_ref()],
        hypothesis=(
            "An observation that supports the finding without rising "
            "to corroboration. Synthetic fixture for promotion tests."
        ),
        target_finding_id=FID,
    )


def _request_followup(cid: str = CID_1) -> RequestFollowupCorrelation:
    return RequestFollowupCorrelation(
        correlation_id=cid,
        case_id="case-rocba",
        iteration_number=0,
        created_at=_NOW,
        audit_line=5,
        evidence_refs=[_ref()],
        hypothesis=(
            "The validator requests a follow-up analyst dispatch with a "
            "focus context. Synthetic fixture for promotion tests."
        ),
        target_analyst="process_analyst",
        related_finding_ids=[FID],
        focus_context={"pids": [7900]},
        rationale="Rationale fixture text for promotion-rule unit tests.",
    )


# ----------------------------------------------------------------------
# R1 — disputed (material/fundamental contradicts wins outright)
# ----------------------------------------------------------------------


class TestR1Disputed:
    def test_material_contradicts_disputes(self):
        d = promote(_draft("HIGH"), [_contradicts("material")], 0)
        assert d.promotion_rule == "R1"
        assert d.new_state == "DRAFT"
        assert d.new_confidence == "DISPUTED"
        assert d.driving_correlation_ids == [CID_1]

    def test_fundamental_contradicts_disputes(self):
        d = promote(_draft("LOW"), [_contradicts("fundamental")], 5)
        assert d.promotion_rule == "R1"
        assert d.new_confidence == "DISPUTED"

    def test_minor_contradicts_does_not_dispute(self):
        # Minor severity does NOT trigger R1. Falls through to R6
        # (no other applicable rule given a single minor contradicts).
        d = promote(_draft("MEDIUM"), [_contradicts("minor")], 0)
        assert d.promotion_rule == "R6"

    def test_contradicts_outranks_corroborates(self):
        # Even with a strong corroboration also present, a material
        # contradiction wins — we cannot confirm under disagreement.
        d = promote(
            _draft("MEDIUM"),
            [_contradicts("material", CID_1), _corroborates("strong", CID_2)],
            0,
        )
        assert d.promotion_rule == "R1"
        assert CID_1 in d.driving_correlation_ids


# ----------------------------------------------------------------------
# R2 — HIGH demoted on weakens
# ----------------------------------------------------------------------


class TestR2DemoteHigh:
    def test_high_with_weakens_becomes_confirmed_medium(self):
        d = promote(_draft("HIGH"), [_weakens()], 0)
        assert d.promotion_rule == "R2"
        assert d.new_state == "CONFIRMED"
        assert d.new_confidence == "MEDIUM"

    def test_medium_with_weakens_falls_through_to_r6(self):
        # R2 only applies when F.confidence == HIGH.
        d = promote(_draft("MEDIUM"), [_weakens()], 0)
        assert d.promotion_rule == "R6"

    def test_low_with_weakens_falls_through_to_r6(self):
        d = promote(_draft("LOW"), [_weakens()], 0)
        assert d.promotion_rule == "R6"


# ----------------------------------------------------------------------
# R3 — strong corroboration
# ----------------------------------------------------------------------


class TestR3StrongCorroboration:
    def test_strong_corroborates_promotes_to_high(self):
        d = promote(_draft("MEDIUM"), [_corroborates("strong")], 0)
        assert d.promotion_rule == "R3"
        assert d.new_state == "CONFIRMED"
        assert d.new_confidence == "HIGH"
        assert d.driving_correlation_ids == [CID_1]

    def test_strong_corroborates_overrides_disputed_via_update(self):
        # A finding currently in DISPUTED (from a prior R1) can be
        # un-disputed by a strong corroboration. R3 fires.
        latest = _update(new_state="DRAFT", new_confidence="DISPUTED")
        d = promote(latest, [_corroborates("strong")], 1)
        assert d.promotion_rule == "R3"
        assert d.new_confidence == "HIGH"


# ----------------------------------------------------------------------
# R4 — moderate corroboration
# ----------------------------------------------------------------------


class TestR4ModerateCorroboration:
    def test_moderate_corroborates_low_promotes_to_medium(self):
        d = promote(_draft("LOW"), [_corroborates("moderate")], 0)
        assert d.promotion_rule == "R4"
        assert d.new_state == "CONFIRMED"
        assert d.new_confidence == "MEDIUM"

    def test_moderate_corroborates_high_keeps_high(self):
        # max(HIGH, MEDIUM) == HIGH.
        d = promote(_draft("HIGH"), [_corroborates("moderate")], 0)
        assert d.promotion_rule == "R4"
        assert d.new_confidence == "HIGH"

    def test_strong_outranks_moderate_in_same_set(self):
        d = promote(
            _draft("LOW"),
            [_corroborates("moderate", CID_1), _corroborates("strong", CID_2)],
            0,
        )
        assert d.promotion_rule == "R3"
        assert CID_2 in d.driving_correlation_ids


# ----------------------------------------------------------------------
# R5 — quiet stabilization (>= 2 iters with no correlations)
# ----------------------------------------------------------------------


class TestR5QuietStabilization:
    def test_two_iters_no_correlations_confirms(self):
        d = promote(_draft("MEDIUM"), [], 2)
        assert d.promotion_rule == "R5"
        assert d.new_state == "CONFIRMED"
        assert d.new_confidence == "MEDIUM"
        assert d.driving_correlation_ids == []

    def test_one_iter_no_correlations_falls_through_to_r6(self):
        d = promote(_draft("MEDIUM"), [], 1)
        assert d.promotion_rule == "R6"

    def test_two_iters_with_strengthens_does_not_quiet_confirm(self):
        # R5 requires *no* correlations. A strengthens (no rule of
        # its own) means R5 doesn't fire — falls through to R6.
        d = promote(_draft("MEDIUM"), [_strengthens()], 2)
        assert d.promotion_rule == "R6"

    def test_r5_decision_is_acceptable_to_finding_update_schema(self):
        """Pure-function pin: the PromotionDecision shape R5 returns
        (empty driving_correlation_ids, new_state=CONFIRMED) is what
        the FindingUpdate model now accepts.

        Verifies the 2026-05-07 schema relaxation didn't change R5's
        rule-engine behavior — `promote()` still returns the same
        decision shape; only the persistence layer changed. If a
        future refactor of `promote()` accidentally returns a
        non-empty list for R5 (or returns DRAFT instead of CONFIRMED
        for R5), this assertion fires before the orchestrator's
        update_finding call would.
        """
        from datetime import datetime, timezone
        from server.schemas import FindingUpdate

        d = promote(_draft("MEDIUM"), [], 2)
        assert d.promotion_rule == "R5"
        assert d.driving_correlation_ids == []  # empty by R5's definition
        assert d.new_state == "CONFIRMED"

        # And the decision's fields are accepted by FindingUpdate.
        # Regression guard: if the schema relaxation is reverted (or
        # the model_validator's R5 carve-out drifts), this raises.
        FindingUpdate(
            update_id="550e8400-e29b-41d4-a716-446655440000",
            finding_id="550e8400-e29b-41d4-a716-446655440001",
            iteration_number=2,
            previous_state="DRAFT",
            new_state=d.new_state,
            previous_confidence="MEDIUM",
            new_confidence=d.new_confidence,
            promotion_rule=d.promotion_rule,
            driving_correlation_ids=d.driving_correlation_ids,
            created_at=datetime.now(tz=timezone.utc),
            audit_line=1,
            orchestrator_version="1.0.0",
        )


# ----------------------------------------------------------------------
# R6 — default (no change)
# ----------------------------------------------------------------------


class TestR6Default:
    def test_no_correlations_iter0_stays_draft(self):
        d = promote(_draft("MEDIUM"), [], 0)
        assert d.promotion_rule == "R6"
        assert d.new_state == "DRAFT"
        assert d.new_confidence == "MEDIUM"
        assert d.driving_correlation_ids == []

    def test_strengthens_alone_does_not_promote(self):
        # strengthens supports but does not corroborate; R6 fires.
        d = promote(_draft("MEDIUM"), [_strengthens()], 0)
        assert d.promotion_rule == "R6"

    def test_request_followup_alone_does_not_promote(self):
        # request_followup is a hint to the orchestrator's next-iter
        # ANALYZE step, not a rule input that drives promotion.
        d = promote(_draft("MEDIUM"), [_request_followup()], 0)
        assert d.promotion_rule == "R6"


# ----------------------------------------------------------------------
# Cross-cutting: rule ordering & input shape
# ----------------------------------------------------------------------


class TestRuleOrdering:
    def test_r1_beats_r2(self):
        # HIGH + weakens (R2 candidate) AND material contradicts
        # (R1) → R1 wins.
        d = promote(
            _draft("HIGH"),
            [_weakens(CID_1), _contradicts("material", CID_2)],
            0,
        )
        assert d.promotion_rule == "R1"

    def test_r2_beats_r3_when_high_demoted_by_weakens(self):
        # Spec wording: "HIGH and any weakens → CONFIRMED/MEDIUM".
        # When a weakens is present and F.confidence==HIGH, R2 fires
        # before R3 considers strong corroboration. This documents
        # the chosen ordering.
        d = promote(
            _draft("HIGH"),
            [_weakens(CID_1), _corroborates("strong", CID_2)],
            0,
        )
        assert d.promotion_rule == "R2"
        assert d.new_confidence == "MEDIUM"


class TestInputShape:
    def test_returns_promotion_decision(self):
        d = promote(_draft("MEDIUM"), [], 0)
        assert isinstance(d, PromotionDecision)

    def test_finding_id_is_passed_through(self):
        d = promote(_draft("MEDIUM"), [_corroborates("strong")], 0)
        assert d.finding_id == FID

    def test_update_record_uses_new_confidence(self):
        # When the latest record on the chain is a FindingUpdate,
        # promote() reasons against new_confidence (not the long-gone
        # original DraftFinding.confidence).
        latest = _update(new_state="CONFIRMED", new_confidence="HIGH")
        d = promote(latest, [_weakens()], 0)
        # F.confidence==HIGH + weakens → R2.
        assert d.promotion_rule == "R2"
        assert d.new_confidence == "MEDIUM"

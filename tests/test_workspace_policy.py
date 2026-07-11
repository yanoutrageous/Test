from __future__ import annotations

import pickle
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from enum import StrEnum
from pathlib import Path
from threading import Event
from typing import Any

import pytest

from app import config as app_config
from app.safety import production_guard as production_guard_module
from app.config import PROJECT_ROOT
from app.safety.audit_events import AuditDecision, CollectingAuditSink
from app.safety.context import (
    Caller,
    ContextError,
    DataClassification,
    OperationContext,
    Purpose,
    ScopeId,
    ScopeKind,
)
from app.safety.namespace_policy import (
    AuditPathMode,
    CapabilityGrant,
    DEFAULT_RULES,
    EXACT_GRANTS,
    NamespaceId,
    NamespaceMode,
    NamespacePolicy,
    NamespacePolicyError,
    NamespaceRule,
    PolicyIntegrityError,
    PolicyErrorCode,
    ScopeBinding,
)
from app.safety.production_guard import (
    BoundaryFailure,
    BoundaryErrorCode,
    BoundaryResult,
    CandidateTicket,
    CONTRACT_PROJECT_ROOT,
    PairEvidence,
    ProductionBoundaryError,
    ProductionWorkspaceBoundary,
    WriterUnavailableError,
    _create_test_boundary,
    get_production_boundary,
)
from app.safety.static_audit import (
    scan_unauthorized_guard_construction,
    scan_unauthorized_guard_source,
)
from app.workspace_guard import ExpectedKind, GuardedPath, PathIntent, WorkspaceGuard


def _scope(kind: ScopeKind, value: str) -> ScopeId:
    return ScopeId(kind, value)


def _context(
    *,
    caller: Caller = Caller.TEST_LAB,
    purpose: Purpose = Purpose.TEST,
    operation_id: str = "OP-TEST-001",
    scopes: tuple[ScopeId, ...] = (),
    manifest_id: str | None = None,
    classification: DataClassification = DataClassification.INTERNAL,
) -> OperationContext:
    return OperationContext(
        run_id="RUN-TEST-001",
        job_id="JOB-TEST-001",
        operation_id=operation_id,
        caller=caller,
        purpose=purpose,
        scopes=scopes,
        manifest_id=manifest_id,
        classification=classification,
    )


def _issued_context(
    boundary: Any,
    *,
    caller: Caller = Caller.TEST_LAB,
    purpose: Purpose = Purpose.TEST,
    operation_id: str = "OP-TEST-001",
    scopes: tuple[ScopeId, ...] = (),
    manifest_id: str | None = None,
    classification: DataClassification = DataClassification.INTERNAL,
) -> OperationContext:
    return boundary.issue_context(
        run_id="RUN-TEST-001",
        job_id="JOB-TEST-001",
        operation_id=operation_id,
        caller=caller,
        purpose=purpose,
        scopes=scopes,
        manifest_id=manifest_id,
        classification=classification,
    )


def _pair_evidence() -> PairEvidence:
    return PairEvidence(
        manifest_id="MANIFEST-001",
        manifest_sha256="1" * 64,
        source_tree_sha256="2" * 64,
        entry_count=2,
        total_bytes=17,
        checkpoint_id="CHECKPOINT-001",
        checkpoint_manifest_sha256="3" * 64,
    )


def _pair_scopes(*extra: ScopeId) -> tuple[ScopeId, ...]:
    return (
        _scope(ScopeKind.JOB_ID, "JOB-TEST-001"),
        _scope(ScopeKind.MANIFEST_ID, "MANIFEST-001"),
        _scope(ScopeKind.CHECKPOINT_ID, "CHECKPOINT-001"),
        *extra,
    )


def _ticket(
    relative_path: str,
    *,
    intent: PathIntent,
    expected_kind: ExpectedKind = ExpectedKind.FILE,
    exists: bool | None = None,
) -> GuardedPath:
    if exists is None:
        exists = intent.requires_existing
    relative = Path(relative_path)
    return GuardedPath(
        issuer_id="TEST-ISSUER",
        requested=relative_path,
        path=PROJECT_ROOT / relative,
        relative_path=relative,
        workspace_root=PROJECT_ROOT,
        intent=intent,
        expected_kind=expected_kind,
        exists=exists,
        nearest_existing_ancestor=PROJECT_ROOT,
        chain_snapshot=(),
    )


_SCOPE_TEST_VALUES = {
    ScopeKind.RUN_ID: "RUN-TEST-001",
    ScopeKind.COPY_ID: "COPY-001",
    ScopeKind.JOB_ID: "JOB-TEST-001",
    ScopeKind.STATE_ID: "STATE-001",
    ScopeKind.OBJECT_ID: "OBJECT-001",
    ScopeKind.REVISION_ID: "REVISION-001",
    ScopeKind.PIPELINE_ID: "PIPELINE-001",
    ScopeKind.INDEX_ID: "INDEX-001",
    ScopeKind.EXPORT_ID: "EXPORT-001",
    ScopeKind.BACKUP_ID: "BACKUP-001",
    ScopeKind.MANIFEST_ID: "MANIFEST-001",
    ScopeKind.CHECKPOINT_ID: "CHECKPOINT-001",
    ScopeKind.OPERATION_ID: "OP-TEST-001",
}


def _normal_grant_case(grant: Any) -> tuple[GuardedPath, OperationContext]:
    matching_rules = tuple(
        rule
        for rule in DEFAULT_RULES
        if rule.namespace is grant.namespace and grant.intent in rule.normal_intents
    )
    assert matching_rules
    rule = matching_rules[0]
    tail = [f"ITEM-{index + 1:03d}" for index in range(rule.minimum_tail_depth)]
    scopes: dict[ScopeKind, ScopeId] = {}
    for binding in rule.scope_bindings:
        value = _SCOPE_TEST_VALUES[binding.scope_kind]
        tail[binding.tail_index] = value
        scopes[binding.scope_kind] = _scope(binding.scope_kind, value)
    for scope_kind in grant.required_scopes:
        value = _SCOPE_TEST_VALUES[scope_kind]
        scopes[scope_kind] = _scope(scope_kind, value)
    relative = "/".join((*rule.prefix, *tail))
    context = _context(
        caller=grant.caller,
        purpose=grant.purpose,
        scopes=tuple(sorted(scopes.values(), key=lambda item: item.kind.value)),
        manifest_id=(
            _SCOPE_TEST_VALUES[ScopeKind.MANIFEST_ID]
            if ScopeKind.MANIFEST_ID in scopes
            else None
        ),
        classification=(
            DataClassification.RESTRICTED
            if rule.restricted
            else DataClassification.INTERNAL
        ),
    )
    return (
        _ticket(
            relative,
            intent=grant.intent,
            expected_kind=grant.expected_kind,
            exists=grant.intent.requires_existing,
        ),
        context,
    )


@pytest.fixture
def policy_lab(tmp_path: Path) -> tuple[Path, Any]:
    project = tmp_path / "project"
    project.mkdir()
    return project, _create_test_boundary(project)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("run_id", "run-lowercase"),
        ("job_id", r"JOB\ESCAPE"),
        ("operation_id", ".."),
        ("operation_id", "OP:ADS"),
        ("operation_id", "OP-TRAILING-"),
    ],
)
def test_operation_context_rejects_noncanonical_ids(field: str, value: str) -> None:
    values: dict[str, Any] = {
        "run_id": "RUN-TEST-001",
        "job_id": "JOB-TEST-001",
        "operation_id": "OP-TEST-001",
        "caller": Caller.TEST_LAB,
        "purpose": Purpose.TEST,
    }
    values[field] = value
    with pytest.raises(ContextError):
        OperationContext(**values)


def test_operation_context_rejects_unknown_enums_and_scope_mismatch() -> None:
    with pytest.raises(ContextError, match="caller"):
        OperationContext(
            run_id="RUN-TEST-001",
            job_id="JOB-TEST-001",
            operation_id="OP-TEST-001",
            caller="CLI",  # type: ignore[arg-type]
            purpose=Purpose.TEST,
        )
    with pytest.raises(ContextError, match="repeated"):
        _context(
            scopes=(
                _scope(ScopeKind.JOB_ID, "JOB-TEST-001"),
                _scope(ScopeKind.JOB_ID, "JOB-TEST-001"),
            )
        )
    with pytest.raises(ContextError, match="RUN_ID"):
        _context(scopes=(_scope(ScopeKind.RUN_ID, "RUN-OTHER-001"),))
    with pytest.raises(ContextError, match="both be present"):
        _context(manifest_id="MANIFEST-001")
    with pytest.raises(ContextError, match="both be present"):
        _context(scopes=(_scope(ScopeKind.MANIFEST_ID, "MANIFEST-001"),))


def test_operation_context_digest_is_scope_order_independent() -> None:
    first = _context(
        scopes=(
            _scope(ScopeKind.JOB_ID, "JOB-TEST-001"),
            _scope(ScopeKind.OBJECT_ID, "OBJECT-001"),
        )
    )
    second = _context(
        scopes=(
            _scope(ScopeKind.OBJECT_ID, "OBJECT-001"),
            _scope(ScopeKind.JOB_ID, "JOB-TEST-001"),
        )
    )
    assert first.digest == second.digest


def test_restricted_context_public_views_are_identifier_free() -> None:
    context = _context(
        scopes=(
            _scope(ScopeKind.JOB_ID, "JOB-TEST-001"),
            _scope(ScopeKind.MANIFEST_ID, "MANIFEST-001"),
        ),
        manifest_id="MANIFEST-001",
        classification=DataClassification.RESTRICTED,
    )
    rendered = str(context.to_audit_dict()) + repr(context)
    assert "RUN-TEST-001" not in rendered
    assert "JOB-TEST-001" not in rendered
    assert "OP-TEST-001" not in rendered
    assert "MANIFEST-001" not in rendered
    scope = context.scopes[0]
    assert "JOB-TEST-001" not in repr(scope)
    assert scope.to_audit_dict()["value"] is None
    with pytest.raises(TypeError):
        pickle.dumps(scope)
    with pytest.raises(TypeError):
        pickle.dumps(context)


def test_context_rejects_polymorphic_scope_and_tuple_claim_sources() -> None:
    class ForgedScope(ScopeId):
        pass

    class ForgedTuple(tuple):
        pass

    with pytest.raises(ContextError, match="tuple of ScopeId"):
        _context(
            scopes=(ForgedScope(ScopeKind.JOB_ID, "JOB-TEST-001"),),
        )
    with pytest.raises(ContextError, match="tuple of ScopeId"):
        _context(
            scopes=ForgedTuple((_scope(ScopeKind.JOB_ID, "JOB-TEST-001"),)),  # type: ignore[arg-type]
        )


def test_policy_uses_longest_component_prefix_and_stable_digest() -> None:
    policy = NamespacePolicy()
    assert policy.classify(Path("data/db/backups/legacy.sqlite3")).namespace is NamespaceId.LEGACY_DB_BACKUP
    assert policy.classify(Path("data/db/active-state.json")).namespace is NamespaceId.ACTIVE_STATE_POINTER
    assert policy.classify(Path("data/db/question_bank.sqlite3-wal")).namespace is NamespaceId.DATABASE_SIDECAR
    assert policy.classify(Path("data/db/question_bank.sqlite3")).namespace is NamespaceId.ACTIVE_DATABASE
    assert NamespacePolicy(tuple(reversed(DEFAULT_RULES))).digest == policy.digest
    assert policy.digest == "8df50ded63443c3310603614fd6d317234ce026c351870d0488a84dd1cfe4d88"
    with pytest.raises(ValueError, match="no exact grant"):
        NamespacePolicy(DEFAULT_RULES, grants=())


def test_policy_constructor_rejects_non_exact_grant_field_types() -> None:
    grant = next(candidate for candidate in EXACT_GRANTS if not candidate.paired)

    class FakeNamespace(StrEnum):
        VALUE = grant.namespace.value

    class FakeIntent(StrEnum):
        VALUE = grant.intent.value

    class FakeExpectedKind(StrEnum):
        VALUE = grant.expected_kind.value

    class FakeCaller(StrEnum):
        VALUE = grant.caller.value

    class FakePurpose(StrEnum):
        VALUE = grant.purpose.value

    class FakeScope(StrEnum):
        VALUE = ScopeKind.RUN_ID.value

    malformed_fields: tuple[tuple[str, object], ...] = (
        ("namespace", FakeNamespace.VALUE),
        ("intent", FakeIntent.VALUE),
        ("expected_kind", FakeExpectedKind.VALUE),
        ("caller", FakeCaller.VALUE),
        ("purpose", FakePurpose.VALUE),
        ("paired", 1),
        ("required_scopes", frozenset({FakeScope.VALUE})),
        ("required_scopes", (ScopeKind.RUN_ID,)),
    )
    for field, value in malformed_fields:
        malformed = replace(grant, **{field: value})
        grants = tuple(
            malformed if candidate is grant else candidate
            for candidate in EXACT_GRANTS
        )
        with pytest.raises(ValueError, match="exact policy types"):
            NamespacePolicy(grants=grants)

    same_value_fake_caller = replace(grant, caller=FakeCaller.VALUE)
    assert same_value_fake_caller.to_canonical_dict() == grant.to_canonical_dict()

    class ForgedGrant(CapabilityGrant):
        pass

    forged = ForgedGrant(
        namespace=grant.namespace,
        intent=grant.intent,
        expected_kind=grant.expected_kind,
        caller=grant.caller,
        purpose=grant.purpose,
        paired=grant.paired,
        required_scopes=grant.required_scopes,
    )
    grants = tuple(
        forged if candidate is grant else candidate for candidate in EXACT_GRANTS
    )
    with pytest.raises(ValueError, match="exact CapabilityGrant"):
        NamespacePolicy(grants=grants)


def test_policy_constructor_rejects_non_exact_rule_field_types() -> None:
    rule = next(candidate for candidate in DEFAULT_RULES if candidate.scope_bindings)

    class FakeNamespace(StrEnum):
        VALUE = rule.namespace.value

    class ForgedBinding(ScopeBinding):
        pass

    malformed_rules = (
        replace(rule, namespace=FakeNamespace.VALUE),
        replace(rule, minimum_tail_depth=True),
        replace(rule, restricted=1),
        replace(rule, normal_intents=set(rule.normal_intents)),
        replace(
            rule,
            scope_bindings=(
                ForgedBinding(
                    rule.scope_bindings[0].tail_index,
                    rule.scope_bindings[0].scope_kind,
                ),
            ),
        ),
    )
    for malformed in malformed_rules:
        rules = tuple(
            malformed if candidate is rule else candidate
            for candidate in DEFAULT_RULES
        )
        with pytest.raises(ValueError, match="exact"):
            NamespacePolicy(rules=rules)

    class ForgedRule(NamespaceRule):
        pass

    forged = ForgedRule(
        **{
            field: getattr(rule, field)
            for field in NamespaceRule.__dataclass_fields__
        }
    )
    rules = tuple(
        forged if candidate is rule else candidate for candidate in DEFAULT_RULES
    )
    with pytest.raises(ValueError, match="exact NamespaceRule"):
        NamespacePolicy(rules=rules)


def test_policy_copies_public_configuration_and_detects_internal_tampering() -> None:
    input_grants = tuple(replace(grant) for grant in EXACT_GRANTS)
    policy = NamespacePolicy(grants=input_grants)
    original_digest = policy.digest

    object.__setattr__(input_grants[0], "caller", Caller.WEB)
    assert policy.digest == original_digest

    public_grant = policy.grants[0]
    object.__setattr__(public_grant, "caller", Caller.WEB)
    assert policy.digest == original_digest

    public_rule = policy.rules[0]
    object.__setattr__(public_rule, "mode", NamespaceMode.FORBIDDEN)
    assert policy.digest == original_digest

    internal_grant = object.__getattribute__(policy, "_grants")[0]
    replacement_caller = (
        Caller.WEB
        if internal_grant.caller is not Caller.WEB
        else Caller.TEST_LAB
    )
    object.__setattr__(internal_grant, "caller", replacement_caller)
    with pytest.raises(PolicyIntegrityError, match="changed after construction"):
        _ = policy.digest

    same_value_policy = NamespacePolicy()
    same_value_internal = object.__getattribute__(same_value_policy, "_grants")[0]

    class FakeCaller(StrEnum):
        VALUE = same_value_internal.caller.value

    object.__setattr__(same_value_internal, "caller", FakeCaller.VALUE)
    with pytest.raises(PolicyIntegrityError, match="cannot be recomputed"):
        _ = same_value_policy.digest

    same_value_rule_policy = NamespacePolicy()
    internal_rule = next(
        rule
        for rule in object.__getattribute__(same_value_rule_policy, "_rules")
        if rule.namespace is NamespaceId.QUARANTINE_INTERNAL
    )

    class FakeAuditMode(StrEnum):
        VALUE = AuditPathMode.HMAC_ONLY.value

    object.__setattr__(internal_rule, "audit_path_mode", FakeAuditMode.VALUE)
    with pytest.raises(PolicyIntegrityError, match="cannot be recomputed"):
        _ = same_value_rule_policy.digest


def test_policy_constructor_rejects_any_unreviewed_grant_set_change() -> None:
    grant = next(
        candidate
        for candidate in EXACT_GRANTS
        if candidate.namespace is NamespaceId.BASE_REFERENCE
        and candidate.intent is PathIntent.EXISTING_READ
        and candidate.caller is Caller.IMPORT_SERVICE
        and candidate.purpose is Purpose.READ_REFERENCE
    )
    cross_product = replace(
        grant,
        caller=Caller.BACKUP_SERVICE,
        purpose=Purpose.READ_REFERENCE,
    )
    with pytest.raises(ValueError, match="grant set is fixed"):
        NamespacePolicy(grants=EXACT_GRANTS + (cross_product,))

    without_one_actor = tuple(
        candidate for candidate in EXACT_GRANTS if candidate is not grant
    )
    with pytest.raises(ValueError, match="grant set is fixed"):
        NamespacePolicy(grants=without_one_actor)


def test_every_normal_exact_grant_is_runtime_reachable() -> None:
    policy = NamespacePolicy()
    normal_grants = tuple(grant for grant in EXACT_GRANTS if not grant.paired)
    assert normal_grants
    for grant in normal_grants:
        ticket, context = _normal_grant_case(grant)
        decision = policy.authorize(ticket, context)
        assert decision.namespace is grant.namespace


def test_every_normal_capability_matches_the_exact_actor_matrix() -> None:
    policy = NamespacePolicy()
    groups: dict[tuple[NamespaceId, PathIntent, ExpectedKind], list[Any]] = {}
    for grant in EXACT_GRANTS:
        if not grant.paired:
            groups.setdefault(
                (grant.namespace, grant.intent, grant.expected_kind),
                [],
            ).append(grant)

    for group_grants in groups.values():
        required_scopes = frozenset(
            scope
            for grant in group_grants
            for scope in grant.required_scopes
        )
        ticket, base_context = _normal_grant_case(
            replace(group_grants[0], required_scopes=required_scopes)
        )
        actual: set[tuple[Caller, Purpose]] = set()
        for caller in Caller:
            for purpose in Purpose:
                context = replace(base_context, caller=caller, purpose=purpose)
                try:
                    policy.authorize(ticket, context)
                except NamespacePolicyError:
                    continue
                actual.add((caller, purpose))
        expected = {(grant.caller, grant.purpose) for grant in group_grants}
        assert actual == expected, (
            group_grants[0].namespace,
            group_grants[0].intent,
            group_grants[0].expected_kind,
        )


def test_every_publish_topology_has_an_exact_actor_intersection() -> None:
    for source_namespace, target_namespace in production_guard_module._PUBLISH_TOPOLOGY:
        source_actors = {
            (grant.caller, grant.purpose)
            for grant in EXACT_GRANTS
            if grant.paired
            and grant.namespace is source_namespace
            and grant.intent is PathIntent.MOVE_SOURCE
            and grant.expected_kind is ExpectedKind.DIRECTORY
        }
        target_actors = {
            (grant.caller, grant.purpose)
            for grant in EXACT_GRANTS
            if grant.paired
            and grant.namespace is target_namespace
            and grant.intent is PathIntent.MOVE_TARGET
            and grant.expected_kind is ExpectedKind.DIRECTORY
        }
        assert source_actors & target_actors, (source_namespace, target_namespace)


def test_policy_constructor_rejects_malformed_rules_and_grants() -> None:
    scoped_rule = next(rule for rule in DEFAULT_RULES if rule.scope_bindings)
    malformed_binding = replace(
        scoped_rule,
        scope_bindings=(ScopeBinding(-1, ScopeKind.JOB_ID),),
    )
    malformed_rules = tuple(
        malformed_binding if rule is scoped_rule else rule for rule in DEFAULT_RULES
    )
    with pytest.raises(ValueError, match="indices cannot be negative"):
        NamespacePolicy(malformed_rules)

    rooted_rule = next(
        rule
        for rule in DEFAULT_RULES
        if rule.object_root_depth is not None and rule.minimum_tail_depth > 0
    )
    malformed_depth = replace(rooted_rule, object_root_depth=0)
    malformed_rules = tuple(
        malformed_depth if rule is rooted_rule else rule for rule in DEFAULT_RULES
    )
    with pytest.raises(ValueError, match="depth bounds"):
        NamespacePolicy(malformed_rules)

    paired_grant = next(grant for grant in EXACT_GRANTS if grant.paired)
    malformed_kind = replace(paired_grant, expected_kind=ExpectedKind.FILE)
    malformed_grants = tuple(
        malformed_kind if grant is paired_grant else grant for grant in EXACT_GRANTS
    )
    with pytest.raises(ValueError, match="actor, purpose, or kind"):
        NamespacePolicy(grants=malformed_grants)

    malformed_actor = replace(paired_grant, caller=Caller.WEB)
    malformed_grants = tuple(
        malformed_actor if grant is paired_grant else grant for grant in EXACT_GRANTS
    )
    with pytest.raises(ValueError, match="actor, purpose, or kind"):
        NamespacePolicy(grants=malformed_grants)

    ledger_rule = next(
        rule for rule in DEFAULT_RULES if rule.namespace is NamespaceId.AUDIT_LOG
    )
    malformed_ledger = replace(
        ledger_rule,
        normal_intents=ledger_rule.normal_intents | frozenset({PathIntent.NEW_WRITE}),
        normal_mutation_kinds=frozenset({ExpectedKind.FILE}),
    )
    malformed_rules = tuple(
        malformed_ledger if rule is ledger_rule else rule for rule in DEFAULT_RULES
    )
    with pytest.raises(ValueError, match="read-only"):
        NamespacePolicy(malformed_rules)


@pytest.mark.parametrize(
    ("mode", "bad_intent"),
    [
        (NamespaceMode.IMMUTABLE_OBJECT_STORE, PathIntent.EXISTING_WRITE),
        (NamespaceMode.VERSIONED_STORE, PathIntent.EXISTING_WRITE),
        (NamespaceMode.JOB_MUTABLE, PathIntent.MOVE_TARGET),
        (NamespaceMode.DATABASE_CONTROLLED, PathIntent.APPEND_EXISTING),
        (NamespaceMode.ATOMIC_POINTER, PathIntent.NEW_WRITE),
        (NamespaceMode.QUARANTINE_ONLY, PathIntent.NEW_WRITE),
    ],
)
def test_policy_constructor_enforces_mode_semantics(
    mode: NamespaceMode,
    bad_intent: PathIntent,
) -> None:
    rule = next(rule for rule in DEFAULT_RULES if rule.mode is mode)
    malformed = replace(
        rule,
        normal_intents=rule.normal_intents | frozenset({bad_intent}),
        normal_mutation_kinds=(
            rule.normal_mutation_kinds | frozenset({ExpectedKind.FILE})
        ),
    )
    rules = tuple(malformed if candidate is rule else candidate for candidate in DEFAULT_RULES)
    with pytest.raises(ValueError, match=f"{mode.value} namespace"):
        NamespacePolicy(rules)


@pytest.mark.parametrize(
    "namespace",
    [
        NamespaceId.COPY_RESTRICTED,
        NamespaceId.COPY_WORK_RESTRICTED,
        NamespaceId.JOB_WORKSPACE_RESTRICTED,
        NamespaceId.QUARANTINE_RESTRICTED,
        NamespaceId.AUDIT_KEY_REVISION,
    ],
)
def test_policy_constructor_cannot_downgrade_restricted_partitions(
    namespace: NamespaceId,
) -> None:
    rule = next(rule for rule in DEFAULT_RULES if rule.namespace is namespace)
    malformed = replace(rule, restricted=False)
    rules = tuple(malformed if candidate is rule else candidate for candidate in DEFAULT_RULES)
    with pytest.raises(ValueError, match="restricted classification"):
        NamespacePolicy(rules)


@pytest.mark.parametrize(
    ("internal_namespace", "restricted_namespace"),
    [
        (NamespaceId.GIT_INTERNAL, NamespaceId.BASE_REFERENCE),
        (NamespaceId.COPY_SOURCE, NamespaceId.COPY_RESTRICTED),
        (NamespaceId.COPY_WORK_INTERNAL, NamespaceId.COPY_WORK_RESTRICTED),
        (NamespaceId.JOB_WORKSPACE_INTERNAL, NamespaceId.JOB_WORKSPACE_RESTRICTED),
        (NamespaceId.QUARANTINE_INTERNAL, NamespaceId.QUARANTINE_RESTRICTED),
        (NamespaceId.ACTIVE_DATABASE, NamespaceId.COPY_LEDGER),
        (NamespaceId.ACTIVE_STATE_POINTER, NamespaceId.AUDIT_LOG),
    ],
)
def test_policy_constructor_cannot_swap_classification_sensitive_prefixes(
    internal_namespace: NamespaceId,
    restricted_namespace: NamespaceId,
) -> None:
    internal = next(
        rule for rule in DEFAULT_RULES if rule.namespace is internal_namespace
    )
    restricted = next(
        rule for rule in DEFAULT_RULES if rule.namespace is restricted_namespace
    )
    swapped_internal = replace(internal, prefix=restricted.prefix)
    swapped_restricted = replace(restricted, prefix=internal.prefix)
    rules = tuple(
        swapped_internal
        if rule is internal
        else swapped_restricted
        if rule is restricted
        else rule
        for rule in DEFAULT_RULES
    )
    with pytest.raises(ValueError, match="prefix is fixed"):
        NamespacePolicy(rules)


@pytest.mark.parametrize(
    "namespace",
    [
        NamespaceId.COPY_RESTRICTED,
        NamespaceId.COPY_WORK_RESTRICTED,
        NamespaceId.JOB_WORKSPACE_RESTRICTED,
        NamespaceId.ORIGINAL_OBJECT,
        NamespaceId.DATABASE_VERSION,
    ],
)
def test_policy_constructor_cannot_remove_fixed_scope_bindings(
    namespace: NamespaceId,
) -> None:
    rule = next(rule for rule in DEFAULT_RULES if rule.namespace is namespace)
    malformed = replace(rule, scope_bindings=())
    rules = tuple(malformed if candidate is rule else candidate for candidate in DEFAULT_RULES)
    with pytest.raises(ValueError, match="scope bindings are fixed"):
        NamespacePolicy(rules)


def test_policy_constructor_cannot_shallow_the_quarantine_object_root() -> None:
    rule = next(
        rule
        for rule in DEFAULT_RULES
        if rule.namespace is NamespaceId.QUARANTINE_RESTRICTED
    )
    malformed = replace(rule, minimum_tail_depth=0, object_root_depth=0)
    rules = tuple(malformed if candidate is rule else candidate for candidate in DEFAULT_RULES)
    with pytest.raises(ValueError, match="depths are fixed"):
        NamespacePolicy(rules)


def test_restricted_rule_actor_pairs_block_future_cross_product_grants() -> None:
    write_base = next(
        grant
        for grant in EXACT_GRANTS
        if grant.namespace is NamespaceId.COPY_WORK_RESTRICTED
        and not grant.paired
        and grant.intent is PathIntent.EXISTING_WRITE
        and grant.purpose is Purpose.BUILD_DERIVED
    )
    append_base = next(
        grant
        for grant in EXACT_GRANTS
        if grant.namespace is NamespaceId.COPY_WORK_RESTRICTED
        and not grant.paired
        and grant.intent is PathIntent.APPEND_EXISTING
    )
    publish_base = next(
        grant
        for grant in EXACT_GRANTS
        if grant.namespace is NamespaceId.COPY_RESTRICTED
        and grant.paired
        and grant.intent is PathIntent.MOVE_TARGET
    )
    malformed = (
        replace(
            write_base,
            caller=Caller.BACKUP_SERVICE,
            purpose=Purpose.QUARANTINE,
        ),
        replace(
            append_base,
            caller=Caller.REPORT_SERVICE,
            purpose=Purpose.QUARANTINE,
        ),
        replace(publish_base, purpose=Purpose.QUARANTINE),
        replace(write_base, expected_kind=ExpectedKind.DIRECTORY),
    )
    for cross_product in malformed:
        with pytest.raises(ValueError, match="actor, purpose, or kind"):
            NamespacePolicy(grants=EXACT_GRANTS + (cross_product,))

    rule = next(
        rule
        for rule in DEFAULT_RULES
        if rule.namespace is NamespaceId.COPY_WORK_RESTRICTED
    )
    widened_projection = replace(
        rule,
        read_callers=rule.read_callers | frozenset({Caller.BACKUP_SERVICE}),
    )
    rules = tuple(
        widened_projection if candidate is rule else candidate
        for candidate in DEFAULT_RULES
    )
    with pytest.raises(ValueError, match="projections exceed"):
        NamespacePolicy(rules)


@pytest.mark.parametrize(
    "namespace",
    [NamespaceId.COPY_WORK_INTERNAL, NamespaceId.JOB_WORKSPACE_INTERNAL],
)
def test_internal_job_rules_block_future_cross_product_grants(
    namespace: NamespaceId,
) -> None:
    base = next(
        grant
        for grant in EXACT_GRANTS
        if grant.namespace is namespace
        and not grant.paired
        and grant.intent is PathIntent.EXISTING_WRITE
    )
    malformed = (
        replace(
            base,
            caller=Caller.BACKUP_SERVICE,
            purpose=Purpose.BUILD_DERIVED,
        ),
        replace(
            base,
            caller=Caller.BACKUP_SERVICE,
            purpose=Purpose.QUARANTINE,
        ),
    )
    for cross_product in malformed:
        with pytest.raises(ValueError, match="actor, purpose, or kind"):
            NamespacePolicy(grants=EXACT_GRANTS + (cross_product,))


@pytest.mark.parametrize(
    "namespace",
    [
        NamespaceId.COPY_WORK_INTERNAL,
        NamespaceId.JOB_WORKSPACE_INTERNAL,
        NamespaceId.QUARANTINE_INTERNAL,
    ],
)
@pytest.mark.parametrize("field", ["read_actor_pairs", "mutation_capabilities"])
def test_internal_rules_require_exact_actor_metadata(
    namespace: NamespaceId,
    field: str,
) -> None:
    rule = next(candidate for candidate in DEFAULT_RULES if candidate.namespace is namespace)
    malformed = replace(rule, **{field: frozenset()})
    rules = tuple(
        malformed if candidate is rule else candidate for candidate in DEFAULT_RULES
    )
    with pytest.raises(ValueError, match="requires exact"):
        NamespacePolicy(rules)


@pytest.mark.parametrize(
    "namespace",
    [NamespaceId.COPY_WORK_INTERNAL, NamespaceId.JOB_WORKSPACE_INTERNAL],
)
def test_internal_job_metadata_must_equal_exact_grants(
    namespace: NamespaceId,
) -> None:
    rule = next(candidate for candidate in DEFAULT_RULES if candidate.namespace is namespace)
    extra = (
        PathIntent.EXISTING_WRITE,
        ExpectedKind.FILE,
        Caller.BACKUP_SERVICE,
        Purpose.BUILD_DERIVED,
    )
    widened = replace(
        rule,
        mutation_capabilities=rule.mutation_capabilities | frozenset({extra}),
    )
    rules = tuple(
        widened if candidate is rule else candidate for candidate in DEFAULT_RULES
    )
    with pytest.raises(ValueError, match="metadata does not equal exact grants"):
        NamespacePolicy(rules)


@pytest.mark.parametrize(
    ("namespace", "extra_pair"),
    [
        (
            NamespaceId.COPY_WORK_INTERNAL,
            (Caller.BACKUP_SERVICE, Purpose.BUILD_DERIVED),
        ),
        (
            NamespaceId.JOB_WORKSPACE_INTERNAL,
            (Caller.BACKUP_SERVICE, Purpose.BUILD_DERIVED),
        ),
        (
            NamespaceId.QUARANTINE_INTERNAL,
            (Caller.BACKUP_SERVICE, Purpose.READ_CONTROL),
        ),
    ],
)
def test_internal_read_metadata_must_equal_exact_grants(
    namespace: NamespaceId,
    extra_pair: tuple[Caller, Purpose],
) -> None:
    rule = next(candidate for candidate in DEFAULT_RULES if candidate.namespace is namespace)
    widened = replace(
        rule,
        read_actor_pairs=rule.read_actor_pairs | frozenset({extra_pair}),
    )
    rules = tuple(
        widened if candidate is rule else candidate for candidate in DEFAULT_RULES
    )
    with pytest.raises(ValueError, match="metadata does not equal exact grants"):
        NamespacePolicy(rules)


@pytest.mark.parametrize(
    "namespace",
    [
        NamespaceId.COPY_LEDGER,
        NamespaceId.AUDIT_LOG,
        NamespaceId.AUDIT_KEY_REVISION,
    ],
)
def test_public_policy_has_no_direct_ledger_mutation_grant(namespace: NamespaceId) -> None:
    assert not any(
        grant.namespace is namespace and grant.intent.mutating
        for grant in EXACT_GRANTS
    )


def test_read_permissions_are_explicit_and_default_deny() -> None:
    policy = NamespacePolicy()
    base_ticket = _ticket("Base/Base.md", intent=PathIntent.EXISTING_READ, exists=True)
    decision = policy.authorize(
        base_ticket,
        _context(caller=Caller.IMPORT_SERVICE, purpose=Purpose.READ_REFERENCE),
    )
    assert decision.namespace is NamespaceId.BASE_REFERENCE

    with pytest.raises(NamespacePolicyError) as wrong_reader:
        policy.authorize(base_ticket, _context())
    assert wrong_reader.value.code is PolicyErrorCode.CALLER_NOT_ALLOWED

    task_ticket = _ticket("Task/README.md", intent=PathIntent.EXISTING_READ, exists=True)
    with pytest.raises(NamespacePolicyError):
        policy.authorize(
            task_ticket,
            _context(caller=Caller.IMPORT_SERVICE, purpose=Purpose.READ_REFERENCE),
        )

    with pytest.raises(NamespacePolicyError) as unknown:
        policy.authorize(
            _ticket("app/existing.py", intent=PathIntent.EXISTING_READ, exists=True),
            _context(),
        )
    assert unknown.value.code is PolicyErrorCode.UNCLASSIFIED_ACCESS


@pytest.mark.parametrize("path", ["Base/new.bin", "Task/new.md"])
def test_permanent_control_namespaces_are_read_only(path: str) -> None:
    with pytest.raises(NamespacePolicyError) as error:
        NamespacePolicy().authorize(
            _ticket(path, intent=PathIntent.NEW_WRITE),
            _context(),
        )
    assert error.value.code in {
        PolicyErrorCode.PROTECTED_NAMESPACE,
        PolicyErrorCode.CALLER_NOT_ALLOWED,
    }


def test_git_namespace_is_forbidden_even_for_read() -> None:
    with pytest.raises(NamespacePolicyError) as error:
        NamespacePolicy().authorize(
            _ticket(".git/config", intent=PathIntent.EXISTING_READ, exists=True),
            _context(),
        )
    assert error.value.code is PolicyErrorCode.FORBIDDEN_NAMESPACE


def test_pair_intents_cannot_be_enabled_by_public_boolean() -> None:
    policy = NamespacePolicy()
    ticket = _ticket(
        "Copy/source/COPY-001",
        intent=PathIntent.MOVE_TARGET,
        expected_kind=ExpectedKind.DIRECTORY,
    )
    with pytest.raises(NamespacePolicyError) as error:
        policy.authorize(
            ticket,
            _context(
                caller=Caller.IMPORT_SERVICE,
                purpose=Purpose.COPY_SOURCE,
                scopes=(_scope(ScopeKind.COPY_ID, "COPY-001"),),
            ),
        )
    assert error.value.code is PolicyErrorCode.PAIR_AUTHORIZATION_REQUIRED
    with pytest.raises(TypeError):
        policy.authorize(  # type: ignore[call-arg]
            ticket,
            _context(),
            paired=True,
        )


def test_pair_policy_authorizes_only_an_atomic_bound_pair() -> None:
    policy = NamespacePolicy()
    context = _context(
        caller=Caller.IMPORT_SERVICE,
        purpose=Purpose.COPY_SOURCE,
        scopes=(_scope(ScopeKind.COPY_ID, "COPY-001"),),
    )
    exact_target = _ticket(
        "Copy/source/COPY-001",
        intent=PathIntent.MOVE_TARGET,
        expected_kind=ExpectedKind.DIRECTORY,
    )
    assert not hasattr(policy, "_issue_pair_claim")
    assert not hasattr(policy, "_authorize_paired")
    assert not hasattr(policy, "_authorize_pair_for_boundary")
    assert not hasattr(policy, "_authorize_pair")
    with pytest.raises(NamespacePolicyError) as direct_private:
        policy._NamespacePolicy__authorize(  # type: ignore[attr-defined]
            exact_target,
            context,
            pair_seal=object(),
        )
    assert direct_private.value.code is PolicyErrorCode.PAIR_AUTHORIZATION_REQUIRED
    forged_type = type(
        "_BoundaryNamespacePolicy",
        (NamespacePolicy,),
        {"__module__": "app.safety.production_guard"},
    )
    forged_policy = forged_type()
    with pytest.raises(PermissionError):
        forged_policy._install_boundary_pair_seal(object())
    with pytest.raises(NamespacePolicyError) as public_denial:
        policy.authorize(exact_target, context)
    assert public_denial.value.code is PolicyErrorCode.PAIR_AUTHORIZATION_REQUIRED
    for path, kind in (
        ("Copy/source/COPY-001/original.pdf", ExpectedKind.FILE),
        ("Copy/source", ExpectedKind.DIRECTORY),
    ):
        with pytest.raises(NamespacePolicyError):
            policy.authorize(
                _ticket(path, intent=PathIntent.MOVE_TARGET, expected_kind=kind),
                context,
            )
    with pytest.raises(NamespacePolicyError):
        policy.authorize(
            _ticket("Copy/source/COPY-001/file", intent=PathIntent.NEW_WRITE),
            context,
        )


def test_active_database_and_sidecars_are_exact_database_capabilities() -> None:
    policy = NamespacePolicy()
    context = _context(
        caller=Caller.DATABASE_SERVICE,
        purpose=Purpose.MUTATE_DATABASE,
    )
    for path in (
        "data/db/question_bank.sqlite3",
        "data/db/question_bank.sqlite3-wal",
        "data/db/question_bank.sqlite3-shm",
        "data/db/question_bank.sqlite3-journal",
    ):
        decision = policy.authorize(
            _ticket(path, intent=PathIntent.NEW_WRITE, expected_kind=ExpectedKind.FILE),
            context,
        )
        assert decision.namespace in {
            NamespaceId.ACTIVE_DATABASE,
            NamespaceId.DATABASE_SIDECAR,
        }
    for path in (
        "data/db/other.sqlite3",
        "data/db/question_bank.sqlite3/child",
        "data/db/question_bank.sqlite3-unknown",
    ):
        with pytest.raises(NamespacePolicyError):
            policy.authorize(
                _ticket(path, intent=PathIntent.NEW_WRITE, expected_kind=ExpectedKind.FILE),
                context,
            )


def test_segment_namespaces_are_fixed_read_only_files_not_direct_write_surfaces() -> None:
    policy = NamespacePolicy()
    allowed = policy.authorize(
        _ticket(
            "Copy/ledger/segments/COPY-001/00000000000000000000-"
            + "a" * 64
            + ".json",
            intent=PathIntent.EXISTING_READ,
            expected_kind=ExpectedKind.FILE,
            exists=True,
        ),
        _context(
            caller=Caller.IMPORT_SERVICE,
            purpose=Purpose.COPY_SOURCE,
            scopes=(_scope(ScopeKind.COPY_ID, "COPY-001"),),
        ),
    )
    assert allowed.namespace is NamespaceId.COPY_LEDGER
    for path, intent, kind in (
        ("Copy/ledger/events.jsonl", PathIntent.EXISTING_READ, ExpectedKind.FILE),
        (
            "Copy/ledger/segments/COPY-001/00000000000000000000-" + "a" * 64 + ".json",
            PathIntent.NEW_WRITE,
            ExpectedKind.FILE,
        ),
        ("Copy/ledger/segments/COPY-001", PathIntent.CREATE_DIRECTORY, ExpectedKind.DIRECTORY),
        ("Copy/ledger", PathIntent.CREATE_DIRECTORY, ExpectedKind.DIRECTORY),
    ):
        with pytest.raises(NamespacePolicyError):
            policy.authorize(
                _ticket(path, intent=intent, expected_kind=kind),
                _context(caller=Caller.IMPORT_SERVICE, purpose=Purpose.COPY_SOURCE),
            )


def test_audit_key_revision_is_restricted_read_only_and_not_report_visible() -> None:
    policy = NamespacePolicy()
    path = "logs/audit/keys/00000001-KEYREV-ONE-" + "b" * 64 + ".json"
    allowed = policy.authorize(
        _ticket(
            path,
            intent=PathIntent.EXISTING_READ,
            expected_kind=ExpectedKind.FILE,
            exists=True,
        ),
        _context(
            caller=Caller.AUDIT_SERVICE,
            purpose=Purpose.READ_CONTROL,
            classification=DataClassification.RESTRICTED,
        ),
    )
    assert allowed.namespace is NamespaceId.AUDIT_KEY_REVISION
    assert allowed.effective_classification is DataClassification.RESTRICTED
    for caller, purpose, classification, intent in (
        (Caller.REPORT_SERVICE, Purpose.READ_CONTROL, DataClassification.RESTRICTED, PathIntent.EXISTING_READ),
        (Caller.AUDIT_SERVICE, Purpose.READ_CONTROL, DataClassification.INTERNAL, PathIntent.EXISTING_READ),
        (Caller.AUDIT_SERVICE, Purpose.READ_CONTROL, DataClassification.RESTRICTED, PathIntent.NEW_WRITE),
    ):
        with pytest.raises(NamespacePolicyError):
            policy.authorize(
                _ticket(
                    path,
                    intent=intent,
                    expected_kind=ExpectedKind.FILE,
                    exists=intent is PathIntent.EXISTING_READ,
                ),
                _context(
                    caller=caller,
                    purpose=purpose,
                    classification=classification,
                ),
            )


@pytest.mark.parametrize(
    ("caller", "purpose"),
    [
        (Caller.AUDIT_SERVICE, Purpose.COPY_SOURCE),
        (Caller.IMPORT_SERVICE, Purpose.APPEND_AUDIT),
    ],
)
def test_exact_grants_reject_caller_purpose_cross_products(
    caller: Caller,
    purpose: Purpose,
) -> None:
    with pytest.raises(NamespacePolicyError):
        NamespacePolicy().authorize(
            _ticket(
                "Copy/ledger/segments/COPY-001/00000000000000000000-"
                + "a" * 64
                + ".json",
                intent=PathIntent.EXISTING_READ,
                expected_kind=ExpectedKind.FILE,
                exists=True,
            ),
            _context(
                caller=caller,
                purpose=purpose,
                scopes=(_scope(ScopeKind.COPY_ID, "COPY-001"),),
            ),
        )


def test_exact_grants_reject_append_directory_and_dead_pointer_mutation() -> None:
    policy = NamespacePolicy()
    with pytest.raises(NamespacePolicyError) as wrong_kind:
        policy.authorize(
            _ticket(
                "tmp/jobs/INTERNAL/JOB-TEST-001/output",
                intent=PathIntent.APPEND_EXISTING,
                expected_kind=ExpectedKind.DIRECTORY,
                exists=True,
            ),
            _context(
                scopes=(_scope(ScopeKind.JOB_ID, "JOB-TEST-001"),),
            ),
        )
    assert wrong_kind.value.code is PolicyErrorCode.EXPECTED_KIND_REQUIRED
    with pytest.raises(NamespacePolicyError):
        policy.authorize(
            _ticket(
                "data/db/active-state.json",
                intent=PathIntent.MOVE_TARGET,
                expected_kind=ExpectedKind.FILE,
            ),
            _context(
                caller=Caller.DATABASE_SERVICE,
                purpose=Purpose.RESTORE,
                scopes=(_scope(ScopeKind.STATE_ID, "STATE-001"),),
            ),
        )


def test_restricted_quarantine_and_staging_require_restricted_context() -> None:
    policy = NamespacePolicy()
    with pytest.raises(NamespacePolicyError) as quarantine_denial:
        policy.authorize(
            _ticket(
                "data/quarantine/RESTRICTED/2026-07-11/PAIR-001/private.xlsx",
                intent=PathIntent.EXISTING_READ,
                exists=True,
            ),
            _context(
                caller=Caller.CONTROL_SERVICE,
                purpose=Purpose.READ_CONTROL,
            ),
        )
    assert quarantine_denial.value.code is PolicyErrorCode.RESTRICTED_CONTEXT_REQUIRED
    with pytest.raises(NamespacePolicyError) as staging_denial:
        policy.authorize(
            _ticket(
                "tmp/jobs/RESTRICTED/JOB-TEST-001/private.bin",
                intent=PathIntent.EXISTING_READ,
                exists=True,
            ),
            _context(
                scopes=(_scope(ScopeKind.JOB_ID, "JOB-TEST-001"),),
            ),
        )
    assert staging_denial.value.code is PolicyErrorCode.RESTRICTED_CONTEXT_REQUIRED


@pytest.mark.parametrize(
    ("path", "scopes"),
    [
        (
            "tmp/jobs/INTERNAL/JOB-TEST-001/output.bin",
            (_scope(ScopeKind.JOB_ID, "JOB-TEST-001"),),
        ),
        (
            "Copy/work/INTERNAL/COPY-001/JOB-TEST-001/output.bin",
            (
                _scope(ScopeKind.COPY_ID, "COPY-001"),
                _scope(ScopeKind.JOB_ID, "JOB-TEST-001"),
            ),
        ),
        ("data/quarantine/INTERNAL/2026-07-11/PAIR-001", ()),
    ],
)
def test_restricted_context_cannot_downgrade_into_internal_partitions(
    path: str,
    scopes: tuple[ScopeId, ...],
) -> None:
    policy = NamespacePolicy()
    with pytest.raises(NamespacePolicyError) as denied:
        policy.authorize(
            _ticket(path, intent=PathIntent.EXISTING_READ, exists=True),
            _context(
                caller=(
                    Caller.CONTROL_SERVICE
                    if path.startswith("data/quarantine")
                    else Caller.TEST_LAB
                ),
                purpose=(
                    Purpose.READ_CONTROL
                    if path.startswith("data/quarantine")
                    else Purpose.TEST
                ),
                scopes=scopes,
                classification=DataClassification.RESTRICTED,
            ),
        )
    assert denied.value.code is PolicyErrorCode.CLASSIFICATION_MISMATCH


@pytest.mark.parametrize(
    ("caller", "purpose"),
    [
        (Caller.BACKUP_SERVICE, Purpose.BACKUP),
        (Caller.BACKUP_SERVICE, Purpose.RESTORE),
        (Caller.EXPORT_SERVICE, Purpose.BUILD_EXPORT),
        (Caller.REPORT_SERVICE, Purpose.BUILD_EXPORT),
        (Caller.DATABASE_SERVICE, Purpose.MUTATE_DATABASE),
        (Caller.ASSET_SERVICE, Purpose.BUILD_DERIVED),
    ],
)
def test_restricted_staging_uses_least_privilege_import_actors(
    caller: Caller,
    purpose: Purpose,
) -> None:
    policy = NamespacePolicy()
    with pytest.raises(NamespacePolicyError) as denied:
        policy.authorize(
            _ticket(
                "tmp/jobs/RESTRICTED/JOB-TEST-001/private.bin",
                intent=PathIntent.NEW_WRITE,
                expected_kind=ExpectedKind.FILE,
                exists=False,
            ),
            _context(
                caller=caller,
                purpose=purpose,
                scopes=(_scope(ScopeKind.JOB_ID, "JOB-TEST-001"),),
                classification=DataClassification.RESTRICTED,
            ),
        )
    assert denied.value.code in {
        PolicyErrorCode.CALLER_NOT_ALLOWED,
        PolicyErrorCode.PURPOSE_NOT_ALLOWED,
    }


@pytest.mark.parametrize(
    "path",
    [
        "data/db/question_bank.sqlite3",
        "data/db/question_bank.sqlite3-wal",
        "data/db/question_bank.sqlite3-shm",
        "data/db/question_bank.sqlite3-journal",
    ],
)
def test_restricted_context_cannot_mutate_internal_active_database(path: str) -> None:
    policy = NamespacePolicy()
    with pytest.raises(NamespacePolicyError) as denied:
        policy.authorize(
            _ticket(
                path,
                intent=PathIntent.EXISTING_WRITE,
                expected_kind=ExpectedKind.FILE,
                exists=True,
            ),
            _context(
                caller=Caller.DATABASE_SERVICE,
                purpose=Purpose.MUTATE_DATABASE,
                classification=DataClassification.RESTRICTED,
            ),
        )
    assert denied.value.code is PolicyErrorCode.CLASSIFICATION_MISMATCH


def test_fixed_production_factory_has_no_injection_and_writer_is_closed() -> None:
    boundary = get_production_boundary()
    assert boundary.project_root == CONTRACT_PROJECT_ROOT
    assert boundary.writer_available is False
    with pytest.raises(WriterUnavailableError):
        boundary.require_writer()
    with pytest.raises(TypeError):
        ProductionWorkspaceBoundary(_guard=object())  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        ProductionWorkspaceBoundary()


def test_fixed_production_boundary_has_one_concurrent_cold_start() -> None:
    production_guard_module._reset_production_boundary_for_tests()
    with ThreadPoolExecutor(max_workers=8) as executor:
        boundaries = tuple(executor.map(lambda _: get_production_boundary(), range(32)))
    assert len({id(boundary) for boundary in boundaries}) == 1


def test_fixed_production_factory_rejects_configured_root_expansion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    production_guard_module._reset_production_boundary_for_tests()
    monkeypatch.setattr(app_config, "PROJECT_ROOT", PROJECT_ROOT.parent)
    monkeypatch.setattr(
        production_guard_module,
        "CONTRACT_PROJECT_ROOT",
        PROJECT_ROOT.parent,
    )
    try:
        with pytest.raises(ProductionBoundaryError) as error:
            get_production_boundary()
        assert error.value.code is BoundaryErrorCode.PRODUCTION_ROOT_MISMATCH
    finally:
        production_guard_module._reset_production_boundary_for_tests()


def test_production_mutation_returns_candidate_only_denial() -> None:
    boundary = get_production_boundary()
    context = _context(scopes=(_scope(ScopeKind.JOB_ID, "JOB-TEST-001"),))
    before = len(boundary.audit_events)
    with pytest.raises(WriterUnavailableError):
        boundary.require_writer()
    result = boundary.authorize(
        "tmp/jobs/INTERNAL/JOB-TEST-001/new.bin",
        intent=PathIntent.NEW_WRITE,
        expected_kind=ExpectedKind.FILE,
        context=context,
    )
    assert isinstance(result, BoundaryResult)
    assert not result.ok
    assert isinstance(result.failure, BoundaryFailure)
    assert result.failure.code is BoundaryErrorCode.INVALID_CONTEXT
    assert not hasattr(result.failure, "__traceback__")
    with pytest.raises(ProductionBoundaryError) as fresh_error:
        result.require()
    assert fresh_error.value.code is BoundaryErrorCode.INVALID_CONTEXT
    traceback_names: list[str] = []
    traceback = fresh_error.value.__traceback__
    while traceback is not None:
        traceback_names.append(traceback.tb_frame.f_code.co_name)
        assert "issue_candidate" not in traceback.tb_frame.f_locals
        traceback = traceback.tb_next
    assert "issue_candidate" not in traceback_names
    event = boundary.audit_events[before]
    assert event.decision is AuditDecision.DENY
    assert event.safe_relative_path is None


def test_candidate_token_is_opaque_bound_and_candidate_audit_is_explicit(
    policy_lab: tuple[Path, Any],
) -> None:
    _, boundary = policy_lab
    context = _issued_context(
        boundary,
        scopes=(_scope(ScopeKind.JOB_ID, "JOB-TEST-001"),),
    )
    event_count = len(boundary.audit_events)
    ticket = boundary.authorize(
        "tmp/jobs/INTERNAL/JOB-TEST-001/future.bin",
        intent=PathIntent.NEW_WRITE,
        expected_kind=ExpectedKind.FILE,
        context=context,
    )
    descriptor = boundary.describe_candidate(ticket, context=context)
    assert descriptor.namespace is NamespaceId.JOB_WORKSPACE_INTERNAL
    assert descriptor.capability_state == "CANDIDATE_ONLY"
    assert not hasattr(ticket, "core_ticket")
    assert not hasattr(ticket, "ticket_id")
    assert not hasattr(ticket, "boundary_instance_id")
    assert not hasattr(ticket, "path")
    assert not hasattr(ticket, "relative_path")
    assert "authenticator" not in repr(ticket).lower()
    with pytest.raises(TypeError):
        pickle.dumps(ticket)
    event = boundary.audit_events[event_count]
    assert event.decision is AuditDecision.CANDIDATE_ALLOW
    assert event.capability_state == "CANDIDATE_ONLY"
    assert event.safe_relative_path == "tmp/jobs/internal/job-test-001/future.bin"
    assert "D:" not in str(event.to_dict())


def test_pair_evidence_is_exact_opaque_and_non_polymorphic(
    policy_lab: tuple[Path, Any],
) -> None:
    _, boundary = policy_lab

    class ForgedEvidence(PairEvidence):
        @property
        def digest(self) -> str:
            return "0" * 64

    base = _pair_evidence()
    forged = ForgedEvidence(
        manifest_id=base.manifest_id,
        manifest_sha256=base.manifest_sha256,
        source_tree_sha256=base.source_tree_sha256,
        entry_count=base.entry_count,
        total_bytes=base.total_bytes,
        checkpoint_id=base.checkpoint_id,
        checkpoint_manifest_sha256=base.checkpoint_manifest_sha256,
    )
    context = _issued_context(
        boundary,
        caller=Caller.IMPORT_SERVICE,
        purpose=Purpose.COPY_SOURCE,
        scopes=_pair_scopes(_scope(ScopeKind.OBJECT_ID, "OBJECT-001")),
        manifest_id="MANIFEST-001",
    )
    with pytest.raises(ProductionBoundaryError) as rejected:
        boundary.authorize_publish(
            "tmp/jobs/INTERNAL/JOB-TEST-001/publish/MANIFEST-001",
            "data/originals/OBJECT-001",
            evidence=forged,
            context=context,
        )
    assert rejected.value.code is BoundaryErrorCode.MANIFEST_BINDING_INVALID
    assert "MANIFEST-001" not in repr(base)
    with pytest.raises(TypeError):
        pickle.dumps(base)


@pytest.mark.parametrize(
    ("field", "value"),
    [("entry_count", True), ("total_bytes", False)],
)
def test_pair_evidence_rejects_boolean_integer_claims(
    field: str,
    value: bool,
) -> None:
    with pytest.raises(ContextError, match="integer"):
        replace(_pair_evidence(), **{field: value})


def test_boundary_rejects_unsigned_and_tampered_context_authority(
    policy_lab: tuple[Path, Any],
) -> None:
    _, boundary = policy_lab
    unsigned = _context(scopes=(_scope(ScopeKind.JOB_ID, "JOB-TEST-001"),))
    with pytest.raises(ProductionBoundaryError) as unsigned_error:
        boundary.authorize(
            "tmp/jobs/INTERNAL/JOB-TEST-001/new.bin",
            intent=PathIntent.NEW_WRITE,
            expected_kind=ExpectedKind.FILE,
            context=unsigned,
        )
    assert unsigned_error.value.code is BoundaryErrorCode.INVALID_CONTEXT

    signed = _issued_context(
        boundary,
        scopes=(_scope(ScopeKind.JOB_ID, "JOB-TEST-001"),),
    )
    object.__setattr__(signed, "caller", Caller.IMPORT_SERVICE)
    with pytest.raises(ProductionBoundaryError) as tampered:
        boundary.authorize(
            "tmp/jobs/INTERNAL/JOB-TEST-001/new.bin",
            intent=PathIntent.NEW_WRITE,
            expected_kind=ExpectedKind.FILE,
            context=signed,
        )
    assert tampered.value.code is BoundaryErrorCode.INVALID_CONTEXT


def test_restricted_path_failure_has_no_raw_exception_chain_or_operation_id(
    policy_lab: tuple[Path, Any],
) -> None:
    project, boundary = policy_lab
    secret = project / "Copy" / "restricted" / "COPY-001" / "秘密姓名.xlsx"
    secret.parent.mkdir(parents=True)
    secret.write_bytes(b"private")
    context = _issued_context(
        boundary,
        caller=Caller.IMPORT_SERVICE,
        purpose=Purpose.COPY_SOURCE,
        scopes=(_scope(ScopeKind.COPY_ID, "COPY-001"),),
        classification=DataClassification.RESTRICTED,
    )
    with pytest.raises(ProductionBoundaryError) as captured:
        boundary.authorize(
            "Copy/restricted/COPY-001/秘密姓名.xlsx",
            intent=PathIntent.NEW_WRITE,
            expected_kind=ExpectedKind.FILE,
            context=context,
        )
    error = captured.value
    assert error.operation_reference is None
    assert error.__cause__ is None
    assert error.__context__ is None
    rendered = repr(error) + str(error)
    assert "秘密姓名" not in rendered
    assert "COPY-001" not in rendered
    assert str(project) not in rendered
    assert "D:\\" not in rendered


def test_candidate_token_tampering_and_context_change_are_rejected(
    policy_lab: tuple[Path, Any],
) -> None:
    _, boundary = policy_lab
    context = _issued_context(
        boundary,
        scopes=(_scope(ScopeKind.JOB_ID, "JOB-TEST-001"),),
    )
    ticket = boundary.authorize(
        "tmp/jobs/INTERNAL/JOB-TEST-001/future.bin",
        intent=PathIntent.NEW_WRITE,
        expected_kind=ExpectedKind.FILE,
        context=context,
    )
    with pytest.raises(TypeError):
        CandidateTicket("X", "Y", b"Z", _constructor=object())
    raw_ticket_id = object.__getattribute__(ticket, "_CandidateTicket__ticket_id")
    raw_boundary_id = object.__getattribute__(
        ticket,
        "_CandidateTicket__boundary_instance_id",
    )
    forged_descriptor_token = object.__new__(CandidateTicket)
    object.__setattr__(
        forged_descriptor_token,
        "_CandidateTicket__ticket_id",
        raw_ticket_id,
    )
    object.__setattr__(
        forged_descriptor_token,
        "_CandidateTicket__boundary_instance_id",
        raw_boundary_id,
    )
    object.__setattr__(
        forged_descriptor_token,
        "_CandidateTicket__authenticator",
        b"0" * 32,
    )
    with pytest.raises(ProductionBoundaryError) as descriptor_forgery:
        boundary.describe_candidate(forged_descriptor_token, context=context)
    assert descriptor_forgery.value.code is BoundaryErrorCode.CANDIDATE_MAC_MISMATCH
    with pytest.raises(ProductionBoundaryError) as changed:
        boundary.revalidate(
            ticket,
            context=_issued_context(
                boundary,
                operation_id="OP-TEST-OTHER",
                scopes=(_scope(ScopeKind.JOB_ID, "JOB-TEST-001"),),
            ),
        )
    assert changed.value.code is BoundaryErrorCode.CANDIDATE_CONTEXT_MISMATCH

    same_claims_different_authority_ticket = _issued_context(
        boundary,
        scopes=(_scope(ScopeKind.JOB_ID, "JOB-TEST-001"),),
    )
    with pytest.raises(ProductionBoundaryError) as swapped_authority:
        boundary.revalidate(ticket, context=same_claims_different_authority_ticket)
    assert swapped_authority.value.code is BoundaryErrorCode.CANDIDATE_CONTEXT_MISMATCH

    object.__setattr__(ticket, "_CandidateTicket__ticket_id", "FORGED-001")
    with pytest.raises(ProductionBoundaryError) as forged:
        boundary.revalidate(ticket, context=context)
    assert forged.value.code is BoundaryErrorCode.CANDIDATE_NOT_ISSUED


def _prepare_publish_source(project: Path) -> Path:
    source = project / "tmp" / "jobs" / "INTERNAL" / "JOB-TEST-001" / "publish" / "MANIFEST-001"
    source.mkdir(parents=True)
    (source / "manifest.json").write_text("{}", encoding="utf-8")
    (source / "payload.bin").write_bytes(b"candidate-only")
    return source


def test_candidate_revalidation_is_single_use(
    policy_lab: tuple[Path, Any],
) -> None:
    _, boundary = policy_lab
    context = _issued_context(
        boundary,
        scopes=(_scope(ScopeKind.JOB_ID, "JOB-TEST-001"),),
    )
    ticket = boundary.authorize(
        "tmp/jobs/INTERNAL/JOB-TEST-001/single-use.bin",
        intent=PathIntent.NEW_WRITE,
        expected_kind=ExpectedKind.FILE,
        context=context,
    )
    assert boundary.revalidate(ticket, context=context) is ticket
    counts = boundary.diagnostic_registry_counts
    assert counts["candidate_live"] == 0
    assert counts["guard_live"] == 0
    assert counts["candidate_tombstones"] == 1
    with pytest.raises(ProductionBoundaryError) as replay:
        boundary.revalidate(ticket, context=context)
    assert replay.value.code is BoundaryErrorCode.CANDIDATE_ALREADY_USED


def test_publish_pair_is_exact_opaque_bound_and_revalidates_without_move(
    policy_lab: tuple[Path, Any],
) -> None:
    project, boundary = policy_lab
    source = _prepare_publish_source(project)
    context = _issued_context(
        boundary,
        caller=Caller.IMPORT_SERVICE,
        purpose=Purpose.COPY_SOURCE,
        scopes=_pair_scopes(_scope(ScopeKind.OBJECT_ID, "OBJECT-001")),
        manifest_id="MANIFEST-001",
    )
    before = len(boundary.audit_events)
    pair = boundary.authorize_publish(
        "tmp/jobs/INTERNAL/JOB-TEST-001/publish/MANIFEST-001",
        "data/originals/OBJECT-001",
        evidence=_pair_evidence(),
        context=context,
    )
    descriptor = boundary.describe_pair(pair, context=context)
    assert descriptor.source_namespace is NamespaceId.JOB_WORKSPACE_INTERNAL
    assert descriptor.target_namespace is NamespaceId.ORIGINAL_OBJECT
    assert not hasattr(pair, "source")
    assert not hasattr(pair, "target")
    assert source.is_dir()
    assert not (project / "data" / "originals" / "OBJECT-001").exists()
    assert boundary.revalidate_pair(pair, context=context) is pair
    counts = boundary.diagnostic_registry_counts
    assert counts["candidate_live"] == 0
    assert counts["pair_live"] == 0
    assert counts["guard_live"] == 0
    assert counts["pair_tombstones"] == 1
    with pytest.raises(ProductionBoundaryError) as replay:
        boundary.revalidate_pair(pair, context=context)
    assert replay.value.code is BoundaryErrorCode.PAIR_ALREADY_USED
    issued = boundary.audit_events[before : before + 2]
    assert len(issued) == 2
    assert {event.pair_id for event in issued} == {descriptor.pair_id}
    assert {event.pair_role.value for event in issued if event.pair_role} == {
        "SOURCE",
        "TARGET",
    }


def test_pair_revalidation_has_one_concurrent_winner(
    policy_lab: tuple[Path, Any],
) -> None:
    project, boundary = policy_lab
    _prepare_publish_source(project)
    context = _issued_context(
        boundary,
        caller=Caller.IMPORT_SERVICE,
        purpose=Purpose.COPY_SOURCE,
        scopes=_pair_scopes(_scope(ScopeKind.OBJECT_ID, "OBJECT-001")),
        manifest_id="MANIFEST-001",
    )
    pair = boundary.authorize_publish(
        "tmp/jobs/INTERNAL/JOB-TEST-001/publish/MANIFEST-001",
        "data/originals/OBJECT-001",
        evidence=_pair_evidence(),
        context=context,
    )

    def attempt() -> str:
        try:
            boundary.revalidate_pair(pair, context=context)
            return "OK"
        except ProductionBoundaryError as error:
            return error.code.value

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = sorted(executor.map(lambda _: attempt(), range(2)))
    assert outcomes == ["OK", BoundaryErrorCode.PAIR_ALREADY_USED.value]


@pytest.mark.parametrize(
    ("source", "target"),
    [
        ("tmp/jobs/INTERNAL/JOB-TEST-001/publish/MANIFEST-001/payload.bin", "data/originals/OBJECT-001"),
        ("tmp/jobs/INTERNAL/JOB-TEST-001/publish/MANIFEST-001", "data/originals/OBJECT-001/file.bin"),
    ],
)
def test_publish_pair_rejects_partial_objects(
    policy_lab: tuple[Path, Any],
    source: str,
    target: str,
) -> None:
    project, boundary = policy_lab
    _prepare_publish_source(project)
    context = _issued_context(
        boundary,
        caller=Caller.IMPORT_SERVICE,
        purpose=Purpose.COPY_SOURCE,
        scopes=_pair_scopes(_scope(ScopeKind.OBJECT_ID, "OBJECT-001")),
        manifest_id="MANIFEST-001",
    )
    with pytest.raises(ProductionBoundaryError):
        boundary.authorize_publish(
            source,
            target,
            evidence=_pair_evidence(),
            context=context,
        )


def test_pair_revalidation_fails_if_target_appears(
    policy_lab: tuple[Path, Any],
) -> None:
    project, boundary = policy_lab
    _prepare_publish_source(project)
    context = _issued_context(
        boundary,
        caller=Caller.IMPORT_SERVICE,
        purpose=Purpose.COPY_SOURCE,
        scopes=_pair_scopes(_scope(ScopeKind.OBJECT_ID, "OBJECT-001")),
        manifest_id="MANIFEST-001",
    )
    pair = boundary.authorize_publish(
        "tmp/jobs/INTERNAL/JOB-TEST-001/publish/MANIFEST-001",
        "data/originals/OBJECT-001",
        evidence=_pair_evidence(),
        context=context,
    )
    (project / "data" / "originals" / "OBJECT-001").mkdir(parents=True)
    with pytest.raises(ProductionBoundaryError) as error:
        boundary.revalidate_pair(pair, context=context)
    assert error.value.code is BoundaryErrorCode.PATH_REJECTED


def test_restricted_namespace_drives_denial_redaction_even_for_internal_context(
    policy_lab: tuple[Path, Any],
) -> None:
    project, boundary = policy_lab
    private = project / "Copy" / "restricted" / "COPY-001" / "姓名.xlsx"
    private.parent.mkdir(parents=True)
    private.write_bytes(b"private")
    context = _issued_context(
        boundary,
        caller=Caller.IMPORT_SERVICE,
        purpose=Purpose.READ_REFERENCE,
        scopes=(_scope(ScopeKind.COPY_ID, "COPY-001"),),
    )
    before = len(boundary.audit_events)
    with pytest.raises(ProductionBoundaryError) as restricted_denial:
        boundary.authorize(
            "Copy/restricted/COPY-001/姓名.xlsx",
            intent=PathIntent.EXISTING_READ,
            expected_kind=ExpectedKind.FILE,
            context=context,
        )
    assert restricted_denial.value.operation_reference is None
    event = boundary.audit_events[before]
    rendered = str(event.to_dict())
    assert event.safe_relative_path is None
    assert event.path_hmac_sha256 is not None
    assert "姓名" not in rendered
    assert "COPY-001" not in rendered


def test_restricted_copy_can_only_be_quarantined_as_bound_directory_pair(
    policy_lab: tuple[Path, Any],
) -> None:
    project, boundary = policy_lab
    source = project / "Copy" / "restricted" / "COPY-001"
    source.mkdir(parents=True)
    (source / "private.xlsx").write_bytes(b"private")
    context = _issued_context(
        boundary,
        caller=Caller.IMPORT_SERVICE,
        purpose=Purpose.QUARANTINE,
        scopes=(
            _scope(ScopeKind.COPY_ID, "COPY-001"),
            _scope(ScopeKind.MANIFEST_ID, "MANIFEST-001"),
            _scope(ScopeKind.CHECKPOINT_ID, "CHECKPOINT-001"),
        ),
        manifest_id="MANIFEST-001",
        classification=DataClassification.RESTRICTED,
    )
    before = len(boundary.audit_events)
    pair = boundary.authorize_quarantine(
        "Copy/restricted/COPY-001",
        evidence=_pair_evidence(),
        context=context,
    )
    descriptor = boundary.describe_pair(pair, context=context)
    assert descriptor.source_namespace is NamespaceId.COPY_RESTRICTED
    assert descriptor.target_namespace is NamespaceId.QUARANTINE_RESTRICTED
    assert source.is_dir()
    pair_events = boundary.audit_events[before : before + 2]
    assert len(pair_events) == 2
    assert all(event.safe_relative_path is None for event in pair_events)
    assert all(event.context_digest is None for event in pair_events)
    assert not hasattr(pair, "pair_id")
    assert "pair_id" not in repr(pair).lower()
    assert descriptor.pair_id not in str([event.to_dict() for event in pair_events])


class _FailingAuditSink:
    @property
    def events(self) -> tuple[Any, ...]:
        return ()

    def record(self, event: Any) -> Any:
        raise OSError("simulated audit failure")

    def record_batch(self, events: tuple[Any, ...]) -> Any:
        raise OSError("simulated audit failure")


class _NoReceiptAuditSink:
    @property
    def events(self) -> tuple[Any, ...]:
        return ()

    def record(self, event: Any) -> None:
        return None

    def record_batch(self, events: tuple[Any, ...]) -> None:
        return None


def test_audit_failure_never_returns_a_candidate(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    boundary = _create_test_boundary(project, audit_sink=_FailingAuditSink())
    context = _issued_context(
        boundary,
        scopes=(_scope(ScopeKind.JOB_ID, "JOB-TEST-001"),),
    )
    for _ in range(3):
        with pytest.raises(ProductionBoundaryError) as error:
            boundary.authorize(
                "tmp/jobs/INTERNAL/JOB-TEST-001/new.bin",
                intent=PathIntent.NEW_WRITE,
                expected_kind=ExpectedKind.FILE,
                context=context,
            )
        assert error.value.code is BoundaryErrorCode.AUDIT_RECORD_FAILED
        counts = boundary.diagnostic_registry_counts
        assert counts["candidate_live"] == 0
        assert counts["guard_live"] == 0


def test_invalid_audit_receipt_fails_closed(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    boundary = _create_test_boundary(project, audit_sink=_NoReceiptAuditSink())
    context = _issued_context(
        boundary,
        scopes=(_scope(ScopeKind.JOB_ID, "JOB-TEST-001"),),
    )
    with pytest.raises(ProductionBoundaryError) as error:
        boundary.authorize(
            "tmp/jobs/INTERNAL/JOB-TEST-001/new.bin",
            intent=PathIntent.NEW_WRITE,
            expected_kind=ExpectedKind.FILE,
            context=context,
        )
    assert error.value.code is BoundaryErrorCode.AUDIT_RECORD_FAILED


def test_pair_audit_capacity_preflight_is_atomic(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    sink = CollectingAuditSink(capacity=1)
    boundary = _create_test_boundary(project, audit_sink=sink)
    _prepare_publish_source(project)
    context = _issued_context(
        boundary,
        caller=Caller.IMPORT_SERVICE,
        purpose=Purpose.COPY_SOURCE,
        scopes=_pair_scopes(_scope(ScopeKind.OBJECT_ID, "OBJECT-001")),
        manifest_id="MANIFEST-001",
    )
    with pytest.raises(ProductionBoundaryError) as error:
        boundary.authorize_publish(
            "tmp/jobs/INTERNAL/JOB-TEST-001/publish/MANIFEST-001",
            "data/originals/OBJECT-001",
            evidence=_pair_evidence(),
            context=context,
        )
    assert error.value.code is BoundaryErrorCode.AUDIT_RECORD_FAILED
    assert sink.events == ()
    counts = boundary.diagnostic_registry_counts
    assert counts["candidate_live"] == 0
    assert counts["pair_live"] == 0
    assert counts["guard_live"] == 0


def test_test_context_has_explicit_bounded_lifetime(
    policy_lab: tuple[Path, Any],
) -> None:
    _, boundary = policy_lab
    context = _issued_context(
        boundary,
        scopes=(_scope(ScopeKind.JOB_ID, "JOB-TEST-001"),),
    )
    assert boundary.diagnostic_registry_counts["context_live"] == 1
    ticket = boundary.authorize(
        "tmp/jobs/INTERNAL/JOB-TEST-001/abandoned.bin",
        intent=PathIntent.NEW_WRITE,
        expected_kind=ExpectedKind.FILE,
        context=context,
    )
    assert ticket is not None
    assert boundary.diagnostic_registry_counts["guard_live"] == 1
    assert boundary.release_context(context)
    assert boundary.release_context(context) is False
    counts = boundary.diagnostic_registry_counts
    assert counts["context_live"] == 0
    assert counts["candidate_live"] == 0
    assert counts["guard_live"] == 0
    with pytest.raises(ProductionBoundaryError) as revoked:
        boundary.authorize(
            "tmp/jobs/INTERNAL/JOB-TEST-001/other.bin",
            intent=PathIntent.NEW_WRITE,
            expected_kind=ExpectedKind.FILE,
            context=context,
        )
    assert revoked.value.code is BoundaryErrorCode.INVALID_CONTEXT


def test_concurrent_duplicate_context_release_has_one_winner(
    policy_lab: tuple[Path, Any],
) -> None:
    _, boundary = policy_lab
    context = _issued_context(
        boundary,
        scopes=(_scope(ScopeKind.JOB_ID, "JOB-TEST-001"),),
    )
    start = Event()

    def release() -> bool:
        assert start.wait(timeout=5)
        return boundary.release_context(context)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(release) for _ in range(2)]
        start.set()
        results = [future.result(timeout=5) for future in futures]
    assert sorted(results) == [False, True]


def test_context_close_cannot_leave_an_issue_race_orphan(
    policy_lab: tuple[Path, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, boundary = policy_lab
    context = _issued_context(
        boundary,
        scopes=(_scope(ScopeKind.JOB_ID, "JOB-TEST-001"),),
    )
    reached_after_core_issue = Event()
    resume_issue = Event()
    original_authorize = WorkspaceGuard.authorize

    def delayed_authorize(self: WorkspaceGuard, *args: Any, **kwargs: Any) -> GuardedPath:
        ticket = original_authorize(self, *args, **kwargs)
        reached_after_core_issue.set()
        if not resume_issue.wait(timeout=5):
            raise TimeoutError("test barrier did not resume candidate issuance")
        return ticket

    monkeypatch.setattr(WorkspaceGuard, "authorize", delayed_authorize)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            boundary.authorize,
            "tmp/jobs/INTERNAL/JOB-TEST-001/race.bin",
            intent=PathIntent.NEW_WRITE,
            expected_kind=ExpectedKind.FILE,
            context=context,
        )
        assert reached_after_core_issue.wait(timeout=5)
        assert boundary.release_context(context)
        resume_issue.set()
        with pytest.raises(ProductionBoundaryError) as closed:
            future.result(timeout=5)
    assert closed.value.code is BoundaryErrorCode.INVALID_CONTEXT
    counts = boundary.diagnostic_registry_counts
    assert counts["context_live"] == 0
    assert counts["candidate_live"] == 0
    assert counts["guard_live"] == 0


def test_no_production_module_bypasses_fixed_workspace_guard_factory() -> None:
    assert scan_unauthorized_guard_construction() == ()


@pytest.mark.parametrize(
    "source, forbidden_name",
    [
        (
            "from app.safety.windows_handle_writer import _WindowsHandleWriter\n",
            "_WindowsHandleWriter",
        ),
        (
            "from app.safety.windows_handle_writer import _HANDLE_WRITER_CONSTRUCTOR\n",
            "_HANDLE_WRITER_CONSTRUCTOR",
        ),
        (
            "from app.safety.production_guard import _create_test_handle_writer\n",
            "_create_test_handle_writer",
        ),
    ],
)
def test_handle_writer_factory_and_constructor_cannot_escape_boundary_service(
    source: str,
    forbidden_name: str,
) -> None:
    findings = scan_unauthorized_guard_source(source)
    assert findings
    assert any(forbidden_name in detail for _, _, detail in findings)


@pytest.mark.parametrize(
    "source, expected_detail",
    [
        (
            "import app.safety.windows_handle_writer as whw\ngetattr(whw, name)\n",
            "dynamic safety attribute lookup",
        ),
        (
            "import app.safety.windows_handle_writer as whw\nvars(whw)\n",
            "dynamic safety module dictionary lookup",
        ),
        (
            "import app.safety.windows_handle_writer as whw\nwhw.__dict__[name]\n",
            "safety module __dict__ lookup",
        ),
        (
            "import app.safety.windows_handle_writer as whw\nobject.__getattribute__(whw, name)\n",
            "reflective safety attribute lookup",
        ),
        (
            "from app.safety.windows_handle_writer import *\n",
            "private import *",
        ),
    ],
)
def test_handle_writer_reflection_and_star_import_are_rejected(
    source: str,
    expected_detail: str,
) -> None:
    findings = scan_unauthorized_guard_source(source)
    assert any(expected_detail in detail for _, _, detail in findings)

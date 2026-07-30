"""JSON-RPC method dispatch (ARCHITECTURE.md §4.8).

Per-session interceptor. Client→upstream messages are routed by method; upstream→client
responses are matched back to their request id (pruning happens on the tools/list
*response*). A method without an explicit handler is passed through unmodified but still
logged — deny-by-default is deliberately not enforced here; visibility in the log is the
day-one guarantee.

tools/call is authorized here regardless of what the pruned tools/list showed: pruning
shapes the LLM's planning surface, authorization happens fresh at the point of action
(§4.1 design principle). The §4.2 pipeline order is replay → RBAC → ABAC → drift →
risk/approval → param validation; ABAC conditions referencing risk.* can't run at
stage 4 (no score exists yet), so they're split at policy load and evaluated right
after scoring, before the threshold mapping — an ABAC deny still wins over
CHALLENGE/HUMAN_APPROVAL_REQUIRED, matching stage precedence. Every decision point is
audit-logged before it takes effect — an ALLOW that can't be recorded is a deny (§5,
"no record, no action").

Schemas come from the shared per-server cache (§8): populated whenever a tools/list
response flows through, invalidated on initialize, and transparently re-fetched from
the upstream on a miss (TTL expiry or a client that calls without listing).
"""

import asyncio
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog
from mcp.shared.message import SessionMessage
from mcp.types import (
    ErrorData,
    JSONRPCError,
    JSONRPCMessage,
    JSONRPCRequest,
    JSONRPCResponse,
    RequestId,
)

from services.gateway import abac, auth, metrics, param_validator, schema_pruner, step_up
from services.gateway.approvals import APPROVAL_META_KEY, ApprovalStore, arguments_hash
from services.gateway.audit_log import AuditWriter
from services.gateway.decision import Decision, DecisionMode, DecisionOutcome, EventType, RiskFactor
from services.gateway.drift_detector import DriftDetector
from services.gateway.policy_engine import PolicyEngine, PolicyStore
from services.gateway.replay_guard import NONCE_META_KEY, TIMESTAMP_META_KEY, ReplayGuard
from services.gateway.risk_engine import RISK_DENY_ABOVE, RiskEngine, threshold_outcome
from services.gateway.schema_cache import SchemaCache

# Implementation-defined JSON-RPC error codes; the canonical Decision object (§4.3)
# travels in error.data for policy denials.
POLICY_DENIED_CODE = -32003
AUDIT_UNAVAILABLE_CODE = -32004
TOOL_CALL_DEADLINE_CODE = -32005

_HANDLED_METHODS = frozenset({"initialize", "tools/list", "tools/call"})
_REFETCH_TIMEOUT_S = 10

# Gateway-facing _meta keys — consumed here, never forwarded upstream.
_GATEWAY_META_KEYS = (
    NONCE_META_KEY,
    TIMESTAMP_META_KEY,
    APPROVAL_META_KEY,
    step_up.CHALLENGE_ID_META_KEY,
    step_up.CHALLENGE_PROOF_META_KEY,
    auth.KEY_ID_META_KEY,
    auth.SIGNATURE_META_KEY,
)


def _strip_gateway_meta(params: dict[str, Any] | None) -> None:
    if not params:
        return
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        return
    for key in _GATEWAY_META_KEYS:
        meta.pop(key, None)
    if not meta:
        params.pop("_meta", None)


@dataclass
class Forward:
    """Send this message on to the upstream server."""

    message: SessionMessage


@dataclass
class Respond:
    """Answer the client directly; nothing reaches the upstream server."""

    message: SessionMessage


def _error(request_id: RequestId, code: int, message: str, data: object = None) -> Respond:
    return Respond(
        SessionMessage(
            JSONRPCMessage(
                JSONRPCError(
                    jsonrpc="2.0",
                    id=request_id,
                    error=ErrorData(code=code, message=message, data=data),
                )
            )
        )
    )


@dataclass
class Interceptor:
    identity_id: str
    server_id: str
    session_id: str
    store: PolicyStore
    writer: AuditWriter
    cache: SchemaCache
    detector: DriftDetector
    replay: ReplayGuard
    risk: RiskEngine
    approvals: ApprovalStore
    challenges: step_up.ChallengeStore
    send_upstream: Callable[[JSONRPCMessage], Awaitable[None]]
    mode: DecisionMode = DecisionMode.ENFORCE
    _pending: dict[RequestId, str] = field(default_factory=dict)  # request id -> method
    # Gateway-initiated upstream requests (transparent tools/list re-fetch): responses
    # to these ids resolve a future and are never forwarded to the client.
    _internal: dict[str, "asyncio.Future[dict[str, Any]]"] = field(default_factory=dict)
    _log: structlog.stdlib.BoundLogger = field(init=False)

    def __post_init__(self) -> None:
        # §7: correlation id = session id. Bound here because interceptor calls run in
        # the per-session pump task, out of reach of request-scoped contextvars.
        self._log = structlog.get_logger(__name__).bind(
            session_id=self.session_id, identity=self.identity_id
        )

    @property
    def engine(self) -> PolicyEngine:
        # Read through the store on every use so a SIGHUP reload takes effect on the
        # very next request of an in-flight session (§8).
        return self.store.engine

    async def on_client_message(self, message: SessionMessage) -> Forward | Respond:
        root = message.message.root
        if not isinstance(root, JSONRPCRequest):
            method = getattr(root, "method", None)
            if method is not None and method not in _HANDLED_METHODS:
                self._log.info("passthrough_no_handler", method=method)
            return Forward(message)
        self._pending[root.id] = root.method
        if root.method == "initialize":
            # A fresh handshake is the trust boundary to re-verify against (§8).
            await self.cache.invalidate(self.server_id)
        elif root.method == "tools/call":
            # §7: decision-pipeline time only — the upstream round trip is not in here.
            start = time.perf_counter()
            try:
                return await self._authorize_call(message, root)
            finally:
                metrics.REQUEST_LATENCY.observe(time.perf_counter() - start)
        elif root.method not in _HANDLED_METHODS:
            self._log.info("passthrough_no_handler", method=root.method)
        # Signed requests (item 34) carry key-id/signature/nonce on every method;
        # none of the gateway's _meta keys belong upstream.
        _strip_gateway_meta(root.params)
        return Forward(message)

    async def _authorize_call(
        self, message: SessionMessage, request: JSONRPCRequest
    ) -> Forward | Respond:
        params = request.params or {}
        tool_name = str(params.get("name", ""))
        arguments = params.get("arguments", {}) or {}
        terminal: Decision | None = None

        async def retain(candidate: Decision) -> Respond | None:
            nonlocal terminal
            terminal = terminal or candidate
            if self.mode is DecisionMode.ENFORCE:
                emitted = await self._emit_decision(
                    message, request, tool_name, arguments, terminal
                )
                assert isinstance(emitted, Respond)
                return emitted
            return None

        # Replay Guard (§4.2 stage 1, cheapest check first). Mandatory for signed
        # identities — nonce/timestamp are members of the edge-verified signature, so
        # a byte-identical replay dies here on dedup while a fresh nonce already died
        # at the edge (401, unsignable). Opportunistic for bearer (item 34): a
        # volunteered nonce/timestamp key is fully enforced (present-but-malformed
        # denies, §5), both absent skips — that's what lets a stock MCP client call
        # at all. Dedup is deliberately tools/call-only: replaying a captured
        # tools/list re-reads a list, no action. Redis failure still denies (§5).
        meta = params.get("_meta") or {}
        identity = self.engine.identity(self.identity_id)
        signed_mode = identity is not None and identity.auth_mode == "signed"
        if signed_mode or NONCE_META_KEY in meta or TIMESTAMP_META_KEY in meta:
            try:
                replay_reason = await self.replay.check(
                    meta.get(NONCE_META_KEY), meta.get(TIMESTAMP_META_KEY)
                )
            except Exception:
                self._log.exception("replay_check_failed_fail_closed", tool=tool_name)
                replay_reason = "replay guard unavailable"
            if replay_reason is not None:
                stopped = await retain(
                    self._decision(
                        DecisionOutcome.DENY,
                        EventType.DENY_REPLAY,
                        f"Replay detected: {replay_reason}",
                        ["replay_guard"],
                    )
                )
                if stopped is not None:
                    return stopped

        grant = self.engine.matching_grant(self.identity_id, self.server_id, tool_name)
        conditions = grant.compiled_conditions if grant is not None else []
        if grant is None:
            stopped = await retain(
                self._decision(
                    DecisionOutcome.DENY,
                    EventType.DENY_RBAC,
                    f"identity {self.identity_id!r} is not authorized to call {tool_name!r}",
                    [f"policy-v{self.engine.version}:rbac"],
                )
            )
            if stopped is not None:
                return stopped

        # ABAC conditions (§4.2 stage 4): ALL conditions on the RBAC-matched grant
        # must hold. Conditions referencing risk.* are deferred until a score exists
        # (right after stage 6 scoring, below); everything else runs here.
        abac_attrs = self._abac_attributes(tool_name, meta) if conditions else {}
        denied = await self._failed_condition(
            tool_name,
            [c for c in conditions if not c.references_risk],
            abac_attrs,
        )
        if denied is not None:
            stopped = await retain(denied)
            if stopped is not None:
                return stopped

        # Schema drift status (§4.2 stage 5): a tool blocked on High/Critical drift is
        # denied until re-approval; a status lookup failure also denies (§5).
        try:
            drift_blocked = await self.detector.is_blocked(self.server_id, tool_name)
        except Exception:
            self._log.exception("drift_status_lookup_failed_fail_closed", tool=tool_name)
            drift_blocked = True
        if drift_blocked:
            stopped = await retain(
                self._decision(
                    DecisionOutcome.DENY,
                    EventType.DENY_DRIFT,
                    f"{tool_name!r} is blocked: schema drifted from its approved baseline"
                    " and is pending re-approval",
                    ["drift_detector"],
                )
            )
            if stopped is not None:
                return stopped

        # Step-up redemption (item 37): a retry carrying a challenge id + TOTP proof
        # consumes the challenge and verifies the code — any failure is a terminal
        # DENY_STEP_UP (§5). Success only sets a flag: unlike an approval, the call
        # is still re-scored below, and a verified proof clears nothing but the
        # CHALLENGE band.
        challenge_id = meta.get(step_up.CHALLENGE_ID_META_KEY)
        step_up_verified = False
        if self.mode is DecisionMode.ENFORCE and challenge_id is not None:
            try:
                failure = await self.challenges.redeem(
                    str(challenge_id),
                    self.identity_id,
                    self.server_id,
                    tool_name,
                    arguments_hash(arguments),
                    meta.get(step_up.CHALLENGE_PROOF_META_KEY),
                    identity.totp_secret if identity is not None else "",
                )
            except Exception:
                self._log.exception("challenge_redeem_failed_fail_closed", tool=tool_name)
                failure = "challenge store unavailable"
            if failure is not None:
                stopped = await retain(
                    self._decision(
                        DecisionOutcome.DENY,
                        EventType.DENY_STEP_UP,
                        f"step-up verification failed: {failure}",
                        ["step_up"],
                    )
                )
                assert stopped is not None
                return stopped
            step_up_verified = True

        # Risk Engine (§4.2 stage 6, before param validation). A retry carrying an
        # approval id redeems it instead of re-scoring: a human reviewed this exact
        # call (§4.8); RBAC/drift/replay above and param validation below still apply.
        approval_id = meta.get(APPROVAL_META_KEY)
        risk_score: int | None = None
        risk_factors: list[RiskFactor] | None = None
        if self.mode is DecisionMode.ENFORCE and approval_id is not None:
            try:
                denial = await self.approvals.redeem(
                    str(approval_id),
                    self.identity_id,
                    self.server_id,
                    tool_name,
                    arguments_hash(arguments),
                )
            except Exception:
                self._log.exception("approval_redeem_failed_fail_closed", tool=tool_name)
                denial = (EventType.DENY_APPROVAL_MISMATCH, "approval store unavailable")
            if denial is not None:
                event_type, reason = denial
                stopped = await retain(
                    self._decision(
                        DecisionOutcome.DENY,
                        event_type,
                        reason,
                        ["approval_lifecycle"],
                    )
                )
                assert stopped is not None
                return stopped
        else:
            try:
                risk_score, risk_factors = await self.risk.score(
                    self.identity_id, self.server_id, tool_name, arguments, self.engine.policy.risk
                )
            except Exception:
                # A crashed risk calculation is maximum risk, not low risk (§5).
                self._log.exception("risk_scoring_failed_fail_closed", tool=tool_name)
                risk_score, risk_factors = (
                    100,
                    [
                        RiskFactor(
                            factor="risk_engine_unavailable",
                            contribution=100,
                            reason="risk scoring failed; treated as maximum risk",
                        )
                    ],
                )
            # Every fresh score passes through here exactly once, whatever the
            # eventual outcome — the one right place for the §7 histogram.
            metrics.RISK_SCORE.observe(risk_score)
            if terminal is not None:
                terminal.risk_score = risk_score
                terminal.risk_factors = risk_factors
            # Deferred ABAC: risk.* conditions run the moment a score exists,
            # before the threshold mapping — an ABAC deny wins over CHALLENGE /
            # HUMAN_APPROVAL_REQUIRED (§4.2: stage 4 precedes stage 6). Deliberately
            # skipped on the redemption branch above: a human approved that exact call.
            abac_attrs["risk.score"] = risk_score
            denied = await self._failed_condition(
                tool_name,
                [c for c in conditions if c.references_risk],
                abac_attrs,
                risk_score=risk_score,
                risk_factors=risk_factors,
            )
            if denied is not None:
                stopped = await retain(denied)
                if stopped is not None:
                    return stopped
            risk_outcome = threshold_outcome(risk_score)
            if risk_outcome is DecisionOutcome.CHALLENGE and step_up_verified:
                pass  # the verified proof satisfies the challenge — continue (item 37)
            elif risk_outcome is not DecisionOutcome.ALLOW:
                stopped = await retain(
                    self._risk_decision(tool_name, risk_outcome, risk_score, risk_factors)
                )
                if stopped is not None:
                    return stopped

        # Parameter validation (§4.2 stage 7, §4.8): cache miss triggers a transparent
        # upstream re-fetch (§8); only an unfetchable schema fails closed.
        input_schema = await self._input_schema_for(tool_name)
        if input_schema is None:
            stopped = await retain(
                self._decision(
                    DecisionOutcome.DENY,
                    EventType.DENY_VALIDATION,
                    f"invalid arguments for {tool_name!r}: tool schema unavailable from upstream",
                    ["param_validator"],
                    risk_score,
                    risk_factors,
                )
            )
            if stopped is not None:
                return stopped
        error = (
            param_validator.validate(arguments, input_schema) if input_schema is not None else None
        )
        if error is not None:
            stopped = await retain(
                self._decision(
                    DecisionOutcome.DENY,
                    EventType.DENY_VALIDATION,
                    f"invalid arguments for {tool_name!r}: {error}",
                    ["param_validator"],
                    risk_score,
                    risk_factors,
                )
            )
            if stopped is not None:
                return stopped

        decision = terminal or self._decision(
            DecisionOutcome.ALLOW,
            EventType.ALLOW,
            f"call to {tool_name!r} allowed",
            [f"policy-v{self.engine.version}:rbac"],
            risk_score,
            risk_factors,
        )
        return await self._emit_decision(
            message,
            request,
            tool_name,
            arguments,
            decision,
            approval_id=str(approval_id) if approval_id is not None else None,
            challenge_id=str(challenge_id) if step_up_verified else None,
        )

    def _abac_attributes(self, tool_name: str, meta: dict[str, Any]) -> dict[str, abac.AttrValue]:
        """The attribute universe conditions resolve against (§4.8): identity.* from
        the policy identity record (identity.id from the id itself), tool.* from the
        current call, context.hour in UTC from the replay timestamp (already validated
        by stage 1) or, when a bearer call carries none (item 34), the gateway's own
        clock. risk.score is bound later, once stage 6 has scored."""
        attrs: dict[str, abac.AttrValue] = {
            "identity.id": self.identity_id,
            "tool.name": tool_name,
            "tool.server_id": self.server_id,
        }
        identity = self.engine.identity(self.identity_id)
        if identity is not None:
            for key, value in identity.attributes.items():
                attrs[f"identity.{key}"] = value
        timestamp = meta.get(TIMESTAMP_META_KEY)
        if not isinstance(timestamp, bool) and isinstance(timestamp, int | float):
            attrs["context.hour"] = datetime.fromtimestamp(timestamp, UTC).hour
        else:
            attrs["context.hour"] = datetime.now(UTC).hour
        return attrs

    def _decision(
        self,
        outcome: DecisionOutcome,
        event_type: EventType,
        reason: str,
        matched_rules: list[str],
        risk_score: int | None = None,
        risk_factors: list[RiskFactor] | None = None,
    ) -> Decision:
        return Decision(
            decision=outcome,
            event_type=event_type,
            mode=self.mode,
            reason=reason,
            matched_rules=matched_rules,
            risk_score=risk_score,
            risk_factors=risk_factors,
            policy_version=self.engine.version,
        )

    async def _failed_condition(
        self,
        tool_name: str,
        conditions: list[abac.Condition],
        attrs: dict[str, abac.AttrValue],
        risk_score: int | None = None,
        risk_factors: list[RiskFactor] | None = None,
    ) -> Decision | None:
        """Evaluate ABAC conditions; None means all satisfied. A condition that is
        not-satisfied *because it couldn't be evaluated* (unresolvable attribute,
        type-mismatch, any exception) additionally writes a POLICY_ERROR row — an
        authoring bug made visible (§4.8) — but the outcome is the same fail-closed
        DENY_ABAC either way, never pass-through (§5)."""
        for condition in conditions:
            problem: str | None = None
            try:
                satisfied, missing = abac.evaluate(condition, attrs)
                if missing:
                    problem = f"unresolvable attributes: {', '.join(missing)}"
            except Exception:
                self._log.exception("abac_evaluation_failed", condition=condition.source)
                satisfied, problem = False, "condition evaluation raised"
            if problem is not None:
                try:
                    await self.writer.write(
                        EventType.POLICY_ERROR,
                        self.identity_id,
                        server_id=self.server_id,
                        tool_name=tool_name,
                        payload_extra={"condition": condition.source, "reason": problem},
                    )
                except Exception:
                    # Best-effort visibility; the deny below stands regardless.
                    self._log.exception(
                        "audit_write_failed", event_type=EventType.POLICY_ERROR.value
                    )
            if not satisfied:
                reason = f"condition {condition.source!r} not satisfied"
                if problem is not None:
                    reason += f" ({problem})"
                return self._decision(
                    DecisionOutcome.DENY,
                    EventType.DENY_ABAC,
                    reason,
                    [f"policy-v{self.engine.version}:abac:{condition.source}"],
                    risk_score,
                    risk_factors,
                )
        return None

    async def _input_schema_for(self, tool_name: str) -> dict[str, Any] | None:
        try:
            tools = await self.cache.get(self.server_id)
        except Exception:
            self._log.exception("schema_cache_read_failed_fail_closed", tool=tool_name)
            tools = None
        if tools is None:
            tools = await self._refetch_tools()
            if tools is None:
                return None
        for tool in tools:
            if tool.get("name") == tool_name:
                schema: dict[str, Any] = tool.get("inputSchema", {})
                return schema
        return None  # RBAC-allowed but the upstream doesn't expose it — fail closed

    async def _refetch_tools(self) -> list[dict[str, Any]] | None:
        """Gateway-initiated tools/list (§8 TTL expiry / cache miss). The re-fetched
        schema goes through the same drift check as a client-initiated list."""
        request_id = f"portunusmcp:{uuid.uuid4().hex}"
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._internal[request_id] = future
        try:
            await self.send_upstream(
                JSONRPCMessage(JSONRPCRequest(jsonrpc="2.0", id=request_id, method="tools/list"))
            )
            result = await asyncio.wait_for(future, timeout=_REFETCH_TIMEOUT_S)
            tools: list[dict[str, Any]] = result.get("tools", [])
            await self.detector.check(self.server_id, tools, self.identity_id)
            await self.cache.put(self.server_id, tools)
        except Exception:
            self._log.exception("tools_list_refetch_failed")
            return None
        finally:
            self._internal.pop(request_id, None)
        return tools

    def _risk_decision(
        self,
        tool_name: str,
        outcome: DecisionOutcome,
        risk_score: int,
        risk_factors: list[RiskFactor],
    ) -> Decision:
        if outcome is DecisionOutcome.DENY:
            return self._decision(
                outcome,
                EventType.DENY_RISK,
                f"risk score {risk_score} for {tool_name!r} exceeds the deny"
                f" threshold ({RISK_DENY_ABOVE})",
                ["risk_engine"],
                risk_score,
                risk_factors,
            )
        identity = self.engine.identity(self.identity_id)
        step_up_capable = identity is not None and bool(identity.totp_secret)
        if outcome is DecisionOutcome.HUMAN_APPROVAL_REQUIRED:
            event_type = EventType.HUMAN_APPROVAL_REQUIRED
            reason = f"risk score {risk_score} for {tool_name!r} requires human approval"
            if self.mode is DecisionMode.OBSERVE:
                reason = f"risk score {risk_score} for {tool_name!r} would require human approval"
            else:
                reason += "; retry with the approval id once granted"
        else:
            event_type = EventType.CHALLENGE
            verb = "would require" if self.mode is DecisionMode.OBSERVE else "requires"
            reason = f"risk score {risk_score} for {tool_name!r} {verb} confirmation"
            if step_up_capable and self.mode is DecisionMode.ENFORCE:
                reason += "; retry with the challenge id and a fresh TOTP code"
        return self._decision(
            outcome,
            event_type,
            reason,
            ["risk_engine"],
            risk_score,
            risk_factors,
        )

    async def _emit_decision(
        self,
        message: SessionMessage,
        request: JSONRPCRequest,
        tool_name: str,
        arguments: dict[str, Any],
        decision: Decision,
        *,
        approval_id: str | None = None,
        challenge_id: str | None = None,
    ) -> Forward | Respond:
        """Audit and emit the one canonical live Decision. Observe forwards only
        after the write succeeds; enforce keeps the existing fail-closed terminals."""
        if decision.decision is DecisionOutcome.DENY:
            try:
                await self.risk.record_denial(self.identity_id)
            except Exception:
                self._log.exception("denial_count_unavailable", tool=tool_name)
        payload_extra: dict[str, Any] = {
            "mode": decision.mode.value,
            "reason": decision.reason,
            "matched_rules": decision.matched_rules,
            "arguments": arguments,
        }
        if decision.risk_factors is not None:
            payload_extra["risk_factors"] = [
                factor.model_dump(mode="json") for factor in decision.risk_factors
            ]
        if approval_id is not None and self.mode is DecisionMode.ENFORCE:
            payload_extra["approval_id"] = approval_id
        if challenge_id is not None and self.mode is DecisionMode.ENFORCE:
            payload_extra["challenge_id"] = challenge_id
        identity = self.engine.identity(self.identity_id)
        step_up_capable = identity is not None and bool(identity.totp_secret)
        try:
            seq = await self.writer.write(
                decision.event_type,
                self.identity_id,
                server_id=self.server_id,
                tool_name=tool_name,
                payload_extra=payload_extra,
                risk_score=decision.risk_score,
            )
            decision.audit_id = str(seq)
            if (
                self.mode is DecisionMode.ENFORCE
                and decision.decision is DecisionOutcome.HUMAN_APPROVAL_REQUIRED
            ):
                decision.approval_id = await self.approvals.create(
                    self.identity_id, self.server_id, tool_name, arguments_hash(arguments), seq
                )
            elif (
                self.mode is DecisionMode.ENFORCE
                and decision.decision is DecisionOutcome.CHALLENGE
                and step_up_capable
            ):
                decision.challenge_id = await self.challenges.create(
                    self.identity_id, self.server_id, tool_name, arguments_hash(arguments), seq
                )
        except Exception:
            if self.mode is DecisionMode.ENFORCE and decision.decision is DecisionOutcome.DENY:
                self._log.exception(
                    "audit_write_failed",
                    event_type=decision.event_type.value,
                    tool=tool_name,
                )
            else:
                self._log.exception("audit_write_failed_fail_closed", tool=tool_name)
                self._pending.pop(request.id, None)
                return _error(
                    request.id, AUDIT_UNAVAILABLE_CODE, "audit log unavailable; call denied"
                )
        self._log.info(
            "decision",
            decision=decision.decision.value,
            event_type=decision.event_type.value,
            mode=decision.mode.value,
            tool=tool_name,
            reason=decision.reason,
            risk_score=decision.risk_score,
            audit_id=decision.audit_id,
            approval_id=decision.approval_id,
            challenge_id=decision.challenge_id,
        )
        await self._record_tool_call(tool_name, decision.event_type)
        if self.mode is DecisionMode.ENFORCE and decision.event_type is EventType.DENY_REPLAY:
            metrics.REPLAY_DENIED.inc()
        if self.mode is DecisionMode.ENFORCE and decision.decision is not DecisionOutcome.ALLOW:
            self._pending.pop(request.id, None)
            return _error(
                request.id,
                POLICY_DENIED_CODE,
                decision.reason,
                data=decision.model_dump(mode="json"),
            )
        _strip_gateway_meta(request.params)
        return Forward(message)

    async def _record_tool_call(self, tool_name: str, event_type: EventType) -> None:
        """Keep attacker-chosen names out of the Prometheus label set."""
        label = "other"
        try:
            tools = await self.cache.get(self.server_id)
            if tools is not None and any(tool.get("name") == tool_name for tool in tools):
                label = tool_name
        except Exception:
            pass
        metrics.TOOL_CALLS.labels(
            self.identity_id,
            self.server_id,
            label,
            event_type.value,
            self.mode.value,
        ).inc()

    async def on_upstream_message(self, message: SessionMessage) -> SessionMessage | None:
        """Returns the message to serve to the client, or None to swallow it
        (responses to gateway-initiated internal requests)."""
        root = message.message.root
        if isinstance(root, JSONRPCResponse):
            if isinstance(root.id, str) and root.id in self._internal:
                future = self._internal[root.id]
                if not future.done():
                    future.set_result(root.result)
                return None
            method = self._pending.pop(root.id, None)
            if method == "tools/list":
                return await self._prune_tools_list(message, root)
        elif isinstance(root, JSONRPCError):
            if isinstance(root.id, str) and root.id in self._internal:
                future = self._internal[root.id]
                if not future.done():
                    future.set_exception(RuntimeError(root.error.message))
                return None
            self._pending.pop(root.id, None)
        return message

    async def _prune_tools_list(
        self, message: SessionMessage, response: JSONRPCResponse
    ) -> SessionMessage:
        full = response.result.get("tools", [])
        try:
            await self.detector.check(self.server_id, full, self.identity_id)
        except Exception:
            self._log.exception("drift_check_failed_fail_closed")
            return _error(
                response.id, AUDIT_UNAVAILABLE_CODE, "drift check unavailable; tools/list denied"
            ).message
        schema_hash = await self.cache.put(self.server_id, full)
        allowed = schema_pruner.prune(full, self.identity_id, self.server_id, self.engine)
        served = full if self.mode is DecisionMode.OBSERVE else allowed
        response.result["tools"] = served
        # §8 ETag, realized as result metadata (per-message conditional HTTP semantics
        # don't exist over the streamed transport).
        response.result["_meta"] = {"etag": f"{self.engine.version}-{schema_hash}"}
        served_names = [str(tool.get("name")) for tool in served]
        would_prune_names = [str(tool.get("name")) for tool in full if tool not in allowed]
        pruned_names = would_prune_names if self.mode is DecisionMode.ENFORCE else []
        try:
            await self.writer.write(
                EventType.TOOLS_LIST,
                self.identity_id,
                server_id=self.server_id,
                payload_extra={
                    "mode": self.mode.value,
                    "served_tools": served_names,
                    "pruned_tools": pruned_names,
                    "would_prune_tools": would_prune_names,
                },
            )
        except Exception:
            self._log.exception(
                "audit_write_failed_fail_closed", event_type=EventType.TOOLS_LIST.value
            )
            return _error(
                response.id, AUDIT_UNAVAILABLE_CODE, "audit log unavailable; tools/list denied"
            ).message
        return message

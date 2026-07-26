"""Loads the YAML policy, validates it, answers RBAC + ABAC questions
(ARCHITECTURE.md §4.8).

The base grant is RBAC (allowed/denied tools per server); each grant may carry
ABAC `conditions` (item 17), compiled at load via services.gateway.abac and
evaluated per tools/call by the interceptor — a malformed condition fails
validation, so startup fails and SIGHUP reload keeps last-known-good. Activation
record-keeping (revision snapshots, policy_versions rows, monotonicity — item 19)
lives in services.gateway.policy_versions. A missing or invalid policy file fails
startup — fail closed (ARCHITECTURE.md §5).
"""

import hashlib
import os
import re
from pathlib import Path, PurePosixPath
from typing import Literal

import canonicaljson
import structlog
import yaml
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator, model_validator

from services.gateway import abac, step_up

logger = structlog.get_logger(__name__)

SensitivityTier = Literal["low", "medium", "high", "critical"]
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_UPSTREAM_ENV_PREFIX = "PORTUNUSMCP_UPSTREAM_"
_VOLUME_PREFIX = "portunusmcp-upstream-"
_RESERVED_MOUNT_TARGETS = (PurePosixPath("/app/secrets"), PurePosixPath("/var/run/docker.sock"))


class RiskPolicy(BaseModel):
    """Static Risk Engine inputs (§4.8, item 16): the sensitivity tier per tool and the
    blast-radius protected list. Factor weights stay code constants in risk_engine."""

    model_config = ConfigDict(extra="forbid")

    # Tool name -> tier; unlisted tools contribute 0.
    tool_sensitivity: dict[str, SensitivityTier] = {}
    # fnmatch patterns matched against every string argument value (repos, paths).
    protected_repos: list[str] = []


class UpstreamResources(BaseModel):
    model_config = ConfigDict(extra="forbid")

    memory_mb: int = Field(default=256, gt=0)
    cpus: float = Field(default=0.5, gt=0)
    pids: int = Field(default=64, gt=0)


class UpstreamMount(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    target: str

    @model_validator(mode="after")
    def _check_mount(self) -> "UpstreamMount":
        if not self.source.startswith(_VOLUME_PREFIX) or "," in self.source:
            raise ValueError(f"volume names must start with {_VOLUME_PREFIX!r}")
        target = PurePosixPath(self.target)
        if not target.is_absolute() or "," in self.target:
            raise ValueError("upstream mount target must be an absolute path without commas")
        if ".." in target.parts:
            raise ValueError("upstream mount target must not contain '..'")
        for reserved in _RESERVED_MOUNT_TARGETS:
            if target == reserved or reserved in target.parents:
                raise ValueError(f"upstream mount target {self.target!r} is reserved")
        return self


class UpstreamServer(BaseModel):
    """Versioned item-39 container launch specification for one upstream server."""

    model_config = ConfigDict(extra="forbid")

    image: str = Field(min_length=1)
    command: list[str] = Field(min_length=1)
    env: dict[str, str] = {}
    volumes: list[UpstreamMount] = []
    network: Literal["none", "bridge"] = "none"
    resources: UpstreamResources = UpstreamResources()
    _resolved_environment: dict[str, str] = PrivateAttr(default_factory=dict)

    @field_validator("image")
    @classmethod
    def _check_image(cls, value: str) -> str:
        if "\0" in value or value.strip() != value:
            raise ValueError("upstream image must not contain NUL or surrounding whitespace")
        return value

    @field_validator("command")
    @classmethod
    def _check_command(cls, value: list[str]) -> list[str]:
        if any(not part or "\0" in part for part in value):
            raise ValueError("upstream command argv entries must be non-empty and NUL-free")
        return value

    @model_validator(mode="after")
    def _resolve_environment(self) -> "UpstreamServer":
        resolved: dict[str, str] = {}
        for destination, source in self.env.items():
            if not _ENV_NAME.fullmatch(destination):
                raise ValueError(f"invalid upstream environment name {destination!r}")
            if not source.startswith(_UPSTREAM_ENV_PREFIX):
                raise ValueError(
                    f"upstream environment source {source!r} must start with"
                    f" {_UPSTREAM_ENV_PREFIX!r}"
                )
            value = os.environ.get(source)
            if value is None:
                raise ValueError(f"upstream environment source {source!r} is unset")
            if "\0" in value:
                raise ValueError(f"upstream environment source {source!r} contains NUL")
            resolved[destination] = value
        self._resolved_environment = resolved
        return self

    @property
    def resolved_environment(self) -> dict[str, str]:
        return dict(self._resolved_environment)

    @property
    def runtime_fingerprint(self) -> str:
        payload = self.model_dump(mode="json")
        payload["environment_value_hashes"] = {
            name: hashlib.sha256(value.encode()).hexdigest()
            for name, value in sorted(self._resolved_environment.items())
        }
        return hashlib.sha256(canonicaljson.encode_canonical_json(payload)).hexdigest()


class ServerGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server_id: str
    allowed_tools: list[str] = []
    denied_tools: list[str] = []
    # ABAC conditions (item 17): ALL must be satisfied once RBAC matches this grant.
    conditions: list[str] = []
    _compiled: list[abac.Condition] = PrivateAttr(default_factory=list)

    @model_validator(mode="after")
    def _compile_conditions(self) -> "ServerGrant":
        self._compiled = [abac.compile_condition(source) for source in self.conditions]
        return self

    @property
    def compiled_conditions(self) -> list[abac.Condition]:
        return self._compiled


class Identity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    # Auth posture (item 34). `bearer`: today's X-PortunusMCP-Key header, looked up by
    # api_key_hash. `signed`: no key on the wire — the request carries a non-secret
    # key_id plus an HMAC in params._meta, verified with a secret resolved from the
    # environment at load time (never stored in the policy file or its revision
    # snapshots; see signing_secret_env).
    auth_mode: Literal["bearer", "signed"] = "bearer"
    api_key_hash: str | None = None
    key_id: str | None = None
    # Name of the env var holding the base64/raw shared secret — indirection keeps
    # the YAML committable and revision snapshots secret-free.
    signing_secret_env: str | None = None
    # Step-up factor (item 37, either auth mode): name of the env var holding the
    # base32 TOTP secret — the same indirection as signing_secret_env. Unset means
    # the identity's CHALLENGE band stays a terminal error.
    totp_secret_env: str | None = None
    # Grants access to /admin endpoints (drift re-approval, and Phase 3's admin API).
    admin: bool = False
    allowed_servers: list[ServerGrant] = []
    # identity.* attributes for ABAC conditions (identity.id comes from `id` itself).
    attributes: dict[str, str | int | float | bool] = {}
    _signing_secret: bytes = PrivateAttr(default=b"")
    _totp_secret: str = PrivateAttr(default="")

    @model_validator(mode="after")
    def _check_auth_fields(self) -> "Identity":
        if self.auth_mode == "bearer":
            if not self.api_key_hash:
                raise ValueError(f"identity {self.id!r}: bearer auth_mode requires api_key_hash")
            if self.key_id or self.signing_secret_env:
                raise ValueError(
                    f"identity {self.id!r}: key_id/signing_secret_env are signed-mode fields"
                )
        else:
            if not self.key_id or not self.signing_secret_env:
                raise ValueError(
                    f"identity {self.id!r}: signed auth_mode requires key_id"
                    " and signing_secret_env"
                )
            if self.api_key_hash:
                raise ValueError(f"identity {self.id!r}: signed auth_mode forbids api_key_hash")
            if self.admin:
                # The /admin API authenticates by bearer key only; an admin that can
                # never authenticate is a misconfiguration — fail at load (§5).
                raise ValueError(f"identity {self.id!r}: admin requires bearer auth_mode")
            secret = os.environ.get(self.signing_secret_env)
            if not secret:
                raise ValueError(
                    f"identity {self.id!r}: env var {self.signing_secret_env!r} is unset"
                    " — signed identities fail closed without their secret"
                )
            self._signing_secret = secret.encode()
        if self.totp_secret_env:
            totp_secret = os.environ.get(self.totp_secret_env)
            if not totp_secret:
                raise ValueError(
                    f"identity {self.id!r}: env var {self.totp_secret_env!r} is unset"
                    " — a step-up factor fails closed without its secret"
                )
            try:
                step_up.decode_totp_secret(totp_secret)
            except Exception as exc:
                # A malformed secret fails load, not every redemption (§5).
                raise ValueError(
                    f"identity {self.id!r}: {self.totp_secret_env!r} is not a valid"
                    " base32 TOTP secret"
                ) from exc
            self._totp_secret = totp_secret
        return self

    @property
    def signing_secret(self) -> bytes:
        return self._signing_secret

    @property
    def totp_secret(self) -> str:
        return self._totp_secret


class PolicyFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int
    # Server registry (items 35 + 39): server_id -> isolated container specification.
    # Clients connect to /mcp/{server_id}; launch state is versioned with enforcement.
    servers: dict[str, UpstreamServer] = {}
    identities: list[Identity] = []
    risk: RiskPolicy = RiskPolicy()

    @model_validator(mode="after")
    def _check_servers(self) -> "PolicyFile":
        if "*" in self.servers:
            raise ValueError('"*" is a grant wildcard, not a registrable server_id')
        for identity in self.identities:
            for grant in identity.allowed_servers:
                if grant.server_id != "*" and grant.server_id not in self.servers:
                    # A grant that can never match is an authoring mistake — fail at
                    # load (§5), like abac's compile-time validation.
                    raise ValueError(
                        f"identity {identity.id!r}: grant references unregistered"
                        f" server {grant.server_id!r}"
                    )
        return self


class PolicyEngine:
    def __init__(self, policy: PolicyFile, content_hash: str = "", raw: bytes = b"") -> None:
        self.policy = policy
        self.content_hash = content_hash
        # Exact file bytes, snapshotted verbatim on activation (item 19) — never
        # re-serialized through yaml.dump, which would change formatting.
        self.raw = raw
        self._identities = {identity.id: identity for identity in policy.identities}
        self._by_key_hash = {
            identity.api_key_hash: identity.id
            for identity in policy.identities
            if identity.api_key_hash
        }
        self._by_key_id = {
            identity.key_id: identity.id for identity in policy.identities if identity.key_id
        }

    @property
    def version(self) -> int:
        return self.policy.version

    def identity_for_key_hash(self, key_hash: str) -> str | None:
        return self._by_key_hash.get(key_hash)

    def identity_for_key_id(self, key_id: str) -> str | None:
        return self._by_key_id.get(key_id)

    def is_admin(self, identity_id: str) -> bool:
        identity = self._identities.get(identity_id)
        return identity is not None and identity.admin

    def identity(self, identity_id: str) -> Identity | None:
        return self._identities.get(identity_id)

    def server_config(self, server_id: str) -> UpstreamServer | None:
        return self.policy.servers.get(server_id)

    def is_allowed(self, identity_id: str | None, server_id: str, tool_name: str) -> bool:
        return self.matching_grant(identity_id, server_id, tool_name) is not None

    def matching_grant(
        self, identity_id: str | None, server_id: str, tool_name: str
    ) -> ServerGrant | None:
        """RBAC resolution: unknown/missing identity denies; a grant matches by exact
        server_id or "*"; denied_tools overrides allowed_tools; "*" allows any tool.
        Returns the first allowing grant — its `conditions` are the ABAC layer the
        interceptor enforces on top (item 17)."""
        if identity_id is None:
            return None
        identity = self._identities.get(identity_id)
        if identity is None:
            return None
        for grant in identity.allowed_servers:
            if grant.server_id not in (server_id, "*"):
                continue
            if tool_name in grant.denied_tools:
                return None
            if "*" in grant.allowed_tools or tool_name in grant.allowed_tools:
                return grant
        return None


def load_bytes(raw: bytes) -> PolicyEngine:
    data = yaml.safe_load(raw)
    return PolicyEngine(
        PolicyFile.model_validate(data), content_hash=hashlib.sha256(raw).hexdigest(), raw=raw
    )


def load(path: str | Path) -> PolicyEngine:
    return load_bytes(Path(path).read_bytes())


class PolicyStore:
    """Holds the live PolicyEngine; hot-swapped on SIGHUP (ARCHITECTURE.md §8). Readers
    go through .engine on every call, so in-flight sessions re-resolve against a new
    version on their next request rather than finishing out the old one."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self.engine = load(self._path)

    def load_candidate(self) -> PolicyEngine | None:
        """Parse + validate the file's current contents without swapping; None on any
        error — a broken reload must not take the gateway down or weaken the active
        policy (last-known-good, item 7). The caller records the activation (item 19)
        before calling swap()."""
        try:
            return load(self._path)
        except Exception:
            logger.exception("policy_reload_failed_keeping_last_known_good")
            return None

    def swap(self, engine: PolicyEngine) -> None:
        self.engine = engine
        logger.info("policy_activated", version=engine.version)

    def reload(self) -> bool:
        """Load + swap in one step; keep last-known-good on any error. The gateway's
        SIGHUP path uses load_candidate()/swap() around activation record-keeping."""
        candidate = self.load_candidate()
        if candidate is None:
            return False
        self.swap(candidate)
        return True

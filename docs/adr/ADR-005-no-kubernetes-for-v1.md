# ADR-005 — No Kubernetes for v1

**Status:** Accepted

**Decision:** Ship two explicit Docker Compose deployments for v1: an unsafe local demo profile and one hardened, single-host, single-gateway-replica production profile. Do not build Kubernetes/EKS, ECS/Fargate, or Terraform yet.

**Reasoning:** The current gateway is not stateless or horizontally safe: session objects and per-session Docker handles are process-local, and two audit writers can fork the hash chain. A cloud orchestrator would package those correctness limits rather than remove them. The production Compose profile provides the deployment boundary the code can honestly support today; Terraform/ECS becomes appropriate only after a concrete cloud deployment is wanted and remains roadmap item 24.

**Alternatives considered:** ECS Fargate + Terraform, EKS, self-managed Kubernetes, Nomad, and implying multi-replica readiness through a future-state diagram.

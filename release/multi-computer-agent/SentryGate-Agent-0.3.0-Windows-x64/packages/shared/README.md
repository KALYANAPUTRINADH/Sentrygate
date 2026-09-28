# Shared Contracts

Milestone 1 keeps API response contracts documented here while avoiding external package dependencies. Later milestones can promote these contracts into generated schemas if the project adopts a build step.

Core response shapes:

- `SessionState`: `{ authenticated, setupRequired, admin }`
- `Asset`: `{ id, name, type, owner, status, createdAt }`
- `Alert`: `{ id, assetId, title, severity, status, evidence, observedFacts, estimate, createdAt }`
- `SecurityEvent`: `{ id, assetId, source, category, action, reason, evidence, createdAt }`
- `AuditLog`: `{ id, actor, action, target, detail, createdAt }`

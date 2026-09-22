---
"@better-auth/scim": patch
---

Use adapter-advertised transaction batch creation for Group memberships and bounded concurrency for independent projection locks and per-user reconciliation. Adapters without the capability retain the existing sequential behavior.

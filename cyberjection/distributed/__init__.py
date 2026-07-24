"""Distributed worker architecture: Celery/Redis task queues, cluster-wide
adaptive rate limiting, Pub/Sub state synchronization, and fault-tolerant
retry/dead-letter handling.

Everything under this package is designed to scale a campaign's evaluation
workload from a single process to a horizontal pool of worker nodes, all
coordinating through a shared Redis instance:

- `celery_app`: the shared Celery application (broker/backend config).
- `rate_limiter`: `DistributedRateLimiter`, an atomic Redis-backed
  RPM + TPM token bucket enforced per target provider, cluster-wide.
- `coordinator`: `DistributedClusterCoordinator`, Redis Pub/Sub broadcast
  and listener for cluster-wide abort signals.
- `retry`: pure exponential-backoff-with-jitter math and dead-letter-queue
  helpers, shared by the Celery task definitions in `tasks`.
- `tasks`: the actual Celery task wrappers worker nodes execute.

None of these modules are wired into the single-node orchestrator from
earlier phases yet -- that integration (deciding when a campaign runs
locally vs. dispatches to the distributed queue) is deliberately left for
a later phase, consistent with how earlier infrastructure-only phases
(e.g. the Phase 4 persistence layer before Phase 5 wired resumability
into the CLI) landed as standalone, independently-tested components
first.
"""

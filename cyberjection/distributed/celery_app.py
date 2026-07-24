"""Central Celery application: the single `celery_app` instance every
worker process and every task module imports, rather than each module
constructing its own.

A prior draft of this module defined `celery_app` inline inside
`tasks.py`. That works for a single task module, but breaks down the
moment a second task module (or the CLI, wiring up
`celery -A cyberjection.distributed.celery_app worker`) needs the same
app instance -- Celery's own convention, and the one used here, is a
dedicated `celery_app.py` that owns configuration, with task modules
importing the shared instance and registering onto it.
"""

from __future__ import annotations

import os

from celery import Celery

# Both broker and result backend default to the same local Redis instance
# on different logical databases (0 for broker, 1 for results) so a
# developer running against a single `redis-server` doesn't need two
# instances, while still keeping broker traffic and result storage
# separately addressable. Overridable via environment variables so
# deployments can point at a real cluster/sentinel/managed Redis endpoint
# without editing source, matching the `CYBERJECTION_DB_URL` convention
# used by `cyberjection.persistence.sqlite`.
DEFAULT_BROKER_URL = "redis://localhost:6379/0"
DEFAULT_RESULT_BACKEND_URL = "redis://localhost:6379/1"

BROKER_URL = os.environ.get("CYBERJECTION_CELERY_BROKER_URL", DEFAULT_BROKER_URL)
RESULT_BACKEND_URL = os.environ.get("CYBERJECTION_CELERY_RESULT_BACKEND_URL", DEFAULT_RESULT_BACKEND_URL)

celery_app = Celery(
    "cyberjection",
    broker=BROKER_URL,
    backend=RESULT_BACKEND_URL,
    include=["cyberjection.distributed.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    # Late ack means a task is only acknowledged (removed from the queue)
    # after it finishes, not the moment a worker picks it up -- so a
    # worker that crashes mid-task leaves the task requeued for another
    # worker rather than silently dropping it.
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    # A prefetch multiplier of 1 means each worker process holds at most
    # one unstarted task at a time. Evaluation tasks are long-running and
    # rate-limited against external APIs (not CPU-bound), so prefetching
    # a deep queue per worker would let one worker hoard tasks that sit
    # idle waiting on a rate-limit token while other workers starve.
    worker_prefetch_multiplier=1,
    worker_concurrency=int(os.environ.get("CYBERJECTION_CELERY_CONCURRENCY", "4")),
    # Tasks default to expiring out of the broker after an hour if no
    # worker has picked them up, so a cluster that's been fully drained
    # (e.g. during a deploy) doesn't silently execute stale campaign
    # tasks hours later against targets that may have since changed.
    task_time_limit=None,
    result_expires=3600,
    timezone="UTC",
    enable_utc=True,
)

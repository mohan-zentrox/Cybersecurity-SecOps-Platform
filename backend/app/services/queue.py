"""
Queue abstraction for event ingestion buffering.

FRD ref: FRD-ING-03 — raw events are buffered on a queue between the
ingest API and the normalization consumer so ingestion spikes don't apply
backpressure directly onto the write path. Two real implementations are
provided:

  * InMemoryQueue  — thread-safe, in-process. Default in tests and for a
    single-process `uvicorn` dev server.
  * RedisStreamQueue — backed by Redis Streams (XADD/XREAD), used when
    QUEUE_BACKEND=redis (see docker-compose.yml).

Extension point (documented, not implemented — see FRD-ING-03 "future
swap-in"): a KafkaQueueAdapter implementing the same `Queue` interface
would let a production deployment swap Redis Streams for Kafka topics
without changing any caller in api/v1/events.py or services/normalizer.py.
Implementing it requires a Kafka client (e.g. `confluent-kafka` or
`aiokafka`), topic/partition provisioning, and consumer-group offset
management — intentionally out of scope for this foundation repo.
"""

import json
import threading
from abc import ABC, abstractmethod
from collections import deque
from typing import Any

from app.core.config import get_settings


class Queue(ABC):
    """Minimal at-least-once queue interface used by the ingestion pipeline."""

    @abstractmethod
    def enqueue(self, topic: str, message: dict[str, Any]) -> None: ...

    @abstractmethod
    def dequeue_batch(self, topic: str, max_messages: int = 100) -> list[dict[str, Any]]:
        """Pop up to `max_messages` off the queue. Removed messages are considered consumed."""
        ...

    @abstractmethod
    def depth(self, topic: str) -> int: ...


class InMemoryQueue(Queue):
    def __init__(self) -> None:
        self._topics: dict[str, deque] = {}
        self._lock = threading.Lock()

    def enqueue(self, topic: str, message: dict[str, Any]) -> None:
        with self._lock:
            self._topics.setdefault(topic, deque()).append(message)

    def dequeue_batch(self, topic: str, max_messages: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            bucket = self._topics.setdefault(topic, deque())
            batch = []
            for _ in range(min(max_messages, len(bucket))):
                batch.append(bucket.popleft())
            return batch

    def depth(self, topic: str) -> int:
        with self._lock:
            return len(self._topics.get(topic, ()))


class RedisStreamQueue(Queue):
    """Redis Streams-backed queue using **consumer groups**.

    Delivery semantics matter here. A naive XRANGE + XDEL implementation
    deletes a message before the normalizer has durably written it, so a
    crash mid-batch silently loses events — at-most-once, not at-least-once.
    This implementation instead:

      1. reads with ``XREADGROUP``, which moves entries into the consumer's
         Pending Entries List (PEL) rather than removing them;
      2. hands the messages to the caller;
      3. acknowledges with ``XACK`` only once the caller confirms the batch
         was processed (``ack_batch``), or via ``dequeue_batch``'s
         auto-acknowledge for the inline/dev path.

    Anything left unacknowledged when a worker dies stays in the PEL and is
    reclaimed by the next worker through ``XAUTOCLAIM`` (``reclaim_stale``).
    """

    def __init__(self, redis_url: str, *, group: str | None = None, consumer: str | None = None) -> None:
        import redis  # local import: keep the `redis` package optional for memory-only setups

        settings = get_settings()
        self._client = redis.Redis.from_url(redis_url)
        self._group = group or settings.QUEUE_CONSUMER_GROUP
        self._consumer = consumer or settings.QUEUE_CONSUMER_NAME
        self._groups_ready: set[str] = set()

    def _ensure_group(self, topic: str) -> None:
        if topic in self._groups_ready:
            return
        import redis

        try:
            # mkstream so the group can be created before the first XADD.
            self._client.xgroup_create(topic, self._group, id="0", mkstream=True)
        except redis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise
        self._groups_ready.add(topic)

    @staticmethod
    def _decode(fields: dict) -> dict[str, Any]:
        raw = fields.get(b"payload") or fields.get("payload")
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        return json.loads(raw)

    def enqueue(self, topic: str, message: dict[str, Any]) -> None:
        self._ensure_group(topic)
        self._client.xadd(topic, {"payload": json.dumps(message)})

    def read_batch(self, topic: str, max_messages: int = 100, block_ms: int = 0) -> list[tuple[Any, dict[str, Any]]]:
        """Read undelivered entries into this consumer's PEL. Returns (entry_id, message) pairs."""
        self._ensure_group(topic)
        response = self._client.xreadgroup(
            groupname=self._group,
            consumername=self._consumer,
            streams={topic: ">"},
            count=max_messages,
            block=block_ms or None,
        )
        if not response:
            return []
        entries = response[0][1]
        return [(entry_id, self._decode(fields)) for entry_id, fields in entries]

    def ack_batch(self, topic: str, entry_ids: list[Any]) -> None:
        """Acknowledge processed entries, removing them from the PEL."""
        if entry_ids:
            self._ensure_group(topic)
            self._client.xack(topic, self._group, *entry_ids)

    def reclaim_stale(self, topic: str, min_idle_ms: int = 60_000, count: int = 100) -> list[tuple[Any, dict[str, Any]]]:
        """Take over entries a dead consumer left pending (at-least-once recovery)."""
        self._ensure_group(topic)
        _, entries, _ = self._client.xautoclaim(
            topic, self._group, self._consumer, min_idle_time=min_idle_ms, count=count
        )
        return [(entry_id, self._decode(fields)) for entry_id, fields in entries if fields]

    def dequeue_batch(self, topic: str, max_messages: int = 100) -> list[dict[str, Any]]:
        """Read-and-acknowledge in one step.

        Used by the inline ingest path, where the caller processes the batch
        inside the same request and there is no separate ack point. Workers
        should use read_batch/ack_batch instead so a crash is recoverable.
        """
        batch = self.read_batch(topic, max_messages)
        self.ack_batch(topic, [entry_id for entry_id, _ in batch])
        return [message for _, message in batch]

    def depth(self, topic: str) -> int:
        return self._client.xlen(topic)


class KafkaQueueAdapter(Queue):
    """Documented extension point — NOT implemented in this foundation repo.

    See the module docstring (FRD-ING-03). Swapping this in would involve:
      1. `pip install confluent-kafka` (or aiokafka for an async client).
      2. Topic provisioning per event source / priority tier.
      3. Producer: enqueue() -> `producer.produce(topic, json.dumps(message))`.
      4. Consumer: dequeue_batch() -> poll a consumer-group with manual offset
         commit only after the normalizer has durably written the event
         (at-least-once delivery, matching the current Redis/in-memory
         semantics).
    """

    def enqueue(self, topic: str, message: dict[str, Any]) -> None:
        raise NotImplementedError("KafkaQueueAdapter is a documented extension point; see FRD-ING-03")

    def dequeue_batch(self, topic: str, max_messages: int = 100) -> list[dict[str, Any]]:
        raise NotImplementedError("KafkaQueueAdapter is a documented extension point; see FRD-ING-03")

    def depth(self, topic: str) -> int:
        raise NotImplementedError("KafkaQueueAdapter is a documented extension point; see FRD-ING-03")


_singleton: Queue | None = None


def get_queue() -> Queue:
    """Process-wide queue singleton, selected by settings.QUEUE_BACKEND."""
    global _singleton
    if _singleton is not None:
        return _singleton

    settings = get_settings()
    if settings.QUEUE_BACKEND == "redis":
        _singleton = RedisStreamQueue(settings.REDIS_URL)
    else:
        _singleton = InMemoryQueue()
    return _singleton


def reset_queue_for_tests() -> None:
    """Test helper: force a fresh InMemoryQueue so tests don't leak state between cases."""
    global _singleton
    _singleton = InMemoryQueue()

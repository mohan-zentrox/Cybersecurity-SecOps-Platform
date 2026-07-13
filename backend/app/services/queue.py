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
    """Redis Streams-backed queue. Requires the `redis` package and a reachable REDIS_URL."""

    def __init__(self, redis_url: str) -> None:
        import redis  # local import: keep the `redis` package optional for memory-only setups

        self._client = redis.Redis.from_url(redis_url)

    def enqueue(self, topic: str, message: dict[str, Any]) -> None:
        self._client.xadd(topic, {"payload": json.dumps(message)})

    def dequeue_batch(self, topic: str, max_messages: int = 100) -> list[dict[str, Any]]:
        entries = self._client.xrange(topic, count=max_messages)
        if not entries:
            return []
        ids_to_ack = []
        messages = []
        for entry_id, fields in entries:
            ids_to_ack.append(entry_id)
            raw = fields.get(b"payload") or fields.get("payload")
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            messages.append(json.loads(raw))
        if ids_to_ack:
            self._client.xdel(topic, *ids_to_ack)
        return messages

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

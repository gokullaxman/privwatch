"""
UATU Linux Edition - Thread-Safe Event Bus
Asynchronous, thread-safe publish-subscribe router for decoupling Linux telemetry ingestion
from detection analytics, correlation engines, containment handlers, and persistence stores.
Supports bounded queue depth, backpressure policies, subscriber error isolation, and operational metrics.
"""

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import logging
import queue
import threading
import time
from typing import Callable, Dict, List, Optional, Any, Set, Tuple

from core.event_schema import UatuEvent

logger = logging.getLogger("uatu.event_bus")


class BackpressureStrategy(str, Enum):
    DROP_OLDEST = "DROP_OLDEST"
    DROP_NEWEST = "DROP_NEWEST"
    BLOCK = "BLOCK"


@dataclass
class Subscription:
    """Subscription record for a registered event listener."""
    topic: str
    callback: Callable[[Any], None]
    predicate: Optional[Callable[[Any], bool]] = None
    subscriber_id: str = ""


@dataclass
class EventBusMetrics:
    """Real-time operational metrics for the event bus."""
    published_count: int = 0
    delivered_count: int = 0
    dropped_count: int = 0
    error_count: int = 0
    current_queue_depth: int = 0
    max_queue_size: int = 10000
    active_subscribers: int = 0


class EventBus:
    """
    High-throughput, in-memory thread-safe event bus.
    Dispatches events from collectors to analytical and defensive subscribers.
    """

    def __init__(
        self,
        max_queue_size: int = 10000,
        backpressure_strategy: BackpressureStrategy = BackpressureStrategy.DROP_OLDEST,
        worker_threads: int = 1
    ):
        self.max_queue_size = max(100, max_queue_size)
        self.backpressure_strategy = backpressure_strategy
        self.worker_threads_count = max(1, worker_threads)

        self._queue: queue.Queue = queue.Queue(maxsize=self.max_queue_size)
        self._subscriptions: List[Subscription] = []
        self._lock = threading.RLock()

        self._running = False
        self._workers: List[threading.Thread] = []

        # Metrics counters
        self._published_count = 0
        self._delivered_count = 0
        self._dropped_count = 0
        self._error_count = 0

    def start(self):
        """Start worker dispatch threads."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._workers = []
            for i in range(self.worker_threads_count):
                worker = threading.Thread(
                    target=self._dispatch_loop,
                    name=f"UatuEventBusWorker-{i}",
                    daemon=True
                )
                worker.start()
                self._workers.append(worker)

    def stop(self, timeout: float = 5.0, drain: bool = True):
        """Stop worker dispatch threads, optionally draining remaining queued events."""
        with self._lock:
            if not self._running:
                return
            self._running = False

        if drain:
            # Wait for queue to empty up to timeout
            start = time.perf_counter()
            while not self._queue.empty() and (time.perf_counter() - start) < timeout:
                time.sleep(0.05)

        # Enqueue termination sentinels
        for _ in self._workers:
            try:
                self._queue.put_nowait(None)
            except queue.Full:
                pass

        for worker in self._workers:
            worker.join(timeout=max(0.5, timeout / len(self._workers)))
        self._workers.clear()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def subscribe(
        self,
        topic: str,
        callback: Callable[[Any], None],
        predicate: Optional[Callable[[Any], bool]] = None,
        subscriber_id: str = ""
    ) -> Subscription:
        """
        Subscribe a callback to an event topic.
        Wildcard '*' subscribes to all events.
        """
        if not callable(callback):
            raise TypeError("callback must be callable")

        sub = Subscription(
            topic=topic,
            callback=callback,
            predicate=predicate,
            subscriber_id=subscriber_id or f"sub_{len(self._subscriptions) + 1}"
        )
        with self._lock:
            self._subscriptions.append(sub)
        return sub

    def unsubscribe(self, subscription: Subscription):
        """Remove an existing subscription."""
        with self._lock:
            if subscription in self._subscriptions:
                self._subscriptions.remove(subscription)

    def publish(self, event: Any, block_timeout: float = 1.0) -> bool:
        """
        Publish an event to the bus.
        Applies configured backpressure strategy when queue is saturated.
        Returns True if accepted, False if dropped.
        """
        with self._lock:
            self._published_count += 1

        try:
            self._queue.put_nowait(event)
            return True
        except queue.Full:
            # Handle saturated queue according to strategy
            if self.backpressure_strategy == BackpressureStrategy.DROP_NEWEST:
                with self._lock:
                    self._dropped_count += 1
                return False

            elif self.backpressure_strategy == BackpressureStrategy.DROP_OLDEST:
                try:
                    # Drop oldest event from queue head
                    _ = self._queue.get_nowait()
                    with self._lock:
                        self._dropped_count += 1
                    self._queue.put_nowait(event)
                    return True
                except (queue.Empty, queue.Full):
                    with self._lock:
                        self._dropped_count += 1
                    return False

            elif self.backpressure_strategy == BackpressureStrategy.BLOCK:
                try:
                    self._queue.put(event, block=True, timeout=block_timeout)
                    return True
                except queue.Full:
                    with self._lock:
                        self._dropped_count += 1
                    return False

        return False

    def publish_sync(self, event: Any):
        """
        Directly invoke subscribers synchronously in current thread without queuing.
        Useful for high-priority synchronous assertions or deterministic unit tests.
        """
        with self._lock:
            self._published_count += 1
            matching = self._get_matching_subscribers(event)

        for sub in matching:
            self._safe_invoke(sub, event)

    def _dispatch_loop(self):
        """Worker loop for event retrieval and subscriber delivery."""
        while True:
            try:
                event = self._queue.get(timeout=0.2)
            except queue.Empty:
                if not self._running:
                    break
                continue

            # Check sentinel
            if event is None:
                self._queue.task_done()
                break

            try:
                with self._lock:
                    matching = self._get_matching_subscribers(event)

                for sub in matching:
                    self._safe_invoke(sub, event)
            finally:
                self._queue.task_done()

    def _get_matching_subscribers(self, event: Any) -> List[Subscription]:
        """Find all subscriptions matching the event topic/type and predicate."""
        event_topic = getattr(event, "event_type", None) or getattr(event, "topic", "GENERIC_EVENT")
        matching = []

        for sub in self._subscriptions:
            if sub.topic == "*" or sub.topic == event_topic:
                if sub.predicate is None or sub.predicate(event):
                    matching.append(sub)

        return matching

    def _safe_invoke(self, sub: Subscription, event: Any):
        """Execute subscriber callback with complete exception isolation."""
        try:
            sub.callback(event)
            with self._lock:
                self._delivered_count += 1
        except Exception as e:
            with self._lock:
                self._error_count += 1
            logger.error(
                f"Exception in subscriber '{sub.subscriber_id}' for topic '{sub.topic}': {e}",
                exc_info=True
            )

    def get_metrics(self) -> EventBusMetrics:
        """Return snapshot of event bus telemetry counters."""
        with self._lock:
            return EventBusMetrics(
                published_count=self._published_count,
                delivered_count=self._delivered_count,
                dropped_count=self._dropped_count,
                error_count=self._error_count,
                current_queue_depth=self._queue.qsize(),
                max_queue_size=self.max_queue_size,
                active_subscribers=len(self._subscriptions)
            )

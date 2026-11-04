"""
UATU Linux Edition - Event Bus Tests
Verifies asynchronous publish-subscribe router:
- Multi-subscriber dispatch
- Topic filtering and wildcard '*' subscriptions
- Subscriber callback exception isolation
- Queue capacity bounding and backpressure policies (DROP_OLDEST, DROP_NEWEST, BLOCK)
- Operational metrics accounting
"""

import time
import pytest

from core.event_schema import UatuEvent, EventSeverity
from core.event_bus import EventBus, BackpressureStrategy


def test_event_bus_pub_sub_async():
    """Verify asynchronous dispatch delivers events to matching topic subscriber."""
    received = []

    def on_event(evt):
        received.append(evt)

    bus = EventBus(max_queue_size=100, worker_threads=1)
    bus.start()
    try:
        bus.subscribe("PROCESS_SPAWN", on_event)

        event = UatuEvent(event_type="PROCESS_SPAWN", user="daemon", pid=123)
        assert bus.publish(event) is True

        # Wait briefly for worker dispatch
        time.sleep(0.1)

        assert len(received) == 1
        assert received[0].event_type == "PROCESS_SPAWN"
        assert received[0].pid == 123
    finally:
        bus.stop(drain=True)


def test_event_bus_wildcard_subscription():
    """Verify wildcard '*' receives all event types."""
    received = []

    bus = EventBus(max_queue_size=100, worker_threads=1)
    bus.start()
    try:
        bus.subscribe("*", lambda evt: received.append(evt))

        bus.publish(UatuEvent(event_type="SUDO_EXEC"))
        bus.publish(UatuEvent(event_type="FILE_MODIFICATION"))

        time.sleep(0.1)
        assert len(received) == 2
        types = {e.event_type for e in received}
        assert types == {"SUDO_EXEC", "FILE_MODIFICATION"}
    finally:
        bus.stop()


def test_event_bus_subscriber_error_isolation():
    """Verify that an exception in one subscriber does not prevent delivery to other subscribers."""
    received_healthy = []

    def faulty_subscriber(evt):
        raise RuntimeError("Simulated subscriber crash")

    def healthy_subscriber(evt):
        received_healthy.append(evt)

    bus = EventBus(max_queue_size=100, worker_threads=1)
    bus.start()
    try:
        bus.subscribe("ERROR_TEST", faulty_subscriber, subscriber_id="faulty_1")
        bus.subscribe("ERROR_TEST", healthy_subscriber, subscriber_id="healthy_1")

        bus.publish(UatuEvent(event_type="ERROR_TEST"))
        time.sleep(0.1)

        # Healthy subscriber must have received the event despite faulty subscriber error
        assert len(received_healthy) == 1
        metrics = bus.get_metrics()
        assert metrics.error_count == 1
        assert metrics.delivered_count == 1
    finally:
        bus.stop()


def test_event_bus_backpressure_drop_oldest():
    """Verify that DROP_OLDEST strategy drops older events when queue is saturated."""
    # Use small queue and do NOT start workers so queue fills up
    bus = EventBus(max_queue_size=100, backpressure_strategy=BackpressureStrategy.DROP_OLDEST)

    # Fill queue to maximum capacity
    for i in range(100):
        bus.publish(UatuEvent(event_type=f"EVT_{i}"))

    # Publish one more: queue is full, so oldest must be dropped
    accepted = bus.publish(UatuEvent(event_type="EVT_OVERFLOW"))
    assert accepted is True

    metrics = bus.get_metrics()
    assert metrics.dropped_count == 1


def test_event_bus_backpressure_drop_newest():
    """Verify that DROP_NEWEST strategy rejects new events when queue is saturated."""
    bus = EventBus(max_queue_size=100, backpressure_strategy=BackpressureStrategy.DROP_NEWEST)

    for i in range(100):
        bus.publish(UatuEvent(event_type=f"EVT_{i}"))

    # Publish one more: newest must be rejected
    accepted = bus.publish(UatuEvent(event_type="EVT_OVERFLOW"))
    assert accepted is False

    metrics = bus.get_metrics()
    assert metrics.dropped_count == 1


def test_event_bus_publish_sync():
    """Verify publish_sync executes subscriber callback immediately in current thread."""
    delivered = []
    bus = EventBus()
    bus.subscribe("SYNC_TEST", lambda evt: delivered.append(evt))

    evt = UatuEvent(event_type="SYNC_TEST")
    bus.publish_sync(evt)

    assert len(delivered) == 1
    assert delivered[0] is evt


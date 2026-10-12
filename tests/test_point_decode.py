from packetbreaker.application_index import can_decode_source
from packetbreaker.topology import Point


def test_subset_or_damaged_capture_still_requires_isolation():
    point = Point(id="a", label="a", device="FW", capture_id="capture")
    inventory = dict(packet_count=10, records_read=10, timestamps_validated=True, interfaces=[{}])
    assert can_decode_source(point, inventory, 10)
    for change in [
        dict(interface=0),
        dict(source_cidr="10.0.0.0/8"),
        dict(vendor="checkpoint", vendor_stage="i"),
    ]:
        assert not can_decode_source(point.model_copy(update=change), inventory, 10)
    for change in [
        dict(damaged_tail=True),
        dict(frame_limit=10),
        dict(records_read=11),
        dict(interfaces=[{}, {}]),
        dict(timestamps_validated=False),
    ]:
        assert not can_decode_source(point, {**inventory, **change}, 10)
    assert not can_decode_source(point, inventory, 9)

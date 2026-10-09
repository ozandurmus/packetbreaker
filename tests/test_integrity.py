from packetbreaker.integrity import endpoint_pattern


def test_origin_patterns_are_not_authentication():
    packet = dict(src="10.0.0.1", ttl=64, ipid=0)
    assert endpoint_pattern([packet] * 2, packet)["status"] == "unknown"
    result = endpoint_pattern([packet] * 3, packet)
    assert result["ip_id_pattern"] == "constant"
    assert "cannot authenticate" in result["ip_id_note"]
    assert endpoint_pattern([packet] * 3, {**packet, "src": "2001:db8::1"})["candidate_ip_id"] is None

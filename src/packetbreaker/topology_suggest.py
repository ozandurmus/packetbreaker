"""Compatibility re-export module for packetbreaker.topology suggestion/assembly APIs."""

from .topology import (
    assemble_and_analyze,
    assemble_topology,
    confirm_suggested_topology,
    suggest_topology,
)

__all__ = [
    "assemble_and_analyze",
    "assemble_topology",
    "confirm_suggested_topology",
    "suggest_topology",
]

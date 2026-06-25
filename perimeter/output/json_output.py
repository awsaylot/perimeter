"""JSON serializer for ScanResult."""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime

from perimeter.models import ScanResult


class _Encoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            return dataclasses.asdict(obj)
        return super().default(obj)


def to_json(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(dataclasses.asdict(result), cls=_Encoder, indent=indent)

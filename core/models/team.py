"""
team.py — Team and Organization Models
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Team:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    owner_id: str = ""
    member_ids: List[str] = field(default_factory=list)
    created_at: str = ""
    
    def to_dict(self) -> Dict:
        return vars(self)

    @classmethod
    def from_dict(cls, data: Dict) -> Team:
        return cls(**data)

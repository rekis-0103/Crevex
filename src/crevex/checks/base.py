from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from crevex.models import Finding, ScanTarget


class BaseCheck(ABC):
    id: str
    name: str
    target_kinds: set[str]

    @abstractmethod
    def run(self, target: ScanTarget) -> Iterable[Finding]:
        raise NotImplementedError

"""语义化模块别名：多源共享去重。完整实现见 :mod:`app.core.source_sharing`。"""
from __future__ import annotations

from app.core.source_sharing import *  # noqa: F401,F403
from app.core import source_sharing as _impl

for _name in dir(_impl):
    if not _name.startswith("_"):
        globals().setdefault(_name, getattr(_impl, _name))

"""语义化模块别名：多源共享去重与采样的完整实现见 :mod:`app.core.source_sharing`。"""
from __future__ import annotations

from app.core.source_sharing import *  # noqa: F401,F403
from app.core import source_sharing as _impl

# 把实现模块的全部公开名称（含下划线之外的工具）透出
for _name in dir(_impl):
    if not _name.startswith("_"):
        globals().setdefault(_name, getattr(_impl, _name))

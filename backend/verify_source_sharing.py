#!/usr/bin/env python3
"""一键核对多源共享去重场景（甲/乙/丙真实输入 + 全部断言）。

用法（在 backend/ 目录）：
    python verify_source_sharing.py
等价于：
    python tests/test_source_sharing.py
"""
from __future__ import annotations

import runpy
from pathlib import Path

if __name__ == "__main__":
    target = Path(__file__).parent / "tests" / "test_source_sharing.py"
    runpy.run_path(str(target), run_name="__main__")

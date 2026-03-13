"""Tests for TUI widgets and app."""

from __future__ import annotations

from kong.tui.widgets import BinaryHeader, ProgressWidget, StatusBar


class TestBinaryHeader:
    def test_set_info_formats_correctly(self) -> None:
        widget = BinaryHeader()
        widget.set_info(
            name="test.bin",
            arch="x86_64",
            fmt="ELF",
            compiler="GCC",
        )
        expected = "Binary: test.bin | x86_64 ELF | GCC"
        assert widget._content == expected


class TestProgressWidget:
    def test_update_phase(self) -> None:
        widget = ProgressWidget()
        widget.update_phase("Analysis")
        assert widget.phase_name == "Analysis"

    def test_update_progress(self) -> None:
        widget = ProgressWidget()
        widget.update_progress(5, 10)
        assert widget.completed == 5
        assert widget.total == 10

    def test_update_confidence(self) -> None:
        widget = ProgressWidget()
        widget.update_confidence(3, 2, 1)
        assert widget.high == 3
        assert widget.medium == 2
        assert widget.low == 1


class TestStatusBar:
    def test_update_status_formats_correctly(self) -> None:
        widget = StatusBar()
        text = widget.build_status_text(elapsed=125.0, llm_calls=10, cost=0.0523, paused=False)
        content = text.plain
        assert "LLM: 10" in content
        assert "$0.0523" in content
        assert "2m 05s" in content
        assert "PAUSED" not in content

    def test_update_status_paused(self) -> None:
        widget = StatusBar()
        text = widget.build_status_text(elapsed=60.0, llm_calls=5, cost=0.01, paused=True)
        content = text.plain
        assert "PAUSED" in content



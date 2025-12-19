"""Tests for the AWARE engine."""

import pytest
from aware.core import AwareEngine, load_default_rules


def test_engine_initialization():
    """Test engine can be initialized with default rules."""
    rules_pack = load_default_rules()
    engine = AwareEngine(rules_pack)
    
    assert engine is not None
    assert len(engine.active_rules) > 0


def test_scan_shell_command():
    """Test scanning a shell command."""
    rules_pack = load_default_rules()
    engine = AwareEngine(rules_pack)
    
    # Test dangerous command
    result = engine.scan_shell_command("rm -rf /")
    
    assert len(result.findings) > 0
    assert result.has_critical_findings


def test_scan_safe_command():
    """Test scanning a safe command."""
    rules_pack = load_default_rules()
    engine = AwareEngine(rules_pack)
    
    # Test safe command
    result = engine.scan_shell_command("ls -la")
    
    assert len(result.findings) == 0
    assert result.exit_code == 0
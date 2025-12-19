"""Pytest configuration and fixtures."""

import pytest
from pathlib import Path


@pytest.fixture
def sample_rules_file():
    """Fixture com arquivo de regras de teste."""
    return Path(__file__).parent / "fixtures" / "test_rules.yaml"


@pytest.fixture
def temp_git_repo(tmp_path):
    """Cria repositório git temporário."""
    import subprocess
    
    repo_dir = tmp_path / "test_repo"
    repo_dir.mkdir()
    
    subprocess.run(["git", "init"], cwd=repo_dir, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repo_dir,
        check=True
    )
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=repo_dir,
        check=True
    )
    
    return repo_dir
"""
AWARE - Git Hooks Installer
Instala e gerencia git hooks para pre-commit e pre-push.
"""

from pathlib import Path
from typing import Dict, List, Optional, Any
import subprocess
import shutil


# =============================================================================
# Exceptions
# =============================================================================

class HookInstallerError(Exception):
    """Exception raised when hook installation fails."""
    pass


# =============================================================================
# Hook Templates
# =============================================================================

PRE_COMMIT_TEMPLATE = """#!/usr/bin/env bash
# AWARE pre-commit hook
# Auto-generated - DO NOT EDIT MANUALLY

set -e

# Check if aware is installed
if ! command -v aware &> /dev/null; then
    if ! command -v python &> /dev/null; then
        echo "❌ Python não encontrado no PATH"
        exit 1
    fi
    
    # Try to run via python if aware command not found
    if [ -f "cli.py" ]; then
        python cli.py scan --staged
        exit $?
    else
        echo "❌ AWARE não encontrado (nem comando 'aware' nem 'cli.py')"
        exit 1
    fi
fi

# Run AWARE scan on staged files
aware scan --staged
exit $?
"""

PRE_PUSH_TEMPLATE = """#!/usr/bin/env bash
# AWARE pre-push hook
# Auto-generated - DO NOT EDIT MANUALLY

set -e

# Get remote and local refs
remote="$1"
url="$2"

# Check if aware is installed
if ! command -v aware &> /dev/null; then
    if ! command -v python &> /dev/null; then
        echo "❌ Python não encontrado no PATH"
        exit 1
    fi
    
    # Try to run via python if aware command not found
    if [ -f "cli.py" ]; then
        AWARE_CMD="python cli.py"
    else
        echo "❌ AWARE não encontrado (nem comando 'aware' nem 'cli.py')"
        exit 1
    fi
else
    AWARE_CMD="aware"
fi

# Read stdin to get refs being pushed
while read local_ref local_sha remote_ref remote_sha
do
    if [ "$local_sha" = "0000000000000000000000000000000000000000" ]; then
        # Branch deletion, skip
        continue
    fi
    
    if [ "$remote_sha" = "0000000000000000000000000000000000000000" ]; then
        # New branch, compare with main/master
        if git rev-parse --verify origin/main &> /dev/null; then
            base="origin/main"
        elif git rev-parse --verify origin/master &> /dev/null; then
            base="origin/master"
        else
            echo "⚠️  Não foi possível determinar branch base, pulando scan"
            continue
        fi
    else
        base="$remote_sha"
    fi
    
    # Run AWARE scan on diff
    $AWARE_CMD scan --diff "$base...HEAD"
    exit_code=$?
    
    if [ $exit_code -eq 20 ]; then
        echo ""
        echo "❌ Push bloqueado por findings críticos"
        exit 1
    elif [ $exit_code -eq 10 ]; then
        echo ""
        echo "⚠️  Push permitido com warnings"
    fi
done

exit 0
"""

HOOK_TEMPLATES = {
    "pre-commit": PRE_COMMIT_TEMPLATE,
    "pre-push": PRE_PUSH_TEMPLATE,
}


# =============================================================================
# Hook Installer Class
# =============================================================================

class HookInstaller:
    """Gerencia instalação e remoção de git hooks."""
    
    def __init__(self, repo_path: Path):
        """
        Inicializa o instalador.
        
        Args:
            repo_path: Caminho para o repositório git
        """
        self.repo_path = Path(repo_path)
        self.hooks_dir = self._find_hooks_dir()
        
        if not self.hooks_dir:
            raise HookInstallerError(
                f"Não é um repositório git: {repo_path}\n"
                "Execute 'git init' primeiro."
            )
    
    def _find_hooks_dir(self) -> Optional[Path]:
        """Encontra diretório .git/hooks (suporta worktrees)."""
        # Try standard .git/hooks
        git_dir = self.repo_path / ".git"
        
        if git_dir.is_dir():
            hooks_dir = git_dir / "hooks"
            if hooks_dir.exists() or git_dir.exists():
                hooks_dir.mkdir(exist_ok=True)
                return hooks_dir
        
        # Try worktree (git file pointing to real git dir)
        if git_dir.is_file():
            try:
                git_content = git_dir.read_text().strip()
                if git_content.startswith("gitdir:"):
                    real_git_dir = Path(git_content.split(":", 1)[1].strip())
                    if not real_git_dir.is_absolute():
                        real_git_dir = self.repo_path / real_git_dir
                    hooks_dir = real_git_dir / "hooks"
                    hooks_dir.mkdir(exist_ok=True)
                    return hooks_dir
            except Exception:
                pass
        
        return None
    
    def install_hook(self, hook_name: str, template: str, force: bool = False) -> Dict[str, Any]:
        """
        Instala um hook específico.
        
        Args:
            hook_name: Nome do hook (pre-commit, pre-push)
            template: Template bash do hook
            force: Se True, sobrescreve hook existente
        
        Returns:
            Dict com resultado da instalação
        """
        hook_path = self.hooks_dir / hook_name
        
        # Check if hook already exists
        if hook_path.exists() and not force:
            # Check if it's an AWARE hook
            try:
                content = hook_path.read_text()
                if "AWARE" in content and "Auto-generated" in content:
                    return {
                        "success": True,
                        "message": "Hook AWARE já instalado",
                        "action": "skipped"
                    }
                else:
                    # Backup existing hook
                    backup_path = self._create_backup(hook_path)
                    return {
                        "success": False,
                        "message": f"Hook existente (backup: {backup_path.name})",
                        "action": "backed_up",
                        "backup": str(backup_path)
                    }
            except Exception as e:
                return {
                    "success": False,
                    "message": f"Erro ao ler hook existente: {e}",
                    "action": "error"
                }
        
        # Backup if forcing over existing hook
        if hook_path.exists() and force:
            try:
                content = hook_path.read_text()
                if "AWARE" not in content:  # Only backup non-AWARE hooks
                    self._create_backup(hook_path)
            except Exception:
                pass
        
        # Write hook
        try:
            hook_path.write_text(template)
            hook_path.chmod(0o755)  # Make executable
            
            return {
                "success": True,
                "message": "Hook instalado com sucesso",
                "action": "installed"
            }
        
        except Exception as e:
            return {
                "success": False,
                "message": f"Erro ao instalar hook: {e}",
                "action": "error"
            }
    
    def _create_backup(self, hook_path: Path) -> Path:
        """Cria backup de um hook existente."""
        backup_num = 1
        while True:
            backup_path = hook_path.parent / f"{hook_path.name}.aware-backup.{backup_num}"
            if not backup_path.exists():
                shutil.copy2(hook_path, backup_path)
                return backup_path
            backup_num += 1
    
    def uninstall_hook(self, hook_name: str, restore_backup: bool = True) -> Dict[str, Any]:
        """
        Remove um hook AWARE.
        
        Args:
            hook_name: Nome do hook
            restore_backup: Se True, restaura backup mais recente
        
        Returns:
            Dict com resultado
        """
        hook_path = self.hooks_dir / hook_name
        
        if not hook_path.exists():
            return {
                "success": False,
                "message": "Hook não instalado",
                "action": "not_found"
            }
        
        # Check if it's an AWARE hook
        try:
            content = hook_path.read_text()
            if "AWARE" not in content or "Auto-generated" not in content:
                return {
                    "success": False,
                    "message": "Hook não é do AWARE (não removido)",
                    "action": "not_aware"
                }
        except Exception as e:
            return {
                "success": False,
                "message": f"Erro ao ler hook: {e}",
                "action": "error"
            }
        
        # Remove hook
        try:
            hook_path.unlink()
            
            # Restore backup if requested
            if restore_backup:
                backup = self._find_latest_backup(hook_name)
                if backup:
                    shutil.copy2(backup, hook_path)
                    backup.unlink()
                    return {
                        "success": True,
                        "message": "Hook removido e backup restaurado",
                        "action": "restored",
                        "restored": True
                    }
            
            return {
                "success": True,
                "message": "Hook removido",
                "action": "removed",
                "restored": False
            }
        
        except Exception as e:
            return {
                "success": False,
                "message": f"Erro ao remover hook: {e}",
                "action": "error"
            }
    
    def _find_latest_backup(self, hook_name: str) -> Optional[Path]:
        """Encontra o backup mais recente de um hook."""
        backups = list(self.hooks_dir.glob(f"{hook_name}.aware-backup.*"))
        if not backups:
            return None
        
        # Sort by number (last part of filename)
        backups.sort(key=lambda p: int(p.name.split(".")[-1]))
        return backups[-1]
    
    def install_all(self, force: bool = False) -> Dict[str, Dict[str, Any]]:
        """Instala todos os hooks disponíveis."""
        results = {}
        for hook_name, template in HOOK_TEMPLATES.items():
            results[hook_name] = self.install_hook(hook_name, template, force)
        return results
    
    def list_installed_hooks(self) -> List[str]:
        """Lista hooks AWARE instalados."""
        installed = []
        for hook_name in HOOK_TEMPLATES.keys():
            hook_path = self.hooks_dir / hook_name
            if hook_path.exists():
                try:
                    content = hook_path.read_text()
                    if "AWARE" in content and "Auto-generated" in content:
                        installed.append(hook_name)
                except Exception:
                    pass
        return installed
    
    def status(self) -> Dict[str, Any]:
        """Retorna status detalhado dos hooks."""
        status = {
            "repo_path": str(self.repo_path),
            "hooks_dir": str(self.hooks_dir),
            "hooks": {}
        }
        
        for hook_name in HOOK_TEMPLATES.keys():
            hook_path = self.hooks_dir / hook_name
            
            if not hook_path.exists():
                status["hooks"][hook_name] = {
                    "installed": False,
                    "is_aware": False,
                    "has_backup": self._find_latest_backup(hook_name) is not None
                }
            else:
                try:
                    content = hook_path.read_text()
                    is_aware = "AWARE" in content and "Auto-generated" in content
                    status["hooks"][hook_name] = {
                        "installed": True,
                        "is_aware": is_aware,
                        "executable": hook_path.stat().st_mode & 0o111 != 0,
                        "has_backup": self._find_latest_backup(hook_name) is not None
                    }
                except Exception as e:
                    status["hooks"][hook_name] = {
                        "installed": True,
                        "is_aware": False,
                        "error": str(e)
                    }
        
        return status


# =============================================================================
# Helper Functions
# =============================================================================

def install_hooks(
    repo_path: Path,
    force: bool = False,
    hooks: Optional[List[str]] = None
) -> Dict[str, Dict[str, Any]]:
    """
    Instala hooks no repositório.
    
    Args:
        repo_path: Caminho do repositório
        force: Sobrescrever hooks existentes
        hooks: Lista de hooks específicos (None = todos)
    
    Returns:
        Dict com resultados
    """
    installer = HookInstaller(repo_path)
    
    if hooks:
        results = {}
        for hook_name in hooks:
            if hook_name not in HOOK_TEMPLATES:
                results[hook_name] = {
                    "success": False,
                    "message": f"Hook desconhecido: {hook_name}",
                    "action": "error"
                }
            else:
                results[hook_name] = installer.install_hook(
                    hook_name,
                    HOOK_TEMPLATES[hook_name],
                    force
                )
        return results
    else:
        return installer.install_all(force)


def uninstall_hooks(
    repo_path: Path,
    restore_backups: bool = True
) -> Dict[str, Dict[str, Any]]:
    """Remove hooks AWARE do repositório."""
    installer = HookInstaller(repo_path)
    results = {}
    
    for hook_name in HOOK_TEMPLATES.keys():
        results[hook_name] = installer.uninstall_hook(hook_name, restore_backups)
    
    return results


def check_hooks_status(repo_path: Path) -> Dict[str, Any]:
    """Verifica status dos hooks."""
    installer = HookInstaller(repo_path)
    return installer.status()


def print_install_summary(results: Dict[str, Dict[str, Any]]):
    """Printa resumo da instalação (helper para CLI)."""
    from rich.console import Console
    from rich.table import Table
    
    console = Console()
    table = Table(title="Instalação de Hooks")
    
    table.add_column("Hook", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Mensagem")
    
    for hook_name, result in results.items():
        status = "✅" if result["success"] else "❌"
        table.add_row(hook_name, status, result["message"])
    
    console.print(table)


def print_status(status: Dict[str, Any]):
    """Printa status dos hooks (helper para CLI)."""
    from rich.console import Console
    from rich.table import Table
    
    console = Console()
    
    console.print(f"\n📁 Repositório: {status['repo_path']}")
    console.print(f"📂 Hooks dir: {status['hooks_dir']}\n")
    
    table = Table(title="Status dos Hooks")
    table.add_column("Hook", style="cyan")
    table.add_column("Instalado", style="yellow")
    table.add_column("AWARE", style="green")
    table.add_column("Executável", style="magenta")
    table.add_column("Backup", style="blue")
    
    for hook_name, hook_status in status["hooks"].items():
        installed = "✅" if hook_status.get("installed") else "❌"
        is_aware = "✅" if hook_status.get("is_aware") else "❌"
        executable = "✅" if hook_status.get("executable") else "❌"
        has_backup = "✅" if hook_status.get("has_backup") else "❌"
        
        table.add_row(hook_name, installed, is_aware, executable, has_backup)
    
    console.print(table)
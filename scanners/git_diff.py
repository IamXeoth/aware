"""
AWARE - Git Diff Scanner
Extrai informações de diff do Git para análise.
"""

import subprocess
import re
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set
from enum import Enum


# =============================================================================
# Exceções
# =============================================================================

class GitError(Exception):
    """Erro ao executar comando git."""
    pass


class NotGitRepositoryError(GitError):
    """Diretório não é um repositório git."""
    pass


# =============================================================================
# Enums
# =============================================================================

class FileStatus(str, Enum):
    """Status de arquivo no git."""
    ADDED = "A"
    MODIFIED = "M"
    DELETED = "D"
    RENAMED = "R"
    COPIED = "C"
    UNMERGED = "U"


# =============================================================================
# Data Classes
# =============================================================================

class GitFile:
    """Representa um arquivo no git diff."""
    
    def __init__(self, path: str, status: FileStatus, old_path: Optional[str] = None):
        self.path = path
        self.status = status
        self.old_path = old_path  # Para renamed files
    
    def __repr__(self):
        if self.old_path:
            return f"GitFile('{self.old_path}' → '{self.path}', {self.status.value})"
        return f"GitFile('{self.path}', {self.status.value})"


# =============================================================================
# Git Diff Scanner
# =============================================================================

class GitDiffScanner:
    """
    Scanner de diffs do Git.
    
    Responsabilidades:
    - Executar comandos git
    - Parsear output de git diff
    - Extrair apenas linhas adicionadas (+)
    - Listar arquivos staged/modificados
    """
    
    def __init__(self, repo_path: Optional[Path] = None):
        """
        Args:
            repo_path: Caminho do repositório git (default: diretório atual)
        """
        self.repo_path = repo_path or Path.cwd()
        
        # Valida que é um repo git
        if not self._is_git_repository():
            raise NotGitRepositoryError(
                f"Diretório não é um repositório git: {self.repo_path}"
            )
    
    def get_staged_files(self) -> List[GitFile]:
        """
        Lista arquivos staged (preparados para commit).
        
        Returns:
            Lista de GitFile com arquivos staged
        """
        cmd = ['git', 'diff', '--cached', '--name-status']
        output = self._run_git_command(cmd)
        
        return self._parse_name_status(output)
    
    def get_staged_diff(self) -> Dict[str, List[str]]:
        """
        Obtém diff dos arquivos staged (apenas linhas adicionadas).
        
        Returns:
            Dict {filepath: [linha1, linha2, ...]} com apenas linhas adicionadas (+)
        """
        cmd = ['git', 'diff', '--cached', '--unified=0']
        output = self._run_git_command(cmd)
        
        return self._parse_diff_added_lines(output)
    
    def get_diff_between(self, base: str, head: str) -> Dict[str, List[str]]:
        """
        Obtém diff entre duas referências (branches, commits, tags).
        
        Args:
            base: Ref base (ex: 'origin/main', 'HEAD~1')
            head: Ref head (ex: 'HEAD', 'feature-branch')
        
        Returns:
            Dict {filepath: [linha1, linha2, ...]} com apenas linhas adicionadas
        """
        cmd = ['git', 'diff', '--unified=0', f'{base}...{head}']
        output = self._run_git_command(cmd)
        
        return self._parse_diff_added_lines(output)
    
    def get_files_between(self, base: str, head: str) -> List[GitFile]:
        """
        Lista arquivos modificados entre duas referências.
        
        Args:
            base: Ref base
            head: Ref head
        
        Returns:
            Lista de GitFile
        """
        cmd = ['git', 'diff', '--name-status', f'{base}...{head}']
        output = self._run_git_command(cmd)
        
        return self._parse_name_status(output)
    
    def get_unstaged_diff(self) -> Dict[str, List[str]]:
        """
        Obtém diff de mudanças não staged (working directory).
        
        Returns:
            Dict {filepath: [linha1, linha2, ...]}
        """
        cmd = ['git', 'diff', '--unified=0']
        output = self._run_git_command(cmd)
        
        return self._parse_diff_added_lines(output)
    
    def is_file_staged(self, filepath: str) -> bool:
        """
        Verifica se um arquivo está staged.
        
        Args:
            filepath: Path do arquivo
            
        Returns:
            True se arquivo está staged
        """
        staged_files = self.get_staged_files()
        staged_paths = {f.path for f in staged_files}
        
        return filepath in staged_paths
    
    def get_remote_branch(self, local_branch: Optional[str] = None) -> Optional[str]:
        """
        Obtém o branch remoto correspondente ao branch local.
        
        Args:
            local_branch: Nome do branch local (default: branch atual)
            
        Returns:
            Nome do remote branch (ex: 'origin/main') ou None se não encontrado
        """
        if not local_branch:
            local_branch = self._get_current_branch()
        
        # Tenta pegar upstream tracking branch
        cmd = ['git', 'rev-parse', '--abbrev-ref', '--symbolic-full-name', f'{local_branch}@{{upstream}}']
        
        try:
            output = self._run_git_command(cmd, check=False)
            if output and not output.startswith('fatal:'):
                return output.strip()
        except GitError:
            pass
        
        # Fallback: tenta origin/<branch>
        return f'origin/{local_branch}'
    
    # =========================================================================
    # Helpers Privados
    # =========================================================================
    
    def _is_git_repository(self) -> bool:
        """Verifica se o diretório é um repositório git."""
        try:
            cmd = ['git', 'rev-parse', '--git-dir']
            self._run_git_command(cmd, check=False)
            return True
        except GitError:
            return False
    
    def _get_current_branch(self) -> str:
        """Obtém nome do branch atual."""
        cmd = ['git', 'rev-parse', '--abbrev-ref', 'HEAD']
        output = self._run_git_command(cmd)
        return output.strip()
    
    def _run_git_command(self, cmd: List[str], check: bool = True) -> str:
        """
        Executa comando git e retorna output.
        
        Args:
            cmd: Lista com comando e argumentos
            check: Se True, levanta exceção em caso de erro
            
        Returns:
            Output do comando (stdout)
            
        Raises:
            GitError: Se comando falhar e check=True
        """
        try:
            result = subprocess.run(
                cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=False,
            )
            
            if check and result.returncode != 0:
                raise GitError(
                    f"Comando git falhou: {' '.join(cmd)}\n"
                    f"Stderr: {result.stderr}"
                )
            
            return result.stdout
            
        except FileNotFoundError:
            raise GitError("Git não encontrado no PATH")
        except Exception as e:
            raise GitError(f"Erro ao executar git: {e}")
    
    def _parse_name_status(self, output: str) -> List[GitFile]:
        """
        Parseia output de 'git diff --name-status'.
        
        Formato:
        A       novo_arquivo.py
        M       arquivo_modificado.py
        D       arquivo_deletado.py
        R100    old_name.py    new_name.py
        
        Args:
            output: Output do git diff --name-status
            
        Returns:
            Lista de GitFile
        """
        files = []
        
        for line in output.strip().split('\n'):
            if not line:
                continue
            
            parts = line.split('\t')
            if len(parts) < 2:
                continue
            
            status_code = parts[0]
            
            # Parse status (pode ter similarity score: R100, C75, etc)
            status_char = status_code[0]
            
            try:
                status = FileStatus(status_char)
            except ValueError:
                # Status desconhecido, pula
                continue
            
            # Renamed/Copied tem dois paths
            if status in [FileStatus.RENAMED, FileStatus.COPIED]:
                if len(parts) >= 3:
                    old_path = parts[1]
                    new_path = parts[2]
                    files.append(GitFile(new_path, status, old_path))
            else:
                filepath = parts[1]
                files.append(GitFile(filepath, status))
        
        return files
    
    def _parse_diff_added_lines(self, diff_output: str) -> Dict[str, List[str]]:
        """
        Parseia output de 'git diff' e extrai apenas linhas adicionadas (+).
        
        Args:
            diff_output: Output completo do git diff
            
        Returns:
            Dict {filepath: [linha1, linha2, ...]} com linhas adicionadas
        """
        result: Dict[str, List[str]] = {}
        current_file: Optional[str] = None
        
        for line in diff_output.split('\n'):
            # Detecta início de arquivo novo
            # Formato: diff --git a/path b/path
            if line.startswith('diff --git '):
                # Extrai path do arquivo
                match = re.search(r'b/(.+)$', line)
                if match:
                    current_file = match.group(1)
                    result[current_file] = []
            
            # Linhas adicionadas começam com +
            # Ignora +++ (header de arquivo)
            elif line.startswith('+') and not line.startswith('+++'):
                if current_file:
                    # Remove o + do início
                    clean_line = line[1:]
                    result[current_file].append(clean_line)
        
        # Remove arquivos sem linhas adicionadas
        result = {k: v for k, v in result.items() if v}
        
        return result


# =============================================================================
# Helper Functions
# =============================================================================

def get_staged_files(repo_path: Optional[Path] = None) -> List[str]:
    """
    Helper function para obter lista de arquivos staged.
    
    Args:
        repo_path: Caminho do repositório (default: diretório atual)
        
    Returns:
        Lista de paths de arquivos staged
    """
    scanner = GitDiffScanner(repo_path)
    git_files = scanner.get_staged_files()
    return [f.path for f in git_files]


def get_staged_diff(repo_path: Optional[Path] = None) -> Dict[str, List[str]]:
    """
    Helper function para obter diff staged.
    
    Args:
        repo_path: Caminho do repositório
        
    Returns:
        Dict {filepath: [linhas adicionadas]}
    """
    scanner = GitDiffScanner(repo_path)
    return scanner.get_staged_diff()


def get_diff_for_push(repo_path: Optional[Path] = None) -> Dict[str, List[str]]:
    """
    Obtém diff que seria enviado em um push.
    Compara branch local com remote tracking branch.
    
    Args:
        repo_path: Caminho do repositório
        
    Returns:
        Dict {filepath: [linhas adicionadas]}
    """
    scanner = GitDiffScanner(repo_path)
    
    # Obtém remote branch
    remote = scanner.get_remote_branch()
    
    if not remote:
        # Fallback: compara com HEAD (sem diff)
        return {}
    
    # Diff entre remote e HEAD
    return scanner.get_diff_between(remote, 'HEAD')


def has_staged_changes(repo_path: Optional[Path] = None) -> bool:
    """
    Verifica se há mudanças staged.
    
    Args:
        repo_path: Caminho do repositório
        
    Returns:
        True se há arquivos staged
    """
    scanner = GitDiffScanner(repo_path)
    staged = scanner.get_staged_files()
    return len(staged) > 0


def get_added_files_only(repo_path: Optional[Path] = None) -> List[str]:
    """
    Obtém apenas arquivos novos (status A) que estão staged.
    
    Args:
        repo_path: Caminho do repositório
        
    Returns:
        Lista de paths de arquivos novos
    """
    scanner = GitDiffScanner(repo_path)
    git_files = scanner.get_staged_files()
    return [f.path for f in git_files if f.status == FileStatus.ADDED]


# =============================================================================
# Statistics Helper
# =============================================================================

def get_diff_stats(diff_by_file: Dict[str, List[str]]) -> Dict[str, int]:
    """
    Calcula estatísticas de um diff.
    
    Args:
        diff_by_file: Dict {filepath: [linhas]}
        
    Returns:
        Dict com estatísticas:
        {
            'files_changed': int,
            'total_lines_added': int,
            'avg_lines_per_file': float,
        }
    """
    files_changed = len(diff_by_file)
    total_lines = sum(len(lines) for lines in diff_by_file.values())
    avg_lines = total_lines / files_changed if files_changed > 0 else 0
    
    return {
        'files_changed': files_changed,
        'total_lines_added': total_lines,
        'avg_lines_per_file': round(avg_lines, 2),
    }


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    # Classes
    'GitDiffScanner',
    'GitFile',
    'FileStatus',
    
    # Exceptions
    'GitError',
    'NotGitRepositoryError',
    
    # Helper functions
    'get_staged_files',
    'get_staged_diff',
    'get_diff_for_push',
    'has_staged_changes',
    'get_added_files_only',
    'get_diff_stats',
]
"""
AWARE - Shell Wrapper
Intercepta e analisa comandos shell antes da execução.
"""

import sys
import os
import subprocess
import shlex
from typing import List, Optional, Tuple
from pathlib import Path

from ..core.rules_loader import load_default_rules, RulesLoadError
from ..core.engine import AwareEngine
from ..core.models import Action, Finding, ScanResult, AwareConfig, ConfirmMode


# =============================================================================
# Exceções
# =============================================================================

class ShellWrapError(Exception):
    """Erro no wrapper de shell."""
    pass


# =============================================================================
# Confirmation Handler
# =============================================================================

class ConfirmationHandler:
    """
    Gerencia confirmações do usuário.
    Implementa os modos: yesno e token.
    """
    
    @staticmethod
    def confirm_yesno(finding: Finding) -> bool:
        """
        Confirmação simples y/N.
        
        Args:
            finding: Finding que requer confirmação
            
        Returns:
            True se usuário confirmou, False caso contrário
        """
        print()
        print("─" * 70)
        ConfirmationHandler._print_finding_details(finding)
        print("─" * 70)
        print()
        
        response = input("Confirmar execução? (y/N): ").strip().lower()
        
        return response in ['y', 'yes']
    
    @staticmethod
    def confirm_token(finding: Finding, token: str) -> bool:
        """
        Confirmação com token específico.
        
        Args:
            finding: Finding que requer confirmação
            token: Token que o usuário deve digitar
            
        Returns:
            True se usuário digitou o token corretamente
        """
        print()
        print("─" * 70)
        ConfirmationHandler._print_finding_details(finding)
        print("─" * 70)
        print()
        
        # Primeira barreira: y/N
        response = input("Confirmar execução? (y/N): ").strip().lower()
        
        if response not in ['y', 'yes']:
            return False
        
        # Segunda barreira: token
        print()
        token_response = input(f"Digite '{token}' para confirmar: ").strip()
        
        return token_response == token
    
    @staticmethod
    def _print_finding_details(finding: Finding):
        """Imprime detalhes do finding de forma clara."""
        
        # Ícone por severidade
        severity_icons = {
            'critical': '🚨',
            'high': '⚠️',
            'medium': '⚡',
            'low': 'ℹ️',
        }
        icon = severity_icons.get(finding.severity.value, '•')
        
        # Header
        print(f"\n{icon} {finding.severity.value.upper()}: {finding.title}")
        print()
        
        # Comando/evidência
        print(f"📍 Comando:")
        print(f"   {finding.evidence}")
        print()
        
        # Impacto
        print(f"💥 Impacto:")
        for line in finding.impact.split('\n'):
            print(f"   {line}")
        print()
        
        # Recomendação
        print(f"💡 Recomendação:")
        for line in finding.recommendation.split('\n'):
            print(f"   {line}")
    
    @staticmethod
    def handle_confirmation(finding: Finding) -> bool:
        """
        Gerencia confirmação baseado no finding.
        
        Args:
            finding: Finding com configuração de confirmação
            
        Returns:
            True se confirmado, False caso contrário
        """
        # Busca regra original para pegar confirm config
        # (Em produção, isso viria do RulesPack)
        # Por enquanto, infere do finding
        
        # Se não tem confirm config na regra, assume token "RISK"
        # (isso será melhorado quando integrarmos com RulesPack)
        
        # Por enquanto, usa heurística baseada no rule_id
        token_map = {
            'SHELL_RM_RF_DANGEROUS_PATH': 'RM',
            'SHELL_GIT_FORCE_PUSH': 'PUSH',
            'SHELL_GIT_RESET_HARD': 'RESET',
            'SHELL_DROP_DATABASE': 'DROP',
            'SEC_API_KEY_HARDCODED': 'KEY',
            'SEC_DATABASE_URL_WITH_PASSWORD': 'DB',
            'SEC_CORS_CREDENTIALS_WITH_WILDCARD': 'CORS',
            'SEC_HARDCODED_PASSWORD': 'PASS',
        }
        
        # Regras que usam apenas yesno
        yesno_rules = {
            'SHELL_CURL_INSECURE',
            'SHELL_DOCKER_PRUNE_ALL',
        }
        
        # Determina modo
        if finding.rule_id in yesno_rules:
            return ConfirmationHandler.confirm_yesno(finding)
        elif finding.rule_id in token_map:
            token = token_map[finding.rule_id]
            return ConfirmationHandler.confirm_token(finding, token)
        else:
            # Default: token "RISK"
            return ConfirmationHandler.confirm_token(finding, "RISK")


# =============================================================================
# Shell Wrapper
# =============================================================================

class ShellWrapper:
    """
    Wrapper principal que intercepta comandos shell.
    
    Responsabilidades:
    - Receber comando original
    - Escanear com engine
    - Apresentar findings
    - Gerenciar confirmações
    - Executar ou abortar comando
    """
    
    def __init__(
        self,
        config: Optional[AwareConfig] = None,
        rules_file: Optional[Path] = None
    ):
        """
        Args:
            config: Configuração do AWARE
            rules_file: Arquivo de regras customizado (opcional)
        """
        self.config = config or AwareConfig()
        
        # Carrega regras
        try:
            if rules_file:
                from ..core.rules_loader import load_rules
                self.rules_pack = load_rules(rules_file)
            else:
                self.rules_pack = load_default_rules()
        except RulesLoadError as e:
            raise ShellWrapError(f"Erro ao carregar regras: {e}")
        
        # Cria engine
        self.engine = AwareEngine(self.rules_pack, self.config)
    
    def wrap_command(self, args: List[str]) -> int:
        """
        Intercepta e analisa comando antes de executar.
        
        Args:
            args: Lista de argumentos do comando (ex: ['rm', '-rf', '/'])
            
        Returns:
            Exit code:
            - 0: Comando executado com sucesso
            - 10: Findings (warn) mas executado
            - 20: Bloqueado ou não confirmado
            - N: Exit code do comando executado
        """
        # Reconstrói comando original
        command = ' '.join(shlex.quote(arg) for arg in args)
        
        # Scan
        result = self.engine.scan_shell_command(command)
        
        # Se não há findings, executa direto
        if not result.findings:
            return self._execute_command(args)
        
        # Processa findings
        return self._handle_findings(result, args, command)
    
    def _handle_findings(
        self,
        result: ScanResult,
        args: List[str],
        command: str
    ) -> int:
        """
        Processa findings e decide se executa comando.
        
        Args:
            result: Resultado do scan
            args: Args do comando original
            command: Comando como string
            
        Returns:
            Exit code apropriado
        """
        # Separa findings por ação
        blocked = [f for f in result.findings if f.action == Action.BLOCK]
        require_confirm = [f for f in result.findings if f.action == Action.REQUIRE_CONFIRM]
        warnings = [f for f in result.findings if f.action == Action.WARN]
        
        # BLOCK: sem opção, aborta
        if blocked:
            print()
            print("🛑 COMANDO BLOQUEADO")
            print()
            
            for finding in blocked:
                ConfirmationHandler._print_finding_details(finding)
                print("─" * 70)
            
            print()
            print("❌ Comando não será executado.")
            print()
            return 20
        
        # REQUIRE_CONFIRM: pede confirmação
        if require_confirm:
            # Pega primeiro finding que requer confirmação
            finding = require_confirm[0]
            
            confirmed = ConfirmationHandler.handle_confirmation(finding)
            
            if not confirmed:
                print()
                print("❌ Comando abortado pelo usuário.")
                print()
                return 20
            
            # Confirmado: executa
            print()
            print("✅ Confirmado. Executando comando...")
            print()
            return self._execute_command(args)
        
        # WARN: só avisa e executa
        if warnings:
            print()
            print("⚠️  AVISOS DETECTADOS:")
            print()
            
            for finding in warnings:
                print(f"• {finding.title}")
                print(f"  💡 {finding.recommendation}")
                print()
            
            print("▶️  Executando comando...")
            print()
            return self._execute_command(args)
        
        # Sem findings que impeçam: executa
        return self._execute_command(args)
    
    def _execute_command(self, args: List[str]) -> int:
        """
        Executa comando original e retorna exit code.
        
        Args:
            args: Lista de argumentos do comando
            
        Returns:
            Exit code do comando executado
        """
        try:
            result = subprocess.run(args, check=False)
            return result.returncode
        except FileNotFoundError:
            print(f"❌ Comando não encontrado: {args[0]}", file=sys.stderr)
            return 127
        except Exception as e:
            print(f"❌ Erro ao executar comando: {e}", file=sys.stderr)
            return 1


# =============================================================================
# CLI Entry Point
# =============================================================================

def main(argv: Optional[List[str]] = None) -> int:
    """
    Entry point para `aware wrap <comando>`.
    
    Args:
        argv: Lista de argumentos (default: sys.argv)
        
    Returns:
        Exit code
    """
    if argv is None:
        argv = sys.argv[1:]  # Remove 'aware wrap'
    
    # Valida argumentos
    if not argv:
        print("Uso: aware wrap <comando> [args...]", file=sys.stderr)
        print()
        print("Exemplos:")
        print("  aware wrap rm -rf /tmp/cache")
        print("  aware wrap git push --force")
        print("  aware wrap curl -k https://api.internal")
        return 1
    
    # Cria wrapper
    try:
        wrapper = ShellWrapper()
    except ShellWrapError as e:
        print(f"❌ Erro: {e}", file=sys.stderr)
        return 1
    
    # Executa
    return wrapper.wrap_command(argv)


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    'ShellWrapper',
    'ConfirmationHandler',
    'ShellWrapError',
    'main',
]
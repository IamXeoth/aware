"""
AWARE - Command Line Interface
Entry point principal para todos os comandos do AWARE.

Author: Vinícius Lisboa <contato@viniciuslisboa.com.br>
GitHub: @IamXeoth
"""

import sys
from pathlib import Path

# ============================================================================
# CRITICAL: Add parent directory to Python path
# ============================================================================
# This allows 'import aware' to work when running cli.py directly
_CLI_DIR = Path(__file__).parent
_PROJECT_ROOT = _CLI_DIR.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))
# ============================================================================

from typing import Optional, List

import typer
from rich.console import Console
from rich.table import Table

from aware.core.rules_loader import (
    load_default_rules,
    load_rules,
    validate_rules_file,
    RulesLoadError,
)
from aware.core.engine import AwareEngine
from aware.core.models import AwareConfig
from aware.core.formatters import FormatterFactory
from aware.scanners.git_diff import (
    GitDiffScanner,
    get_staged_files,
    get_staged_diff,
    get_diff_for_push,
    NotGitRepositoryError,
)
from aware.hooks.install import (
    install_hooks,
    uninstall_hooks,
    check_hooks_status,
    print_install_summary,
    print_status,
)
from aware.wrappers.shell_wrap import main as wrap_main


# =============================================================================
# Typer App Setup
# =============================================================================

app = typer.Typer(
    name="aware",
    help="🧠 AWARE - Cognitive Awareness for Developers",
    add_completion=True,
    rich_markup_mode="rich",
)

console = Console()


# =============================================================================
# Global Options
# =============================================================================

def version_callback(value: bool):
    """Callback para --version."""
    if value:
        console.print("🧠 AWARE version 1.0.0", style="bold cyan")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Mostra versão do AWARE"
    )
):
    """
    🧠 AWARE - Cognitive Awareness for Developers
    
    Ferramenta que intercepta decisões perigosas no desenvolvimento.
    """
    pass


# =============================================================================
# Command: scan
# =============================================================================

@app.command()
def scan(
    staged: bool = typer.Option(
        False,
        "--staged",
        help="Scanneia arquivos staged (pre-commit)"
    ),
    diff: Optional[str] = typer.Option(
        None,
        "--diff",
        help="Scanneia diff entre refs (ex: origin/main...HEAD)"
    ),
    rules_file: Optional[Path] = typer.Option(
        None,
        "--rules",
        help="Caminho para arquivo de regras customizado"
    ),
    format: str = typer.Option(
        "console",
        "--format",
        "-f",
        help="Formato de output: console, compact, json, sarif, github"
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Salvar output em arquivo"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Modo verbose (mostra impact + recommendation)"
    ),
):
    """
    🔍 Scanneia código em busca de decisões perigosas
    
    Exemplos:
    
    \b
    # Pre-commit (arquivos staged)
    aware scan --staged
    
    \b
    # Pre-push (diff com main)
    aware scan --diff origin/main...HEAD
    
    \b
    # Output JSON
    aware scan --staged --format json --output result.json
    """
    
    try:
        # Load rules
        if rules_file:
            rules_pack = load_rules(str(rules_file))
        else:
            rules_pack = load_default_rules()
        
        # Initialize engine
        engine = AwareEngine(rules_pack)
        
        # Determine scan type
        if staged:
            scan_type = "STAGED"
            staged_files = get_staged_files()
            diff_by_file = get_staged_diff()
            result = engine.scan_git_staged(staged_files, diff_by_file)
        
        elif diff:
            scan_type = f"DIFF ({diff})"
            # Parse diff refs
            if "..." in diff:
                base, head = diff.split("...")
            elif ".." in diff:
                base, head = diff.split("..")
            else:
                console.print(f"❌ Formato de diff inválido: {diff}", style="red")
                console.print("   Use: origin/main...HEAD ou base..head")
                raise typer.Exit(1)
            
            scanner = GitDiffScanner()
            diff_by_file = scanner.get_diff_between(base, head)
            result = engine.scan_diff(diff_by_file)
        
        else:
            console.print("❌ Especifique --staged ou --diff", style="red")
            raise typer.Exit(1)
        
        # Format output
        formatter = FormatterFactory.create(
            format_type=format,
            use_colors=(output is None),  # Colors only for console
            verbose=verbose,
            pretty=(format == "json")
        )
        
        formatted = formatter.format(result)
        
        # Output
        if output:
            output.write_text(formatted)
            console.print(f"✅ Output salvo em: {output}", style="green")
        else:
            console.print(formatted)
        
        # Exit with appropriate code
        sys.exit(result.exit_code)
    
    except NotGitRepositoryError:
        console.print("❌ Não é um repositório Git", style="red")
        raise typer.Exit(1)
    
    except RulesLoadError as e:
        console.print(f"❌ Erro ao carregar regras: {e}", style="red")
        raise typer.Exit(1)
    
    except Exception as e:
        console.print(f"❌ Erro interno: {e}", style="red")
        raise typer.Exit(30)


# =============================================================================
# Command: wrap
# =============================================================================

@app.command()
def wrap(
    command: List[str] = typer.Argument(
        ...,
        help="Comando a ser interceptado e analisado"
    ),
):
    """
    🛡️ Intercepta e analisa comando antes de executar
    
    Exemplos:
    
    \b
    # Comando perigoso (requer confirmação)
    aware wrap rm -rf /
    
    \b
    # Git force push (requer token)
    aware wrap git push --force
    
    \b
    # Curl insecure
    aware wrap curl -k https://api.internal
    """
    
    # Delegate to shell_wrap main
    sys.argv = ["aware-wrap"] + command
    sys.exit(wrap_main())


# =============================================================================
# Command: install
# =============================================================================

@app.command()
def install(
    hook: Optional[str] = typer.Option(
        None,
        "--hook",
        help="Instalar hook específico: pre-commit, pre-push"
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Sobrescrever hooks existentes"
    ),
):
    """
    🪝 Instala git hooks
    
    Exemplos:
    
    \b
    # Instalar todos os hooks
    aware install
    
    \b
    # Instalar apenas pre-commit
    aware install --hook pre-commit
    
    \b
    # Forçar sobrescrita
    aware install --force
    """
    
    try:
        hooks_to_install = [hook] if hook else None
        results = install_hooks(
            repo_path=Path.cwd(),
            force=force,
            hooks=hooks_to_install
        )
        
        print_install_summary(results)
        
        # Exit code
        if all(r.get("success") for r in results.values()):
            sys.exit(0)
        else:
            sys.exit(1)
    
    except Exception as e:
        console.print(f"❌ {e}", style="red")
        raise typer.Exit(1)


# =============================================================================
# Command: uninstall
# =============================================================================

@app.command()
def uninstall(
    no_restore: bool = typer.Option(
        False,
        "--no-restore",
        help="Não restaurar backups de hooks anteriores"
    ),
):
    """
    🗑️ Remove git hooks instalados pelo AWARE
    
    Exemplos:
    
    \b
    # Remover hooks e restaurar backups
    aware uninstall
    
    \b
    # Remover sem restaurar backups
    aware uninstall --no-restore
    """
    
    try:
        results = uninstall_hooks(
            repo_path=Path.cwd(),
            restore_backups=not no_restore
        )
        
        for hook_name, result in results.items():
            if result.get("success"):
                action = "removido e backup restaurado" if result.get("restored") else "removido"
                console.print(f"✅ {hook_name}: {action}", style="green")
            else:
                console.print(f"⚠️  {hook_name}: {result.get('message')}", style="yellow")
        
        sys.exit(0)
    
    except Exception as e:
        console.print(f"❌ {e}", style="red")
        raise typer.Exit(1)


# =============================================================================
# Command: status
# =============================================================================

@app.command()
def status():
    """
    📊 Mostra status dos git hooks
    
    Exemplo:
    
    \b
    aware status
    """
    
    try:
        status_info = check_hooks_status(Path.cwd())
        print_status(status_info)
        sys.exit(0)
    
    except Exception as e:
        console.print(f"❌ {e}", style="red")
        raise typer.Exit(1)


# =============================================================================
# Command Group: rules
# =============================================================================

rules_app = typer.Typer(help="📋 Gerencia regras")
app.add_typer(rules_app, name="rules")


@rules_app.command("list")
def rules_list(
    by_risk: bool = typer.Option(
        False,
        "--by-risk",
        help="Agrupar por categoria de risco"
    ),
    by_severity: bool = typer.Option(
        False,
        "--by-severity",
        help="Agrupar por severidade"
    ),
    rules_file: Optional[Path] = typer.Option(
        None,
        "--rules",
        help="Arquivo de regras customizado"
    ),
):
    """
    📋 Lista regras disponíveis
    
    Exemplos:
    
    \b
    # Listar todas
    aware rules list
    
    \b
    # Agrupar por risco
    aware rules list --by-risk
    
    \b
    # Agrupar por severidade
    aware rules list --by-severity
    """
    
    try:
        # Load rules
        if rules_file:
            rules_pack = load_rules(str(rules_file))
        else:
            rules_pack = load_default_rules()
        
        console.print(f"\n📦 {rules_pack.total_rules} regras carregadas\n")
        
        if by_risk:
            # Group by risk
            for risk, rules in rules_pack.rules_by_risk().items():
                console.print(f"\n🏷️  {risk.value} ({len(rules)} regras)", style="bold cyan")
                
                table = Table(show_header=True)
                table.add_column("ID", style="cyan")
                table.add_column("Severity", style="yellow")
                table.add_column("Action", style="red")
                table.add_column("Message")
                
                for rule in rules:
                    table.add_row(
                        rule.id,
                        rule.severity.value,
                        rule.action.value,
                        rule.message[:60] + "..." if len(rule.message) > 60 else rule.message
                    )
                
                console.print(table)
        
        elif by_severity:
            # Group by severity
            from aware.core.models import Severity
            severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
            
            for severity in severity_order:
                rules = [r for r in rules_pack.rules if r.severity == severity]
                if not rules:
                    continue
                
                console.print(f"\n🚨 {severity.value.upper()} ({len(rules)} regras)", style="bold red")
                
                table = Table(show_header=True)
                table.add_column("ID", style="cyan")
                table.add_column("Risk", style="yellow")
                table.add_column("Action", style="red")
                table.add_column("Message")
                
                for rule in rules:
                    table.add_row(
                        rule.id,
                        rule.risk.value,
                        rule.action.value,
                        rule.message[:60] + "..." if len(rule.message) > 60 else rule.message
                    )
                
                console.print(table)
        
        else:
            # Simple list
            table = Table(show_header=True, title="AWARE Rules")
            table.add_column("ID", style="cyan", no_wrap=True)
            table.add_column("Severity", style="yellow")
            table.add_column("Risk", style="magenta")
            table.add_column("Message")
            
            for rule in rules_pack.rules:
                table.add_row(
                    rule.id,
                    rule.severity.value,
                    rule.risk.value,
                    rule.message[:50] + "..." if len(rule.message) > 50 else rule.message
                )
            
            console.print(table)
    
    except RulesLoadError as e:
        console.print(f"❌ Erro ao carregar regras: {e}", style="red")
        raise typer.Exit(1)


@rules_app.command("validate")
def rules_validate(
    rules_file: Path = typer.Argument(
        ...,
        help="Arquivo de regras a validar"
    ),
):
    """
    ✅ Valida arquivo de regras
    
    Exemplo:
    
    \b
    aware rules validate custom_rules.yaml
    """
    
    try:
        errors = validate_rules_file(str(rules_file))
        
        if not errors:
            console.print(f"✅ {rules_file}: Válido!", style="green")
            sys.exit(0)
        else:
            console.print(f"❌ {rules_file}: {len(errors)} erros encontrados\n", style="red")
            
            for error in errors:
                console.print(f"  • {error}", style="red")
            
            sys.exit(1)
    
    except Exception as e:
        console.print(f"❌ Erro ao validar: {e}", style="red")
        raise typer.Exit(1)


@rules_app.command("explain")
def rules_explain(
    rule_id: str = typer.Argument(
        ...,
        help="ID da regra a explicar"
    ),
    rules_file: Optional[Path] = typer.Option(
        None,
        "--rules",
        help="Arquivo de regras customizado"
    ),
):
    """
    📖 Explica uma regra específica
    
    Exemplo:
    
    \b
    aware rules explain SEC_ENV_FILE_COMMITTED
    """
    
    try:
        # Load rules
        if rules_file:
            rules_pack = load_rules(str(rules_file))
        else:
            rules_pack = load_default_rules()
        
        # Find rule
        rule = rules_pack.get_rule(rule_id)
        
        if not rule:
            console.print(f"❌ Regra não encontrada: {rule_id}", style="red")
            raise typer.Exit(1)
        
        # Display
        console.print(f"\n📋 Regra: {rule.id}\n", style="bold cyan")
        
        table = Table(show_header=False, box=None)
        table.add_column("Field", style="bold yellow")
        table.add_column("Value")
        
        table.add_row("🏷️  Risk", rule.risk.value)
        table.add_row("🚨 Severity", rule.severity.value)
        table.add_row("⚡ Action", rule.action.value)
        table.add_row("📝 Type", rule.type.value)
        table.add_row("💬 Message", rule.message)
        table.add_row("💥 Impact", rule.impact)
        table.add_row("💡 Recommendation", rule.recommendation)
        
        if rule.confirm:
            table.add_row("🔐 Confirm Mode", rule.confirm.mode.value)
            if rule.confirm.token:
                table.add_row("🔑 Token", rule.confirm.token)
        
        console.print(table)
        console.print()
    
    except RulesLoadError as e:
        console.print(f"❌ Erro ao carregar regras: {e}", style="red")
        raise typer.Exit(1)


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    """Entry point principal."""
    app()


if __name__ == "__main__":
    main()
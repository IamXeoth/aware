"""
AWARE - Output Formatters
Formatação de findings para diferentes contextos (terminal, JSON, etc).
"""

import sys
import json
from typing import List, Dict, Any, Optional, TextIO
from dataclasses import asdict

from .models import Finding, ScanResult, Severity, Action, RiskCategory


# =============================================================================
# ANSI Color Codes
# =============================================================================

class Colors:
    """Códigos de cor ANSI para terminal."""
    
    # Reset
    RESET = "\033[0m"
    
    # Estilos
    BOLD = "\033[1m"
    DIM = "\033[2m"
    
    # Cores básicas
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"
    WHITE = "\033[97m"
    
    # Background
    BG_RED = "\033[101m"
    BG_YELLOW = "\033[103m"
    
    @staticmethod
    def strip_colors(text: str) -> str:
        """Remove códigos de cor de uma string."""
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)
    
    @staticmethod
    def is_tty(file: TextIO = sys.stdout) -> bool:
        """Verifica se o output é um terminal (suporta cores)."""
        return hasattr(file, 'isatty') and file.isatty()


# =============================================================================
# Base Formatter
# =============================================================================

class BaseFormatter:
    """
    Classe base para formatters.
    """
    
    def __init__(self, use_colors: Optional[bool] = None):
        """
        Args:
            use_colors: Se True, usa cores ANSI. Se None, detecta automaticamente.
        """
        if use_colors is None:
            self.use_colors = Colors.is_tty()
        else:
            self.use_colors = use_colors
    
    def colorize(self, text: str, color: str) -> str:
        """Aplica cor ao texto se use_colors=True."""
        if not self.use_colors:
            return text
        return f"{color}{text}{Colors.RESET}"
    
    def format_result(self, result: ScanResult) -> str:
        """Formata ScanResult (deve ser implementado por subclasses)."""
        raise NotImplementedError
    
    def format_finding(self, finding: Finding) -> str:
        """Formata Finding individual (deve ser implementado por subclasses)."""
        raise NotImplementedError


# =============================================================================
# Console Formatter (Default)
# =============================================================================

class ConsoleFormatter(BaseFormatter):
    """
    Formatter para output no terminal (human-readable).
    """
    
    def __init__(self, use_colors: Optional[bool] = None, verbose: bool = False):
        """
        Args:
            use_colors: Usar cores ANSI
            verbose: Se True, mostra mais detalhes
        """
        super().__init__(use_colors)
        self.verbose = verbose
    
    def format_result(self, result: ScanResult) -> str:
        """
        Formata resultado completo do scan.
        
        Args:
            result: ScanResult do engine
            
        Returns:
            String formatada para terminal
        """
        lines = []
        
        # Header
        lines.append("")
        lines.append(self._format_header(result))
        lines.append("")
        
        # Findings
        if not result.findings:
            lines.append(self.colorize("✅ Nenhum problema encontrado", Colors.GREEN))
            lines.append("")
            return "\n".join(lines)
        
        # Agrupa por severidade
        by_severity = result.findings_by_severity()
        
        # Mostra findings por severidade (critical → low)
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            findings = by_severity.get(severity, [])
            if not findings:
                continue
            
            lines.append(self._format_severity_header(severity, len(findings)))
            lines.append("")
            
            for finding in findings:
                lines.append(self.format_finding(finding))
                lines.append("")
        
        # Summary
        lines.append(self._format_summary(result))
        lines.append("")
        
        return "\n".join(lines)
    
    def format_finding(self, finding: Finding) -> str:
        """
        Formata finding individual.
        
        Args:
            finding: Finding a ser formatado
            
        Returns:
            String formatada
        """
        lines = []
        
        # Ícone + título
        icon = self._get_severity_icon(finding.severity)
        severity_color = self._get_severity_color(finding.severity)
        
        title_line = f"{icon} {self.colorize(finding.title, severity_color)}"
        lines.append(title_line)
        
        # Location
        location = self.colorize(f"📍 {finding.location}", Colors.CYAN)
        lines.append(f"   {location}")
        
        # Evidence (resumido se muito longo)
        evidence = finding.evidence
        if len(evidence) > 100:
            evidence = evidence[:97] + "..."
        lines.append(f"   {self.colorize('Evidence:', Colors.DIM)} {evidence}")
        
        # Se verbose, mostra impacto e recomendação
        if self.verbose:
            lines.append("")
            lines.append(f"   {self.colorize('💥 Impacto:', Colors.BOLD)}")
            for line in finding.impact.split('\n'):
                lines.append(f"      {line}")
            
            lines.append("")
            lines.append(f"   {self.colorize('💡 Recomendação:', Colors.BOLD)}")
            for line in finding.recommendation.split('\n'):
                lines.append(f"      {line}")
        
        return "\n".join(lines)
    
    def _format_header(self, result: ScanResult) -> str:
        """Formata header do resultado."""
        scan_type = result.scan_type.upper()
        total = len(result.findings)
        
        if total == 0:
            return self.colorize(f"🔍 AWARE Scan ({scan_type})", Colors.BOLD)
        
        return self.colorize(f"🔍 AWARE Scan ({scan_type}) - {total} findings", Colors.BOLD)
    
    def _format_severity_header(self, severity: Severity, count: int) -> str:
        """Formata header de severidade."""
        color = self._get_severity_color(severity)
        severity_text = severity.value.upper()
        
        header = f"━━━ {severity_text} ({count}) "
        header += "━" * max(0, 70 - len(header))
        
        return self.colorize(header, color)
    
    def _format_summary(self, result: ScanResult) -> str:
        """Formata summary final."""
        lines = []
        
        lines.append("─" * 70)
        
        # Total findings
        total = len(result.findings)
        lines.append(f"Total de findings: {total}")
        
        # Por severidade
        by_severity = result.findings_by_severity()
        severity_counts = []
        
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = len(by_severity.get(severity, []))
            if count > 0:
                color = self._get_severity_color(severity)
                text = f"{severity.value}: {count}"
                severity_counts.append(self.colorize(text, color))
        
        if severity_counts:
            lines.append(f"Por severidade: {', '.join(severity_counts)}")
        
        # Exit code
        exit_code = result.exit_code
        if exit_code == 0:
            exit_msg = self.colorize("✅ Exit code: 0 (OK)", Colors.GREEN)
        elif exit_code == 10:
            exit_msg = self.colorize("⚠️  Exit code: 10 (Warnings)", Colors.YELLOW)
        else:
            exit_msg = self.colorize("❌ Exit code: 20 (Blocked)", Colors.RED)
        
        lines.append(exit_msg)
        lines.append("─" * 70)
        
        return "\n".join(lines)
    
    def _get_severity_icon(self, severity: Severity) -> str:
        """Retorna ícone para severidade."""
        icons = {
            Severity.CRITICAL: "🚨",
            Severity.HIGH: "⚠️",
            Severity.MEDIUM: "⚡",
            Severity.LOW: "ℹ️",
            Severity.INFO: "💬",
        }
        return icons.get(severity, "•")
    
    def _get_severity_color(self, severity: Severity) -> str:
        """Retorna cor ANSI para severidade."""
        colors = {
            Severity.CRITICAL: Colors.RED,
            Severity.HIGH: Colors.YELLOW,
            Severity.MEDIUM: Colors.BLUE,
            Severity.LOW: Colors.CYAN,
            Severity.INFO: Colors.GRAY,
        }
        return colors.get(severity, Colors.WHITE)


# =============================================================================
# Compact Formatter
# =============================================================================

class CompactFormatter(BaseFormatter):
    """
    Formatter compacto (uma linha por finding).
    Útil para CI/CD ou quando há muitos findings.
    """
    
    def format_result(self, result: ScanResult) -> str:
        """Formata resultado em formato compacto."""
        lines = []
        
        if not result.findings:
            lines.append(self.colorize("✅ No findings", Colors.GREEN))
            return "\n".join(lines)
        
        # Header
        total = len(result.findings)
        lines.append(f"🔍 {total} finding(s):")
        lines.append("")
        
        # Findings (uma linha cada)
        for finding in result.findings:
            lines.append(self.format_finding(finding))
        
        return "\n".join(lines)
    
    def format_finding(self, finding: Finding) -> str:
        """Formata finding em uma linha."""
        severity_color = self._get_severity_color(finding.severity)
        
        # Format: [SEVERITY] location: title
        severity_tag = f"[{finding.severity.value.upper()}]"
        severity_tag = self.colorize(severity_tag, severity_color)
        
        return f"{severity_tag} {finding.location}: {finding.title}"
    
    def _get_severity_color(self, severity: Severity) -> str:
        """Retorna cor para severidade."""
        colors = {
            Severity.CRITICAL: Colors.RED,
            Severity.HIGH: Colors.YELLOW,
            Severity.MEDIUM: Colors.BLUE,
            Severity.LOW: Colors.CYAN,
        }
        return colors.get(severity, Colors.WHITE)


# =============================================================================
# JSON Formatter
# =============================================================================

class JSONFormatter(BaseFormatter):
    """
    Formatter JSON (machine-readable).
    Útil para integração com outras ferramentas.
    """
    
    def __init__(self, pretty: bool = True):
        """
        Args:
            pretty: Se True, formata JSON com indentação
        """
        super().__init__(use_colors=False)  # JSON não usa cores
        self.pretty = pretty
    
    def format_result(self, result: ScanResult) -> str:
        """Formata resultado como JSON."""
        data = result.to_dict()
        
        if self.pretty:
            return json.dumps(data, indent=2, ensure_ascii=False)
        else:
            return json.dumps(data, ensure_ascii=False)
    
    def format_finding(self, finding: Finding) -> str:
        """Formata finding como JSON."""
        data = finding.to_dict()
        
        if self.pretty:
            return json.dumps(data, indent=2, ensure_ascii=False)
        else:
            return json.dumps(data, ensure_ascii=False)


# =============================================================================
# SARIF Formatter
# =============================================================================

class SARIFFormatter(BaseFormatter):
    """
    Formatter SARIF (Static Analysis Results Interchange Format).
    Usado por GitHub Code Scanning e outras ferramentas.
    """
    
    def __init__(self):
        super().__init__(use_colors=False)
    
    def format_result(self, result: ScanResult) -> str:
        """Formata resultado no formato SARIF 2.1.0."""
        
        # Agrupa findings por regra
        rules_map: Dict[str, List[Finding]] = {}
        for finding in result.findings:
            if finding.rule_id not in rules_map:
                rules_map[finding.rule_id] = []
            rules_map[finding.rule_id].append(finding)
        
        # Constrói SARIF
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AWARE",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/aware/aware",
                            "rules": self._build_rules(rules_map),
                        }
                    },
                    "results": self._build_results(result.findings),
                }
            ]
        }
        
        return json.dumps(sarif, indent=2, ensure_ascii=False)
    
    def format_finding(self, finding: Finding) -> str:
        """SARIF é sempre full result, não finding individual."""
        raise NotImplementedError("Use format_result() para SARIF")
    
    def _build_rules(self, rules_map: Dict[str, List[Finding]]) -> List[Dict[str, Any]]:
        """Constrói seção de rules do SARIF."""
        rules = []
        
        for rule_id, findings in rules_map.items():
            # Pega primeiro finding como referência
            finding = findings[0]
            
            rule = {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {
                    "text": finding.title
                },
                "fullDescription": {
                    "text": finding.impact
                },
                "help": {
                    "text": finding.recommendation
                },
                "defaultConfiguration": {
                    "level": self._severity_to_sarif_level(finding.severity)
                },
                "properties": {
                    "tags": [finding.risk.value],
                }
            }
            
            rules.append(rule)
        
        return rules
    
    def _build_results(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Constrói seção de results do SARIF."""
        results = []
        
        for finding in findings:
            # Parse location
            location_parts = finding.location.split(':')
            filepath = location_parts[0]
            
            result = {
                "ruleId": finding.rule_id,
                "level": self._severity_to_sarif_level(finding.severity),
                "message": {
                    "text": finding.title
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": filepath
                            }
                        }
                    }
                ]
            }
            
            results.append(result)
        
        return results
    
    def _severity_to_sarif_level(self, severity: Severity) -> str:
        """Converte Severity para SARIF level."""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        return mapping.get(severity, "warning")


# =============================================================================
# GitHub Annotations Formatter
# =============================================================================

class GitHubFormatter(BaseFormatter):
    """
    Formatter para GitHub Actions annotations.
    Cria annotations que aparecem no PR/commit.
    """
    
    def __init__(self):
        super().__init__(use_colors=False)
    
    def format_result(self, result: ScanResult) -> str:
        """Formata findings como GitHub annotations."""
        lines = []
        
        for finding in result.findings:
            lines.append(self.format_finding(finding))
        
        return "\n".join(lines)
    
    def format_finding(self, finding: Finding) -> str:
        """Formata finding como GitHub annotation."""
        
        # Parse location
        location_parts = finding.location.split(':')
        filepath = location_parts[0]
        
        # Determina tipo de annotation
        annotation_type = self._severity_to_github_type(finding.severity)
        
        # Format: ::error file=path,line=1::message
        annotation = f"::{annotation_type} file={filepath},title={finding.rule_id}::{finding.title}"
        
        return annotation
    
    def _severity_to_github_type(self, severity: Severity) -> str:
        """Converte Severity para GitHub annotation type."""
        if severity in [Severity.CRITICAL, Severity.HIGH]:
            return "error"
        elif severity == Severity.MEDIUM:
            return "warning"
        else:
            return "notice"


# =============================================================================
# Formatter Factory
# =============================================================================

class FormatterFactory:
    """Factory para criar formatters."""
    
    @staticmethod
    def create(
        format_type: str,
        use_colors: Optional[bool] = None,
        verbose: bool = False,
        pretty: bool = True
    ) -> BaseFormatter:
        """
        Cria formatter apropriado.
        
        Args:
            format_type: Tipo do formatter (console, compact, json, sarif, github)
            use_colors: Usar cores (apenas console/compact)
            verbose: Modo verbose (apenas console)
            pretty: Pretty print JSON (apenas json)
            
        Returns:
            BaseFormatter configurado
        """
        format_type = format_type.lower()
        
        if format_type == "console":
            return ConsoleFormatter(use_colors=use_colors, verbose=verbose)
        
        elif format_type == "compact":
            return CompactFormatter(use_colors=use_colors)
        
        elif format_type == "json":
            return JSONFormatter(pretty=pretty)
        
        elif format_type == "sarif":
            return SARIFFormatter()
        
        elif format_type == "github":
            return GitHubFormatter()
        
        else:
            raise ValueError(
                f"Formato desconhecido: {format_type}. "
                f"Formatos válidos: console, compact, json, sarif, github"
            )


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    # Formatters
    'BaseFormatter',
    'ConsoleFormatter',
    'CompactFormatter',
    'JSONFormatter',
    'SARIFFormatter',
    'GitHubFormatter',
    
    # Factory
    'FormatterFactory',
    
    # Utils
    'Colors',
]
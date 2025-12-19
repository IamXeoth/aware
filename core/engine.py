"""
AWARE - Core Engine
Motor de execução de regras e geração de findings.
"""

import re
import hashlib
import shlex
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from fnmatch import fnmatch

from .models import (
    Rule,
    RulesPack,
    RuleType,
    Finding,
    ScanResult,
    Severity,
    Action,
    ParsedShellCommand,
    GitFileAddedMatch,
    CodeRegexMatch,
    ContextualMultiMatch,
    ShellMatch,
    AwareConfig,
)


# =============================================================================
# Engine Principal
# =============================================================================

class AwareEngine:
    """
    Motor principal do AWARE.
    
    Responsabilidades:
    - Executar regras contra inputs (diff, arquivos, comandos)
    - Gerar findings
    - Aplicar políticas (severity_by_context)
    - Deduplicar findings
    """
    
    def __init__(self, rules_pack: RulesPack, config: Optional[AwareConfig] = None):
        """
        Args:
            rules_pack: Pack de regras carregado
            config: Configuração global (opcional)
        """
        self.rules_pack = rules_pack
        self.config = config or AwareConfig()
        
        # Filtra apenas regras habilitadas
        self.active_rules = rules_pack.filter_enabled(self.config)
    
    def scan_git_staged(self, staged_files: List[str], diff_by_file: Dict[str, List[str]]) -> ScanResult:
        """
        Escaneia arquivos staged no git.
        
        Args:
            staged_files: Lista de paths de arquivos staged
            diff_by_file: Dict {filepath: [linha1, linha2, ...]} com apenas linhas adicionadas (+)
            
        Returns:
            ScanResult com findings encontrados
        """
        findings = []
        
        for rule in self.active_rules:
            if rule.type == RuleType.GIT_FILE_ADDED:
                findings.extend(self._match_git_file_added(rule, staged_files))
            
            elif rule.type == RuleType.CODE_REGEX:
                findings.extend(self._match_code_regex(rule, diff_by_file))
            
            elif rule.type == RuleType.CONTEXTUAL_MULTI_MATCH:
                findings.extend(self._match_contextual_multi(rule, diff_by_file))
        
        # Deduplica findings
        findings = self._deduplicate_findings(findings)
        
        return ScanResult(
            findings=findings,
            total_files_scanned=len(staged_files),
            scan_type="staged"
        )
    
    def scan_shell_command(self, command: str) -> ScanResult:
        """
        Escaneia um comando shell.
        
        Args:
            command: Comando completo como string
            
        Returns:
            ScanResult com findings encontrados
        """
        findings = []
        
        # Parseia comando
        parsed = self._parse_shell_command(command)
        
        # Executa regras shell
        for rule in self.active_rules:
            if rule.type == RuleType.SHELL:
                finding = self._match_shell_command(rule, parsed)
                if finding:
                    findings.append(finding)
        
        return ScanResult(
            findings=findings,
            total_files_scanned=0,
            scan_type="shell"
        )
    
    def scan_diff(self, diff_by_file: Dict[str, List[str]]) -> ScanResult:
        """
        Escaneia um diff (ex: pre-push, entre branches).
        
        Args:
            diff_by_file: Dict {filepath: [linha1, linha2, ...]} com linhas adicionadas
            
        Returns:
            ScanResult com findings encontrados
        """
        findings = []
        
        for rule in self.active_rules:
            if rule.type == RuleType.CODE_REGEX:
                findings.extend(self._match_code_regex(rule, diff_by_file))
            
            elif rule.type == RuleType.CONTEXTUAL_MULTI_MATCH:
                findings.extend(self._match_contextual_multi(rule, diff_by_file))
        
        findings = self._deduplicate_findings(findings)
        
        return ScanResult(
            findings=findings,
            total_files_scanned=len(diff_by_file),
            scan_type="diff"
        )
    
    # =========================================================================
    # Matchers por Tipo de Regra
    # =========================================================================
    
    def _match_git_file_added(self, rule: Rule, staged_files: List[str]) -> List[Finding]:
        """Executa regra git_file_added."""
        findings = []
        match_config: GitFileAddedMatch = rule.match
        
        for filepath in staged_files:
            # Skip ignored paths
            if self._is_path_ignored(filepath):
                continue
            
            matched = False
            
            # Check file_path_regex
            if match_config.file_path_regex:
                if re.search(match_config.file_path_regex, filepath):
                    matched = True
            
            # Check file_extensions
            if match_config.file_extensions:
                _, ext = Path(filepath).stem, Path(filepath).suffix
                if ext in match_config.file_extensions:
                    matched = True
            
            # Check file_patterns (glob on basename)
            if match_config.file_patterns:
                basename = Path(filepath).name
                for pattern in match_config.file_patterns:
                    if fnmatch(basename, pattern):
                        matched = True
                        break
            
            if matched:
                finding = self._create_finding(
                    rule=rule,
                    evidence=filepath,
                    location=filepath,
                    filepath=filepath,
                )
                findings.append(finding)
        
        return findings
    
    def _match_code_regex(self, rule: Rule, diff_by_file: Dict[str, List[str]]) -> List[Finding]:
        """Executa regra code_regex."""
        findings = []
        match_config: CodeRegexMatch = rule.match
        
        for filepath, added_lines in diff_by_file.items():
            # Skip if file doesn't match globs
            if not self._matches_any_glob(filepath, match_config.file_globs):
                continue
            
            # Skip excluded paths
            if self._matches_any_glob(filepath, match_config.exclude_paths):
                continue
            
            # Skip ignored paths (global config)
            if self._is_path_ignored(filepath):
                continue
            
            if not added_lines:
                continue
            
            # Join added lines
            content = '\n'.join(added_lines)
            
            # Check must_contain_any
            if match_config.must_contain_any:
                if not any(term in content for term in match_config.must_contain_any):
                    continue
            
            # Check must_not_contain
            if match_config.must_not_contain:
                if any(term in content for term in match_config.must_not_contain):
                    continue
            
            # Check context_must_contain_any (para k8s, etc)
            if match_config.context_must_contain_any:
                if not any(term in content for term in match_config.context_must_contain_any):
                    continue
            
            # Check each pattern
            for pattern in match_config.patterns:
                matches = list(re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE))
                
                for match in matches:
                    matched_text = match.group(0)
                    
                    # Check exclusions (substring simples, case-insensitive)
                    if match_config.exclusions:
                        excluded = False
                        for exclusion in match_config.exclusions:
                            if exclusion.lower() in matched_text.lower():
                                excluded = True
                                break
                        if excluded:
                            continue
                    
                    # Create finding
                    finding = self._create_finding(
                        rule=rule,
                        evidence=matched_text[:200],  # Truncate long matches
                        location=f"{filepath}:+",
                        filepath=filepath,
                        context={'pattern': pattern}
                    )
                    findings.append(finding)
        
        return findings
    
    def _match_contextual_multi(self, rule: Rule, diff_by_file: Dict[str, List[str]]) -> List[Finding]:
        """Executa regra contextual_multi_match."""
        findings = []
        match_config: ContextualMultiMatch = rule.match
        
        for filepath, added_lines in diff_by_file.items():
            # Skip if file doesn't match globs
            if not self._matches_any_glob(filepath, match_config.file_globs):
                continue
            
            # Skip ignored paths
            if self._is_path_ignored(filepath):
                continue
            
            if not added_lines:
                continue
            
            content = '\n'.join(added_lines)
            
            # Check which patterns matched
            matched_patterns = []
            for pattern_obj in match_config.patterns:
                if re.search(pattern_obj.pattern, content, re.MULTILINE | re.IGNORECASE):
                    matched_patterns.append(pattern_obj.name or pattern_obj.pattern)
            
            # Evaluate condition
            should_trigger = False
            
            if match_config.condition == 'AND':
                should_trigger = len(matched_patterns) == len(match_config.patterns)
            
            elif match_config.condition == 'OR':
                should_trigger = len(matched_patterns) > 0
            
            if should_trigger:
                evidence = f"Patterns matched: {', '.join(matched_patterns)}"
                
                finding = self._create_finding(
                    rule=rule,
                    evidence=evidence,
                    location=filepath,
                    filepath=filepath,
                    context={'matched_patterns': matched_patterns}
                )
                findings.append(finding)
        
        return findings
    
    def _match_shell_command(self, rule: Rule, parsed: ParsedShellCommand) -> Optional[Finding]:
        """Executa regra shell."""
        match_config: ShellMatch = rule.match
        
        # Check program
        if match_config.program:
            if parsed.program != match_config.program:
                return None
        
        if match_config.program_any:
            if parsed.program not in match_config.program_any:
                return None
        
        # Check subcommand
        if match_config.subcommand:
            if parsed.subcommand != match_config.subcommand:
                return None
        
        # Check flags_contain_all (todas precisam estar presentes)
        if match_config.flags_contain_all:
            if not parsed.has_all_flags(match_config.flags_contain_all):
                return None
        
        # Check flags_any (qualquer uma)
        if match_config.flags_any:
            matched = False
            for flag in match_config.flags_any:
                if parsed.has_flag(flag):
                    matched = True
                    break
            if not matched:
                return None
        
        # Check args_contains
        if match_config.args_contains:
            if not parsed.contains_substring(match_config.args_contains):
                return None
        
        # Check command_contains_any
        if match_config.command_contains_any:
            matched = False
            for substring in match_config.command_contains_any:
                if substring.lower() in parsed.full_command.lower():
                    matched = True
                    break
            if not matched:
                return None
        
        # Check path_any (heurística: args que parecem paths)
        if match_config.path_any:
            paths_in_command = parsed.path_args
            matched = False
            for path in paths_in_command:
                if path in match_config.path_any:
                    matched = True
                    break
            if not matched:
                return None
        
        # Matched!
        return self._create_finding(
            rule=rule,
            evidence=parsed.full_command,
            location="shell",
            filepath=None,
        )
    
    # =========================================================================
    # Helpers
    # =========================================================================
    
    def _create_finding(
        self,
        rule: Rule,
        evidence: str,
        location: str,
        filepath: Optional[str],
        context: Optional[Dict[str, Any]] = None
    ) -> Finding:
        """
        Cria um Finding e aplica severity_by_context se aplicável.
        """
        # Determina severity/action (pode ser sobrescrito por context)
        severity = rule.severity
        action = rule.action
        
        # Aplica severity_by_context se filepath disponível
        if filepath and rule.severity_by_context:
            for severity_context in rule.severity_by_context:
                if self._matches_any_glob(filepath, severity_context.paths):
                    # Primeira match vence
                    if severity_context.severity:
                        severity = severity_context.severity
                    if severity_context.action:
                        action = severity_context.action
                    break
        
        # Gera fingerprint
        fingerprint = Finding.generate_fingerprint(
            rule_id=rule.id,
            location=location,
            evidence=evidence
        )
        
        return Finding(
            rule_id=rule.id,
            risk=rule.risk,
            severity=severity,
            action=action,
            title=rule.message,
            impact=rule.impact,
            recommendation=rule.recommendation,
            evidence=evidence,
            location=location,
            fingerprint=fingerprint,
            context=context or {},
        )
    
    def _parse_shell_command(self, command: str) -> ParsedShellCommand:
        """
        Parseia e normaliza um comando shell.
        
        Args:
            command: Comando completo como string
            
        Returns:
            ParsedShellCommand com flags normalizados
        """
        try:
            args = shlex.split(command)
        except ValueError:
            # Fallback se shlex falhar (comandos mal formados)
            args = command.split()
        
        if not args:
            return ParsedShellCommand(
                program="",
                full_command=command
            )
        
        program = args[0]
        subcommand = None
        flags = set()
        long_flags = []
        regular_args = []
        raw_args = args[1:] if len(args) > 1 else []
        
        # Detecta subcommand (ex: git push)
        if len(args) > 1 and not args[1].startswith('-'):
            # Possível subcommando
            potential_subcommand = args[1]
            # Lista de comandos conhecidos com subcomandos
            programs_with_subcommands = {'git', 'docker', 'kubectl', 'npm', 'cargo'}
            if program in programs_with_subcommands:
                subcommand = potential_subcommand
                args_to_parse = args[2:]
            else:
                args_to_parse = args[1:]
        else:
            args_to_parse = args[1:]
        
        # Parseia flags e args
        for arg in args_to_parse:
            if arg.startswith('--'):
                # Long flag
                long_flags.append(arg)
            elif arg.startswith('-') and len(arg) > 1:
                # Short flag(s) - explode
                for char in arg[1:]:
                    if char.isalnum():  # Ignora caracteres especiais
                        flags.add(char)
            else:
                # Regular argument
                regular_args.append(arg)
        
        return ParsedShellCommand(
            program=program,
            subcommand=subcommand,
            flags=flags,
            long_flags=long_flags,
            args=regular_args,
            raw_args=raw_args,
            full_command=command,
        )
    
    def _matches_any_glob(self, filepath: str, globs: List[str]) -> bool:
        """Verifica se filepath casa com qualquer glob da lista."""
        if not globs:
            return False
        
        for glob_pattern in globs:
            # Suporte a ** (glob recursivo)
            if '**' in glob_pattern:
                # Converte ** para regex
                regex_pattern = glob_pattern.replace('**', '.*').replace('*', '[^/]*')
                regex_pattern = regex_pattern.replace('?', '.')
                if re.search(f"^{regex_pattern}$", filepath):
                    return True
            else:
                # Glob simples
                if fnmatch(filepath, glob_pattern):
                    return True
        
        return False
    
    def _is_path_ignored(self, filepath: str) -> bool:
        """Verifica se o path está na lista de ignore global."""
        return self._matches_any_glob(filepath, self.config.ignore_paths)
    
    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Remove findings duplicados baseado no fingerprint.
        
        Args:
            findings: Lista de findings (pode conter duplicatas)
            
        Returns:
            Lista de findings únicos
        """
        seen_fingerprints: Set[str] = set()
        unique_findings = []
        
        for finding in findings:
            if finding.fingerprint not in seen_fingerprints:
                seen_fingerprints.add(finding.fingerprint)
                unique_findings.append(finding)
        
        return unique_findings


# =============================================================================
# Engine Factory
# =============================================================================

def create_engine(
    rules_pack: RulesPack,
    config: Optional[AwareConfig] = None
) -> AwareEngine:
    """
    Factory function para criar engine.
    
    Args:
        rules_pack: Pack de regras carregado
        config: Configuração opcional
        
    Returns:
        AwareEngine configurado
    """
    return AwareEngine(rules_pack, config)


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    'AwareEngine',
    'create_engine',
]
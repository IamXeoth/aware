"""
AWARE - Core Data Models
Estruturas de dados fundamentais do engine de regras.

Author: Vinícius Lisboa <contato@viniciuslisboa.com.br>
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Literal
from enum import Enum
import hashlib


# =============================================================================
# Enums
# =============================================================================

class Severity(str, Enum):
    """Níveis de severidade de um finding."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(str, Enum):
    """Ações a serem tomadas quando uma regra dispara."""
    WARN = "warn"
    REQUIRE_CONFIRM = "require_confirm"
    BLOCK = "block"


class RuleType(str, Enum):
    """Tipos de regras suportadas pelo engine."""
    GIT_FILE_ADDED = "git_file_added"
    CODE_REGEX = "code_regex"
    CONTEXTUAL_MULTI_MATCH = "contextual_multi_match"
    SHELL = "shell"


class RiskCategory(str, Enum):
    """Categorias de risco (taxonomia do AWARE)."""
    SECRETS_EXPOSED = "SECRETS_EXPOSED"
    TLS_DISABLED = "TLS_DISABLED"
    DEBUG_IN_PRODUCTION = "DEBUG_IN_PRODUCTION"
    SENSITIVE_DATA_LOGGED = "SENSITIVE_DATA_LOGGED"
    CORS_MISCONFIGURATION = "CORS_MISCONFIGURATION"
    AUTH_WEAKNESS = "AUTH_WEAKNESS"
    DESTRUCTIVE_COMMAND = "DESTRUCTIVE_COMMAND"
    DEPENDENCY_RISK = "DEPENDENCY_RISK"
    INFRASTRUCTURE_RISK = "INFRASTRUCTURE_RISK"


class ConfirmMode(str, Enum):
    """Modos de confirmação disponíveis."""
    TOKEN = "token"
    YESNO = "yesno"


# =============================================================================
# Match Configuration Classes
# =============================================================================

@dataclass
class GitFileAddedMatch:
    """Configuração de match para regras git_file_added."""
    file_path_regex: Optional[str] = None
    file_extensions: Optional[List[str]] = None
    file_patterns: Optional[List[str]] = None
    
    def __post_init__(self):
        """Valida que pelo menos um critério foi definido."""
        if not any([self.file_path_regex, self.file_extensions, self.file_patterns]):
            raise ValueError("git_file_added match requer pelo menos um critério")


@dataclass
class CodeRegexMatch:
    """Configuração de match para regras code_regex."""
    patterns: List[str]
    file_globs: List[str] = field(default_factory=lambda: ["**/*"])
    exclude_paths: List[str] = field(default_factory=list)
    exclusions: List[str] = field(default_factory=list)
    must_contain_any: List[str] = field(default_factory=list)
    must_not_contain: List[str] = field(default_factory=list)
    context_must_contain_any: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Valida que há pelo menos um pattern."""
        if not self.patterns:
            raise ValueError("code_regex match requer pelo menos um pattern")


@dataclass
class ContextualPattern:
    """Um pattern individual dentro de contextual_multi_match."""
    pattern: str
    name: Optional[str] = None


@dataclass
class ContextualMultiMatch:
    """Configuração de match para regras contextual_multi_match."""
    condition: Literal["AND", "OR"]
    scope: Literal["file"]
    patterns: List[ContextualPattern]
    file_globs: List[str] = field(default_factory=lambda: ["**/*"])
    
    def __post_init__(self):
        """Valida configuração."""
        if len(self.patterns) < 2:
            raise ValueError("contextual_multi_match requer pelo menos 2 patterns")
        if self.condition not in ["AND", "OR"]:
            raise ValueError("condition deve ser 'AND' ou 'OR'")
        if self.scope != "file":
            raise ValueError("MVP suporta apenas scope='file'")


@dataclass
class ShellMatch:
    """Configuração de match para regras shell."""
    program: Optional[str] = None
    program_any: Optional[List[str]] = None
    subcommand: Optional[str] = None
    flags_any: Optional[List[str]] = None
    flags_contain_all: Optional[List[str]] = None
    args_contains: Optional[str] = None
    command_contains_any: Optional[List[str]] = None
    path_any: Optional[List[str]] = None
    has_flag: Optional[List[str]] = None
    
    def __post_init__(self):
        """Valida que pelo menos program ou program_any foi definido."""
        if not self.program and not self.program_any:
            raise ValueError("shell match requer 'program' ou 'program_any'")
        
        if self.has_flag and not self.flags_any:
            self.flags_any = self.has_flag


# =============================================================================
# Severity by Context
# =============================================================================

@dataclass
class SeverityContext:
    """Define severidade/ação baseada em paths."""
    paths: List[str]
    severity: Optional[Severity] = None
    action: Optional[Action] = None
    
    def __post_init__(self):
        """Valida que pelo menos severity ou action foi definido."""
        if not self.severity and not self.action:
            raise ValueError("severity_by_context requer 'severity' e/ou 'action'")


# =============================================================================
# Confirm Configuration
# =============================================================================

@dataclass
class ConfirmConfig:
    """Configuração de confirmação para require_confirm."""
    mode: ConfirmMode = ConfirmMode.TOKEN
    token: Optional[str] = None
    
    def __post_init__(self):
        """Valida configuração."""
        if self.mode == ConfirmMode.TOKEN:
            if not self.token:
                raise ValueError("mode='token' requer campo 'token'")
            
            if not (2 <= len(self.token) <= 8):
                raise ValueError("token deve ter 2-8 caracteres")
            
            if not self.token.replace('_', '').replace('-', '').isalnum():
                raise ValueError("token deve ser alfanumérico (a-z, A-Z, 0-9, _, -)")
    
    @staticmethod
    def from_severity(severity: Severity, default_token: str = "RISK") -> "ConfirmConfig":
        """Cria ConfirmConfig apropriado baseado na severidade."""
        if severity in [Severity.CRITICAL, Severity.HIGH]:
            return ConfirmConfig(mode=ConfirmMode.TOKEN, token=default_token)
        else:
            return ConfirmConfig(mode=ConfirmMode.YESNO)


# =============================================================================
# Rule Definition
# =============================================================================

@dataclass
class Rule:
    """Definição completa de uma regra do AWARE."""
    id: str
    risk: RiskCategory
    severity: Severity
    action: Action
    type: RuleType
    message: str
    impact: str
    recommendation: str
    match: Any
    severity_by_context: List[SeverityContext] = field(default_factory=list)
    confirm: Optional[ConfirmConfig] = None
    
    def __post_init__(self):
        """Valida configuração da regra."""
        if self.action == Action.REQUIRE_CONFIRM and not self.confirm:
            raise ValueError(f"Regra {self.id}: action='require_confirm' requer campo 'confirm'")
        
        type_match_map = {
            RuleType.GIT_FILE_ADDED: GitFileAddedMatch,
            RuleType.CODE_REGEX: CodeRegexMatch,
            RuleType.CONTEXTUAL_MULTI_MATCH: ContextualMultiMatch,
            RuleType.SHELL: ShellMatch,
        }
        
        expected_match_type = type_match_map.get(self.type)
        if expected_match_type and not isinstance(self.match, expected_match_type):
            raise ValueError(
                f"Regra {self.id}: type='{self.type.value}' requer match do tipo {expected_match_type.__name__}"
            )


# =============================================================================
# Finding (Resultado de Detecção)
# =============================================================================

@dataclass
class Finding:
    """Representa um achado/detecção de uma regra."""
    rule_id: str
    risk: RiskCategory
    severity: Severity
    action: Action
    title: str
    impact: str
    recommendation: str
    evidence: str
    location: str
    fingerprint: str
    affected_stacks: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Valida campos obrigatórios."""
        if not self.rule_id:
            raise ValueError("Finding requer rule_id")
        if not self.fingerprint:
            raise ValueError("Finding requer fingerprint")
    
    @staticmethod
    def generate_fingerprint(rule_id: str, location: str, evidence: str) -> str:
        """Gera fingerprint único para um finding."""
        content = f"{rule_id}:{location}:{evidence[:100]}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Serializa Finding para dict."""
        return {
            "rule_id": self.rule_id,
            "risk": self.risk.value,
            "severity": self.severity.value,
            "action": self.action.value,
            "title": self.title,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "location": self.location,
            "fingerprint": self.fingerprint,
            "affected_stacks": self.affected_stacks,
            "context": self.context,
        }


# =============================================================================
# Scan Result
# =============================================================================

@dataclass
class ScanResult:
    """Resultado completo de um scan."""
    findings: List[Finding]
    total_files_scanned: int = 0
    scan_type: str = "unknown"
    
    @property
    def has_blocking_findings(self) -> bool:
        """Retorna True se há findings com action=block."""
        return any(f.action == Action.BLOCK for f in self.findings)
    
    @property
    def has_critical_findings(self) -> bool:
        """Retorna True se há findings críticos."""
        return any(
            f.action in [Action.BLOCK, Action.REQUIRE_CONFIRM] 
            for f in self.findings
        )
    
    @property
    def exit_code(self) -> int:
        """
        Calcula exit code apropriado baseado nos findings.
        
        0  = OK, sem findings
        10 = Findings (warn) mas não bloqueou
        20 = Bloqueado/abortado (critical)
        """
        if not self.findings:
            return 0
        
        if self.has_blocking_findings:
            return 20
        
        if self.has_critical_findings:
            return 20
        
        return 10
    
    def findings_by_severity(self) -> Dict[Severity, List[Finding]]:
        """Agrupa findings por severidade."""
        result: Dict[Severity, List[Finding]] = {
            Severity.INFO: [],
            Severity.LOW: [],
            Severity.MEDIUM: [],
            Severity.HIGH: [],
            Severity.CRITICAL: [],
        }
        
        for finding in self.findings:
            result[finding.severity].append(finding)
        
        return result
    
    def findings_by_risk(self) -> Dict[RiskCategory, List[Finding]]:
        """Agrupa findings por categoria de risco."""
        result: Dict[RiskCategory, List[Finding]] = {}
        
        for finding in self.findings:
            if finding.risk not in result:
                result[finding.risk] = []
            result[finding.risk].append(finding)
        
        return result
    
    def to_dict(self) -> Dict[str, Any]:
        """Serializa ScanResult para dict."""
        return {
            "findings": [f.to_dict() for f in self.findings],
            "total_files_scanned": self.total_files_scanned,
            "scan_type": self.scan_type,
            "summary": {
                "total_findings": len(self.findings),
                "has_blocking": self.has_blocking_findings,
                "has_critical": self.has_critical_findings,
                "exit_code": self.exit_code,
                "by_severity": {
                    severity.value: len(findings)
                    for severity, findings in self.findings_by_severity().items()
                    if findings
                },
                "by_risk": {
                    risk.value: len(findings)
                    for risk, findings in self.findings_by_risk().items()
                    if findings
                },
            }
        }


# =============================================================================
# Parsed Shell Command
# =============================================================================

@dataclass
class ParsedShellCommand:
    """Representa um comando shell parseado e normalizado."""
    program: str
    subcommand: Optional[str] = None
    flags: set = field(default_factory=set)
    long_flags: List[str] = field(default_factory=list)
    args: List[str] = field(default_factory=list)
    raw_args: List[str] = field(default_factory=list)
    full_command: str = ""
    
    @property
    def has_flags(self) -> bool:
        """Retorna True se o comando tem flags."""
        return bool(self.flags or self.long_flags)
    
    @property
    def path_args(self) -> List[str]:
        """Retorna argumentos que parecem ser paths."""
        return [arg for arg in self.args if not arg.startswith('-')]
    
    def has_flag(self, flag: str) -> bool:
        """Verifica se o comando tem uma flag específica."""
        if flag.startswith('--'):
            return flag in self.long_flags
        else:
            clean_flag = flag.lstrip('-')
            return clean_flag in self.flags
    
    def has_all_flags(self, flags: List[str]) -> bool:
        """Verifica se o comando tem TODAS as flags listadas."""
        required = {f.lstrip('-') for f in flags}
        return required.issubset(self.flags)
    
    def contains_substring(self, substring: str) -> bool:
        """Verifica se algum arg contém a substring."""
        return any(substring in arg for arg in self.raw_args)


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class AwareConfig:
    """Configuração global do AWARE."""
    rules_file: str = "default_rules.yaml"
    disabled_rules: List[str] = field(default_factory=list)
    enabled_rules: List[str] = field(default_factory=list)
    default_action_for_critical: Optional[Action] = None
    ignore_paths: List[str] = field(default_factory=lambda: [
        "node_modules/**",
        "venv/**",
        ".venv/**",
        "__pycache__/**",
        "dist/**",
        "build/**",
        ".git/**",
    ])
    max_file_size_kb: int = 1024
    
    def is_rule_enabled(self, rule_id: str) -> bool:
        """Verifica se uma regra está habilitada."""
        if rule_id in self.disabled_rules:
            return False
        
        if not self.enabled_rules:
            return True
        
        return rule_id in self.enabled_rules


# =============================================================================
# Rules Pack Metadata
# =============================================================================

@dataclass
class RulesPack:
    """Representa um pack de regras carregado."""
    version: str
    rules: List[Rule]
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_rule(self, rule_id: str) -> Optional[Rule]:
        """Busca uma regra por ID."""
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None
    
    def filter_enabled(self, config: AwareConfig) -> List[Rule]:
        """Retorna apenas regras habilitadas pela config."""
        return [
            rule for rule in self.rules
            if config.is_rule_enabled(rule.id)
        ]
    
    @property
    def total_rules(self) -> int:
        """Total de regras no pack."""
        return len(self.rules)
    
    def rules_by_type(self) -> Dict[RuleType, List[Rule]]:
        """Agrupa regras por tipo."""
        result: Dict[RuleType, List[Rule]] = {}
        for rule in self.rules:
            if rule.type not in result:
                result[rule.type] = []
            result[rule.type].append(rule)
        return result
    
    def rules_by_risk(self) -> Dict[RiskCategory, List[Rule]]:
        """Agrupa regras por categoria de risco."""
        result: Dict[RiskCategory, List[Rule]] = {}
        for rule in self.rules:
            if rule.risk not in result:
                result[rule.risk] = []
            result[rule.risk].append(rule)
        return result


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    # Enums
    "Severity",
    "Action",
    "RuleType",
    "RiskCategory",
    "ConfirmMode",
    
    # Match configurations
    "GitFileAddedMatch",
    "CodeRegexMatch",
    "ContextualPattern",
    "ContextualMultiMatch",
    "ShellMatch",
    
    # Core models
    "Rule",
    "Finding",
    "ScanResult",
    "ParsedShellCommand",
    
    # Configuration
    "SeverityContext",
    "ConfirmConfig",
    "AwareConfig",
    "RulesPack",
]
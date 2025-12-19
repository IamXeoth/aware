"""
AWARE - Rules Loader
Carrega e valida regras do arquivo YAML.
"""

import os
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
import yaml

from .models import (
    Rule,
    RulesPack,
    RuleType,
    Severity,
    Action,
    RiskCategory,
    GitFileAddedMatch,
    CodeRegexMatch,
    ContextualPattern,
    ContextualMultiMatch,
    ShellMatch,
    SeverityContext,
    ConfirmConfig,
    ConfirmMode,
)


# =============================================================================
# Exceções Customizadas
# =============================================================================

class RulesLoadError(Exception):
    """Erro ao carregar arquivo de regras."""
    pass


class RuleValidationError(Exception):
    """Erro de validação de uma regra específica."""
    
    def __init__(self, rule_id: str, message: str):
        self.rule_id = rule_id
        super().__init__(f"Regra '{rule_id}': {message}")


# =============================================================================
# Loader Principal
# =============================================================================

class RulesLoader:
    """
    Carrega e valida regras do YAML.
    
    Responsabilidades:
    - Ler arquivo YAML
    - Validar estrutura
    - Converter para objetos tipados (Rule, RulesPack)
    - Validar referências e dependências
    """
    
    def __init__(self, strict: bool = True):
        """
        Args:
            strict: Se True, valida rigorosamente (recomendado).
                   Se False, permite algumas inconsistências.
        """
        self.strict = strict
    
    def load_from_file(self, filepath: Union[str, Path]) -> RulesPack:
        """
        Carrega regras de um arquivo YAML.
        
        Args:
            filepath: Caminho para o arquivo de regras
            
        Returns:
            RulesPack com regras carregadas e validadas
            
        Raises:
            RulesLoadError: Se não conseguir ler o arquivo
            RuleValidationError: Se alguma regra for inválida
        """
        filepath = Path(filepath)
        
        if not filepath.exists():
            raise RulesLoadError(f"Arquivo não encontrado: {filepath}")
        
        if not filepath.is_file():
            raise RulesLoadError(f"Path não é um arquivo: {filepath}")
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise RulesLoadError(f"Erro ao parsear YAML: {e}")
        except Exception as e:
            raise RulesLoadError(f"Erro ao ler arquivo: {e}")
        
        return self.load_from_dict(data, source_file=str(filepath))
    
    def load_from_dict(self, data: Dict[str, Any], source_file: str = "unknown") -> RulesPack:
        """
        Carrega regras de um dicionário (já parseado do YAML).
        
        Args:
            data: Dicionário com estrutura do YAML
            source_file: Nome do arquivo de origem (para debug)
            
        Returns:
            RulesPack com regras carregadas
        """
        # Valida estrutura básica
        if not isinstance(data, dict):
            raise RulesLoadError("YAML deve conter um objeto no nível raiz")
        
        if 'rules' not in data:
            raise RulesLoadError("Campo 'rules' não encontrado no YAML")
        
        if not isinstance(data['rules'], list):
            raise RulesLoadError("Campo 'rules' deve ser uma lista")
        
        # Extrai metadata
        version = data.get('version', '1.0')
        metadata = {
            'source_file': source_file,
            'version': version,
        }
        
        # Carrega cada regra
        rules: List[Rule] = []
        rule_ids_seen = set()
        
        for idx, rule_data in enumerate(data['rules']):
            try:
                rule = self._load_rule(rule_data, index=idx)
                
                # Valida ID único
                if rule.id in rule_ids_seen:
                    raise RuleValidationError(
                        rule.id,
                        f"ID duplicado (já existe outra regra com este ID)"
                    )
                
                rule_ids_seen.add(rule.id)
                rules.append(rule)
                
            except RuleValidationError:
                raise  # Re-raise validation errors
            except Exception as e:
                # Tenta pegar ID se possível
                rule_id = rule_data.get('id', f'rule_#{idx}')
                raise RuleValidationError(rule_id, str(e))
        
        return RulesPack(
            version=version,
            rules=rules,
            metadata=metadata
        )
    
    def _load_rule(self, data: Dict[str, Any], index: int) -> Rule:
        """
        Carrega uma regra individual do dicionário.
        
        Args:
            data: Dicionário com dados da regra
            index: Índice da regra na lista (para debug)
            
        Returns:
            Rule objeto validado
        """
        # Campos obrigatórios
        required_fields = ['id', 'risk', 'severity', 'action', 'type', 'message', 'impact', 'recommendation', 'match']
        
        for field in required_fields:
            if field not in data:
                rule_id = data.get('id', f'rule_#{index}')
                raise RuleValidationError(rule_id, f"Campo obrigatório '{field}' não encontrado")
        
        rule_id = data['id']
        
        # Valida e converte enums
        try:
            risk = RiskCategory(data['risk'])
        except ValueError:
            raise RuleValidationError(
                rule_id,
                f"Valor inválido para 'risk': {data['risk']}. "
                f"Valores válidos: {[r.value for r in RiskCategory]}"
            )
        
        try:
            severity = Severity(data['severity'])
        except ValueError:
            raise RuleValidationError(
                rule_id,
                f"Valor inválido para 'severity': {data['severity']}. "
                f"Valores válidos: {[s.value for s in Severity]}"
            )
        
        try:
            action = Action(data['action'])
        except ValueError:
            raise RuleValidationError(
                rule_id,
                f"Valor inválido para 'action': {data['action']}. "
                f"Valores válidos: {[a.value for a in Action]}"
            )
        
        try:
            rule_type = RuleType(data['type'])
        except ValueError:
            raise RuleValidationError(
                rule_id,
                f"Valor inválido para 'type': {data['type']}. "
                f"Valores válidos: {[t.value for t in RuleType]}"
            )
        
        # Carrega match configuration (tipo depende de rule_type)
        match_config = self._load_match_config(rule_id, rule_type, data['match'])
        
        # Carrega severity_by_context (opcional)
        severity_by_context = []
        if 'severity_by_context' in data:
            severity_by_context = self._load_severity_contexts(
                rule_id,
                data['severity_by_context']
            )
        
        # Carrega confirm config (opcional, mas obrigatório se action=require_confirm)
        confirm_config = None
        if 'confirm' in data:
            confirm_config = self._load_confirm_config(rule_id, data['confirm'])
        
        # Cria Rule object
        try:
            rule = Rule(
                id=rule_id,
                risk=risk,
                severity=severity,
                action=action,
                type=rule_type,
                message=data['message'],
                impact=data['impact'],
                recommendation=data['recommendation'],
                match=match_config,
                severity_by_context=severity_by_context,
                confirm=confirm_config,
            )
        except ValueError as e:
            raise RuleValidationError(rule_id, str(e))
        
        return rule
    
    def _load_match_config(
        self,
        rule_id: str,
        rule_type: RuleType,
        data: Dict[str, Any]
    ) -> Union[GitFileAddedMatch, CodeRegexMatch, ContextualMultiMatch, ShellMatch]:
        """Carrega configuração de match baseado no tipo da regra."""
        
        if rule_type == RuleType.GIT_FILE_ADDED:
            return self._load_git_file_added_match(rule_id, data)
        
        elif rule_type == RuleType.CODE_REGEX:
            return self._load_code_regex_match(rule_id, data)
        
        elif rule_type == RuleType.CONTEXTUAL_MULTI_MATCH:
            return self._load_contextual_multi_match(rule_id, data)
        
        elif rule_type == RuleType.SHELL:
            return self._load_shell_match(rule_id, data)
        
        else:
            raise RuleValidationError(rule_id, f"Tipo de regra não suportado: {rule_type}")
    
    def _load_git_file_added_match(self, rule_id: str, data: Dict[str, Any]) -> GitFileAddedMatch:
        """Carrega match config para git_file_added."""
        
        file_path_regex = data.get('file_path_regex')
        file_extensions = data.get('file_extensions')
        file_patterns = data.get('file_patterns')
        
        # Valida que pelo menos um critério foi definido
        if not any([file_path_regex, file_extensions, file_patterns]):
            raise RuleValidationError(
                rule_id,
                "git_file_added requer pelo menos um de: file_path_regex, file_extensions, file_patterns"
            )
        
        # Valida regex se presente
        if file_path_regex:
            try:
                re.compile(file_path_regex)
            except re.error as e:
                raise RuleValidationError(
                    rule_id,
                    f"file_path_regex inválido: {e}"
                )
        
        return GitFileAddedMatch(
            file_path_regex=file_path_regex,
            file_extensions=file_extensions,
            file_patterns=file_patterns,
        )
    
    def _load_code_regex_match(self, rule_id: str, data: Dict[str, Any]) -> CodeRegexMatch:
        """Carrega match config para code_regex."""
        
        if 'patterns' not in data:
            raise RuleValidationError(rule_id, "code_regex requer campo 'patterns'")
        
        patterns = data['patterns']
        
        if not isinstance(patterns, list) or not patterns:
            raise RuleValidationError(rule_id, "'patterns' deve ser uma lista não-vazia")
        
        # Valida cada regex
        for idx, pattern in enumerate(patterns):
            try:
                re.compile(pattern)
            except re.error as e:
                raise RuleValidationError(
                    rule_id,
                    f"Pattern #{idx} inválido: {e}"
                )
        
        return CodeRegexMatch(
            patterns=patterns,
            file_globs=data.get('file_globs', ['**/*']),
            exclude_paths=data.get('exclude_paths', []),
            exclusions=data.get('exclusions', []),
            must_contain_any=data.get('must_contain_any', []),
            must_not_contain=data.get('must_not_contain', []),
            context_must_contain_any=data.get('context_must_contain_any', []),
        )
    
    def _load_contextual_multi_match(self, rule_id: str, data: Dict[str, Any]) -> ContextualMultiMatch:
        """Carrega match config para contextual_multi_match."""
        
        # Valida campos obrigatórios
        if 'condition' not in data:
            raise RuleValidationError(rule_id, "contextual_multi_match requer campo 'condition'")
        
        if 'patterns' not in data:
            raise RuleValidationError(rule_id, "contextual_multi_match requer campo 'patterns'")
        
        condition = data['condition']
        if condition not in ['AND', 'OR']:
            raise RuleValidationError(
                rule_id,
                f"condition deve ser 'AND' ou 'OR', encontrado: {condition}"
            )
        
        # Carrega patterns
        patterns_data = data['patterns']
        
        if not isinstance(patterns_data, list) or len(patterns_data) < 2:
            raise RuleValidationError(
                rule_id,
                "contextual_multi_match requer pelo menos 2 patterns"
            )
        
        patterns = []
        for idx, pattern_data in enumerate(patterns_data):
            if isinstance(pattern_data, str):
                # Formato simplificado: apenas pattern como string
                patterns.append(ContextualPattern(pattern=pattern_data))
            elif isinstance(pattern_data, dict):
                # Formato completo: {pattern, name}
                if 'pattern' not in pattern_data:
                    raise RuleValidationError(
                        rule_id,
                        f"Pattern #{idx} requer campo 'pattern'"
                    )
                
                # Valida regex
                try:
                    re.compile(pattern_data['pattern'])
                except re.error as e:
                    raise RuleValidationError(
                        rule_id,
                        f"Pattern #{idx} inválido: {e}"
                    )
                
                patterns.append(ContextualPattern(
                    pattern=pattern_data['pattern'],
                    name=pattern_data.get('name'),
                ))
            else:
                raise RuleValidationError(
                    rule_id,
                    f"Pattern #{idx} deve ser string ou objeto"
                )
        
        scope = data.get('scope', 'file')
        if scope != 'file':
            raise RuleValidationError(
                rule_id,
                f"MVP suporta apenas scope='file', encontrado: {scope}"
            )
        
        return ContextualMultiMatch(
            condition=condition,
            scope=scope,
            patterns=patterns,
            file_globs=data.get('file_globs', ['**/*']),
        )
    
    def _load_shell_match(self, rule_id: str, data: Dict[str, Any]) -> ShellMatch:
        """Carrega match config para shell."""
        
        # Valida que pelo menos program ou program_any está presente
        if 'program' not in data and 'program_any' not in data:
            raise RuleValidationError(
                rule_id,
                "shell match requer 'program' ou 'program_any'"
            )
        
        return ShellMatch(
            program=data.get('program'),
            program_any=data.get('program_any'),
            subcommand=data.get('subcommand'),
            flags_any=data.get('flags_any'),
            flags_contain_all=data.get('flags_contain_all'),
            args_contains=data.get('args_contains'),
            command_contains_any=data.get('command_contains_any'),
            path_any=data.get('path_any'),
            has_flag=data.get('has_flag'),  # Alias para flags_any
        )
    
    def _load_severity_contexts(
        self,
        rule_id: str,
        data: List[Dict[str, Any]]
    ) -> List[SeverityContext]:
        """Carrega lista de severity_by_context."""
        
        if not isinstance(data, list):
            raise RuleValidationError(
                rule_id,
                "severity_by_context deve ser uma lista"
            )
        
        contexts = []
        
        for idx, context_data in enumerate(data):
            if 'paths' not in context_data:
                raise RuleValidationError(
                    rule_id,
                    f"severity_by_context #{idx} requer campo 'paths'"
                )
            
            # Valida severity se presente
            severity = None
            if 'severity' in context_data:
                try:
                    severity = Severity(context_data['severity'])
                except ValueError:
                    raise RuleValidationError(
                        rule_id,
                        f"severity_by_context #{idx}: severity inválida: {context_data['severity']}"
                    )
            
            # Valida action se presente
            action = None
            if 'action' in context_data:
                try:
                    action = Action(context_data['action'])
                except ValueError:
                    raise RuleValidationError(
                        rule_id,
                        f"severity_by_context #{idx}: action inválida: {context_data['action']}"
                    )
            
            # Valida que pelo menos severity ou action foi definido
            if severity is None and action is None:
                raise RuleValidationError(
                    rule_id,
                    f"severity_by_context #{idx} requer 'severity' e/ou 'action'"
                )
            
            contexts.append(SeverityContext(
                paths=context_data['paths'],
                severity=severity,
                action=action,
            ))
        
        return contexts
    
    def _load_confirm_config(self, rule_id: str, data: Dict[str, Any]) -> ConfirmConfig:
        """Carrega configuração de confirmação."""
        
        if not isinstance(data, dict):
            raise RuleValidationError(rule_id, "'confirm' deve ser um objeto")
        
        # Valida mode
        mode_str = data.get('mode', 'token')
        try:
            mode = ConfirmMode(mode_str)
        except ValueError:
            raise RuleValidationError(
                rule_id,
                f"confirm.mode inválido: {mode_str}. Valores válidos: {[m.value for m in ConfirmMode]}"
            )
        
        # Valida token se mode=token
        token = data.get('token')
        
        if mode == ConfirmMode.TOKEN:
            if not token:
                raise RuleValidationError(
                    rule_id,
                    "confirm.mode='token' requer campo 'token'"
                )
            
            # Valida comprimento do token
            if not (2 <= len(token) <= 8):
                raise RuleValidationError(
                    rule_id,
                    f"confirm.token deve ter 2-8 caracteres, encontrado: {len(token)}"
                )
            
            # Valida caracteres do token
            if not token.replace('_', '').replace('-', '').isalnum():
                raise RuleValidationError(
                    rule_id,
                    "confirm.token deve ser alfanumérico (a-z, A-Z, 0-9, _, -)"
                )
        
        return ConfirmConfig(mode=mode, token=token)


# =============================================================================
# Helper Functions
# =============================================================================

def load_rules(filepath: Union[str, Path], strict: bool = True) -> RulesPack:
    """
    Helper function para carregar regras de um arquivo.
    
    Args:
        filepath: Caminho para o arquivo YAML
        strict: Se True, valida rigorosamente
        
    Returns:
        RulesPack com regras carregadas
    """
    loader = RulesLoader(strict=strict)
    return loader.load_from_file(filepath)


def load_default_rules() -> RulesPack:
    """
    Carrega regras padrão do AWARE (default_rules.yaml).
    
    Returns:
        RulesPack com regras padrão
    """
    # Procura default_rules.yaml no diretório config
    config_dir = Path(__file__).parent.parent / "config"
    rules_file = config_dir / "default_rules.yaml"
    
    if not rules_file.exists():
        raise RulesLoadError(
            f"Arquivo de regras padrão não encontrado: {rules_file}"
        )
    
    return load_rules(rules_file)


def validate_rules_file(filepath: Union[str, Path]) -> Dict[str, Any]:
    """
    Valida um arquivo de regras e retorna relatório de validação.
    
    Args:
        filepath: Caminho para o arquivo YAML
        
    Returns:
        Dict com resultados da validação:
        {
            'valid': bool,
            'total_rules': int,
            'errors': List[str],
            'warnings': List[str],
        }
    """
    result = {
        'valid': True,
        'total_rules': 0,
        'errors': [],
        'warnings': [],
    }
    
    try:
        loader = RulesLoader(strict=True)
        rules_pack = loader.load_from_file(filepath)
        result['total_rules'] = rules_pack.total_rules
        
        # Validações adicionais (warnings)
        
        # Verifica se há regras duplicadas por risco
        risk_counts = {}
        for rule in rules_pack.rules:
            risk_counts[rule.risk] = risk_counts.get(rule.risk, 0) + 1
        
        # Avisa se alguma categoria tem muitas regras
        for risk, count in risk_counts.items():
            if count > 10:
                result['warnings'].append(
                    f"Categoria '{risk.value}' tem {count} regras (considere dividir)"
                )
        
        # Verifica regras sem confirm config quando action=require_confirm
        for rule in rules_pack.rules:
            if rule.action == Action.REQUIRE_CONFIRM and not rule.confirm:
                result['errors'].append(
                    f"Regra '{rule.id}': action='require_confirm' mas sem campo 'confirm'"
                )
                result['valid'] = False
        
    except (RulesLoadError, RuleValidationError) as e:
        result['valid'] = False
        result['errors'].append(str(e))
    except Exception as e:
        result['valid'] = False
        result['errors'].append(f"Erro inesperado: {e}")
    
    return result


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    'RulesLoader',
    'RulesLoadError',
    'RuleValidationError',
    'load_rules',
    'load_default_rules',
    'validate_rules_file',
]
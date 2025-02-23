import re
from typing import Any, Dict, List
from models import Subrule, Rule

# Container configuration options
DEFAULT_DOCKER_CONFIG = {
    "CapAdd": [],
    "PidMode": "",
    "Privileged": False,
    "SecurityOpt": [],
    "Mounts": []
}

def parse_configuration(dsl: str) -> Dict[str, Any]:
    """Funtion for parsing container configuration options from CSDSL rule

    Args:
        dsl (str): rules

    Returns:
        Dict[str, Any]: container configuration
    """
    config_pattern = r'Configuration\s+([^\{]+)\s*\{([^}]*)\}'
    match = re.search(config_pattern, dsl, re.DOTALL)
    if not match:
        return None
    
    config_name = match.group(1).strip()
    config_body = match.group(2).strip()
    
    # Копируем дефолтную конфигурацию, чтобы не менять оригинал
    config_fields = DEFAULT_DOCKER_CONFIG.copy()
    
    # Разбор полей конфигурации
    for line in config_body.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip().strip('[],')
            
            # Преобразуем поля CapAdd, SecurityOpt, Mounts в списки
            if key in ["CapAdd", "SecurityOpt", "Mounts"]:
                value = [v.strip() for v in value.split(",") if v.strip()]
            elif value == "True":
                value = True
            elif value == "False":
                value = False
            else:
                value = value.strip('"')
            
            config_fields[key] = value
    
    return config_name, config_fields

def parse_event(dsl: str) -> Dict[str, Any]:
    """Funtion for parsing event data from CSDSL rule

    Args:
        dsl (str): rules

    Returns:
        Dict[str, Any]: event data
    """
    event_pattern = r'Event\s+([^\{]+)\s*\{([^}]*)\}'
    match = re.search(event_pattern, dsl, re.DOTALL)
    if not match:
        return None
    
    event_name = match.group(1).strip()
    event_body = match.group(2).strip()
    
    event_fields = {}
    for line in event_body.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip().strip('"')
            event_fields[key] = value
    
    return event_name, event_fields

def parse_rule(dsl: str, events: Dict[str, dict], configs: Dict[str, dict]) -> Rule:
    """Function for parsing one rule

    Args:
        dsl (str): rules
        events (Dict[str, dict]): all parsed events
        configs (Dict[str, dict]): all parsed configs

    Returns:
        Rule: rule description
    """
    rule_pattern = r'Rule\s+([^\{]+)\s*\{([^}]*)\}'
    match = re.search(rule_pattern, dsl, re.DOTALL)
    if not match:
        return None
    
    rule_name = match.group(1).strip()
    rule_body = match.group(2).strip()
    
    detect_pattern = r'detect\s+([^\s]+(?:\s+and\s+[^\s]+)*)\s*(?:if\s+([^\s]+))?'
    detect_match = re.search(detect_pattern, rule_body)
    
    if not detect_match:
        return None
    
    events_list = detect_match.group(1).split(" and ")
    config_name = detect_match.group(2) if detect_match.group(2) else None
    
    subrules = []
    for event_name in events_list:
        if event_name in events:
            subrule = Subrule(name=event_name, syscall=events[event_name])
            subrules.append(subrule)
    
    # Если конфигурация не указана, используем дефолтную
    docker_config = configs.get(config_name, DEFAULT_DOCKER_CONFIG.copy())
    
    return Rule(name=rule_name, subrules=subrules, docker_config=docker_config)

def parse_dsl(dsl: str) -> List[Rule]:
    """Main function for parsing CSDSL file

    Args:
        dsl (str): rules

    Returns:
        List[Rule]: converted rules
    """
    configurations = {}
    events = {}
    rules = []
    
    # Разбираем конфигурации
    config_matches = re.findall(r'Configuration\s+[^\{]+\s*\{[^}]*\}', dsl, re.DOTALL)
    for config_match in config_matches:
        config_name, config_fields = parse_configuration(config_match)
        configurations[config_name] = config_fields
    
    # Разбираем события
    event_matches = re.findall(r'Event\s+[^\{]+\s*\{[^}]*\}', dsl, re.DOTALL)
    for event_match in event_matches:
        event_name, event_fields = parse_event(event_match)
        events[event_name] = event_fields
    
    # Разбираем правила
    rule_matches = re.findall(r'Rule\s+[^\{]+\s*\{[^}]*\}', dsl, re.DOTALL)
    for rule_match in rule_matches:
        rule = parse_rule(rule_match, events, configurations)
        if rule:
            rules.append(rule)
    
    return rules
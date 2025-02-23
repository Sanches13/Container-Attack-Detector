import json
import util
from typing import Any
from datetime import datetime
from models import Events, Container, Process, Rule, Subrule


def json_form_rules(rules_filename: str) -> list[Rule]:
    with open(rules_filename, "r") as fr:
        data = json.load(fr)
        return [Rule(**rule) for rule in data]   
    
def csdsl_form_rules(rules_json: str) -> list[Rule]:
    return [Rule(**rule) for rule in rules_json]
    
def find_container_by_name(container_id: str,
                           events_json: Events) -> Container | None:
        for container in events_json.containers:
            if container.name == container_id:
                return container
        return None
    
def find_process_by_pid(pid: int,
                        container: Container) -> Process | None:
    for process in container.processes:
        if process.pid == pid:
            return process
    return None

def find_rule_by_name(rule: Rule,
                      process: Process) -> Rule | None:
    for process_rule in process.rules:
        if process_rule.name == rule.name:
            return process_rule
    return None

def is_subrule_worked(subrule: Subrule,
                      process_rule: Rule) -> Subrule | None:
    for process_rule_subrule in process_rule.subrules:
        if process_rule_subrule.name == subrule.name:
            if len(process_rule_subrule.syscall) != 0:
                return None
            else:
                return process_rule_subrule
    return None

def add_subrule_to_events_json(container_id: str,
                               pid: int,
                               rule: Rule,
                               subrule: Subrule,
                               syscall: dict[str, Any],
                               events_json: Events) -> None:
    container = find_container_by_name(container_id, events_json)
        
    process = find_process_by_pid(pid, container)
    if not process:
        process = Process(pid=pid, ppid=syscall["ppid"], rules=list())
        container.processes.append(process)
    
    process_rule = find_rule_by_name(rule, process)
    if not process_rule:
        process_rule = Rule(name=rule.name, subrules=list(), docker_config=rule.docker_config)
        for rule_subrule in rule.subrules:
            process_rule_subrule = Subrule(name=rule_subrule.name, syscall=dict())
            process_rule.subrules.append(process_rule_subrule)
        process.rules.append(process_rule)
    
    process_rule_subrule = is_subrule_worked(subrule, process_rule)
    if process_rule_subrule:
        process_rule_subrule.syscall = syscall
        
def check_syscall(container_id: str,
                  pid: int,
                  syscall: dict[str, Any],
                  rules: list[Rule],
                  events_json: Events,
                  docker_config: dict[str, Any]) -> None:
    for rule in rules:
        # Проверка конфига
        # PidMode - пустая строка или строка
        # Privileged - True или False
        # CapAdd - массив строк или None
        # Mounts - пустой массив или массив строк
        # SecurityOpt - None или массив строк
        if rule.docker_config["PidMode"] != "" and docker_config["Pidmode"] != rule.docker_config["Pidmode"]:
            continue
        if rule.docker_config["Privileged"] != False and str(docker_config["Privileged"]) != str(rule.docker_config["Privileged"]):
            continue
        if len(rule.docker_config["CapAdd"]) > 0:
            if docker_config["CapAdd"]:
                for capability in rule.docker_config["CapAdd"]:
                    if capability not in docker_config["CapAdd"]:
                        continue
            else:
                continue
        if len(rule.docker_config["Mounts"]) > 0:
            if len(docker_config["Mounts"]) > 0:
                for mount_dir in rule.docker_config["Mounts"]:
                    if mount_dir not in docker_config["Mounts"]:
                        continue
            else:
                continue
        # if len(rule.docker_config["SecurityOpt"]) > 0:
        #     if docker_config["SecurityOpt"]:
        #         flag = False
        #         for entity in rule.docker_config["SecurityOpt"]:
        #             flag = False
        #             for docker_entity in docker_config["SecurityOpt"]:
        #                 if entity in docker_entity:
        #                     flag = True
        #                     break
        #             if not flag:
        #                 break
        #         if not flag:
        #             continue
            
        for subrule in rule.subrules:
            match_count = 0
            for field, value in syscall.items():
                if field not in subrule.syscall:
                    continue
                elif subrule.syscall[field] != value:
                    break
                else:
                    match_count += 1
            if match_count == len(subrule.syscall):
                add_subrule_to_events_json(container_id, pid, rule, subrule, syscall, events_json)
                return
    return

def check_events(events_json: Events) -> None:
    to_delete: list[tuple[Process, Rule]] = list()
    for container in events_json.containers:
        for process in container.processes:
            for rule in process.rules:
                subrules_count = 0
                for subrule in rule.subrules:
                    if len(subrule.syscall) == 0:
                        break
                    else:
                        subrules_count += 1
                if subrules_count == len(rule.subrules):
                    print("=" * 86)
                    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}: Для контейнера {container.name} (процесса {process.pid}) сработало правило {rule.name}")
                    tmp_string = ""
                    for subrule in rule.subrules:
                        tmp_string += f"Подправило {subrule.name}: "
                        for k, v in subrule.syscall.items():
                            tmp_string += f"{k}: {v}, "
                        tmp_string += "\n"
                    print(tmp_string.strip().removesuffix(","))
                    tmp_string = "Настройки Docker-контейнера: "
                    for k, v in rule.docker_config.items():
                        tmp_string += f"{k}: {v}, "
                    print(tmp_string.strip().removesuffix(","))
                    # if psutil.pid_exists(process.pid):
                    #     p = psutil.Process(process.pid)
                    #     p.kill()
                    # elif psutil.pid_exists(process.ppid):
                    #     p = psutil.Process(process.ppid)
                    #     p.kill()
                    to_delete.append(tuple([process, rule]))            
    for pair in to_delete:
        pair[0].rules.remove(pair[1])
            
def clean_events(events_json: Events) -> None:
    container_to_delete: list[Container] = list()
    running_containers = util.get_active_containers()
    for container in events_json.containers:
        if container.name not in running_containers:
            container_to_delete.append(container)
    for container in container_to_delete:
        events_json.containers.remove(container)
    
    # pid_to_delete: list[tuple[Container, Process]] = list()
    # for container in events_json.containers:
    #     for process in container.processes:
    #         if not util.is_process_active(process.pid):
    #             pid_to_delete.append(tuple([container, process]))
    # for pair in pid_to_delete:
    #     pair[0].processes.remove(pair[1])
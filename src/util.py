import os
import subprocess
import json
import docker
import psutil
from typing import Any

def get_container_id(pid: int) -> str:
    # https://habr.com/ru/companies/rvision/articles/766126/
    container_id = "-"

    try:
        with open(f"/proc/{pid}/cpuset", "r") as cpuset_file:
            cpuset = cpuset_file.read()
    except IOError:
        return container_id
    
    if "/docker" in cpuset:
        container_id = cpuset.split("/")[-1].replace("docker-", "")[:12]

    return container_id

def get_pid_realpath(pid: int) -> str:
    try:
        path = os.readlink(f"/proc/{pid}/exe")
    except IOError:
        return ""
    
    return path

def get_ppid(pid: int) -> int | None:
    try:
        with open(f"/proc/{pid}/status") as status:
            for line in status:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except IOError:
        return None

def get_docker_json(container_id: str) -> Any:
    result = subprocess.run(f"docker inspect {container_id}", shell=True,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    docker_json = json.loads(result.stdout.decode("utf-8"))
    if docker_json and len(docker_json) > 0:
        return docker_json[0]
    else:
        return None

def get_docker_security_params(container_id: str) -> dict[str, Any]:
    docker_json = get_docker_json(container_id)
    docker_security_params = dict()
    if docker_json and "HostConfig" in docker_json:
        if "CapAdd" in docker_json["HostConfig"]:
            docker_security_params["CapAdd"] = docker_json["HostConfig"]["CapAdd"]
        if "PidMode" in docker_json["HostConfig"]:
            docker_security_params["PidMode"] = docker_json["HostConfig"]["PidMode"]
        if "Privileged" in docker_json["HostConfig"]:
            docker_security_params["Privileged"] = docker_json["HostConfig"]["Privileged"]
        if "SecurityOpt" in docker_json["HostConfig"]:
            docker_security_params["SecurityOpt"] = docker_json["HostConfig"]["SecurityOpt"]
        if "Mounts" in docker_json:
            docker_security_params["Mounts"] = []
            for entity in docker_json["Mounts"]:
                docker_security_params["Mounts"].append(entity["Source"])
    return docker_security_params

def get_active_containers() -> list[str]:
    # Создаем клиент для взаимодействия с Docker
    client = docker.from_env()
    # Получаем список всех запущенных контейнеров
    containers = client.containers.list()
    # Выводим ID каждого контейнера
    container_ids = [container.id[:12] for container in containers]
    return container_ids

def is_process_active(pid: int) -> bool:
    try:
        # Получаем объект процесса по PID
        process = psutil.Process(pid)
        # Возвращаем статус процесса
        return True
    except Exception as e:
        return False

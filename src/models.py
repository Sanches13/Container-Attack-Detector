from pydantic import BaseModel
from typing import Any


class Subrule(BaseModel):
    name: str
    syscall: dict[str, Any]
    
class Rule(BaseModel):
    name: str
    subrules: list[Subrule]
    docker_config: dict[str, Any]
    
class Process(BaseModel):
    pid: int
    ppid: int
    rules: list[Rule]
    
class Container(BaseModel):
    name: str
    processes: list[Process]
    docker_config: dict[str, Any]
    
class Events(BaseModel):
    containers: list[Container]
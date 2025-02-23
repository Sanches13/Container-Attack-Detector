from bcc import BPF
import ctypes
import os
import syscall_structures
import socket
import util
import rules
import dsl_parser
from typing import Any
from models import Container, Events
from argument_parser import arguments_parser


def main() -> None:
    bpf_text = ""
    c_files_dir = "./handlers"
    args = arguments_parser()
    rules_filename = args.rules
    if not os.path.exists(rules_filename):
        print(f"Файла {rules_filename} не найдено")
        return

    # Собираем и читаем все файлы с расширением .c
    for filename in os.listdir(c_files_dir):
        if filename.endswith(".c"):
            with open(os.path.join(c_files_dir, filename), "r") as c_file:
                bpf_text += c_file.read() + "\n"

    b = BPF(text=bpf_text)

    # вот тут будет чтение файла собственного формата
    # обработка его значений, возможно небольшая проверка корректности
    # и заполнение rules_json
    
    if args.rules_format == "csdsl":
        with open(rules_filename, "r") as fr:
            parsed_rules = dsl_parser.parse_dsl(fr.read())
            # Преобразуем в JSON
            json_output = [rule.dict() for rule in parsed_rules]
            rules_json = rules.csdsl_form_rules(json_output)
    elif args.rules_format == "json":
        rules_json: dict[str, list[dict[str, Any]]] = rules.json_form_rules(rules_filename)
    else:
        print(f"Формат правил {args.rules_format} не поддерживается")
        return
    events_json: Events = Events(containers=list())

    def handle_syscall(cpu, data, size):
        syscall_name = ctypes.cast(data, ctypes.POINTER(syscall_structures.SyscallData)).contents.name
        syscall_name_str = syscall_name.decode()
        
        event_class = syscall_structures.syscall_dict[syscall_name_str]
        event = ctypes.cast(data, ctypes.POINTER(event_class)).contents
        
        pid = event.syscall_data.pid
        ppid = event.syscall_data.ppid
        container_id = util.get_container_id(pid)
        if container_id == "-":
            container_id = util.get_container_id(ppid)
        # print(f"{syscall_name_str=}, {container_id=}, {pid=}, {ppid=}")
        if container_id == "-":
            return
        container = rules.find_container_by_name(container_id, events_json)
        if not container:
            docker_config = util.get_docker_security_params(container_id)
            container = Container(name=container_id, processes=list(), docker_config=docker_config)
            events_json.containers.append(container)        
        
        tmp_json: dict[str, Any] = {}
        
        tmp_json["name"] = syscall_name_str
        tmp_json["pid"] = pid
        tmp_json["tgid"] = event.syscall_data.tgid
        tmp_json["uid"] = event.syscall_data.uid
        
        tmp_json["ppid"] = ppid
        if tmp_json["ppid"] == 0:
            tmp_json["ppid"] = util.get_ppid(pid)
            
        tmp_json["cgroup"] = event.syscall_data.cgroup
        tmp_json["timestamp"] = event.syscall_data.timestamp
        tmp_json["comm"] = event.syscall_data.comm.decode('utf-8').strip()
        tmp_json["cpu"] = event.syscall_data.cpu
        tmp_json["task_flags"] = event.syscall_data.task_flags
        tmp_json["retval"] = event.syscall_data.retval
        
        match syscall_name_str:
            case "ptrace":
                tmp_json["request"] = event.request
                tmp_json["pid"] = event.pid
                tmp_json["addr"] = event.addr
                tmp_json["data"] = event.data
            case "openat":
                tmp_json["dfd"] = event.dfd
                tmp_json["flags"] = event.flags
                tmp_json["mode"] = event.mode
                tmp_json["filename"] = event.filename.decode('utf-8').strip()
            case "getdents64":
                tmp_json["fd"] = event.fd
                tmp_json["filename"] = event.filename.decode('utf-8').strip()
            case "open_by_handle_at":
                tmp_json["mountdirfd"] = event.mountdirfd
                tmp_json["flags"] = event.flags
                tmp_json["filename"] = event.filename.decode('utf-8').strip()
            case "pwrite64":
                tmp_json["fd"] = event.fd
                tmp_json["count"] = event.count
                tmp_json["pos"] = event.pos
                tmp_json["buf"] = event.buf.decode('utf-8').strip()
                tmp_json["filename"] = event.filename.decode('utf-8').strip()
            case "pread64":
                tmp_json["fd"] = event.fd
                tmp_json["count"] = event.count
                tmp_json["pos"] = event.pos
                tmp_json["buf"] = event.buf.decode('utf-8').strip()
                tmp_json["filename"] = event.filename.decode('utf-8').strip()
            case "write":
                tmp_json["fd"] = event.fd
                tmp_json["count"] = event.count
                tmp_json["buf"] = event.buf.decode('latin-1').strip()
                tmp_json["filename"] = event.filename.decode('utf-8').strip()
            case "read":
                tmp_json["fd"] = event.fd
                tmp_json["count"] = event.count
                tmp_json["buf"] = event.buf.decode('latin-1').strip()
                tmp_json["filename"] = event.filename.decode('utf-8').strip()
            case "dup2":
                tmp_json["oldfd"] = event.oldfd
                tmp_json["newfd"] = event.newfd
            case "close":
                tmp_json["fd"] = event.fd
            case "finit_module":
                tmp_json["fd"] = event.fd
                tmp_json["flags"] = event.flags
                tmp_json["uargs"] = event.uargs.decode('utf-8').strip()
                tmp_json["filename"] = event.filename.decode('utf-8').strip()
            case "mknodat":
                tmp_json["dfd"] = event.dfd
                tmp_json["filename"] = event.filename.decode('utf-8').strip()
                tmp_json["mode"] = event.mode
                tmp_json["dev"] = event.dev
            case "mount":
                tmp_json["dev_name"] = event.dev_name.decode('utf-8').strip()
                tmp_json["dir_name"] = event.dir_name.decode('utf-8').strip()
                tmp_json["type"] = event.type.decode('utf-8').strip()
                tmp_json["flags"] = event.flags
                tmp_json["data"] = event.data.decode('utf-8').strip()
            case "connect":
                tmp_json["sockfd"] = event.sockfd
                tmp_json["addrlen"] = event.addrlen
                match event.sa_family:
                    case socket.AF_UNIX:
                        tmp_json["sa_family"] = "AF_UNIX"
                        tmp_json["sock_filename"] = event.sock_filename.decode('utf-8')
                    case socket.AF_INET:
                        tmp_json["sa_family"] = "AF_INET"
                        tmp = str(socket.inet_ntoa(ctypes.c_uint(event.ip_addr).value.to_bytes(4, byteorder="big"))).split(".")
                        tmp_json["ip_addr"] = ".".join(tmp[::-1])
                        tmp_json["port"] = str(socket.ntohs(event.port))
                    case socket.AF_INET6:
                        tmp_json["sa_family"] = "AF_INET6"
                        tmp_json["ip6_addr"] = socket.inet_ntop(socket.AF_INET6, event.ip6_addr)
                        tmp_json["port"] = socket.ntohs(event.port)
            case "sendto":
                tmp_json["sockfd"] = event.sockfd
                tmp_json["msg_len"] = event.msg_len
                tmp_json["flags"] = event.flags
                tmp_json["addrlen"] = event.addrlen
                tmp_json["buff"] = event.buff.decode('utf-8').strip()
                match event.sa_family:
                    case socket.AF_UNIX:
                        tmp_json["sa_family"] = "AF_UNIX"
                        tmp_json["sock_filename"] = event.sock_filename.decode('utf-8')
                    case socket.AF_INET:
                        tmp_json["sa_family"] = "AF_INET"
                        tmp_json["ip_addr"] = socket.inet_ntoa(ctypes.c_uint(event.ip_addr).value.to_bytes(4, byteorder="big"))
                        tmp_json["port"] = socket.ntohs(event.port)
                    case socket.AF_INET6:
                        tmp_json["sa_family"] = "AF_INET6"
                        tmp_json["ip6_addr"] = socket.inet_ntop(socket.AF_INET6, event.ip6_addr)
                        tmp_json["port"] = socket.ntohs(event.port)
            case "setuid":
                tmp_json["new_uid"] = event.new_uid
            case "setgid":
                tmp_json["new_gid"] = event.new_gid
                
        rules.check_syscall(container_id, pid, tmp_json, rules_json, events_json, container.docker_config)
        # print(events_json.json())
        rules.check_events(events_json)
        
        rules.clean_events(events_json)

    b["events"].open_ring_buffer(handle_syscall)

    try:
        print("Отслеживание событий запущено")
        while True:
            b.ring_buffer_poll()
    except KeyboardInterrupt:
        print("Tracing stopped.")
        exit()
    
if __name__ == "__main__":
    main()
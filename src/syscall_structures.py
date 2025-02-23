import ctypes


class SyscallData(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * 32),
        ("pid", ctypes.c_uint32),
        ("tgid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("cgroup", ctypes.c_uint64),
        ("timestamp", ctypes.c_uint64),
        ("comm", ctypes.c_char * 16),
        ("cpu", ctypes.c_int),
        ("task_flags", ctypes.c_uint64),
        ("retval", ctypes.c_uint64),
    ]

class PtraceData(ctypes.Structure):
    _fields_ = [
        ("syscall_data", SyscallData),
        ("request", ctypes.c_uint64),
        ("pid", ctypes.c_uint64),
        ("addr", ctypes.c_uint64),
        ("data", ctypes.c_uint64),
    ]
    
class OpenByHandleAtData(ctypes.Structure):
    _fields_ = [
        ("syscall_data", SyscallData),
        ("mountdirfd", ctypes.c_uint32),
        ("filename", ctypes.c_char * 256),
        ("flags", ctypes.c_uint32),
    ]
    
class OpenatData(ctypes.Structure):
    _fields_ = [
        ("syscall_data", SyscallData),
        ("dfd", ctypes.c_uint32),
        ("filename", ctypes.c_char * 256),
        ("flags", ctypes.c_uint32),
        ("mode", ctypes.c_uint16),
    ]
    
class Pwrite64Data(ctypes.Structure):
    _fields_ = [
        ("syscall_data", SyscallData),
        ("fd", ctypes.c_uint32),
        ("buf", ctypes.c_char * 1024),
        ("count", ctypes.c_uint64),
        ("pos", ctypes.c_longlong),
        ("filename", ctypes.c_char * 256),
    ]
    
class Pread64Data(ctypes.Structure):
    _fields_ = [
        ("syscall_data", SyscallData),
        ("fd", ctypes.c_uint32),
        ("buf", ctypes.c_char * 1024),
        ("count", ctypes.c_uint64),
        ("pos", ctypes.c_longlong),
        ("filename", ctypes.c_char * 256),
    ]
    
class WriteData(ctypes.Structure):
    _fields_ = [
        ("syscall_data", SyscallData),
        ("fd", ctypes.c_uint32),
        ("buf", ctypes.c_char * 1024),
        ("count", ctypes.c_uint64),
        ("filename", ctypes.c_char * 256),
    ]
    
class ReadData(ctypes.Structure):
    _fields_ = [
        ("syscall_data", SyscallData),
        ("fd", ctypes.c_uint32),
        ("buf", ctypes.c_char * 1024),
        ("count", ctypes.c_uint64),
        ("filename", ctypes.c_char * 256),
    ]
    
class CloseData(ctypes.Structure):
    _fields_ = [
        ("syscall_data", SyscallData),
        ("fd", ctypes.c_uint32),
    ]
    
class FinitModuleData(ctypes.Structure):
    _fields_ = [
        ("syscall_data", SyscallData),
        ("fd", ctypes.c_uint32),
        ("uargs", ctypes.c_char * 256),
        ("flags", ctypes.c_uint32),
        ("filename", ctypes.c_char * 256),
    ]
    
class MknodatData(ctypes.Structure):
    _fields_ = [
        ("syscall_data", SyscallData),
        ("dfd", ctypes.c_uint32),
        ("filename", ctypes.c_char * 256),
        ("mode", ctypes.c_uint16),
        ("dev", ctypes.c_uint32),
    ]
    
class MountData(ctypes.Structure):
    _fields_ = [
        ("syscall_data", SyscallData),
        ("dev_name", ctypes.c_char * 256),
        ("dir_name", ctypes.c_char * 256),
        ("type", ctypes.c_char * 256),
        ("flags", ctypes.c_uint64),
        ("data", ctypes.c_char * 1024),
    ]
    
class ConnectData(ctypes.Structure):
    _fields_ = [
        ("syscall_data", SyscallData),
        ("sockfd", ctypes.c_uint32),
        ("sock_filename", ctypes.c_char * 108),
        ("addrlen", ctypes.c_uint32),
        ("sa_family", ctypes.c_uint16),
        ("port", ctypes.c_uint16),
        ("ip_addr", ctypes.c_uint32),
        ("ip6_addr", ctypes.c_ubyte * 16),
    ]

class SendtoData(ctypes.Structure):
    _fields_ = [
        ("syscall_data", SyscallData),  # Поля общей системной информации
        ("sa_family", ctypes.c_uint16),
        ("sockfd", ctypes.c_uint32),                      # Дескриптор сокета
        ("buff", ctypes.c_char * 256),                    # Буфер сообщения
        ("msg_len", ctypes.c_uint32),                     # Длина сообщения
        ("flags", ctypes.c_uint32),                       # Флаги
        ("addrlen", ctypes.c_uint32),                     # Длина адреса
        ("port", ctypes.c_uint16),                        # Порт
        ("ip_addr", ctypes.c_uint32),                     # IPv4-адрес
        ("ip6_addr", ctypes.c_ubyte * 16),                # IPv6-адрес
        ("sock_filename", ctypes.c_char * 108),           # Путь для UNIX-сокета
    ]
    
class Dup2Data(ctypes.Structure):
    _fields_ = [
        ("syscall_data", SyscallData),
        ("oldfd", ctypes.c_uint32),
        ("newfd", ctypes.c_uint32),
    ]
    
class SetuidData(ctypes.Structure):
    _fields_ = [
        ("syscall_data", SyscallData),
        ("new_uid", ctypes.c_uint32),
    ]
    
class SetgidData(ctypes.Structure):
    _fields_ = [
        ("syscall_data", SyscallData),
        ("new_gid", ctypes.c_uint32),
    ]
    
class GetDents64Data(ctypes.Structure):
    _fields_ = [
        ("syscall_data", SyscallData),
        ("fd", ctypes.c_uint32),
        ("filename", ctypes.c_char * 256),
    ]
    
class GetRandomData(ctypes.Structure):
    _fields_ = [
        ("syscall_data", SyscallData),
    ]
    
syscall_dict = {
    "ptrace": PtraceData,
    "openat": OpenatData,
    "pwrite64": Pwrite64Data,
    "pread64": Pread64Data,
    "write": WriteData,
    "dup2": Dup2Data,
    "close": CloseData,
    "finit_module": FinitModuleData,
    "mknodat": MknodatData,
    "mount": MountData,
    "connect": ConnectData,
    "sendto": SendtoData,
    "read": ReadData,
    "setuid": SetuidData,
    "setgid": SetgidData,
    "open_by_handle_at": OpenByHandleAtData,
    "getrandom": GetRandomData,
    "getdents64": GetDents64Data,
}
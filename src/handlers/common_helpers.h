#ifndef __SYSCALL_INFO_H
#define __SYSCALL_INFO_H

#include <uapi/linux/ptrace.h>
#include <linux/ptrace.h>
#include <net/sock.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/un.h>
#include <linux/in6.h>
#include <bcc/proto.h>

#define FILE_NAME_LEN 256
#define TYPE_LEN 32

struct syscall_data_t {
    char name[TYPE_LEN];        // Название процесса (Process name)
    u32 pid;                    // Идентификатор процесса (PID)
    u32 tgid;                   // Идентификатор группы процессов (TGID)
    u32 uid;                    // Идентификатор пользователя (UID)
    u32 gid;                    // Идентификатор группы (GID)
    u32 ppid;                   // Идентификатор родительского процесса (PPID)
    u64 cgroup;                 // Идентификатор контрольной группы (Cgroup ID)
    u64 timestamp;              // Время вызова или завершения системного вызова (Syscall time)
    char comm[TASK_COMM_LEN];   // Имя процесса (Task name)
    int cpu;                    // Идентификатор процессора (CPU ID)
    u64 task_flags;             // Флаги задачи (Task flags)
    u64 retval;                 // Возвращаемое значение
};

// Функция для заполнения общей информации о процессе
static void fill_syscall_data(struct syscall_data_t *syscall_data, char *syscall_name) {

    __builtin_strncpy(syscall_data->name, syscall_name, sizeof(syscall_data->name));
    syscall_data->pid = bpf_get_current_pid_tgid() >> 32;
    syscall_data->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    syscall_data->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    syscall_data->gid = bpf_get_current_uid_gid() >> 32;
    syscall_data->cgroup = bpf_get_current_cgroup_id();
    syscall_data->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&syscall_data->comm, sizeof(syscall_data->comm));
    syscall_data->cpu = bpf_get_smp_processor_id();
}

// для событий
BPF_RINGBUF_OUTPUT(events, 256 * 1024);

struct file_data_t {
    char filename[FILE_NAME_LEN];
    u32 fd;
};

// Таблица сопоставления fd и имени файла
BPF_HASH(opened_files, u64, struct file_data_t);

#endif
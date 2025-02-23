#include "handlers/common_helpers.h"

struct getdents64_data_t {
    struct syscall_data_t syscall_data;
    u32 fd;
    char filename[FILE_NAME_LEN];
};

BPF_HASH(getdents64_tmp_buffer, u64, struct getdents64_data_t);

TRACEPOINT_PROBE(syscalls, sys_enter_getdents64) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct pid_namespace *pid_ns;
    pid_ns = task->nsproxy->pid_ns_for_children;
    
    if (pid_ns->level <= 0) {
        return 0;
    }

    struct getdents64_data_t data = {};

    fill_syscall_data(&data.syscall_data, "getdents64");

    data.syscall_data.ppid = task->real_parent->pid;
    data.syscall_data.task_flags = task->flags;

    data.fd = args->fd;

    u64 file_id = ( bpf_get_current_pid_tgid() & 0xFFFFFFFF00000000 ) + args->fd;
    struct file_data_t *file_entry = opened_files.lookup(&file_id);
    if (file_entry && file_entry->fd == args->fd) {
        bpf_probe_read_kernel(&data.filename, sizeof(data.filename), file_entry->filename);
    }
    else {
        bpf_probe_read_kernel(&data.filename, sizeof(data.filename), NULL);
    }

    u64 temp_file_id = bpf_get_current_pid_tgid();
    getdents64_tmp_buffer.update(&temp_file_id, &data);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_getdents64) {
    u64 temp_file_id = bpf_get_current_pid_tgid();

    struct getdents64_data_t *data = getdents64_tmp_buffer.lookup(&temp_file_id);
    if (data == NULL) {
        return 0;
    }

    data->syscall_data.retval = args->ret;
    events.ringbuf_output(data, sizeof(*data), 0);

    getdents64_tmp_buffer.delete(&temp_file_id);
    return 0;
}
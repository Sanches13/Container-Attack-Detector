#include "handlers/common_helpers.h"

struct dup2_data_t {
    struct syscall_data_t syscall_data;
    u32 oldfd;
    u32 newfd;
};

BPF_HASH(dup2_tmp_buffer, u64, struct dup2_data_t);

TRACEPOINT_PROBE(syscalls, sys_enter_dup2) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct pid_namespace *pid_ns;
    pid_ns = task->nsproxy->pid_ns_for_children;
    
    if (pid_ns->level <= 0) {
        return 0;
    }

    struct dup2_data_t data = {};

    fill_syscall_data(&data.syscall_data, "dup2");

    data.syscall_data.ppid = task->real_parent->pid;
    data.syscall_data.task_flags = task->flags;

    data.oldfd = args->oldfd;
    data.newfd = args->newfd;

    u64 file_id = ( bpf_get_current_pid_tgid() & 0xFFFFFFFF00000000 ) + args->oldfd;

    struct file_data_t *file_entry = opened_files.lookup(&file_id);
    if (file_entry && file_entry->fd == args->oldfd) {
        u64 new_file_id = ( bpf_get_current_pid_tgid() & 0xFFFFFFFF00000000 ) + args->newfd;
        file_entry->fd = args->newfd;
        opened_files.update(&new_file_id, file_entry);
    }

    u64 temp_file_id = bpf_get_current_pid_tgid();
    dup2_tmp_buffer.update(&temp_file_id, &data);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_dup2) {
    u64 temp_file_id = bpf_get_current_pid_tgid();

    struct dup2_data_t *data = dup2_tmp_buffer.lookup(&temp_file_id);
    if (data == NULL) {
        return 0;
    }

    data->syscall_data.retval = args->ret;
    events.ringbuf_output(data, sizeof(*data), 0);

    dup2_tmp_buffer.delete(&temp_file_id);
    return 0;
}
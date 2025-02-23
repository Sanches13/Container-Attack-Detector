#include "handlers/common_helpers.h"

struct mknodat_data_t {
    struct syscall_data_t syscall_data;
    u32 dfd;
    char filename[FILE_NAME_LEN];
    u16 mode;
    u32 dev;
};

BPF_HASH(mknodat_tmp_buffer, u64, struct mknodat_data_t);

TRACEPOINT_PROBE(syscalls, sys_enter_mknodat) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct pid_namespace *pid_ns;
    pid_ns = task->nsproxy->pid_ns_for_children;
    
    if (pid_ns->level <= 0) {
        return 0;
    }

    struct mknodat_data_t data = {};

    fill_syscall_data(&data.syscall_data, "mknodat");

    data.syscall_data.ppid = task->real_parent->pid;
    data.syscall_data.task_flags = task->flags;

    data.dfd = args->dfd;
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);
    data.mode = args->mode;
    data.dev = args->dev;

    u64 temp_file_id = bpf_get_current_pid_tgid();
    mknodat_tmp_buffer.update(&temp_file_id, &data);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_mknodat) {
    u64 temp_file_id = bpf_get_current_pid_tgid();

    struct mknodat_data_t *data = mknodat_tmp_buffer.lookup(&temp_file_id);
    if (data == NULL) {
        return 0;
    }

    data->syscall_data.retval = args->ret;
    events.ringbuf_output(data, sizeof(*data), 0);

    mknodat_tmp_buffer.delete(&temp_file_id);
    return 0;
}
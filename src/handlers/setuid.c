#include "handlers/common_helpers.h"

struct setuid_data_t {
    struct syscall_data_t syscall_data;
    u32 new_uid;
};

BPF_HASH(setuid_tmp_buffer, u64, struct setuid_data_t);

TRACEPOINT_PROBE(syscalls, sys_enter_setuid) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct pid_namespace *pid_ns;
    pid_ns = task->nsproxy->pid_ns_for_children;
    
    if (pid_ns->level <= 0) {
        return 0;
    }

    struct setuid_data_t data = {};

    fill_syscall_data(&data.syscall_data, "setuid");

    data.syscall_data.ppid = task->real_parent->pid;
    data.syscall_data.task_flags = task->flags;

    data.new_uid = args->uid;

    u64 temp_file_id = bpf_get_current_pid_tgid();
    setuid_tmp_buffer.update(&temp_file_id, &data);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_setuid) {
    u64 temp_file_id = bpf_get_current_pid_tgid();

    struct setuid_data_t *data = setuid_tmp_buffer.lookup(&temp_file_id);
    if (data == NULL) {
        return 0;
    }

    data->syscall_data.retval = args->ret;

    events.ringbuf_output(data, sizeof(*data), 0);
    setuid_tmp_buffer.delete(&temp_file_id);
    
    return 0;
}
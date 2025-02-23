#include "handlers/common_helpers.h"

struct setgid_data_t {
    struct syscall_data_t syscall_data;
    u32 new_gid;
};

BPF_HASH(setgid_tmp_buffer, u64, struct setgid_data_t);

TRACEPOINT_PROBE(syscalls, sys_enter_setgid) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct pid_namespace *pid_ns;
    pid_ns = task->nsproxy->pid_ns_for_children;
    
    if (pid_ns->level <= 0) {
        return 0;
    }

    struct setgid_data_t data = {};

    fill_syscall_data(&data.syscall_data, "setgid");

    data.syscall_data.ppid = task->real_parent->pid;
    data.syscall_data.task_flags = task->flags;

    data.new_gid = args->gid;

    u64 temp_file_id = bpf_get_current_pid_tgid();
    setgid_tmp_buffer.update(&temp_file_id, &data);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_setgid) {
    u64 temp_file_id = bpf_get_current_pid_tgid();

    struct setgid_data_t *data = setgid_tmp_buffer.lookup(&temp_file_id);
    if (data == NULL) {
        return 0;
    }

    data->syscall_data.retval = args->ret;

    events.ringbuf_output(data, sizeof(*data), 0);
    setgid_tmp_buffer.delete(&temp_file_id);
    
    return 0;
}
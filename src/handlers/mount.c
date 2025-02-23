#include "handlers/common_helpers.h"

struct mount_data_t {
    struct syscall_data_t syscall_data;
    char dev_name[256];
    char dir_name[256];
    char type[256];
    u64 flags;
    char data[1024];
};

BPF_ARRAY(mount_data, struct mount_data_t, 1);
BPF_HASH(mount_tmp_buffer, u64, struct mount_data_t);

TRACEPOINT_PROBE(syscalls, sys_enter_mount) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct pid_namespace *pid_ns;
    pid_ns = task->nsproxy->pid_ns_for_children;
    
    if (pid_ns->level <= 0) {
        return 0;
    }

    int index = 0;
    struct mount_data_t *data = mount_data.lookup(&index);

    if (data == NULL) return 1;

    fill_syscall_data(&data->syscall_data, "mount");

    data->syscall_data.ppid = task->real_parent->pid;
    data->syscall_data.task_flags = task->flags;

    bpf_probe_read_user_str(data->dev_name, 256, args->dev_name);
    bpf_probe_read_user_str(data->dir_name, 256, args->dir_name);
    bpf_probe_read_user_str(data->type, 256, args->type);
    data->flags = args->flags;
    bpf_probe_read_user_str(data->data, 1024, args->data);

    u64 temp_file_id = bpf_get_current_pid_tgid();
    mount_tmp_buffer.update(&temp_file_id, data);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_mount) {
    u64 temp_file_id = bpf_get_current_pid_tgid();

    struct mount_data_t *data = mount_tmp_buffer.lookup(&temp_file_id);
    if (data == NULL) {
        return 0;
    }

    data->syscall_data.retval = args->ret;
    events.ringbuf_output(data, sizeof(*data), 0);

    mount_tmp_buffer.delete(&temp_file_id);
    return 0;
}
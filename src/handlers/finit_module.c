#include "handlers/common_helpers.h"

struct finit_module_data_t {
    struct syscall_data_t syscall_data;
    u32 fd;
    unsigned char uargs[256];
    u32 flags;
    char filename[256];
};

BPF_HASH(finit_module_tmp_buffer, u64, struct finit_module_data_t);
BPF_ARRAY(finit_module_data, struct finit_module_data_t, 1);

TRACEPOINT_PROBE(syscalls, sys_enter_finit_module) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct pid_namespace *pid_ns;
    pid_ns = task->nsproxy->pid_ns_for_children;
    
    if (pid_ns->level <= 0) {
        return 0;
    }

    int index = 0;
    struct finit_module_data_t *data = finit_module_data.lookup(&index);

    if (data == NULL) return 1;

    fill_syscall_data(&data->syscall_data, "finit_module");

    data->syscall_data.ppid = task->real_parent->pid;
    data->syscall_data.task_flags = task->flags;

    data->fd = args->fd;
    bpf_probe_read_user_str(data->uargs, sizeof(data->uargs), args->uargs);
    data->flags = args->flags;

    u64 file_id = ( bpf_get_current_pid_tgid() & 0xFFFFFFFF00000000 ) + args->fd;
    struct file_data_t *file_entry = opened_files.lookup(&file_id);
    if (file_entry && file_entry->fd == args->fd) {
        bpf_probe_read_kernel(data->filename, sizeof(data->filename), file_entry->filename);
    }
    else {
        bpf_probe_read_kernel(data->filename, sizeof(data->filename), NULL);
    }
    u64 temp_file_id = bpf_get_current_pid_tgid();
    finit_module_tmp_buffer.update(&temp_file_id, data);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_finit_module) {
    u64 temp_file_id = bpf_get_current_pid_tgid();

    struct finit_module_data_t *data = finit_module_tmp_buffer.lookup(&temp_file_id);
    if (data == NULL) {
        return 0;
    }

    data->syscall_data.retval = args->ret;
    events.ringbuf_output(data, sizeof(*data), 0);

    finit_module_tmp_buffer.delete(&temp_file_id);
    return 0;
}
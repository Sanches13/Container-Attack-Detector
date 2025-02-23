#include "handlers/common_helpers.h"

struct open_by_handle_at_data_t {
    struct syscall_data_t syscall_data;
    u32 mountdirfd;
    char filename[FILE_NAME_LEN];
    u32 flags;
};

BPF_HASH(open_by_handle_at_tmp_buffer, u64, struct open_by_handle_at_data_t);

TRACEPOINT_PROBE(syscalls, sys_enter_open_by_handle_at) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct pid_namespace *pid_ns;
    pid_ns = task->nsproxy->pid_ns_for_children;
    
    if (pid_ns->level <= 0) {
        return 0;
    }

    struct open_by_handle_at_data_t data = {};

    fill_syscall_data(&data.syscall_data, "open_by_handle_at");
    
    data.syscall_data.ppid = task->real_parent->pid;
    data.syscall_data.task_flags = task->flags;

    data.mountdirfd = args->mountdirfd;
    data.flags = args->flags;

    u64 file_id = ( bpf_get_current_pid_tgid() & 0xFFFFFFFF00000000 ) + args->mountdirfd;
    struct file_data_t *file_entry = opened_files.lookup(&file_id);
    if (file_entry && file_entry->fd == args->mountdirfd) {
        bpf_probe_read_kernel(&data.filename, sizeof(data.filename), file_entry->filename);
    }
    else {
        bpf_probe_read_kernel(&data.filename, sizeof(data.filename), NULL);
    }

    u64 temp_file_id = bpf_get_current_pid_tgid();
    open_by_handle_at_tmp_buffer.update(&temp_file_id, &data);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_open_by_handle_at) {
    u64 temp_file_id = bpf_get_current_pid_tgid();

    struct open_by_handle_at_data_t *data = open_by_handle_at_tmp_buffer.lookup(&temp_file_id);
    if (data == NULL) {
        return 0;
    }

    data->syscall_data.retval = args->ret;

    // получаем "итоговый" id файла из pid и номера полученного дескриптора
    u64 file_id = (bpf_get_current_pid_tgid() & 0xFFFFFFFF00000000) + args->ret;
    struct file_data_t file_entry = {};
    bpf_probe_read_str(&file_entry.filename, sizeof(file_entry.filename), data->filename);
    file_entry.fd = args->ret;
    opened_files.update(&file_id, &file_entry);

    events.ringbuf_output(data, sizeof(*data), 0);
    open_by_handle_at_tmp_buffer.delete(&temp_file_id);
    
    return 0;
}
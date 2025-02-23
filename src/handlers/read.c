#include "handlers/common_helpers.h"

#define WRITE_BUF_MAX_LEN 1024
#define MIN(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })

struct read_data_t {
    struct syscall_data_t syscall_data;
    u32 fd;
    unsigned char buf[WRITE_BUF_MAX_LEN];
    u64 count;
    char filename[256];
};

BPF_ARRAY(read_data, struct read_data_t, 1);
BPF_HASH(read_tmp_buffer, u64, struct read_data_t);

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct pid_namespace *pid_ns;
    pid_ns = task->nsproxy->pid_ns_for_children;
    
    if (pid_ns->level <= 0) {
        return 0;
    }

    int index = 0;
    struct read_data_t *data = read_data.lookup(&index);

    if (data == NULL) return 1;

    fill_syscall_data(&data->syscall_data, "read");

    data->syscall_data.ppid = task->real_parent->pid;
    data->syscall_data.task_flags = task->flags;

    data->fd = args->fd;
    u32 result_len = MIN(WRITE_BUF_MAX_LEN, args->count);
    bpf_probe_read_user_str(data->buf, result_len, args->buf);
    data->count = result_len;

    u64 file_id = ( bpf_get_current_pid_tgid() & 0xFFFFFFFF00000000 ) + args->fd;
    struct file_data_t *file_entry = opened_files.lookup(&file_id);
    if (file_entry && file_entry->fd == args->fd) {
        bpf_probe_read_kernel(data->filename, sizeof(data->filename), file_entry->filename);
    }
    else {
        bpf_probe_read_kernel(data->filename, sizeof(data->filename), NULL);
    }

    u64 temp_file_id = bpf_get_current_pid_tgid();
    read_tmp_buffer.update(&temp_file_id, data);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_read) {
    u64 temp_file_id = bpf_get_current_pid_tgid();

    struct read_data_t *data = read_tmp_buffer.lookup(&temp_file_id);
    if (data == NULL) {
        return 0;
    }

    data->syscall_data.retval = args->ret;
    events.ringbuf_output(data, sizeof(*data), 0);

    read_tmp_buffer.delete(&temp_file_id);
    return 0;
}
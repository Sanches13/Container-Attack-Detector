#include "handlers/common_helpers.h"

struct sendto_data_t {
    struct syscall_data_t syscall_data;
    u16 sa_family;
    u32 sockfd;
    char buff[256];
    u32 msg_len;
    u32 flags;
    u32 addrlen;
    u16 port;
    u32 ip_addr;
    struct in6_addr ip6_addr;
    char sock_filename[108];
};

BPF_HASH(sendto_tmp_buffer, u64, struct sendto_data_t);
BPF_ARRAY(sendto_data, struct sendto_data_t, 1);

TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct pid_namespace *pid_ns;
    pid_ns = task->nsproxy->pid_ns_for_children;
    
    if (pid_ns->level <= 0) {
        return 0;
    }

    struct sockaddr *sockaddr_ptr = (struct sockaddr *)args->addr;
    u16 sa_family;

    bpf_probe_read_user(&sa_family, sizeof(sa_family), &sockaddr_ptr->sa_family);

    if (sa_family == AF_UNIX || sa_family == AF_INET || sa_family == AF_INET6) {
        int index = 0;
        struct sendto_data_t *data = sendto_data.lookup(&index);

        if (data == NULL) return 1;

        fill_syscall_data(&data->syscall_data, "sendto");
        data->syscall_data.ppid = task->real_parent->tgid;
        data->syscall_data.task_flags = task->flags;

        data->sa_family = sa_family;

        data->sockfd = args->fd;
        data->msg_len = args->len;
        data->flags = args->flags;
        data->addrlen = args->addr_len;
        bpf_probe_read_user(&data->buff, sizeof(data->buff), &args->buff);

        if (sa_family == AF_UNIX) {
            struct sockaddr_un *sockaddr_un_ptr = (struct sockaddr_un *)sockaddr_ptr;
            bpf_probe_read_user(&data->sock_filename, sizeof(data->sock_filename), &sockaddr_un_ptr->sun_path);
        } else if (sa_family == AF_INET) {
            struct sockaddr_in *sockaddr_in_ptr = (struct sockaddr_in *)sockaddr_ptr;
            bpf_probe_read_user(&data->port, sizeof(data->port), &sockaddr_in_ptr->sin_port);
            bpf_probe_read_user(&data->ip_addr, sizeof(data->ip_addr), &sockaddr_in_ptr->sin_addr);
        } else if (sa_family == AF_INET6) {
            struct sockaddr_in6 *sockaddr_in6_ptr = (struct sockaddr_in6 *)sockaddr_ptr;
            bpf_probe_read_user(&data->port, sizeof(data->port), &sockaddr_in6_ptr->sin6_port);
            bpf_probe_read_user(&data->ip6_addr, sizeof(data->ip6_addr), &sockaddr_in6_ptr->sin6_addr);
        }

        u64 temp_file_id = bpf_get_current_pid_tgid();
        sendto_tmp_buffer.update(&temp_file_id, data);
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendto) {
    u64 temp_file_id = bpf_get_current_pid_tgid();

    struct sendto_data_t *data = sendto_tmp_buffer.lookup(&temp_file_id);
    if (data == NULL) {
        return 0;
    }

    data->syscall_data.retval = args->ret;
    events.ringbuf_output(data, sizeof(*data), 0);

    sendto_tmp_buffer.delete(&temp_file_id);
    return 0;
}
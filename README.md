# Container-Attack-Detector
System for detecting computer attacks on Docker-containers in Linux

## Description
The diploma project **Container Attack Detector (CAD)** is a proof of concept system for detecting attacks on Docker containers on Linux. It is a variant of intercepting system calls based on eBPF technology (in particular, BCC) and compares these events with patterns describing illegal actions in the system (actions of an attacker during computer attacks).

![project](/img/project.png)

## Install
To install the project, do the following:

```bash
git clone https://github.com/Sanches13/Container-Attack-Detector.git
pip3 install -r requirements.txt
```

You may need to install some other libraries to work with ebpf 🙃

## Usage
To run you need sudo rights:

```bash
cd src
sudo python3 handler.py -r <rules_file> -f <rules_format>
```

Options:

 - `-r, --rules` - a file with rules describing intercepted events;
 - `-f, --format` - format in which the rules are written (json or csdsl).

## Rules
To create rules you can use two formats: JSON and CSDSL.

### JSON
Template for rules in JSON format:

```json
[
    {
        "name": "rule1",
        "subrules": [
            {
                "name": "subrule1",
                "syscall": {
                    "name": "write",
                    "filename": "/host/proc/sys/kernel/core_pattern"
                    "another_argument": ...,
                    ...
                }
            }
        ],
        "docker_config": {
            "CapAdd": [],
            "PidMode": "",
            "Privileged": false,
            "SecurityOpt": [],
            "Mounts": []
        }
    }
]
```

### CSDSL
Container Security Domain-Specific Language (DSL) - a language for a simplified description of events occurring in a container, initial configurations of containers, and rules for detecting computer attacks. Consists of three entities: Event, Configuration, Rule. Template for rules in CSDSL format:

```
Configuration DAC_READ_SEARCH_granted {
	CapAdd: DAC_READ_SEARCH
}
Event open_by_handle_at_syscall {
	name: open_by_handle_at
	filename: /etc/hostname
}
Event read_syscall {
	name: read
	filename: /etc/hostname
}
Event getrandom_syscall {
	name: getrandom
}
Event getdents64_syscall {
	name: getdents64
	filename: /etc/hostname
}
Rule DAC_READ_SEARCH_detection {
	detect open_by_handle_at_syscall and read_syscall and getrandom_syscall and getdents64_syscall if DAC_READ_SEARCH_granted
}
```

## Tracked syscalls
Currently, the project implements interception of the following system calls: read, write, close, dup2, connect, finit_module, getdents65, getrandom, mknodat, mount, open_by_handle_at, openat, pread64, ptrace, pwrite64, read, sendto, setgid, setuid. If necessary, you can add modules to intercept other system calls.

## Example
![test](/img/test.png)
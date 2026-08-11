// go:build ignore  // Build constraint to ignore this file during Go builds

#undef __WCHAR_TYPE__
#define __WCHAR_TYPE__ u16
#include "vmlinux.h"
#include "libbpf/src/bpf_helpers.h"
#include "libbpf/src/bpf_core_read.h"
#include "libbpf/src/bpf_tracing.h"
#include <stddef.h>
#include "common.h"

/// @description "Process ID to trace."
const volatile int pid_target = 0; // Volatile constant for the target PID; if 0, trace all PIDs

#define TASK_COMM_LEN 16

#define INPUT_PATH_MAX 1024
#define EPERM 1
#define MAY_READ		0x00000004
#define MAY_WRITE 0x2
#define PROC_SUPER_MAGIC 0x9fa0

#define PTRACE_MODE_READ    0x01  /* 1  */
#define PTRACE_MODE_ATTACH  0x02  /* 2  */
#define PTRACE_MODE_NOAUDIT 0x04  /* 4  */
#define PTRACE_MODE_FSCREDS 0x08  /* 8  */
#define PTRACE_MODE_REALCREDS 0x10 /* 16 */

#define VIOL_TRUSTED 2
#define VIOL_RESTRICTED 3
#define VIOL_EXECUTE 4
#define VIOL_GPU 5
#define VIOL_MAP_SECURITY 6
#define VIOL_TASK_KILL 7
#define VIOL_PTRACE 8
#define VIOL_BIND_MOUNT 9
#define VIOL_FILELESS_EXEC 10
#define VIOL_ANON_MAP_EXEC 11
#define VIOL_LD_ENV 12
#define VIOL_NETWORK_EGRESS 13
#define VIOL_BPF_LOAD 14
#define VIOL_BPF_PIN 15

#define VIOL_FSVERITY_DENIED 17

#define FSVERITY_MAX_DIGEST_SIZE 64


// Index's in tempmap
#define TEMP_FILEPATH_PATH_CHECK 0
#define TEMP_FILEPATH_TASK_EXEC_FALLBACK 2
#define TEMP_FILEPATH_PATH_RENAME_OLD 3
#define TEMP_FILEPATH_PATH_RENAME_NEW 4
#define TEMP_FILEPATH_PATH_UNLINK 5
#define TEMP_FILEPATH_PATH_RMDIR 6
#define TEMP_FILEPATH_PATH_BIND_MOUNT 7
#define TEMP_FILEPATH_TASK_EXE_FALLBACK 8
#define TEMP_FILEPATH_OPENAT_EXE_FALLBACK 9
#define TEMP_FILEPATH_MMAP_FILE 10

#define TEMP_CONTAINER_PATH_TRUSTED_EXECUTABLE 0
#define TEMP_CONTAINER_PATH_RESTRICTED_FILEPATH 1
#define TEMP_CONTAINER_PATH_EXEC_FALLBACK 2
#define TEMP_CONTAINER_PATH_BPRM 3
#define TEMP_CONTAINER_PATH_ALLOWED_PTRACE_EXECUTABLE 4
#define TEMP_CONTAINER_PATH_FSVERITY 5
#define TEMP_FILEPATH_TASK_CWD 10

// Index's for file_info temp map
#define TEMP_FILE_INFO_FILE_OPEN 0
#define TEMP_FILE_INFO_BPRM_CHECK 1

// Define the maximum number of extensions and maximum extension length
#define MAX_EXTENSIONS 50
#define MAX_EXTENSION_LENGTH 16
#define MAX_PROCESS_NAMES 50
#define MAX_PROCESS_NAME_LENGTH 16

// Capture one extra argv slot so we can observe the NULL terminator for exact-match policies.
#define MAX_EXACT_ARGS 64
#define MAX_ARGS (MAX_EXACT_ARGS + 1)
#define MAX_ARG_LEN 128 // Maximum length of each argument

// Define constants for file access modes
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR   2
#define O_ACCMODE 3

// Define file type constants if not already defined
#define S_IFMT  0170000
#define S_IFDIR 0040000

// Define memory protection and mapping constants
#define PROT_EXEC 0x4
#define MAP_ANONYMOUS 0x20

#define ACCESS_READ 1
#define ACCESS_WRITE 2

// Check for character device file type
#define S_IFCHR 0020000

// Mount flags for bind mount detection
#define MS_BIND 4096

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef SOCK_STREAM
#define SOCK_STREAM 1
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#define ETH_P_IP 0x0800

#define INVALID_CGROUP_ID 0xFFFFFFFFFFFFFFFF
#define INVALID_MNT_NS_ID 0

#define RINGBUF_SIZE (1 << 24)
#define BITMASK_WORDS 2
#define BITMASK_BITS_PER_WORD 32

#define INODE_POLICY_CACHE_NO_POLICY 0
#define INODE_POLICY_CACHE_ACCESS_INDEX 1
#define INODE_POLICY_CACHE_GLOBAL_READ_ONLY 2
#define INODE_POLICY_CACHE_ACCESS_INDEX_AND_GLOBAL_RO 3

struct container_id {
    u64 cgroup_id;
    u64 container_correlation_counter_index;
    u64 timestamp;
};

struct process_id {
    u32 tgid;
    u64 start_time;
    struct container_id container;
    char boot_id[41];
};

struct file_info {
    char filename[INPUT_PATH_MAX];
    struct process_id process;
    u32 open_mode;
    char exepath[INPUT_PATH_MAX];
};

struct bitmask_array {
    u32 words[BITMASK_WORDS];
};

struct access_control {
    struct bitmask_array read;
    struct bitmask_array write;
    struct bitmask_array execute;
    u32 gpu;
    struct bitmask_array ip_egress;
    struct bitmask_array ip_exclusive_owner;
    u32 output_openats;
};

struct inode_cache_key {
    u64 mntns_id;
    u64 mount_id;
    u64 inode;
};

struct inode_policy_cache_value {
    u32 access_index;
    u8 state;
};

// Define the event structure that will be sent to user space

struct violation {
    struct process_id process;
    u64 timestamp;
    u32 type;
    char filename[INPUT_PATH_MAX];
    char exepath[INPUT_PATH_MAX];
};

struct openat_event
{
    struct process_id process;
    char filename[INPUT_PATH_MAX]; // Filename being accessed
    u32 open_mode;
    char exepath[INPUT_PATH_MAX];  // Executable path of the process
};

struct execve_event_t {
    char comm[TASK_COMM_LEN];
    char exepath[INPUT_PATH_MAX];
    struct process_id process;
    struct process_id parent;
    char argv[MAX_ARGS][MAX_ARG_LEN]; // Arguments plus one terminator-observation slot so that we can observe the NULL terminator for args.
    char envp[MAX_ARGS][MAX_ARG_LEN]; // Environment variables plus one extra slot
};

struct path_check_ctx {
    const char *filename;
    int open_mode;
    struct access_control access;
    bool should_block;
    bool found_policy;
    bool found_global_read_only;
    u32 matched_access_index;
    u32 policy_id;
};

struct path_container_id_component_ctx {
    const char *path;
    u64 container_correlation_counter_index;
    u32 component_start;
    u32 component_len;
    u32 policy_id;
    u8  saw_path_byte;
};
struct task_ctx {
    struct access_control access;
    struct execve_event_t execve_event; // this is used to store the execve event for the process
    u32 is_protected_process;
    u32 has_been_pushed; // this is used so that we don't log the same process multiple times in trace_execve
    u32 execve_argv_exact_ready; // set when trace_execve captured the full argv for the current exec
    u32 ld_env_detected; // this is used to identify if the process has LD_* environment variables
    u32 procstat_gate;  /* one-shot allow token */
    u32 procstat_pid;   /* target task pid (/proc/<pid>/stat) */
    u32 access_initialized; // this is used to identify if the access control has been initialized for the process
};

struct process_metadata { // we have a struct for when more values are added to the process metadata
    u32 has_violated_policy; // this is used to identify if the process has violated the policy
};

struct path_key {
    u32 policy_id;
    char directory_path[INPUT_PATH_MAX];
};

struct ip_to_id_key {
    u32 policy_id;
    u32 dst_ipv4;
    u16 dst_port;
    u16 _pad;
};

struct container_context {
    u32 policy_id;
    u64 correlation_index;
};

struct fsverity_digest_bpf {
    __u16 digest_algorithm;
    __u16 digest_size;
    __u8  digest[FSVERITY_MAX_DIGEST_SIZE];
};

struct fsverity_allowlist_key {
    __u16 alg;
    __u8  digest[FSVERITY_MAX_DIGEST_SIZE];
};

extern int bpf_get_fsverity_digest(struct file *file, struct bpf_dynptr *digest_p) __ksym __weak;

struct python_identifier {
    struct path_key executable;
    char cwd[INPUT_PATH_MAX];
    char argv[MAX_ARGS][MAX_ARG_LEN];
};

// ----------------- Maps for storing data for securing bpf itself (meta security maps)-----------------
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} bomfather_userspace_process_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} bomfather_should_stop_shutdown SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} bomfather_should_secure_maps SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} bomfather_block_ptrace SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} bomfather_block_in_memory_exec SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} bomfather_restrict_bpf_ops SEC(".maps");

// ----------------- Maps for storing misc data-----------------

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64); // cgroup id
    __type(value, struct container_id); // does the cgroup exist
} bomfather_active_cgroups SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct process_id); // pid
    __type(value, struct process_metadata);
} bomfather_process_metadata SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[41]); // 41 characters for the boot id (UUID)
} bomfather_boot_id SEC(".maps");
// ----------------- Maps for storing security policies-----------------
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, struct path_key);
    __type(value, struct access_control);
} bomfather_trusted_executables SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, struct path_key);
    __type(value, u32);
} bomfather_ld_env_allowed_executables SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, struct path_key);
    __type(value, u32);
} bomfather_allowed_ptrace_executables SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 30);
    __type(key, struct path_key);
    __type(value, u32);
} bomfather_dir_to_id SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, struct inode_cache_key);
    __type(value, struct inode_policy_cache_value);
} bomfather_inode_policy_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 30);
    __type(key, struct path_key);
    __type(value, u32);
} bomfather_executable_to_id SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct ip_to_id_key);
    __type(value, u32);
} bomfather_ip_to_id SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, struct bitmask_array);
} bomfather_exclusive_ip_mask SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} bomfather_restrict_gpu_access SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, struct path_key);
    __type(value, u32);
} bomfather_global_read_only SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct path_key);
    __type(value, struct fsverity_allowlist_key);
} bomfather_fsverity_pinlist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);  // mount namespace id
    __type(value, struct container_context);
} bomfather_mntns_to_container_context SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, char[64]);  // container id
    __type(value, struct container_context);
} bomfather_container_id_to_container_context SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, u64);  // cgroup id
    __type(value, struct container_context);
} bomfather_cgroup_id_to_container_context SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct python_identifier);  // python identifier
    __type(value, struct access_control);
} bomfather_python_identifier_id SEC(".maps");

// ----------------- Config map for runtime flags -----------------
// Single boolean: true = enable printk debug, false = disable
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u8);
} bomfather_debug_config SEC(".maps");

#define DBG_PRINTK(fmt, ...)                               \
    do {                                                   \
        u32 __key = 0;                                     \
        u8 *__cfg = bpf_map_lookup_elem(&bomfather_debug_config, &__key); \
        if (__cfg && *__cfg) {                             \
            bpf_printk(fmt, ##__VA_ARGS__);                 \
        }                                                  \
    } while (0)

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} bomfather_should_output_openats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} bomfather_should_stop_ld_env SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} bomfather_security_level SEC(".maps");

// ----------------- INODE CACHE STATS -----------------
#define BUCKET_WIDTH_NS 1000000000ULL  // 1 second buckets
#define MAX_BUCKETS 300                // 300 seconds = 5 minutes

struct inode_cache_stats {
    __u64 abs_bucket;
    __u64 lookups;
    __u64 hits_no_policy;
    __u64 hits_allow;
    __u64 hits_deny;
    __u64 misses_walk;
    __u64 fills;
    __u64 skips_nlink;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_BUCKETS);
    __type(key, __u32);
    __type(value, struct inode_cache_stats);
} bomfather_inode_cache_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} bomfather_inode_cache_stats_epoch_map SEC(".maps");

enum inode_cache_stat {
    INODE_CACHE_STATS_LOOKUPS = 0,
    INODE_CACHE_STATS_HITS_NO_POLICY,
    INODE_CACHE_STATS_HITS_ALLOW,
    INODE_CACHE_STATS_HITS_DENY,
    INODE_CACHE_STATS_MISSES_WALK,
    INODE_CACHE_STATS_FILLS,
    INODE_CACHE_STATS_SKIPS_NLINK,
    INODE_CACHE_STATS_MAX,
};


// ----------------- Maps for storing temporary data -----------------

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, u32);
    __type(value, struct file_info);
} bomfather_file_info_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 11);
    __type(key, u32);
    __type(value, char[INPUT_PATH_MAX]);
} bomfather_temp_filename_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct python_identifier);
} bomfather_temp_python_identifier_map SEC(".maps");

// Temporary storage for composite keys (avoid large stack frames)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 6);
    __type(key, u32);
    __type(value, struct path_key);
} bomfather_temp_path_key_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct fsverity_digest_bpf);
} bomfather_fsverity_scratch SEC(".maps");

// ----------------- TASK STORAGE MAP -----------------
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);  // Required for task storage
    __type(key, int);                       // Must be 4 bytes per docs
    __type(value, struct task_ctx);
} bomfather_task_security SEC(".maps");

// ----------------- Jump Table -----------------
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 5);
    __type(key, u32);
    __type(value, u32);
} bomfather_file_open_jump_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} bomfather_mount_check_jump_table SEC(".maps");


// ----------------- Maps for sending data to userspace-----------------
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} bomfather_log_failures SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF); // Map type is ring buffer for efficient communication
    __uint(max_entries, RINGBUF_SIZE);       // Buffer size: 16MB (1 << 24 bytes)
} bomfather_openat_events SEC(".maps");                  // Place the map in the ".maps" section

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); // Map type is perf event array
    __uint(max_entries, RINGBUF_SIZE);      // Buffer size: 16MB (1 << 24 bytes)
} bomfather_execve_events SEC(".maps");                    // Place the map in the ".maps" section


static __always_inline void inode_cache_stats_inc(u32 idx) {
    __u32 zero = 0;
    __u64 *epoch = bpf_map_lookup_elem(&bomfather_inode_cache_stats_epoch_map, &zero);
    if (!epoch) {
        return;
    }
    __u64 now = bpf_ktime_get_ns();
    if (*epoch == 0) {
        *epoch = now;
    }
    __u64 abs_bucket = (now - *epoch) / BUCKET_WIDTH_NS;
    __u32 bucket = (__u32)(abs_bucket % MAX_BUCKETS);

    struct inode_cache_stats *b = bpf_map_lookup_elem(&bomfather_inode_cache_stats_map, &bucket);
    if (!b) {
        return;
    }

    // Ring buffer: clear a slot when it is reused for a new absolute second.
    if (b->abs_bucket != abs_bucket) {
        __builtin_memset(b, 0, sizeof(*b));
        b->abs_bucket = abs_bucket;
    }

    switch (idx) {
        case INODE_CACHE_STATS_LOOKUPS:        b->lookups++; break;
        case INODE_CACHE_STATS_HITS_NO_POLICY: b->hits_no_policy++; break;
        case INODE_CACHE_STATS_HITS_ALLOW:     b->hits_allow++; break;
        case INODE_CACHE_STATS_HITS_DENY:      b->hits_deny++; break;
        case INODE_CACHE_STATS_MISSES_WALK:     b->misses_walk++; break;
        case INODE_CACHE_STATS_FILLS:          b->fills++; break;
        case INODE_CACHE_STATS_SKIPS_NLINK:    b->skips_nlink++; break;
    }
}

// ----------------- SMALL UTILITY HELPERS -----------------

static __always_inline bool is_character_device(int mode) {
    return (mode & S_IFMT) == S_IFCHR;
}

static __always_inline bool should_kill_process() {
    u32 zero = 0;
    u32 *should_kill = bpf_map_lookup_elem(&bomfather_security_level, &zero);
    if (should_kill && *should_kill >= 3) {
        return true;
    }
    return false;
}
static __always_inline bool should_block_process() {
    u32 zero = 0;

    u32 *should_block = bpf_map_lookup_elem(&bomfather_security_level, &zero);
    if (should_block && *should_block >= 2) {
        return true;
    }

    return false;
}
static __always_inline int return_value() {
    u32 zero = 0;
    u32 *should_monitor = bpf_map_lookup_elem(&bomfather_security_level, &zero);
    if (should_monitor == NULL || *should_monitor >= 1) {
        return -EPERM;
    }
    return 0;
}

// Returns true only when this is a valid IPv4 TCP connect attempt and dst_addr is filled.
static __always_inline bool get_ipv4_tcp_connect_destination(
    struct socket *sock,
    struct sockaddr *address,
    int addrlen,
    struct sockaddr_in *dst_addr
) {
    if (!sock || !dst_addr) {
        return false;
    }

    int sock_type = BPF_CORE_READ(sock, type);
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk) {
        return false;
    }
    int protocol = BPF_CORE_READ(sk, sk_protocol);

    if (sock_type != SOCK_STREAM || protocol != IPPROTO_TCP) {
        return false;
    }

    if (address == NULL || addrlen < sizeof(struct sockaddr_in)) {
        return false;
    }

    if (bpf_probe_read_kernel(dst_addr, sizeof(*dst_addr), address)) {
        return false;
    }

    return dst_addr->sin_family == AF_INET;
}

static __always_inline unsigned int get_major(dev_t dev) {
    return ((unsigned int)(dev >> 20) & 0xfff); // Shift right by 20 and mask with 12 bits
}

static __always_inline bool is_directory(struct inode *inode, int mode) {
    return (mode & S_IFMT) == S_IFDIR;
}

static __always_inline struct task_ctx *get_task_ctx(struct task_struct *task, bool should_create) {
    return (struct task_ctx *)bpf_task_storage_get(&bomfather_task_security, task, NULL, should_create ? BPF_LOCAL_STORAGE_GET_F_CREATE : 0);
}

static __always_inline void get_boot_id_str(char out[41]) {
    u32 zero = 0;
    char *p = bpf_map_lookup_elem(&bomfather_boot_id, &zero);
    if (!p) {
        out[0] = 0;
        return;
    }
    bpf_probe_read_kernel(out, 41, p);
}

// ----------------- MOUNT NAMESPACE HELPERS -----------------

// Return the container context if there is a match for the current mount namespace, otherwise return NULL.
static __always_inline struct container_context *get_container_context_for_task_mnt_ns(struct task_struct *task) {
    struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
    if (!nsproxy) {
        return NULL;
    }

    struct mnt_namespace *mnt_ns = BPF_CORE_READ(nsproxy, mnt_ns);
    if (!mnt_ns) {
        return NULL;
    }

    u32 mnt_ns_inum = 0;
    if (BPF_CORE_READ_INTO(&mnt_ns_inum, mnt_ns, ns.inum)) {
        return NULL;
    }
    u64 mnt_ns_id = mnt_ns_inum;
    return bpf_map_lookup_elem(&bomfather_mntns_to_container_context, &mnt_ns_id);
}

static __always_inline u64 get_cgroup_id_from_task(struct task_struct *task) {
    struct cgroup *cgrp = BPF_CORE_READ(task, cgroups, dfl_cgrp);
    if (!cgrp) {
        return INVALID_CGROUP_ID;
    }

    struct kernfs_node *kn = BPF_CORE_READ(cgrp, kn);
    if (!kn) {
        return INVALID_CGROUP_ID;
    }

    return BPF_CORE_READ(kn, id);
}

static __always_inline struct container_context *get_container_context_for_task(struct task_struct *task) {
    struct container_context *ctx = get_container_context_for_task_mnt_ns(task);
    if (ctx) {
        return ctx;
    }

    u64 cgroup_id = get_cgroup_id_from_task(task);
    if (cgroup_id == INVALID_CGROUP_ID) {
        return NULL;
    }
    return bpf_map_lookup_elem(&bomfather_cgroup_id_to_container_context, &cgroup_id);
}

static __always_inline u32 *get_policy_id_for_task_mnt_ns(struct task_struct *task) {
    struct container_context *ctx = get_container_context_for_task(task);
    if (!ctx) {
        return NULL;
    }
    return &ctx->policy_id;
}

static __always_inline u32 *get_policy_id_for_current_mnt_ns(void) {
    struct task_struct *task = bpf_get_current_task_btf();
    if (!task) {
        return NULL;
    }
    return get_policy_id_for_task_mnt_ns(task);
}

static __always_inline bool build_inode_cache_key(struct file *file, struct inode *inode, struct inode_cache_key *out) {
    u32 nlink = 0;

    if (!file || !inode || !out) {
        return false;
    }

    if (BPF_CORE_READ_INTO(&nlink, inode, i_nlink)) {
        return false;
    }

    if (nlink != 1) {
        inode_cache_stats_inc(INODE_CACHE_STATS_SKIPS_NLINK);
        return false;
    }

    __builtin_memset(out, 0, sizeof(*out));

    struct task_struct *task = bpf_get_current_task_btf();
    if (!task) {
        return false;
    }

    // get the mount namespace id
    struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
    if (!nsproxy) {
        return false;
    }

    struct mnt_namespace *mnt_ns = BPF_CORE_READ(nsproxy, mnt_ns);
    if (!mnt_ns) {
        return false;
    }

    u32 mnt_ns_inum = 0;
    if (BPF_CORE_READ_INTO(&mnt_ns_inum, mnt_ns, ns.inum)) {
        return false;
    }
    out->mntns_id = mnt_ns_inum;

    // get the mount id
    struct vfsmount *vfsmnt = BPF_CORE_READ(file, f_path.mnt);
    if (!vfsmnt) {
        return false;
    }

    struct mount *mnt = real_mount(vfsmnt);
    if (!mnt) {
        return false;
    }

    // newer kernels might have mnt_id_unique, otherwise we use mnt_id
    if (bpf_core_field_exists(mnt->mnt_id_unique)) {
        if (BPF_CORE_READ_INTO(&out->mount_id, mnt, mnt_id_unique)) {
            return false;
        }
    } else {
        int mount_id = 0;
        if (BPF_CORE_READ_INTO(&mount_id, mnt, mnt_id)) {
            return false;
        }
        out->mount_id = (u64)(u32)mount_id;
    }

    // get the inode number
    u64 inode_ino = 0;
    if (BPF_CORE_READ_INTO(&inode_ino, inode, i_ino)) {
        return false;
    }
    out->inode = inode_ino;

    return true;
}

 // ----------------- CGROUP HELPERS -----------------

 static __inline void remove_cgroup_id(struct bpf_raw_tracepoint_args *ctx) {
    u64 id = 0;
    id = ctx->args[2];
    bpf_map_delete_elem(&bomfather_active_cgroups, &id);
}

static __always_inline struct container_id get_current_container_id_from_task(struct task_struct *task) {
    u64 cgroup_id = get_cgroup_id_from_task(task);
    if (cgroup_id == INVALID_CGROUP_ID) {
        return (struct container_id){INVALID_CGROUP_ID, 0, 0};
    }

    struct container_context *container_ctx = get_container_context_for_task(task);
    if (!container_ctx) {
        return (struct container_id){INVALID_CGROUP_ID, 0, 0};
    }

    u64 timestamp = 0;
    struct container_id *container_fetch = bpf_map_lookup_elem(&bomfather_active_cgroups, &cgroup_id);
    if (container_fetch) {
        timestamp = container_fetch->timestamp;
    }

    return (struct container_id){
        cgroup_id,
        container_ctx->correlation_index,
        timestamp,
    };
}

static __always_inline struct container_id get_current_container_id(void) {
    struct task_struct *task = bpf_get_current_task_btf();
    if (!task) {
        return (struct container_id){INVALID_CGROUP_ID, 0};
    }
    return get_current_container_id_from_task(task);
}

// ----------------- GENERAL HELPERS -----------------
static __always_inline void  get_process_id_from_task(struct task_struct *task, struct process_id *process) {
    struct task_struct *leader = BPF_CORE_READ(task, group_leader);

    __u64 start_ns = 0;
    if (bpf_core_field_exists(leader->start_boottime)) { // newer kernels
        start_ns = BPF_CORE_READ(leader, start_boottime);
    } else {
        start_ns = BPF_CORE_READ(leader, start_time);
    }

    process->tgid = BPF_CORE_READ(task, tgid);
    process->start_time = start_ns;
    process->container = get_current_container_id_from_task(task);
    get_boot_id_str(process->boot_id);
}

static __always_inline void get_process_id(struct process_id *process) {
    struct task_struct *task = bpf_get_current_task_btf();
    if (!task) {
        return;
    }
    get_process_id_from_task(task, process);
}

static __always_inline void get_filename(struct file *file, struct dentry *dentry, char *buf, size_t size) {
    // Try to get the full path using get_path_str from path.h
    char *path_str = get_path_str(&file->f_path);
    if (path_str) {
        bpf_probe_read_kernel_str(buf, size, path_str);
        return;
    }

    __builtin_memcpy(buf, "unknown", sizeof("unknown"));
}

static __always_inline char *get_filename_from_path(struct path *path, u32 temp_map_index) {
    char *key = bpf_map_lookup_elem(&bomfather_temp_filename_map, &temp_map_index);
    if (!key) {
        return NULL;
    }
    __builtin_memset(key, 0, INPUT_PATH_MAX);
    char *path_str = get_path_str(path);
    if (path_str) {
        bpf_probe_read_kernel_str(key, INPUT_PATH_MAX, path_str);
        return key;
    }
    __builtin_memcpy(key, "unknown", sizeof("unknown"));
    return key;
}

static __always_inline void fmt_violation_data(char *dst, __u32 dst_size, const char *fmt, const char *name) {
    __u64 args[1];
    __builtin_memset(dst, 0, dst_size);
    args[0] = (__u64)(unsigned long)name;
    bpf_snprintf(dst, dst_size, fmt, args, sizeof(args));
}

static __always_inline void fmt_ptrace_violation(char *dst, __u32 dst_size, const char *reason, unsigned int mode) {
    __u64 args[6];
    __builtin_memset(dst, 0, dst_size);
    args[0] = (__u64)(unsigned long)reason;
    args[1] = (mode & PTRACE_MODE_READ) ? 1 : 0;
    args[2] = (mode & PTRACE_MODE_ATTACH) ? 1 : 0;
    args[3] = (mode & PTRACE_MODE_NOAUDIT) ? 1 : 0;
    args[4] = (mode & PTRACE_MODE_FSCREDS) ? 1 : 0;
    args[5] = (mode & PTRACE_MODE_REALCREDS) ? 1 : 0;
    bpf_snprintf(dst, dst_size, "%s (READ=%d,ATTACH=%d,NOAUDIT=%d,FSCREDS=%d,REALCREDS=%d)", args, sizeof(args));
}

// whether the bitmask has the given id
// NOTE: use constant-offset word reads for verifier compatibility.
static __always_inline bool bitmask_has_id(const struct bitmask_array *mask, u32 id) {
    if (id == 0 || id > (BITMASK_WORDS * BITMASK_BITS_PER_WORD)) {
        return false;
    }
    u32 zero_based = id - 1;
    u32 bit_index = zero_based & (BITMASK_BITS_PER_WORD - 1);
    u32 bit = 1U << bit_index;
    if (zero_based < BITMASK_BITS_PER_WORD) {
        return (mask->words[0] & bit) != 0;
    }
    return (mask->words[1] & bit) != 0;
}

// bitmask_or performs a bitwise OR operation on every bitmask in two arrays.
static __always_inline void bitmask_or(u32 dst[BITMASK_WORDS], const u32 src[BITMASK_WORDS]) {
    #pragma unroll
    for (int i = 0; i < BITMASK_WORDS; i++) {
        dst[i] |= src[i];
    }
}

// bitmask_any returns true if any of the bits in the array are set.
static __always_inline bool bitmask_any(const u32 words[BITMASK_WORDS]) {
    #pragma unroll
    for (int i = 0; i < BITMASK_WORDS; i++) {
        if (words[i] != 0) {
            return true;
        }
    }
    return false;
}

static __always_inline bool has_prefix(const char *path, const char *prefix, int len)
{
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (i >= len)
            break;

        char c = 0;
        if (bpf_probe_read_kernel(&c, sizeof(c), &path[i]) != 0)
            return false;
        if (c != prefix[i])
            return false;
    }
    return true;
}

static __always_inline bool is_fileless_path(const char *path)
{
    if (has_prefix(path, "memfd:", 6))
        return true;
    if (has_prefix(path, "/dev/shm/", 9))
        return true;
    if (has_prefix(path, "/run/shm/", 9))
        return true;
    return false;
}

// process_id may be NULL; when NULL, get_process_id is fetched lazily on violation only.
static int push_violation(char *output_buffer, int type, struct process_id *process_id) {
    struct violation *v = bpf_ringbuf_reserve(&bomfather_log_failures, sizeof(*v), 0);
    if (!v) {
        DBG_PRINTK("Failed to reserve ringbuf for violation\n");
        if (should_kill_process()) {
            bpf_send_signal(9); // SIGKILL
        }
        return -1;
    }

    bpf_probe_read_kernel_str(v->filename, sizeof(v->filename), output_buffer);

    struct task_struct *task = bpf_get_current_task_btf();
    if (task) {
        struct file *exe_file = BPF_CORE_READ(task, mm, exe_file);
        if (exe_file) {
            char *exe_path = get_filename_from_path(&exe_file->f_path, TEMP_FILEPATH_TASK_EXE_FALLBACK);
            if (exe_path) {
                bpf_probe_read_kernel_str(v->exepath, sizeof(v->exepath), exe_path);
            }
        }
    }
    v->type = type;
    v->timestamp = bpf_ktime_get_ns();
    struct process_id local_process;
    if (!process_id) {
        __builtin_memset(&local_process, 0, sizeof(local_process));
        get_process_id(&local_process);
        process_id = &local_process;
    }
    v->process = *process_id;
    struct process_metadata process_metadata = {
        .has_violated_policy = 1,
    };
    // Map key must be stack or map memory; ringbuf-backed v->process is alloc_mem.
    bpf_map_update_elem(&bomfather_process_metadata, process_id, &process_metadata, BPF_ANY);

    if (should_kill_process()) {
        bpf_send_signal(9); // SIGKILL
    }

    bpf_ringbuf_submit(v, 0);
    return 0;
}

 //------------------ SECURITY CHECK HELPERS -----------------

 static __always_inline int check_has_violated_policy_with_id(struct process_id *process, char *output_string, int type) {
    struct process_metadata *process_metadata = bpf_map_lookup_elem(&bomfather_process_metadata, process);
    if (process_metadata && should_block_process()) {
        if (process_metadata->has_violated_policy == 1) {
            process_metadata->has_violated_policy = 2;
            bpf_map_update_elem(&bomfather_process_metadata, process, process_metadata, BPF_ANY);
            push_violation(output_string, type, process);
            return return_value();
        } else if (process_metadata->has_violated_policy == 2) {
            return return_value();
        }
    }
    return 0;
}

 static __always_inline int check_has_violated_policy(char *output_string, int type) {
    struct process_id process;
    __builtin_memset(&process, 0, sizeof(process));
    get_process_id(&process);
    return check_has_violated_policy_with_id(&process, output_string, type);
}
 // This is used to make a path key from the current mount namespace.
 // Fail-closed: known containers with no mountns->policy mapping are invalidated.
 // Host processes (not in active_cgroups) default to policy_id 0.
static __always_inline struct path_key *make_path_key_from_current_mnt_ns(const char *path,  u32 temp_map_index) {
    struct path_key *out = bpf_map_lookup_elem(&bomfather_temp_path_key_map, &temp_map_index);
    if (!out) return NULL;

    u32 *policy_id_ptr = get_policy_id_for_current_mnt_ns();
    struct container_id cgroup_id = get_current_container_id();

    __builtin_memset(out->directory_path, 0, sizeof(out->directory_path));
    bpf_probe_read_kernel_str(out->directory_path, sizeof(out->directory_path), path);

    if (policy_id_ptr == NULL) {
        out->policy_id = 0;
        if (cgroup_id.cgroup_id != INVALID_CGROUP_ID) {
            // if its inside a container, but we don't have a policy id, then
            //  we cannot be confident about the path key, therefore, we
            // invlaidate it by setting the policy id to -1
            out->policy_id = -1;
        }
    } else {
        out->policy_id = *policy_id_ptr;
    }

    return out;
}

static __noinline int fsverity_check_path(const char *filename, struct file *file)
{
    // Step 1: look up the path in the pinlist.
    struct path_key *pkey = make_path_key_from_current_mnt_ns(filename, TEMP_CONTAINER_PATH_FSVERITY);
    if (!pkey)
        return 0;

    struct fsverity_allowlist_key *expected_ptr = bpf_map_lookup_elem(&bomfather_fsverity_pinlist, pkey);
    if (!expected_ptr)
        return 0; // Path is not in the map return it.

    //copying the expected digest to the stack to avoid the map value being overwritten by other calls.
    struct fsverity_allowlist_key expected = *expected_ptr;

    u32 zero = 0;
    struct fsverity_digest_bpf *digest = bpf_map_lookup_elem(&bomfather_fsverity_scratch, &zero);
    if (!digest)
        return -1;
    __builtin_memset(digest, 0, sizeof(*digest));

    // bpf_get_fsverity_digest might not be available on older kernels.
    if (!bpf_get_fsverity_digest)
        return 0;

    struct bpf_dynptr ptr;
    bpf_dynptr_from_mem(digest, sizeof(*digest), 0, &ptr);

    if (bpf_get_fsverity_digest(file, &ptr) != 0 || digest->digest_size == 0)
        return -1; // fsverity not present deny.

    // copying to stack to avoid the map value being overwritten by other calls.
    struct fsverity_allowlist_key live = {};
    live.alg = digest->digest_algorithm;
    __builtin_memcpy(live.digest, digest->digest, FSVERITY_MAX_DIGEST_SIZE);

    if (live.alg != expected.alg)
        return -1;
    if (__builtin_memcmp(live.digest, expected.digest, FSVERITY_MAX_DIGEST_SIZE) != 0)
        return -1;

    return 0;
}

 // Returns true if the given pid should be protected from sensitive operations
// based on its executable identity (trusted or mapped as protected).
static bool should_protect_process(struct task_struct *task) {
    struct task_ctx *task_ctx = get_task_ctx(task, false);
    if (task_ctx) {
        return task_ctx->is_protected_process == 1;
    }
    return false;
}

static bool is_trusted_executable(const char *filename) {
    struct path_key *pkey = make_path_key_from_current_mnt_ns(filename, TEMP_CONTAINER_PATH_TRUSTED_EXECUTABLE);
    if (!pkey) return false;
    u8 *trusted = bpf_map_lookup_elem(&bomfather_trusted_executables, pkey);
    return trusted != NULL;
}

// This is used to make a path key from a given policy id and directory path.
// It is used to make a path key for the trusted executables map and the global read only map.
static __always_inline struct path_key *make_path_key(u32 policy_id, const char *directory_path, u32 temp_map_index) {
    struct path_key *out = bpf_map_lookup_elem(&bomfather_temp_path_key_map, &temp_map_index);
    if (!out) return NULL;

    out->policy_id = policy_id;

    __builtin_memset(out->directory_path, 0, sizeof(out->directory_path));
    bpf_probe_read_kernel_str(out->directory_path, sizeof(out->directory_path), directory_path);
    return out;
}

static long mount_check_callback(u64 index, void *ctx) {
    struct path_container_id_component_ctx *pctx = (struct path_container_id_component_ctx *)ctx;


    if (index >= INPUT_PATH_MAX - 1) return 1;

    int i = (INPUT_PATH_MAX - 2) - (int)index;

    if (i < 0 || i >= INPUT_PATH_MAX) return 1;

    char c;
    if (bpf_probe_read_kernel(&c, 1, &pctx->path[i]) != 0) {
       return 1;
    }

    if (!pctx->saw_path_byte) {
        if (c == '\0') {
            return 0;
        }
        pctx->saw_path_byte = 1;
    }

    if (c == '/') {
        pctx->component_start = (u32)(i + 1);
        if (pctx->component_len == 64) {
            char container_id[64];

            if (bpf_probe_read_kernel(container_id, sizeof(container_id), &pctx->path[pctx->component_start]) != 0) {
                return 1;
            }

            struct container_context *container_ctx = bpf_map_lookup_elem(&bomfather_container_id_to_container_context, &container_id);
            if (container_ctx != NULL) {
                pctx->policy_id = container_ctx->policy_id;
                pctx->container_correlation_counter_index = container_ctx->correlation_index;
                return 1;
            }
        }
        pctx->component_len = 0;
    } else if (pctx->component_len < 64) {
        pctx->component_len++;
    }
    return 0;
}

static long path_check_callback(u64 index, void *ctx) {
    struct path_check_ctx *pctx = (struct path_check_ctx *)ctx;

    if (index >= INPUT_PATH_MAX - 1) return 1;

    int i = (INPUT_PATH_MAX - 2) - (int)index;

    if (i < 0 || i >= INPUT_PATH_MAX) return 1;

    char c;
    if (bpf_probe_read_kernel(&c, 1, &pctx->filename[i]) != 0) {
       return 1;
    }

    if (c == '/' || i == INPUT_PATH_MAX - 2) {
        u32 temp_map_index = TEMP_FILEPATH_PATH_CHECK;
        char *key = bpf_map_lookup_elem(&bomfather_temp_filename_map, &temp_map_index);
        if (!key) {
            return 1;
        }
        __builtin_memset(key, 0, INPUT_PATH_MAX);

        bpf_probe_read_kernel_str(key, i + 1 , pctx->filename);

        struct path_key *pkey = make_path_key(
            pctx->policy_id,
            key,
            TEMP_CONTAINER_PATH_RESTRICTED_FILEPATH
        );
        if (!pkey) {
            return 1;
        }

        u32 *access_index = bpf_map_lookup_elem(&bomfather_dir_to_id, pkey);
        if (access_index != NULL) {
            u32 *global_read_only_index = bpf_map_lookup_elem(&bomfather_global_read_only, pkey);
            if (!pctx->found_policy) {
                pctx->found_policy = true;
                pctx->matched_access_index = *access_index;
                pctx->found_global_read_only = global_read_only_index != NULL;
            }

            // Check write access
            if (pctx->open_mode == ACCESS_WRITE && bitmask_has_id(&pctx->access.write, *access_index)) {
                pctx->should_block = false;
                return 1;
            }
            // Check read access
            if (pctx->open_mode == ACCESS_READ &&
                (bitmask_has_id(&pctx->access.read, *access_index) || bitmask_has_id(&pctx->access.write, *access_index))) {
                pctx->should_block = false;
                return 1;
            } else {
                // if this directory is a global read only directory, then we allow read access,
                // even if their is a rule around it that blocks read access, since the global read map allows it.
                if (global_read_only_index != NULL && pctx->open_mode == ACCESS_READ) {
                    pctx->should_block = false;
                    return 1;
                }
            }
            // No access at this level, mark as blocked.
            // We do not return 1 here, since we want to continue checking parent directories.
            pctx->should_block = true;
        } else {
            // Only if there are no rules on this directory, we check if it is an immutable directory.
            u32 *global_read_only_index = bpf_map_lookup_elem(&bomfather_global_read_only, pkey);
            if (global_read_only_index != NULL) {
                if (!pctx->found_policy) {
                    pctx->found_policy = true;
                    pctx->matched_access_index = 0;
                    pctx->found_global_read_only = true;
                }

                if (pctx->open_mode == ACCESS_WRITE) {
                    pctx->should_block = true;
                }
            }
        }
    }
    return 0;
}

// This is used for processes that were already running (like runc) and never went through execve.
// Returning the map value pointer avoids copying a full access_control onto the BPF stack.
static __always_inline struct access_control *get_exe_access_fallback_ptr(struct task_struct *task) {
    struct file *exe_file = BPF_CORE_READ(task, mm, exe_file);
    if (!exe_file) {
        return NULL;
    }

    char *exe_path = get_filename_from_path(&exe_file->f_path, TEMP_FILEPATH_TASK_EXEC_FALLBACK);
    if (!exe_path) {
        return NULL;
    }
    struct path_key *pkey = make_path_key_from_current_mnt_ns(exe_path, TEMP_CONTAINER_PATH_EXEC_FALLBACK);
    if (!pkey) {
        return NULL;
    }
    return bpf_map_lookup_elem(&bomfather_trusted_executables, pkey);
}


// Get task context with null check and fallback for access control
static __always_inline struct task_ctx *get_task_ctx_safe(struct task_struct *task ) {
    if (!task) {
        return NULL;
    }

    struct task_ctx *task_ctx = get_task_ctx(task, false);
    if (!task_ctx) {
        task_ctx = get_task_ctx(task, true);
        if (!task_ctx) {
            return NULL;
        }
    }
    if (task_ctx->access_initialized == 1) {
        return task_ctx;
    }
    struct access_control *fallback_access = get_exe_access_fallback_ptr(task);
    if (fallback_access) {
        bitmask_or(task_ctx->access.read.words, fallback_access->read.words);
        bitmask_or(task_ctx->access.write.words, fallback_access->write.words);
        bitmask_or(task_ctx->access.execute.words, fallback_access->execute.words);
        task_ctx->access.gpu |= fallback_access->gpu;
        bitmask_or(task_ctx->access.ip_egress.words, fallback_access->ip_egress.words);
        bitmask_or(task_ctx->access.ip_exclusive_owner.words, fallback_access->ip_exclusive_owner.words);
        task_ctx->access.output_openats |= fallback_access->output_openats;
        task_ctx->access_initialized = 1;
    }

    return task_ctx;
}


static __always_inline void clear_procstat_gate(void)
{
    struct task_struct *task = bpf_get_current_task_btf();
    if (!task) {
        return;
    }
    struct task_ctx *tctx = get_task_ctx_safe(task);
    if (!tctx) {
        return;
    }
    tctx->procstat_gate = 0;
    tctx->procstat_pid  = 0;
}

static __always_inline int is_proc_pid_stat_inode(struct inode *inode, u32 *out_pid)
{
    if (BPF_CORE_READ(inode, i_sb, s_magic) != PROC_SUPER_MAGIC) {
        return 0;
    }

    /* procfs: inode->i_private typically points to struct proc_inode */
    struct proc_inode *pi = (struct proc_inode *)BPF_CORE_READ(inode, i_private);
    if (!pi) {
        return 0;
    }

    struct proc_dir_entry *pde = BPF_CORE_READ(pi, pde);
    if (!pde) {
        return 0;
    }

    const char *namep = BPF_CORE_READ(pde, name);
    if (!namep) {
        return 0;
    }

    char name[5];
    int read_len = bpf_core_read_str(name, sizeof(name), namep);
    if (read_len != 5) {
        return 0;
    }

    if (__builtin_memcmp(name, "stat", 5)) {
        return 0;
    }

    struct pid *pid = BPF_CORE_READ(pi, pid);
    if (!pid) {
        return 0;
    }

    *out_pid = BPF_CORE_READ(pid, numbers[0].nr);
    return *out_pid != 0;
}

static __always_inline bool allow_procstat_ptrace(struct task_struct *child, unsigned int mode) {
    struct task_struct *task = bpf_get_current_task_btf();
    if (!task) {
        return false;
    }
    struct task_ctx *tctx = get_task_ctx(task, false);
    if (!tctx) {
        return false;
    }

    bool ok = tctx && tctx->procstat_gate && (BPF_CORE_READ(child, pid) == tctx->procstat_pid) && (mode & PTRACE_MODE_READ) && !(mode & PTRACE_MODE_ATTACH);

    /* consume one-shot token no matter what */
    if (tctx) {
        tctx->procstat_gate = 0;
        tctx->procstat_pid  = 0;
    }
    return ok;
}

static bool is_restricted_filepath(const char *filename, int open_mode, struct inode_cache_key *inode_key) {
    struct task_struct *task = bpf_get_current_task_btf();
    struct task_ctx *task_ctx = get_task_ctx_safe(task);

    // Lookup policy_id for current mount namespace (defaults to 0 for unmapped host)
    u32 *policy_id_ptr = get_policy_id_for_current_mnt_ns();
    u32 policy_id = (policy_id_ptr != NULL) ? *policy_id_ptr : 0;

    // Set up context for bpf_loop
    struct path_check_ctx ctx = {
        .filename = filename,
        .policy_id = policy_id,
        .open_mode = open_mode,
        .should_block = false,
    };
    if (task_ctx) {
        ctx.access = task_ctx->access;
    }

    // Use bpf_loop to iterate through path components
    bpf_loop(INPUT_PATH_MAX - 1, path_check_callback, &ctx, 0);

    // writing the inode cache value
    if (inode_key) {
        struct inode_policy_cache_value cache_value = {};
        if (ctx.found_policy) {
            if (ctx.matched_access_index != 0 && ctx.found_global_read_only) {
                cache_value.state = INODE_POLICY_CACHE_ACCESS_INDEX_AND_GLOBAL_RO;
                cache_value.access_index = ctx.matched_access_index;
            } else if (ctx.matched_access_index != 0) {
                cache_value.state = INODE_POLICY_CACHE_ACCESS_INDEX;
                cache_value.access_index = ctx.matched_access_index;
            } else if (ctx.found_global_read_only) {
                cache_value.state = INODE_POLICY_CACHE_GLOBAL_READ_ONLY;
            } else {
                cache_value.state = INODE_POLICY_CACHE_NO_POLICY;
            }
        } else {
            cache_value.state = INODE_POLICY_CACHE_NO_POLICY;
        }
        bpf_map_update_elem(&bomfather_inode_policy_cache, inode_key, &cache_value, BPF_ANY);
        inode_cache_stats_inc(INODE_CACHE_STATS_FILLS);
    }

    return ctx.should_block;
}

static __always_inline bool task_has_access_for_mode(u32 access_index, int open_mode) {
    struct task_struct *task = bpf_get_current_task_btf();
    if (!task) {
        return false;
    }

    struct task_ctx *task_ctx = get_task_ctx_safe(task);
    if (!task_ctx) {
        return false;
    }

    if (open_mode == ACCESS_WRITE) {
        return bitmask_has_id(&task_ctx->access.write, access_index);
    }

    if (open_mode == ACCESS_READ) {
        return bitmask_has_id(&task_ctx->access.read, access_index) ||
               bitmask_has_id(&task_ctx->access.write, access_index);
    }

    return false;
}

static __always_inline int enforce_restricted_filepath_policy(int open_mode, char *filename, struct process_id *process_id, struct inode_cache_key *inode_key) {
    if (is_restricted_filepath(filename, open_mode, inode_key)) {
        push_violation(filename, VIOL_RESTRICTED, process_id);
        return return_value();
    }

    return 0;
}

static __inline int enforce_access_policy(int open_mode, char *filename, struct process_id *process_id) {
    // keep the access mode check first for perf optimization
    if (open_mode == ACCESS_WRITE && is_trusted_executable(filename)) {
        push_violation(filename, VIOL_TRUSTED, process_id);
        return return_value();
    }

    return enforce_restricted_filepath_policy(open_mode, filename, process_id, NULL);
}

// ----------------- CGROUP TRACER FUNCTIONS -----------------

SEC("tracepoint/cgroup/cgroup_mkdir")
int trace_cgroup_mkdir(struct bpf_raw_tracepoint_args *ctx) {
    u64 id = 0;
    id = ctx->args[2];
    struct container_id info = {0,0};
    info.cgroup_id = id;
    info.timestamp = bpf_ktime_get_ns();
    bpf_map_update_elem(&bomfather_active_cgroups, &id, &info, BPF_ANY);
    return 0;
}

SEC("tracepoint/cgroup/cgroup_rmdir")
int trace_cgroup_rmdir(struct bpf_raw_tracepoint_args *ctx) {
    // when the container is removed
    remove_cgroup_id(ctx);
    return 0;
}

SEC("tracepoint/cgroup/cgroup_freeze")
int trace_cgroup_freeze(struct bpf_raw_tracepoint_args *ctx) {
    // when the container is stopped and not removed
    remove_cgroup_id(ctx);
    return 0;
}

// ----------------- SECURE BPF WITH BPF HOOKS -----------------

SEC("lsm/bpf_map")
int BPF_PROG(lsm_bpf_map, struct bpf_map *map, fmode_t fmode) {
    u32 zero = 0;
    u32 *should_secure_map = bpf_map_lookup_elem(&bomfather_should_secure_maps, &zero);
    if (should_secure_map == NULL || *should_secure_map == 0)
        return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (has_prefix(map->name, "bomfather_", 10) &&
        !bpf_map_lookup_elem(&bomfather_userspace_process_pid, &pid)) {
        char buf[64];
        fmt_violation_data(buf, sizeof(buf), "bpf_map %s", map->name);
        struct process_id process = {0};
        get_process_id(&process);
        push_violation(buf, VIOL_MAP_SECURITY, &process);
        return return_value();
    }
    return 0;
}

static __always_inline bool enforce_bpf_op_policy(int cmd) {
    if (cmd != BPF_PROG_LOAD && cmd != BPF_OBJ_PIN)
        return false;

    u32 zero = 0;
    u32 *should_restrict = bpf_map_lookup_elem(&bomfather_restrict_bpf_ops, &zero);
    if (should_restrict == NULL || *should_restrict == 0)
        return false;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&bomfather_userspace_process_pid, &pid))
        return false;

    struct process_id process = {0};
    get_process_id(&process);
    if (cmd == BPF_PROG_LOAD)
        push_violation("bpf_prog_load", VIOL_BPF_LOAD, &process);
    else
        push_violation("bpf_obj_pin", VIOL_BPF_PIN, &process);

    return true;
}

SEC("lsm/bpf")
int BPF_PROG(lsm_bpf, int cmd, union bpf_attr *attr, unsigned int size, bool kernel) {
    if (kernel)
        return 0;

    if (enforce_bpf_op_policy(cmd))
        return return_value();

    return 0;
}

SEC("lsm/bpf")
int BPF_PROG(lsm_bpf_compat, int cmd, union bpf_attr *attr, unsigned int size) {
    if (enforce_bpf_op_policy(cmd))
        return return_value();

    return 0;
}
SEC("lsm/task_kill")
int BPF_PROG(lsm_task_kill, struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred) {
    u32 zero = 0;

    u32 *should_stop_shutdown = bpf_map_lookup_elem(&bomfather_should_stop_shutdown, &zero);
    if (!should_stop_shutdown) {
        return 0;
    }

    u32 pid = BPF_CORE_READ(p, pid);
    u32 *is_userspace_process = bpf_map_lookup_elem(&bomfather_userspace_process_pid, &pid);
    if (is_userspace_process) {
        struct process_id process = {0};
        get_process_id(&process);
        push_violation("Kill attempt on bomfather agent userspace process", VIOL_TASK_KILL, &process);
        return return_value();
    }
    return 0;
}

// ----------------- PTRACE SECURITY HOOKS -----------------

SEC("lsm/inode_permission")
int BPF_PROG(lsm_inode_permission, struct inode *inode, int mask)
{
    if (!(mask & MAY_READ))
        return 0;

    u32 target_pid = 0;
    if (!is_proc_pid_stat_inode(inode, &target_pid))
        return 0;

    struct task_ctx *tctx = get_task_ctx(bpf_get_current_task_btf(), true);
    if (!tctx)
        return 0;

    tctx->procstat_gate = 1;
    tctx->procstat_pid = target_pid;
    return 0;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(lsm_ptrace_access_check, struct task_struct *child, unsigned int mode) {
    /*
     * Block ALL ptrace operations on protected processes:
     *  - GDB/debugger attachment
     *  - strace system call tracing
     *  - /proc/<pid>/mem access
     *  - process_vm_{readv,writev} syscalls
     *  - Any other ptrace-based inspection
     *
     * This provides maximum protection against process introspection.
     */

    u32 zero = 0;
    u32 *block = bpf_map_lookup_elem(&bomfather_block_ptrace, &zero);

    // If ptrace blocking is disabled, allow all ptrace operations
    if (!block || *block == 0) {
        return 0;
    }
    struct task_struct *task = bpf_get_current_task_btf();

    if (!task) {
        return 0;
    }

    struct task_ctx *tctx = get_task_ctx_safe(task);
    if (!tctx) {
        return 0;
    }
    struct path_key *pkey = make_path_key_from_current_mnt_ns(tctx->execve_event.exepath, TEMP_CONTAINER_PATH_ALLOWED_PTRACE_EXECUTABLE);
    if (!pkey) {
        return 0;
    }

    u32 *allowed_ptrace_executable = bpf_map_lookup_elem(&bomfather_allowed_ptrace_executables, pkey);
    if (allowed_ptrace_executable && *allowed_ptrace_executable != 0) {
        return 0;
    }

    if (allow_procstat_ptrace(child, mode)) {
        return 0;
    }

    u32 child_pid = BPF_CORE_READ(child, pid);
    u32 *is_userspace_process = bpf_map_lookup_elem(&bomfather_userspace_process_pid, &child_pid);
    if (is_userspace_process || should_protect_process(child)) {
        push_violation(is_userspace_process ? "ptrace on bomfather agent" : "ptrace on protected process", VIOL_PTRACE, NULL);
        return return_value();
    }
    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(lsm_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
    struct process_id process = {0};
    get_process_id(&process);
    int ret = check_has_violated_policy_with_id(&process, "socket_connect blocked after prior policy violation", VIOL_NETWORK_EGRESS);
    if (ret != 0)
        return ret;
    struct sockaddr_in dst_addr = {};
    if (!get_ipv4_tcp_connect_destination(sock, address, addrlen, &dst_addr)) {
        return 0;
    }

    // Read policy id associated with current cgroup when available.
    // If no mapping exists, default to host policy id (0).

    u32 policy_id = 0;
    struct container_id cgroup_id = get_current_container_id();
    u32 *policy_id_ptr = get_policy_id_for_current_mnt_ns();
    if (policy_id_ptr != NULL) {
        policy_id = *policy_id_ptr;
    } else if (cgroup_id.cgroup_id != INVALID_CGROUP_ID) {
        // Container is known but mountns->policy mapping is not ready yet.
        // Do not fall back to host policy in this race window.
        return 0;
    }

    struct task_struct *task = bpf_get_current_task_btf();
    if (!task) {
        return 0;
    }

    struct task_ctx *tctx = get_task_ctx_safe(task);
    if (!tctx) {
        return return_value();
    }

    // Build destination lookup key with resolved policy id and destination tuple.
    // Convert destination IP and port to normalized host-order values for map lookup consistency.

    struct ip_to_id_key lookup_key = {
        .policy_id = policy_id,
        .dst_ipv4 = bpf_ntohl(dst_addr.sin_addr.s_addr),
        .dst_port = bpf_ntohs(dst_addr.sin_port),
        ._pad = 0,
    };

    // If the dst_port is 0 then the user didn't pass in a port and only passed in an IP
    // We are using 0 as a placeholder to indicate that the user didn't pass in a port

    // Resolve destination IDs for exact ip:port and wildcard ip:any-port.

    u32 *ip_id_exact = bpf_map_lookup_elem(&bomfather_ip_to_id, &lookup_key);

    struct ip_to_id_key wildcard_lookup_key = lookup_key;
    wildcard_lookup_key.dst_port = 0; // setting the wildcard to have a 0 port to check whether it is in the map.

    u32 *ip_id_wildcard = NULL;
    if (lookup_key.dst_port != 0) {
        ip_id_wildcard = bpf_map_lookup_elem(&bomfather_ip_to_id, &wildcard_lookup_key);
    }

    bool allow_by_ownership = true;
    bool allow_by_egress = true;

    if (bitmask_any(tctx->access.ip_egress.words)) { // First part of the IP protection
        bool allow_exact = ip_id_exact && bitmask_has_id(&tctx->access.ip_egress, *ip_id_exact);
        bool allow_wildcard = ip_id_wildcard && bitmask_has_id(&tctx->access.ip_egress, *ip_id_wildcard);
        allow_by_egress = allow_exact || allow_wildcard;
    }

    // Enforce executable ownership only for destinations explicitly marked as exclusive.
    struct bitmask_array *exclusive_ip_mask = bpf_map_lookup_elem(&bomfather_exclusive_ip_mask, &policy_id);

    bool is_exclusive_exact = exclusive_ip_mask && ip_id_exact && bitmask_has_id(exclusive_ip_mask, *ip_id_exact);
    bool is_exclusive_wildcard = exclusive_ip_mask && ip_id_wildcard && bitmask_has_id(exclusive_ip_mask, *ip_id_wildcard);

    bool should_enforce_ownership = is_exclusive_exact || is_exclusive_wildcard;
    if (should_enforce_ownership) {
        // Exclusive destinations are fail-closed:
        // if process has no access profile, it cannot own the destination.

        bool owned_exact = ip_id_exact && bitmask_has_id(&tctx->access.ip_exclusive_owner, *ip_id_exact);
        bool owned_wildcard = ip_id_wildcard && bitmask_has_id(&tctx->access.ip_exclusive_owner, *ip_id_wildcard);

        allow_by_ownership = owned_exact || owned_wildcard;
    }

    if (allow_by_egress && allow_by_ownership) {
       return 0;
    }

    u32 msg_idx = TEMP_FILEPATH_PATH_CHECK;
    char *buf = bpf_map_lookup_elem(&bomfather_temp_filename_map, &msg_idx);
    if (!buf) {
        return return_value();
    }
    u32 dst_ipv4_host = bpf_ntohl(dst_addr.sin_addr.s_addr);
    __u64 args[5];
    args[0] = (__u64)((dst_ipv4_host >> 24) & 0xFF);
    args[1] = (__u64)((dst_ipv4_host >> 16) & 0xFF);
    args[2] = (__u64)((dst_ipv4_host >> 8) & 0xFF);
    args[3] = (__u64)(dst_ipv4_host & 0xFF);
    args[4] = (__u64)lookup_key.dst_port;
    __builtin_memset(buf, 0, 96);
    bpf_snprintf(buf, 96, "tcp connect %u.%u.%u.%u:%u", args, sizeof(args));
    push_violation(buf, VIOL_NETWORK_EGRESS, &process);
    return return_value();
}


SEC("lsm/socket_sendmsg")
int BPF_PROG(lsm_socket_sendmsg, struct socket *sock, struct msghdr *msg, int size) {
    return check_has_violated_policy("socket_sendmsg blocked after prior policy violation", VIOL_NETWORK_EGRESS);
}

SEC("lsm/socket_recvmsg")
int BPF_PROG(lsm_socket_recvmsg, struct socket *sock, struct msghdr *msg, int size, int flags) {
    return check_has_violated_policy("socket_recvmsg blocked after prior policy violation", VIOL_NETWORK_EGRESS);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tp_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
    clear_procstat_gate();
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int tp_exit_openat2(struct trace_event_raw_sys_exit *ctx)
{
    clear_procstat_gate();
    return 0;
}

// ----------------- FILE OPEN SECURITY HOOKS -----------------

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file) {
    u32 zero = 0;
    u32 temp_map_index = TEMP_FILE_INFO_FILE_OPEN;
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // Extract the higher 32 bits as the PID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);

    struct file_info *file_info;

    file_info = bpf_map_lookup_elem(&bomfather_file_info_map, &zero);

    if (!file_info) {
        return 0;
    }

    int open_mode = 0;

    unsigned int flags = BPF_CORE_READ(file, f_flags);

    if ((flags & O_ACCMODE) != O_RDONLY) {
        open_mode = ACCESS_WRITE;
    } else {
        open_mode = ACCESS_READ;
    }

    __builtin_memset(file_info->filename, 0, sizeof(file_info->filename));

    get_filename(file, dentry, file_info->filename, sizeof(file_info->filename));

    file_info->open_mode = open_mode;

    //bpf_map_update_elem(&bomfather_file_info_map, &temp_map_index, file_info, BPF_ANY);

    //skip gpu check tail call if restrict_gpu_access is enabled or not
    u32 *restrict_gpu = bpf_map_lookup_elem(&bomfather_restrict_gpu_access, &zero);
    u32 next_tail_call = restrict_gpu && *restrict_gpu != 0 ? 0 : 1;
    bpf_tail_call(ctx, &bomfather_file_open_jump_table, next_tail_call);

    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(tail_call_gpu, struct file *file) {
    u32 zero = 0;
    u32 temp_map_index = TEMP_FILE_INFO_FILE_OPEN;
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    u32 major = get_major(BPF_CORE_READ(inode, i_rdev));
    struct file_info *file_info = bpf_map_lookup_elem(&bomfather_file_info_map, &temp_map_index);

    if (!file_info) {
        return 0;
    }

    u32 *restrict_gpu = bpf_map_lookup_elem(&bomfather_restrict_gpu_access, &zero);

    if (restrict_gpu && *restrict_gpu != 0) {
        if ((is_character_device(BPF_CORE_READ(inode, i_mode)) && (major == 195 || major == 226) || has_prefix(file_info->filename, "/dev/kfd", 9))) {
            struct task_struct *task = bpf_get_current_task_btf();
            // Get task context with process that could have been created before we started monitoring it.
            // For example, nvidia-smi is a process that is not monitored by us, but it is a process that can access the GPU.
            struct task_ctx *task_ctx = get_task_ctx_safe(task);
            if (!task_ctx) {
                return return_value();
            }
            if (task_ctx->access.gpu == 0) {
                // process is null for perf reasons.
                // push_violation will fetch the process id if it is not there
                push_violation(file_info->filename, VIOL_GPU, NULL);
                return return_value();
            }
        }
    }

    bpf_tail_call(ctx, &bomfather_file_open_jump_table, 1);
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(tail_call_security_check, struct file *file) {
    u32 zero = 0;
    u32 temp_map_index = TEMP_FILE_INFO_FILE_OPEN;
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    struct inode_cache_key inode_key = {};
    struct inode_policy_cache_value *inode_policy_cache_entry = NULL;
    bool inode_key_ready = false;

    struct file_info *file_info = bpf_map_lookup_elem(&bomfather_file_info_map, &temp_map_index);

    if (!file_info) {
        return 0;
    }

    inode_key_ready = build_inode_cache_key(file, inode, &inode_key);
    if (inode_key_ready) {
        inode_cache_stats_inc(INODE_CACHE_STATS_LOOKUPS);
        inode_policy_cache_entry = bpf_map_lookup_elem(&bomfather_inode_policy_cache, &inode_key);
    }

    // Keep the trusted executable check on every path. The inode cache only
    // shortcuts the restricted filepath walk.
    if (file_info->open_mode == ACCESS_WRITE && is_trusted_executable(file_info->filename)) {
        push_violation(file_info->filename, VIOL_TRUSTED, NULL);
        return return_value();
    }

    bool skip_restricted_filepath_check = false;
    if (inode_policy_cache_entry) {
        if (inode_policy_cache_entry->state == INODE_POLICY_CACHE_NO_POLICY) {
            inode_cache_stats_inc(INODE_CACHE_STATS_HITS_NO_POLICY);
            skip_restricted_filepath_check = true;
        }
        if (inode_policy_cache_entry->state == INODE_POLICY_CACHE_ACCESS_INDEX) {
            if (task_has_access_for_mode(inode_policy_cache_entry->access_index, file_info->open_mode)) {
                inode_cache_stats_inc(INODE_CACHE_STATS_HITS_ALLOW);
                skip_restricted_filepath_check = true;
            } else {
                inode_cache_stats_inc(INODE_CACHE_STATS_HITS_DENY);
                push_violation(file_info->filename, VIOL_RESTRICTED, NULL);
                return return_value();
            }
        }
        if (inode_policy_cache_entry->state == INODE_POLICY_CACHE_GLOBAL_READ_ONLY) {
            if (file_info->open_mode == ACCESS_READ) {
                inode_cache_stats_inc(INODE_CACHE_STATS_HITS_ALLOW);
                skip_restricted_filepath_check = true;
            } else {
                inode_cache_stats_inc(INODE_CACHE_STATS_HITS_DENY);
                push_violation(file_info->filename, VIOL_RESTRICTED, NULL);
                return return_value();
            }
        }
        if (inode_policy_cache_entry->state == INODE_POLICY_CACHE_ACCESS_INDEX_AND_GLOBAL_RO) {
            if (task_has_access_for_mode(inode_policy_cache_entry->access_index, file_info->open_mode)) {
                inode_cache_stats_inc(INODE_CACHE_STATS_HITS_ALLOW);
                skip_restricted_filepath_check = true;
            } else if (file_info->open_mode == ACCESS_READ) {
                inode_cache_stats_inc(INODE_CACHE_STATS_HITS_ALLOW);
                skip_restricted_filepath_check = true;
            } else {
                inode_cache_stats_inc(INODE_CACHE_STATS_HITS_DENY);
                push_violation(file_info->filename, VIOL_RESTRICTED, NULL);
                return return_value();
            }
        }
    }

    if (!skip_restricted_filepath_check) {
        // Only count a cache miss when a lookup was attempted.
        if (inode_key_ready) {
            inode_cache_stats_inc(INODE_CACHE_STATS_MISSES_WALK);
        }
        struct inode_cache_key *cache_key_for_write = inode_key_ready ? &inode_key : NULL;
        int ret = enforce_restricted_filepath_policy(file_info->open_mode, file_info->filename, NULL, cache_key_for_write);
        if (ret != 0) {
            return ret;
        }
    }

    // return early if output openats is not enabled
    u32 *should_output_openats = bpf_map_lookup_elem(&bomfather_should_output_openats, &zero);
    if (!should_output_openats || *should_output_openats == 0) {
        return 0;
    }

    bpf_tail_call(ctx, &bomfather_file_open_jump_table, 2);

    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(tail_call_send_data, struct file *file) {
    u32 zero = 0;
    u32 temp_map_index = TEMP_FILE_INFO_FILE_OPEN;
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = bpf_get_current_task_btf();
    if (is_directory(inode, BPF_CORE_READ(inode, i_mode))) {
        return 0;
    }


    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    struct openat_event *event = bpf_ringbuf_reserve(&bomfather_openat_events, sizeof(*event), 0);
    if (!event) {
        DBG_PRINTK("Failed to reserve ringbuf\n");
        return 0;
    }



    // Zero-initialize exepath to avoid leaking uninitialized kernel memory.
    // Ring buffer memory is not zeroed, so we must initialize before submit.
    __builtin_memset(event->exepath, 0, sizeof(event->exepath));

    // Try to get exepath from task_ctx first (set during execve)
    struct task_ctx *task_ctx = get_task_ctx(task, false);
    bool has_exepath = false;
    if (task_ctx && task_ctx->execve_event.exepath[0] != '\0') {
        __builtin_memcpy(event->exepath, task_ctx->execve_event.exepath, sizeof(event->exepath));
        has_exepath = true;
    }

    struct file_info *file_info = bpf_map_lookup_elem(&bomfather_file_info_map, &temp_map_index);


    u32 *policy_id = get_policy_id_for_current_mnt_ns();
    u32 *should_output_openats = bpf_map_lookup_elem(&bomfather_should_output_openats, &zero);
    if (!file_info || ((policy_id == NULL || should_output_openats == NULL || *should_output_openats == 0) && (task_ctx == NULL || task_ctx->access.output_openats == 0))) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    struct process_id process = {0};
    get_process_id(&process);
    event->process = process;
    event->open_mode = file_info->open_mode;

    // Fallback: get exepath directly from task->mm->exe_file
    // This handles processes that existed before eBPF loaded or race conditions
    if (!has_exepath) {
        struct file *exe_file = BPF_CORE_READ(task, mm, exe_file);
        if (exe_file) {
            char *exe_path = get_filename_from_path(&exe_file->f_path, TEMP_FILEPATH_OPENAT_EXE_FALLBACK);
            if (exe_path) {
                __builtin_memcpy(event->exepath, exe_path, sizeof(event->exepath));
            }
        }
    }

    __builtin_memcpy(event->filename, file_info->filename, sizeof(event->filename));

    bpf_ringbuf_submit(event, 0);

    return 0;
}
// ----------------- MISC FILE OPEN HOOKS -----------------

SEC("lsm/path_rename")
int BPF_PROG(lsm_path_rename, struct path *old_dir, struct dentry *old_dentry, struct path *new_dir, struct dentry *new_dentry) {
    struct path p = {.mnt = BPF_CORE_READ(old_dir, mnt), .dentry = old_dentry}; // we copy since in this hook the path struct in the arguments is not properly populated
    char *old_path_str = get_filename_from_path(&p, TEMP_FILEPATH_PATH_RENAME_OLD);
    if (!old_path_str) {
        return 0;
    }
    p.mnt = BPF_CORE_READ(new_dir, mnt);
    p.dentry = new_dentry;
    char *new_path_str = get_filename_from_path(&p, TEMP_FILEPATH_PATH_RENAME_NEW);
    if (!new_path_str) {
        return 0;
    }

    if (enforce_access_policy(ACCESS_WRITE, old_path_str, NULL) != 0) {
        return return_value();
    }
    return enforce_access_policy(ACCESS_WRITE, new_path_str, NULL);
}

SEC("lsm/path_unlink")
int BPF_PROG(lsm_path_unlink, struct path *dir, struct dentry *dentry) {
    struct path p = {.mnt = BPF_CORE_READ(dir, mnt), .dentry = dentry};// we copy since in this hook the path struct in the arguments is not properly populated
    char *path_str = get_filename_from_path(&p, TEMP_FILEPATH_PATH_UNLINK);
    if (!path_str) {
        return 0;
    }
    return enforce_access_policy(ACCESS_WRITE, path_str, NULL);
}

SEC("lsm/path_rmdir")
int BPF_PROG(lsm_path_rmdir, struct path *dir, struct dentry *dentry) {
    struct path p = {};

   // we copy since in this hook the path struct in the arguments is not properly populated
   if (bpf_probe_read_kernel(&p, sizeof(p), dir)) {
        return 0;
    }

    p.dentry = dentry;

    char *path_str = get_filename_from_path(&p, TEMP_FILEPATH_PATH_RMDIR);
    if (!path_str) {
        return 0;
    }
    return enforce_access_policy(ACCESS_WRITE, path_str, NULL);
}

// ----------------- PROCESS START HOOKS -----------------

// The sequence of hooks that run is as follows:
// 1. lsm_task_alloc
// 2. trace_execve
// 3. lsm_bprm_check_security

// ----------------- ON FORK OR CLONE HOOK -----------------
// this hook is to add inheritance of access control to the process
SEC("lsm/task_alloc")
int BPF_PROG(lsm_task_alloc, struct task_struct *current_task, unsigned long clone_flags) {
    struct task_struct *parent_task = bpf_get_current_task_btf();
    if (!parent_task) {
        return 0;
    }
    struct task_ctx *parent_task_ctx = get_task_ctx_safe(parent_task); // we do this, since we want to inherit the access control from the parent process, even if we were not their to track it.
    if (!parent_task_ctx) {
        return 0;
    }
    struct task_ctx *current_task_ctx = get_task_ctx(current_task, true);
    if (!current_task_ctx) {
        return 0;
    }

    struct process_id process = {0};
    get_process_id_from_task(current_task, &process);
    struct process_id parent_process = {0};
    get_process_id_from_task(parent_task, &parent_process);


    bitmask_or(current_task_ctx->access.read.words, parent_task_ctx->access.read.words);
    bitmask_or(current_task_ctx->access.write.words, parent_task_ctx->access.write.words);
    bitmask_or(current_task_ctx->access.execute.words, parent_task_ctx->access.execute.words);
    bitmask_or(current_task_ctx->access.ip_egress.words, parent_task_ctx->access.ip_egress.words);
    bitmask_or(current_task_ctx->access.ip_exclusive_owner.words, parent_task_ctx->access.ip_exclusive_owner.words);
    current_task_ctx->access.gpu |= parent_task_ctx->access.gpu;
    current_task_ctx->execve_event.process = process;
    current_task_ctx->is_protected_process = parent_task_ctx->is_protected_process | current_task_ctx->is_protected_process;
    current_task_ctx->execve_event.parent = parent_process;
    current_task_ctx->access.output_openats = parent_task_ctx->access.output_openats | current_task_ctx->access.output_openats;
    current_task_ctx->access_initialized = parent_task_ctx->access_initialized; // we inherit the access control initialization from the parent process
    struct process_metadata *parent_process_metadata = bpf_map_lookup_elem(&bomfather_process_metadata, &parent_process);
    struct process_metadata process_metadata = {0};
    if (parent_process_metadata) {
        process_metadata.has_violated_policy = parent_process_metadata->has_violated_policy;
        bpf_map_update_elem(&bomfather_process_metadata, &process, &process_metadata, BPF_ANY);
    }

    return 0;
}

// ----------------- EXECVE TRACER HOOK -----------------
// this is only really to scrape argument and environment variables
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter* ctx) {
    int zero = 0;

    struct task_struct *task = bpf_get_current_task_btf();
    if (!task) {
        return 0;
    }
    struct task_ctx *task_ctx = get_task_ctx(task, true);
    if (!task_ctx) {
        return 0;
    }

    const char **argv = (const char**)ctx->args[1];
    const char **envp = (const char**)ctx->args[2];

    struct process_id process = {0};
    get_process_id(&process);
    task_ctx->execve_event.process = process;

    bpf_get_current_comm(&task_ctx->execve_event.comm, sizeof(task_ctx->execve_event.comm));
    task_ctx->execve_argv_exact_ready = 0;
    u32 argv_done = 0;
    u32 argv_capture_complete = 0;

    // Copy arguments
    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *arg_ptr = NULL;
        __builtin_memset(&task_ctx->execve_event.argv[i], 0, sizeof(task_ctx->execve_event.argv[i]));
        if (argv_done)
            continue;
        if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv[i]) != 0) {
            argv_done = 1;
            continue;
        }
        if (!arg_ptr) {
            // If argument pointer is NULL, this means we've reached the end of the arguments
            argv_capture_complete = 1;
            argv_done = 1;
            continue;
        }

        if (bpf_probe_read_user_str(task_ctx->execve_event.argv[i], sizeof(task_ctx->execve_event.argv[i]), arg_ptr) < 0) {
            argv_done = 1;
            continue;
        }
    }


    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *env_ptr = NULL;
        if (bpf_probe_read_user(&env_ptr, sizeof(env_ptr), &envp[i]) != 0)
            break;
        if (!env_ptr)
            // If environment variable pointer is NULL, this means we've reached the end of the environment variables
            break;

        // Initialize buffer to zero before reading
        __builtin_memset(&task_ctx->execve_event.envp[i], 0, sizeof(task_ctx->execve_event.envp[i]));

        // Only check for LD_* if reading the environment string succeeds.
        if (bpf_probe_read_user_str(task_ctx->execve_event.envp[i], sizeof(task_ctx->execve_event.envp[i]), env_ptr) >= 0) {
            // Check if this env var starts with "LD_" (uppercase only, as required by dynamic linker)
            if (has_prefix(task_ctx->execve_event.envp[i], "LD_", 3)) {
                // Mark this PID as having LD_* environment variable
                task_ctx->ld_env_detected = 1;
                break;
            }
        }
    }

    task_ctx->execve_argv_exact_ready = argv_capture_complete;

    return 0;
}

// ----------------- ACTUAL PROCESS START HOOK -----------------
// this is the hook that actually checks the security of the process, and adds access control to the process
SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check_security, struct linux_binprm *bprm, int ret){
    int rc = 0;
    int zero = 0;
    u32 temp_map_index = TEMP_FILE_INFO_BPRM_CHECK;
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // Extract the higher 32 bits as the PID
    struct file *file = bprm->file;
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);


    struct file_info *file_info;

    file_info = bpf_map_lookup_elem(&bomfather_file_info_map, &temp_map_index);

    if (!file_info)
        goto out;

    __builtin_memset(file_info->filename, 0, sizeof(file_info->filename)); // used to clear out this buffer, and remove leftover data from previous executions.
    get_process_id(&file_info->process);
    get_filename(bprm->file, dentry, file_info->filename, sizeof(file_info->filename));

    // Prevent fileless (memfd/tmpfs) execution
    u32 *block_in_memory = bpf_map_lookup_elem(&bomfather_block_in_memory_exec, &zero);
    if (block_in_memory && *block_in_memory && is_fileless_path(file_info->filename)) {
        push_violation(file_info->filename, VIOL_FILELESS_EXEC, &file_info->process);
        rc = return_value();
        goto out;
    }

    if (fsverity_check_path(file_info->filename, file) < 0) {
        push_violation(file_info->filename, VIOL_FSVERITY_DENIED, &file_info->process);
        rc = return_value();
        goto out;
    }

    struct path_key *exe_pkey = make_path_key_from_current_mnt_ns(file_info->filename, TEMP_CONTAINER_PATH_BPRM);
    if (!exe_pkey)
        goto out;
    struct access_control *current_trusted_fetch = bpf_map_lookup_elem(&bomfather_trusted_executables, exe_pkey);
    struct access_control current_trusted = {0,0};
    if (current_trusted_fetch != NULL) {
        current_trusted = *current_trusted_fetch;
    }

    struct access_control current_access = {};

    struct task_struct *task = bpf_get_current_task_btf();
    if (!task)
        goto out;

    struct task_ctx *task_ctx = get_task_ctx(task, true);
    bool has_exact_execve_argv = false;
    if (task_ctx) {
        has_exact_execve_argv = task_ctx->execve_argv_exact_ready == 1;
        task_ctx->execve_argv_exact_ready = 0;
    }

    u32 *should_stop_ld_env = bpf_map_lookup_elem(&bomfather_should_stop_ld_env, &zero);
    // Check for LD_* environment variable violation early
    if (should_stop_ld_env && task_ctx && task_ctx->ld_env_detected == 1) {
        u32 *ld_env_allowed_executable = bpf_map_lookup_elem(&bomfather_ld_env_allowed_executables, exe_pkey);
        if (ld_env_allowed_executable && *ld_env_allowed_executable != 0) {
            // Allowed - continue with normal processing
        } else {
            push_violation(file_info->filename, VIOL_LD_ENV, &file_info->process);
            rc = return_value();
            goto out;
        }
    }

    if (task_ctx) {
        current_access = task_ctx->access;
    }

    struct access_control newval = current_access;
    bitmask_or(newval.read.words, current_trusted.read.words);
    bitmask_or(newval.write.words, current_trusted.write.words);
    bitmask_or(newval.execute.words, current_trusted.execute.words);
    newval.gpu |= current_trusted.gpu;
    bitmask_or(newval.ip_egress.words, current_trusted.ip_egress.words);
    bitmask_or(newval.ip_exclusive_owner.words, current_trusted.ip_exclusive_owner.words);
    newval.output_openats = current_access.output_openats | current_trusted.output_openats;

    if (task_ctx && has_exact_execve_argv) {
        // We need a temp map for python id (executable path, cwd, args)
        struct python_identifier *python_identifier_key;

        python_identifier_key = bpf_map_lookup_elem(&bomfather_temp_python_identifier_map, &zero);

        if (python_identifier_key) {
            // We need to pull down the temp map (variable called python_identifier_key) and empty out the python_identifier_key before we use it
            __builtin_memset(python_identifier_key->executable.directory_path, 0, sizeof(python_identifier_key->executable.directory_path));

            volatile u32 *cwd_words = (volatile u32 *)python_identifier_key->cwd;
            #pragma unroll
            for (int i = 0; i < INPUT_PATH_MAX / sizeof(u32); i++) {
                cwd_words[i] = 0;
            }

            // The argv slots are emptyed out by the trace_execve hook

            // We need to populate the python_identifier_key with the executable path, cwd, and argv
            python_identifier_key->executable.policy_id = exe_pkey->policy_id;
            __builtin_memcpy(python_identifier_key->executable.directory_path, exe_pkey->directory_path, sizeof(python_identifier_key->executable.directory_path));

            // we need to get the current working directory of the process
            struct fs_struct *fs = BPF_CORE_READ(task, fs);
            if (fs) {
                struct path pwd = BPF_CORE_READ(fs, pwd);
                if (pwd.mnt && pwd.dentry) {
                    char *cwd = get_filename_from_path(&pwd, TEMP_FILEPATH_TASK_CWD);
                    if (cwd) {
                        // populating the python_identifier_key with the cwd
                        __builtin_memcpy(python_identifier_key->cwd, cwd, sizeof(python_identifier_key->cwd));
                    }
                }
            }

            #pragma unroll
            for (int i = 0; i < MAX_ARGS; i++) {
                // populating the python_identifier_key with the argv
                __builtin_memcpy(&python_identifier_key->argv[i], &task_ctx->execve_event.argv[i], sizeof(python_identifier_key->argv[i]));
            }

            // We need to hit the map with the python_identifier_key
            struct access_control *python_access_control = bpf_map_lookup_elem(&bomfather_python_identifier_id, python_identifier_key);
            if (python_access_control == NULL && python_identifier_key->cwd[0] != '\0') {
                // The cwd isn't required, so we also need to check the access control for the python_identifier_key without the cwd
                #pragma unroll
                for (int i = 0; i < INPUT_PATH_MAX / sizeof(u32); i++) {
                    cwd_words[i] = 0;
                }
                python_access_control = bpf_map_lookup_elem(&bomfather_python_identifier_id, python_identifier_key);
            }

            if (python_access_control != NULL) {
                bitmask_or(newval.read.words, python_access_control->read.words);
                bitmask_or(newval.write.words, python_access_control->write.words);
                bitmask_or(newval.execute.words, python_access_control->execute.words);
                newval.gpu |= python_access_control->gpu;
                bitmask_or(newval.ip_egress.words, python_access_control->ip_egress.words);
                bitmask_or(newval.ip_exclusive_owner.words, python_access_control->ip_exclusive_owner.words);
                newval.output_openats |= python_access_control->output_openats;
            }
        }
    }
    u32 protected_flag = (
        bitmask_any(newval.read.words) ||
        bitmask_any(newval.write.words) ||
        bitmask_any(newval.execute.words) ||
        newval.gpu ||
        bitmask_any(newval.ip_egress.words) ||
        bitmask_any(newval.ip_exclusive_owner.words) ||
        newval.output_openats
    ) ? 1 : 0;

    if (task_ctx) {
        task_ctx->is_protected_process = protected_flag;
    }

    int *protected_executable_id = bpf_map_lookup_elem(&bomfather_executable_to_id, exe_pkey);
    if (protected_executable_id) {
        if (!bitmask_has_id(&newval.execute, *protected_executable_id)) {
            push_violation(file_info->filename, VIOL_EXECUTE, &file_info->process);
            rc = return_value();
            goto out;
        }
    }
    if (task_ctx) {
        // if the execpath is not empty do not overwrite it
        if (task_ctx->execve_event.exepath[0] == '\0') {
            __builtin_memcpy(task_ctx->execve_event.exepath, file_info->filename, sizeof(task_ctx->execve_event.exepath));
        }
    }

    if (task_ctx && task_ctx->has_been_pushed == 0) {
        bpf_perf_event_output(ctx, &bomfather_execve_events, BPF_F_CURRENT_CPU, &task_ctx->execve_event, sizeof(task_ctx->execve_event));
        task_ctx->has_been_pushed = 1;
    }
    if (task_ctx) {
        task_ctx->access = newval;
        task_ctx->access_initialized = 1;
    }

out:
    barrier_var(rc);
    return rc;
}

SEC("tracepoint/sched/sched_process_exit")
int tp_sched_process_exit(void *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = (u32)id;

    if (tgid != pid) {
        // this is a thread that is exiting, not the main thread, so we don't want to remove the process.
        return 0;
    }

    struct process_id process_id = {0};
    get_process_id(&process_id);
    bpf_map_delete_elem(&bomfather_process_metadata, &process_id);
    return 0;
}

// ----------------- BIND MOUNT PROTECTION LSM HOOK -----------------

SEC("lsm/sb_mount")
int BPF_PROG(lsm_sb_mount, const char *dev_name, struct path *path, const char *type, unsigned long flags, void *data) {

    // Only enforce on bind mounts
    if (!(flags & MS_BIND)) {
        return 0;  // Regular mounts are allowed
    }

    // Populate the shared path buffer before the tail call.
    if (!get_filename_from_path(path, TEMP_FILEPATH_PATH_BIND_MOUNT)) {
        return 0;
    }

    bpf_tail_call(ctx, &bomfather_mount_check_jump_table, 0);
    return 0;
}

SEC("lsm/sb_mount")
int BPF_PROG(tail_call_mount_check, const char *dev_name, struct path *path, const char *type, unsigned long flags, void *data) {
    u32 key = TEMP_FILEPATH_PATH_BIND_MOUNT;
    char *path_str = bpf_map_lookup_elem(&bomfather_temp_filename_map, &key);
    if (!path_str) {
        return 0;
    }
    struct path_container_id_component_ctx pctx = {
        .path = path_str,
        .container_correlation_counter_index = 0,
        .component_start = 0,
        .component_len = 0,
        .policy_id = 0,
        .saw_path_byte = 0,
    };
    bpf_loop(INPUT_PATH_MAX - 1, mount_check_callback, &pctx, 0);

    if (pctx.policy_id != 0) {
        struct task_struct *task = bpf_get_current_task_btf();
        if (!task) {
            return 0;
        }
        struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
        if (!nsproxy) {
            return 0;
        }

        struct mnt_namespace *mnt_ns = BPF_CORE_READ(nsproxy, mnt_ns);
        if (!mnt_ns) {
            return 0;
        }

        u32 mnt_ns_inum = 0;
        if (BPF_CORE_READ_INTO(&mnt_ns_inum, mnt_ns, ns.inum)) {
            return 0;
        }
        u64 mnt_ns_id = mnt_ns_inum;
        struct container_context container_ctx = {
            .policy_id = (u32)pctx.policy_id,
            .correlation_index = pctx.container_correlation_counter_index,
        };
        bpf_map_update_elem(&bomfather_mntns_to_container_context, &mnt_ns_id, &container_ctx, BPF_ANY);
    }

    bool is_trusted = is_trusted_executable(path_str);
    if (is_trusted) {
        struct process_id process = {0};
        get_process_id(&process);
        push_violation(path_str, VIOL_BIND_MOUNT, &process);
        return return_value();
    }
    return 0;
}


// ----------------- ANONYMOUS MEMORY MAPPING SECURITY HOOK -----------------

SEC("lsm/mmap_file")
int BPF_PROG(lsm_mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags) {
    u32 zero = 0;
    u32 temp_map_index = TEMP_FILEPATH_MMAP_FILE;

    // If the mapping is not executable, return.
    if (!(prot & PROT_EXEC)) {
        return 0;
    }

    // File-backed executable mappings must match fs-verity pinning when configured.
    if (file) {
        char *filename = bpf_map_lookup_elem(&bomfather_temp_filename_map, &temp_map_index);
        if (filename) {
            struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
            __builtin_memset(filename, 0, INPUT_PATH_MAX);
            get_filename(file, dentry, filename, INPUT_PATH_MAX);

            if (fsverity_check_path(filename, file) < 0) {
                struct process_id process = {0};
                get_process_id(&process);
                push_violation(filename, VIOL_FSVERITY_DENIED, &process);
                return return_value();
            }
        }
    }

    // In-memory exec blocking (anonymous mappings) is a separate, opt-in control.
    u32 *block_in_memory = bpf_map_lookup_elem(&bomfather_block_in_memory_exec, &zero);
    if (!(block_in_memory && *block_in_memory)) {
        return 0;
    }

    if ((prot & PROT_EXEC) && (flags & MAP_ANONYMOUS)) {
        struct process_id process = {0};
        get_process_id(&process);
        push_violation("anonymous executable mapping", VIOL_ANON_MAP_EXEC, &process);
        return return_value();
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL"; // Program is licensed under GPL

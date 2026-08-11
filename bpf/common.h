#include "vmlinux.h"
#include "libbpf/src/bpf_helpers.h"
#include "libbpf/src/bpf_core_read.h"
#include "libbpf/src/bpf_tracing.h"
#include "libbpf/src/bpf_endian.h"

#ifndef __PATH_STR_BUF_H__
#define __PATH_STR_BUF_H__
#define MAX_PERCPU_BUFSIZE (1 << 15)
#define MAX_STRING_SIZE    4096
#define MAX_PATH_COMPONENTS 20

enum buf_idx_e
{
    STRING_BUF_IDX,
    FILE_BUF_IDX,
    MAX_BUFFERS
};

typedef struct simple_buf {
    u8 buf[MAX_PERCPU_BUFSIZE];
} buf_t;

typedef struct file_id {
    dev_t device;
    unsigned long inode;
    u64 ctime;
} file_id_t;

typedef struct path_buf {
    u8 buf[MAX_STRING_SIZE];
} path_buf_t;

#ifndef container_of
#define container_of(ptr, type, member) ({          \
    const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
    (type *)( (char *)__mptr - offsetof(type, member) );})
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_BUFFERS);
    __type(key, u32);
    __type(value, buf_t);
} bufs SEC(".maps");

static inline buf_t *get_buf(int idx)
{
    return (buf_t *)bpf_map_lookup_elem(&bufs, &idx);
}

static inline struct mount *real_mount(struct vfsmount *mnt)
{
    return container_of(mnt, struct mount, mnt);
}

static inline struct dentry *get_mnt_root_ptr_from_vfsmnt(struct vfsmount *vfsmnt)
{
    return BPF_CORE_READ(vfsmnt, mnt_root);
}

static inline struct dentry *get_d_parent_ptr_from_dentry(struct dentry *dentry)
{
    return BPF_CORE_READ(dentry, d_parent);
}

static inline struct qstr get_d_name_from_dentry(struct dentry *dentry)
{
    return BPF_CORE_READ(dentry, d_name);
}

static inline size_t get_path_str_buf(struct path *path, buf_t *out_buf)
{
    if (path == NULL || out_buf == NULL) {
        return 0;
    }

    char slash = '/';
    int zero = 0;
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    struct vfsmount *vfsmnt = BPF_CORE_READ(path, mnt);
    struct mount *mnt_parent_p;
    struct mount *mnt_p = real_mount(vfsmnt);
    bpf_core_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);

    u32 buf_off = (MAX_PERCPU_BUFSIZE >> 1);
    struct dentry *mnt_root;
    struct dentry *d_parent;
    struct qstr d_name;
    unsigned int len;
    unsigned int off;
    int sz;

    #pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        mnt_root = get_mnt_root_ptr_from_vfsmnt(vfsmnt);
        d_parent = get_d_parent_ptr_from_dentry(dentry);

        if (dentry == mnt_root || dentry == d_parent) {
            if (dentry != mnt_root) {
                break;
            }
            if (mnt_p != mnt_parent_p) {
                bpf_core_read(&dentry, sizeof(struct dentry *), &mnt_p->mnt_mountpoint);
                bpf_core_read(&mnt_p, sizeof(struct mount *), &mnt_p->mnt_parent);
                bpf_core_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);
                vfsmnt = &mnt_p->mnt;
                continue;
            }
            break;
        }

        d_name = get_d_name_from_dentry(dentry);

        len = (d_name.len + 1) & (MAX_STRING_SIZE - 1);
        off = buf_off - len;

        sz = 0;
        if (off <= buf_off) {
            len = len & ((MAX_PERCPU_BUFSIZE >> 1) - 1);
            sz = bpf_probe_read_kernel_str(
                &(out_buf->buf[off & ((MAX_PERCPU_BUFSIZE >> 1) - 1)]),
                len,
                (void *) d_name.name);
        } else {
            break;
        }

        if (sz > 1) {
            buf_off -= 1;
            bpf_probe_read_kernel(&(out_buf->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &slash);
            buf_off -= sz - 1;
        } else {
            break;
        }

        dentry = d_parent;
    }

    if (buf_off == (MAX_PERCPU_BUFSIZE >> 1)) {
        buf_off = 0;
        d_name = get_d_name_from_dentry(dentry);
        bpf_probe_read_kernel_str(&(out_buf->buf[0]), MAX_STRING_SIZE, (void *) d_name.name);
    } else {
        buf_off -= 1;
        bpf_probe_read_kernel(&(out_buf->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &slash);
        bpf_probe_read_kernel(&(out_buf->buf[(MAX_PERCPU_BUFSIZE >> 1) - 1]), 1, &zero);
    }

    return buf_off;
}

static inline void *get_path_str(struct path *path)
{
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return NULL;

    size_t buf_off = get_path_str_buf(path, string_p);
    return &string_p->buf[buf_off & ((MAX_PERCPU_BUFSIZE >> 1) - 1)];
}

#endif /* __PATH_STR_BUF_H__ */

let install_filter = null, syscall_thread_ptr, call_task, lock, unlock, findSoinfoByAddr, solist_get_head_ptr, get_soname, get_base, get_size, maps = [];
const MAX_STACK_TRACE_DEPTH = 10;
const Target_NR = 207;
const prctl_ptr = Module.findExportByName(null, 'prctl')
const strcpy_ptr = Module.findExportByName(null, 'strcpy')
const fopen_ptr = Module.findExportByName(null, 'fopen')
const fclose_ptr = Module.findExportByName(null, 'fclose')
const fgets_ptr = Module.findExportByName(null, 'fgets')
const strtoul_ptr = Module.findExportByName(null, 'strtoul')
const strtok_ptr = Module.findExportByName(null, 'strtok')
const malloc_ptr = Module.findExportByName(null, 'malloc')
const __android_log_print_ptr = Module.findExportByName(null, '__android_log_print')
const pthread_create_ptr = Module.findExportByName(null, 'pthread_create')
const pthread_mutex_init_ptr = Module.findExportByName(null, 'pthread_mutex_init')
const pthread_mutex_lock_ptr = Module.findExportByName(null, 'pthread_mutex_lock')
const pthread_mutex_unlock_ptr = Module.findExportByName(null, 'pthread_mutex_unlock')
const pthread_join_ptr = Module.findExportByName(null, 'pthread_join')
const syscall_ptr = Module.findExportByName(null, 'syscall')
const linker = Process.findModuleByName("linker64");
const linker_symbols = linker.enumerateSymbols()
for (let index = 0; index < linker_symbols.length; index++) {
    const element = linker_symbols[index];
    if (element.name == '__dl__Z15solist_get_headv') {
        solist_get_head_ptr = element.address
    } else if (element.name == '__dl__ZNK6soinfo10get_sonameEv') {
        get_soname = new NativeFunction(element.address, "pointer", ["pointer"])
    }
}

function init() {
    //初始化，需要在主线程初始化且需要一个比较早的时机，frida脚本运行在它自己创建的一个线程，所以需要通过hook安装seccomp规则
    syscall_thread_ptr = new NativeFunction(cm.pthread_syscall_create, "pointer", [])()
    findSoinfoByAddr = new NativeFunction(cm.findSoinfoByAddr, "pointer", ["pointer"])
    get_base = new NativeFunction(cm.get_base, "uint64", ["pointer"])
    get_size = new NativeFunction(cm.get_size, "size_t", ["pointer"])
    call_task = new NativeFunction(cm.call_task, "pointer", ["pointer", "pointer", "int"])
    install_filter = new NativeFunction(cm.install_filter, "int", ['uint32'])
    lock = new NativeFunction(cm.lock, "int", ["pointer"])
    unlock = new NativeFunction(cm.unlock, "int", ["pointer"])
    // 异常处理
    Process.setExceptionHandler(function (details) {
        const current_off = details.context.pc - 4;
        // 判断是否是seccomp导致的异常 读取opcode 010000d4 == svc 0
        if (details.message == "system error" && details.type == "system" && hex(ptr(current_off).readByteArray(4)) == "010000d4") {
            // 上锁避免多线程问题
            lock(syscall_thread_ptr)
            // 获取x8寄存器中的调用号
            const nr = details.context.x8.toString(10);
            let loginfo = "\n=================="
            loginfo += `\nSVC[${syscalls[nr][1]}|${nr}] ==> PC:${addrToString(current_off)} P${Process.id}-T${Process.getCurrentThreadId()}`
            // 构造线程syscall调用参数
            const args = Memory.alloc(7 * 8)
            args.writePointer(details.context.x8)
            let args_reg_arr = {}
            for (let index = 0; index < 6; index++) {
                eval(`args.add(8 * (index + 1)).writePointer(details.context.x${index})`)
                eval(`args_reg_arr["arg${index}"] = details.context.x${index}`)
            }
            // 获取手动堆栈信息
            loginfo += "\n" + stacktrace(ptr(current_off), details.context.fp, details.context.sp).map(addrToString).join('\n')
            // 打印传参
            loginfo += "\nargs = " + JSON.stringify(args_reg_arr)
            // 调用线程syscall 赋值x0寄存器
            details.context.x0 = call_task(syscall_thread_ptr, args, 0)
            loginfo += "\nret = " + details.context.x0.toString()
            // 打印信息
            call_thread_log(loginfo)
            // 解锁
            unlock(syscall_thread_ptr)
            return true;
        }
        return false;
    })
    // openat的调用号
    install_filter(Target_NR)
}

// CModule模块编写
const cm = new CModule(`
#include <stdio.h>
#include <gum/gumprocess.h>
#define BPF_STMT(code,k) { (unsigned short) (code), 0, 0, k }
#define BPF_JUMP(code,k,jt,jf) { (unsigned short) (code), jt, jf, k }
#define BPF_LD 0x00
#define BPF_W 0x00
#define BPF_ABS 0x20
#define BPF_JEQ 0x10
#define BPF_JMP 0x05
#define BPF_K 0x00
#define BPF_RET 0x06

#define PR_SET_SECCOMP	22
#define PR_SET_NO_NEW_PRIVS	38
#define SECCOMP_MODE_FILTER	2
#define SECCOMP_RET_TRAP 0x00030000U
#define SECCOMP_RET_ALLOW 0x7fff0000U

#define SIGSYS  12
#define SIG_UNBLOCK     2

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef unsigned long sigset_t;
typedef long pthread_t;

typedef struct {
    uint32_t flags;
    void* stack_base;
    size_t stack_size;
    size_t guard_size;
    int32_t sched_policy;
    int32_t sched_priority;
  #ifdef __LP64__
    char __reserved[16];
  #endif
  } pthread_attr_t;

typedef struct {
#if defined(__LP64__)
  int32_t __private[10];
#else
  int32_t __private[1];
#endif
} pthread_mutex_t;

typedef struct {
    int type;
    int isTask;
    void *args;
    int isReturn;
    void *ret;
    pthread_t thread;
    pthread_mutex_t mutex;
} thread_syscall_t;

typedef struct{
    const void *phdr;
    size_t phnum;
    uint64_t base;
    size_t size;
    void *dynamic;
    void *next;
} soinfo;

extern char* strcpy(char* __dst, const char* __src);
extern void* fopen(const char* __path, const char* __mode);
extern int fclose(void* __fp);
extern char* fgets(char* __buf, int __size, void* __fp);
extern unsigned long strtoul(const char* __s, char** __end_ptr, int __base);
extern char* strtok(char* __s, const char* __delimiter);
extern soinfo *solist_get_head();
extern int __android_log_print(int prio, const char* tag, const char* fmt, ...);
extern void *malloc(size_t __byte_count);
extern long syscall(long __number, ...);
extern int pthread_create(pthread_t* __pthread_ptr, pthread_attr_t const* __attr, void* (*__start_routine)(void*), void*);
extern int pthread_mutex_init(pthread_mutex_t* __mutex, const void* __attr);
extern int pthread_mutex_lock(pthread_mutex_t* __mutex);
extern int pthread_mutex_unlock(pthread_mutex_t* __mutex);
extern int pthread_join(pthread_t __pthread, void** __return_value_ptr);
extern void on_message(const gchar *message);
extern int prctl(int __option, ...);

uint64_t get_base(soinfo *si){
    return si->base;
}

size_t get_size(soinfo *si){
    return si->size;
}

soinfo *findSoinfoByAddr(void *addr_v) {
    uint64_t addr = (uint64_t) addr_v;
    for (soinfo *si = (soinfo *)solist_get_head(); si != NULL; si = si->next) {
      if (addr >= si->base && addr < (si->base + si->size)) {
        return si;
      }
    }
    return NULL;
}

static void log(const gchar *format, ...)
{
    gchar *message;
    va_list args;
    va_start(args, format);
    message = g_strdup_vprintf(format, args);
    va_end(args);
    on_message(message);
    g_free(message);
}

int lock(thread_syscall_t *syscall_thread){
    return pthread_mutex_lock(&syscall_thread->mutex);
}

int unlock(thread_syscall_t *syscall_thread){
    return pthread_mutex_unlock(&syscall_thread->mutex);
}

void *call_syscall(void *args){
    void **d_args = (void **)args;
    void *ret = (void *)syscall((long)d_args[0] ,d_args[1] ,d_args[2] ,d_args[3], d_args[4], d_args[5], d_args[6]);
    return ret;
}

void *call_log(void *args){
    __android_log_print(3, "seccomp", (const char *)args);
    return NULL;
}

void *call_read_maps(void *args){
    uint64_t addr = (uint64_t) args;
    FILE *fp = fopen("/proc/self/maps", "r");
    char line[1024];
    char _line[1024];
    uint64_t start, end;
    while (fgets(line, sizeof(line), fp) != NULL) {
        strcpy(_line, line);
        start = (uint64_t) strtoul(strtok(line, "-"), NULL, 16);
        end = (uint64_t) strtoul(strtok(NULL, " "), NULL, 16);
        if (addr >= start && addr < end) {
          break;
        }
    }
    fclose(fp);
    return (void *)_line;
}

void *call_task(thread_syscall_t *syscall_thread,void *args,int type){
    if(syscall_thread->isTask == 0){
        syscall_thread->args = args;
        syscall_thread->type = type;
        syscall_thread->isTask = 1;
    }
    do{
        if(syscall_thread->isReturn){
            syscall_thread->isReturn = 0;
            return syscall_thread->ret;
        }
    }while(1);
}

void *pthread_syscall(void *args){
    thread_syscall_t *syscall_thread = (thread_syscall_t *)args;
    while(1){
        if(syscall_thread->isTask){
            if(syscall_thread->type == 0){
                syscall_thread->ret = call_syscall(syscall_thread->args);
            }else if(syscall_thread->type == 1){
                syscall_thread->ret = call_log(syscall_thread->args);
            }else if(syscall_thread->type == 2){
                syscall_thread->ret = call_read_maps(syscall_thread->args);
            }
            syscall_thread->args = NULL;
            syscall_thread->isReturn = 1;
            syscall_thread->isTask = 0;
        }
    }
    return NULL;
}

//syscall线程创建

thread_syscall_t *pthread_syscall_create(){
    thread_syscall_t *syscall_thread = (thread_syscall_t *)malloc(sizeof(thread_syscall_t));
    syscall_thread->type = 0;
    syscall_thread->isTask = 0;
    syscall_thread->args = NULL;
    syscall_thread->ret = NULL;
    syscall_thread->isReturn = 0;
    pthread_mutex_init(&syscall_thread->mutex, NULL);
    pthread_t threadId;
    pthread_create(&threadId, NULL, &pthread_syscall, (void *)syscall_thread);
    syscall_thread->thread = threadId;
    return syscall_thread;
}

struct seccomp_data {
    int nr;
    __u32 arch;
    __u64 instruction_pointer;
    __u64 args[6];
};

struct sock_filter {
    __u16 code;
    __u8 jt;
    __u8 jf;
    __u32 k;
};

struct sock_fprog {
    unsigned short len;
    struct sock_filter * filter;
};

int install_filter(__u32 nr) {
    log("install_filter(%lu)",nr);
    struct sock_filter filter[] = {
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, nr, 0, 1),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRAP),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
            .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
            .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        on_message("prctl(NO_NEW_PRIVS)");
        return 1;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        on_message("prctl(PR_SET_SECCOMP)");
        return 1;
    }
    return 0;
}
`, {
    malloc: malloc_ptr,
    prctl: prctl_ptr,
    fopen: fopen_ptr,
    fclose: fclose_ptr,
    fgets: fgets_ptr,
    strtok: strtok_ptr,
    strcpy: strcpy_ptr,
    strtoul: strtoul_ptr,
    __android_log_print: __android_log_print_ptr,
    pthread_create: pthread_create_ptr,
    pthread_join: pthread_join_ptr,
    pthread_mutex_init: pthread_mutex_init_ptr,
    pthread_mutex_lock: pthread_mutex_lock_ptr,
    pthread_mutex_unlock: pthread_mutex_unlock_ptr,
    syscall: syscall_ptr,
    solist_get_head: solist_get_head_ptr,
    on_message: new NativeCallback(messagePtr => {
        const message = messagePtr.readUtf8String();
        console.log(message)
    }, 'void', ['pointer'])
});

Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
    onEnter(args) {
        if (install_filter == null) {
            init()
        }
    }
})


const byteToHex = [];

for (let n = 0; n <= 0xff; ++n) {
    const hexOctet = n.toString(16).padStart(2, "0");
    byteToHex.push(hexOctet);
}

function hex(arrayBuffer) {
    const buff = new Uint8Array(arrayBuffer);
    const hexOctets = [];
    for (let i = 0; i < buff.length; ++i)
        hexOctets.push(byteToHex[buff[i]]);
    return hexOctets.join("");
}

function call_thread_log(str) {
    call_task(syscall_thread_ptr, Memory.allocUtf8String(str), 1)
}

function call_thread_read_maps(addr) {
    for (let index = 0; index < maps.length; index++) {
        const element = maps[index];
        if (parseInt(addr.toString()) >= element[0] && parseInt(addr.toString()) < element[1]) {
            return { start: element[0], end: element[1], name: element[2] }
        }
    }
    const map_info = call_task(syscall_thread_ptr, ptr(addr), 2).readUtf8String()
    const start = parseInt("0x" + map_info.split("-")[0])
    const end = parseInt("0x" + map_info.split("-")[1].split(" ")[0])
    const name_arr = map_info.split("                              ")
    const name = name_arr.length == 2 ? name_arr[2] : ""
    maps.push([start, end, name])
    return { start, end, name }
}

function addrToString(addr) {
    const add_s = parseInt(addr.toString(10))
    const addr_soinfo = findSoinfoByAddr(ptr(add_s));
    if (addr_soinfo != 0) {
        return `0x${addr.toString(16)}[${get_soname(addr_soinfo).readUtf8String()}:0x${(addr - get_base(addr_soinfo)).toString(16)}]`
    }
    if (add_s >= linker.base && add_s < linker.base + linker.size) {
        return `0x${add_s.toString(16)}[${linker.name}:0x${(add_s - linker.base).toString(16)}]`
    }
    const mem_region = call_thread_read_maps(add_s);
    if (mem_region.name != "") {
        return `0x${add_s.toString(16)}[${mem_region.name}:0x${(add_s - mem_region.start).toString(16)}]`
    }
    return `0x${addr.toString(16)}[unkownmem:]`
}

function stacktrace(pc, fp, sp) {
    let n = 0, stack_arr = [], fp_c = fp;
    stack_arr[n++] = pc;
    const mem_region = call_thread_read_maps(sp);
    while (n < MAX_STACK_TRACE_DEPTH) {
        if (parseInt(fp_c.toString()) < parseInt(sp.toString()) || fp_c < mem_region.start || fp_c > mem_region.end) {
            break
        }
        let next_fp = fp_c.readPointer()
        let lr = fp_c.add(8).readPointer()
        fp_c = next_fp
        stack_arr[n++] = lr
    }
    return stack_arr;
}

const syscalls = [
    [0, "io_setup", 0x00, "unsigned nr_reqs", "aio_context_t *ctx", "-", "-", "-"],
    [1, "io_destroy", 0x01, "aio_context_t ctx", "-", "-", "-", "-"],
    [2, "io_submit", 0x02, "aio_context_t", "long", "struct iocb * *", "-", "-"],
    [3, "io_cancel", 0x03, "aio_context_t ctx_id", "struct iocb *iocb", "struct io_event *result", "-", "-"],
    [4, "io_getevents", 0x04, "aio_context_t ctx_id", "long min_nr", "long nr", "struct io_event *events", "struct __kernel_timespec *timeout"],
    [5, "setxattr", 0x05, "const char *path", "const char *name", "const void *value", "size_t size", "int flags"],
    [6, "lsetxattr", 0x06, "const char *path", "const char *name", "const void *value", "size_t size", "int flags"],
    [7, "fsetxattr", 0x07, "int fd", "const char *name", "const void *value", "size_t size", "int flags"],
    [8, "getxattr", 0x08, "const char *path", "const char *name", "void *value", "size_t size", "-"],
    [9, "lgetxattr", 0x09, "const char *path", "const char *name", "void *value", "size_t size", "-"],
    [10, "fgetxattr", 0x0a, "int fd", "const char *name", "void *value", "size_t size"],
    [11, "listxattr", 0x0b, "const char *path", "char *list", "size_t size", "-"],
    [12, "llistxattr", 0x0c, "const char *path", "char *list", "size_t size", "-"],
    [13, "flistxattr", 0x0d, "int fd", "char *list", "size_t size", "-"],
    [14, "removexattr", 0x0e, "const char *path", "const char *name", "-", "-"],
    [15, "lremovexattr", 0x0f, "const char *path", "const char *name", "-", "-"],
    [16, "fremovexattr", 0x10, "int fd", "const char *name", "-", "-"],
    [17, "getcwd", 0x11, "char *buf", "unsigned long size", "-", "-"],
    [18, "lookup_dcookie", 0x12, "u64 cookie64", "char *buf", "size_t len", "-"],
    [19, "eventfd2", 0x13, "unsigned int count", "int flags", "-", "-"],
    [20, "epoll_create1", 0x14, "int flags"],
    [21, "epoll_ctl", 0x15, "int epfd", "int op", "int fd", "struct epoll_event *event"],
    [22, "epoll_pwait", 0x16, "int epfd", "struct epoll_event *events", "int maxevents", "int timeout", "const sigset_t *sigmask", "size_t sigsetsize"],
    [23, "dup", 0x17, "unsigned int fildes"],
    [24, "dup3", 0x18, "unsigned int oldfd", "unsigned int newfd", "int flags", "-"],
    [25, "fcntl", 0x19, "unsigned int fd", "unsigned int cmd", "unsigned long arg", "-"],
    [26, "inotify_init1", 0x1a, "int flags"],
    [27, "inotify_add_watch", 0x1b, "int fd", "const char *path", "u32 mask", "-"],
    [28, "inotify_rm_watch", 0x1c, "int fd", "__s32 wd", "-", "-"],
    [29, "ioctl", 0x1d, "unsigned int fd", "unsigned int cmd", "unsigned long arg", "-"],
    [30, "ioprio_set", 0x1e, "int which", "int who", "int ioprio", "-"],
    [31, "ioprio_get", 0x1f, "int which", "int who", "-", "-"],
    [32, "flock", 0x20, "unsigned int fd", "unsigned int cmd", "-", "-"],
    [33, "mknodat", 0x21, "int dfd", "const char * filename", "umode_t mode", "unsigned dev"],
    [34, "mkdirat", 0x22, "int dfd", "const char * pathname", "umode_t mode", "-"],
    [35, "unlinkat", 0x23, "int dfd", "const char * pathname", "int flag", "-"],
    [36, "symlinkat", 0x24, "const char * oldname", "int newdfd", "const char * newname", "-"],
    [37, "linkat", 0x25, "int olddfd", "const char *oldname", "int newdfd", "const char *newname", "int flag"],
    [38, "renameat", 0x26, "int olddfd", "const char * oldname", "int newdfd", "const char * newname"],
    [39, "umount2", 0x27, "?", "?", "?", "?", "?", "?["],
    [40, "mount", 0x28, "char *dev_name", "char *dir_name", "char *type", "unsigned long flags", "void *dat"],
    [41, "pivot_root", 0x29, "const char *new_root", "const char *put_old", "-", "-"],
    [42, "nfsservctl", 0x2a, "?", "?", "?", "?", "?", "?["],
    [43, "statfs", 0x2b, "const char * path", "struct statfs *buf", "-", "-"],
    [44, "fstatfs", 0x2c, "unsigned int fd", "struct statfs *buf", "-", "-"],
    [45, "truncate", 0x2d, "const char *path", "long length", "-", "-"],
    [46, "ftruncate", 0x2e, "unsigned int fd", "unsigned long length", "-", "-"],
    [47, "fallocate", 0x2f, "int fd", "int mode", "loff_t offset", "loff_t len"],
    [48, "faccessat", 0x30, "int dfd", "const char *filename", "int mode", "-"],
    [49, "chdir", 0x31, "const char *filename"],
    [50, "fchdir", 0x32, "unsigned int fd"],
    [51, "chroot", 0x33, "const char *filename"],
    [52, "fchmod", 0x34, "unsigned int fd", "umode_t mode", "-", "-"],
    [53, "fchmodat", 0x35, "int dfd", "const char * filename", "umode_t mode", "-"],
    [54, "fchownat", 0x36, "int dfd", "const char *filename", "uid_t user", "gid_t group", "int fla"],
    [55, "fchown", 0x37, "unsigned int fd", "uid_t user", "gid_t group", "-"],
    [56, "openat", 0x38, "int dfd", "const char *filename", "int flags", "umode_t mode"],
    [57, "close", 0x39, "unsigned int fd"],
    [58, "vhangup", 0x3a, "-"],
    [59, "pipe2", 0x3b, "int *fildes", "int flags", "-", "-"],
    [60, "quotactl", 0x3c, "unsigned int cmd", "const char *special", "qid_t id", "void *addr"],
    [61, "getdents64", 0x3d, "unsigned int fd", "struct linux_dirent64 *dirent", "unsigned int count", "-"],
    [62, "lseek", 0x3e, "unsigned int fd", "off_t offset", "unsigned int whence", "-"],
    [63, "read", 0x3f, "unsigned int fd", "char *buf", "size_t count", "-"],
    [64, "write", 0x40, "unsigned int fd", "const char *buf", "size_t count", "-"],
    [65, "readv", 0x41, "unsigned long fd", "const struct iovec *vec", "unsigned long vlen", "-"],
    [66, "writev", 0x42, "unsigned long fd", "const struct iovec *vec", "unsigned long vlen", "-"],
    [67, "pread64", 0x43, "unsigned int fd", "char *buf", "size_t count", "loff_t pos"],
    [68, "pwrite64", 0x44, "unsigned int fd", "const char *buf", "size_t count", "loff_t pos"],
    [69, "preadv", 0x45, "unsigned long fd", "const struct iovec *vec", "unsigned long vlen", "unsigned long pos_l", "unsigned long pos_"],
    [70, "pwritev", 0x46, "unsigned long fd", "const struct iovec *vec", "unsigned long vlen", "unsigned long pos_l", "unsigned long pos_"],
    [71, "sendfile", 0x47, "int out_fd", "int in_fd", "off_t *offset", "size_t count"],
    [72, "pselect6", 0x48, "int", "fd_set *", "fd_set *", "fd_set *", "struct __kernel_timespec *", "void *["],
    [73, "ppoll", 0x49, "struct pollfd *", "unsigned int", "struct __kernel_timespec *", "const sigset_t *", "size_"],
    [74, "signalfd4", 0x4a, "int ufd", "sigset_t *user_mask", "size_t sizemask", "int flags"],
    [75, "vmsplice", 0x4b, "int fd", "const struct iovec *iov", "unsigned long nr_segs", "unsigned int flags"],
    [76, "splice", 0x4c, "int fd_in", "loff_t *off_in", "int fd_out", "loff_t *off_out", "size_t len", "unsigned int flags["],
    [77, "tee", 0x4d, "int fdin", "int fdout", "size_t len", "unsigned int flags"],
    [78, "readlinkat", 0x4e, "int dfd", "const char *path", "char *buf", "int bufsiz"],
    [79, "newfstatat", 0x4f, "int dfd", "const char *filename", "struct stat *statbuf", "int flag"],
    [80, "fstat", 0x50, "unsigned int fd", "struct __old_kernel_stat *statbuf", "-", "-"],
    [81, "sync", 0x51, "-"],
    [82, "fsync", 0x52, "unsigned int fd"],
    [83, "fdatasync", 0x53, "unsigned int fd"],
    [84, "sync_file_range", 0x54, "int fd", "loff_t offset", "loff_t nbytes", "unsigned int flags"],
    [85, "timerfd_create", 0x55, "int clockid", "int flags", "-", "-"],
    [86, "timerfd_settime", 0x56, "int ufd", "int flags", "const struct __kernel_itimerspec *utmr", "struct __kernel_itimerspec *otmr"],
    [87, "timerfd_gettime", 0x57, "int ufd", "struct __kernel_itimerspec *otmr", "-", "-"],
    [88, "utimensat", 0x58, "int dfd", "const char *filename", "struct __kernel_timespec *utimes", "int flags"],
    [89, "acct", 0x59, "const char *name"],
    [90, "capget", 0x5a, "cap_user_header_t header", "cap_user_data_t dataptr", "-", "-"],
    [91, "capset", 0x5b, "cap_user_header_t header", "const cap_user_data_t data", "-", "-"],
    [92, "personality", 0x5c, "unsigned int personality"],
    [93, "exit", 0x5d, "int error_code"],
    [94, "exit_group", 0x5e, "int error_code"],
    [95, "waitid", 0x5f, "int which", "pid_t pid", "struct siginfo *infop", "int options", "struct rusage *r"],
    [96, "set_tid_address", 0x60, "int *tidptr"],
    [97, "unshare", 0x61, "unsigned long unshare_flags"],
    [98, "futex", 0x62, "u32 *uaddr", "int op", "u32 val", "struct __kernel_timespec *utime", "u32 *uaddr2", "u32 val3["],
    [99, "set_robust_list", 0x63, "struct robust_list_head *head", "size_t len", "-", "-"],
    [100, "get_robust_list", 0x64, "int pid", "struct robust_list_head * *head_ptr", "size_t *len_ptr", "-", "-", "-"],
    [101, "nanosleep", 0x65, "struct __kernel_timespec *rqtp", "struct __kernel_timespec *rmtp", "-", "-", "-", "-"],
    [102, "getitimer", 0x66, "int which", "struct itimerval *value", "-", "-", "-", "-"],
    [103, "setitimer", 0x67, "int which", "struct itimerval *value", "struct itimerval *ovalue", "-", "-", "-"],
    [104, "kexec_load", 0x68, "unsigned long entry", "unsigned long nr_segments", "struct kexec_segment *segments", "unsigned long flags", "-", "-"],
    [105, "init_module", 0x69, "void *umod", "unsigned long len", "const char *uargs", "-", "-", "-"],
    [106, "delete_module", 0x6a, "const char *name_user", "unsigned int flags", "-", "-", "-", "-"],
    [107, "timer_create", 0x6b, "clockid_t which_clock", "struct sigevent *timer_event_spec", "timer_t * created_timer_id", "-", "-", "-"],
    [108, "timer_gettime", 0x6c, "timer_t timer_id", "struct __kernel_itimerspec *setting", "-", "-", "-", "-"],
    [109, "timer_getoverrun", 0x6d, "timer_t timer_id", "-", "-", "-", "-", "-"],
    [110, "timer_settime", 0x6e, "timer_t timer_id", "int flags", "const struct __kernel_itimerspec *new_setting", "struct __kernel_itimerspec *old_setting", "-", "-"],
    [111, "timer_delete", 0x6f, "timer_t timer_id", "-", "-", "-", "-", "-"],
    [112, "clock_settime", 0x70, "clockid_t which_clock", "const struct __kernel_timespec *tp", "-", "-", "-", "-"],
    [113, "clock_gettime", 0x71, "clockid_t which_clock", "struct __kernel_timespec *tp", "-", "-", "-", "-"],
    [114, "clock_getres", 0x72, "clockid_t which_clock", "struct __kernel_timespec *tp", "-", "-", "-", "-"],
    [115, "clock_nanosleep", 0x73, "clockid_t which_clock", "int flags", "const struct __kernel_timespec *rqtp", "struct __kernel_timespec *rmtp", "-", "-"],
    [116, "syslog", 0x74, "int type", "char *buf", "int len", "-", "-", "-"],
    [117, "ptrace", 0x75, "long request", "long pid", "unsigned long addr", "unsigned long data", "-", "-"],
    [118, "sched_setparam", 0x76, "pid_t pid", "struct sched_param *param", "-", "-", "-", "-"],
    [119, "sched_setscheduler", 0x77, "pid_t pid", "int policy", "struct sched_param *param", "-", "-", "-"],
    [120, "sched_getscheduler", 0x78, "pid_t pid", "-", "-", "-", "-", "-"],
    [121, "sched_getparam", 0x79, "pid_t pid", "struct sched_param *param", "-", "-", "-", "-"],
    [122, "sched_setaffinity", 0x7a, "pid_t pid", "unsigned int len", "unsigned long *user_mask_ptr", "-", "-", "-"],
    [123, "sched_getaffinity", 0x7b, "pid_t pid", "unsigned int len", "unsigned long *user_mask_ptr", "-", "-", "-"],
    [124, "sched_yield", 0x7c, "-", "-", "-", "-", "-", "-"],
    [125, "sched_get_priority_max", 0x7d, "int policy", "-", "-", "-", "-", "-"],
    [126, "sched_get_priority_min", 0x7e, "int policy", "-", "-", "-", "-", "-"],
    [127, "sched_rr_get_interval", 0x7f, "pid_t pid", "struct __kernel_timespec *interval", "-", "-", "-", "-"],
    [128, "restart_syscall", 0x80, "-", "-", "-", "-", "-", "-"],
    [129, "kill", 0x81, "pid_t pid", "int sig", "-", "-", "-", "-"],
    [130, "tkill", 0x82, "pid_t pid", "int sig", "-", "-", "-", "-"],
    [131, "tgkill", 0x83, "pid_t tgid", "pid_t pid", "int sig", "-", "-", "-"],
    [132, "sigaltstack", 0x84, "const struct sigaltstack *uss", "struct sigaltstack *uoss", "-", "-", "-", "-"],
    [133, "rt_sigsuspend", 0x85, "sigset_t *unewset", "size_t sigsetsize", "-", "-", "-", "-"],
    [134, "rt_sigaction", 0x86, "int", "const struct sigaction *", "struct sigaction *", "size_t", "-", "-"],
    [135, "rt_sigprocmask", 0x87, "int how", "sigset_t *set", "sigset_t *oset", "size_t sigsetsize", "-", "-"],
    [136, "rt_sigpending", 0x88, "sigset_t *set", "size_t sigsetsize", "-", "-", "-", "-"],
    [137, "rt_sigtimedwait", 0x89, "const sigset_t *uthese", "siginfo_t *uinfo", "const struct __kernel_timespec *uts", "size_t sigsetsize", "-", "-"],
    [138, "rt_sigqueueinfo", 0x8a, "pid_t pid", "int sig", "siginfo_t *uinfo", "-", "-", "-"],
    [139, "rt_sigreturn", 0x8b, "?", "?", "?", "?", "?", "?"],
    [140, "setpriority", 0x8c, "int which", "int who", "int niceval", "-", "-", "-"],
    [141, "getpriority", 0x8d, "int which", "int who", "-", "-", "-", "-"],
    [142, "reboot", 0x8e, "int magic1", "int magic2", "unsigned int cmd", "void *arg", "-", "-"],
    [143, "setregid", 0x8f, "gid_t rgid", "gid_t egid", "-", "-", "-", "-"],
    [144, "setgid", 0x90, "gid_t gid", "-", "-", "-", "-", "-"],
    [145, "setreuid", 0x91, "uid_t ruid", "uid_t euid", "-", "-", "-", "-"],
    [146, "setuid", 0x92, "uid_t uid", "-", "-", "-", "-", "-"],
    [147, "setresuid", 0x93, "uid_t ruid", "uid_t euid", "uid_t suid", "-", "-", "-"],
    [148, "getresuid", 0x94, "uid_t *ruid", "uid_t *euid", "uid_t *suid", "-", "-", "-"],
    [149, "setresgid", 0x95, "gid_t rgid", "gid_t egid", "gid_t sgid", "-", "-", "-"],
    [150, "getresgid", 0x96, "gid_t *rgid", "gid_t *egid", "gid_t *sgid", "-", "-", "-"],
    [151, "setfsuid", 0x97, "uid_t uid", "-", "-", "-", "-", "-"],
    [152, "setfsgid", 0x98, "gid_t gid", "-", "-", "-", "-", "-"],
    [153, "times", 0x99, "struct tms *tbuf", "-", "-", "-", "-", "-"],
    [154, "setpgid", 0x9a, "pid_t pid", "pid_t pgid", "-", "-", "-", "-"],
    [155, "getpgid", 0x9b, "pid_t pid", "-", "-", "-", "-", "-"],
    [156, "getsid", 0x9c, "pid_t pid", "-", "-", "-", "-", "-"],
    [157, "setsid", 0x9d, "-", "-", "-", "-", "-", "-"],
    [158, "getgroups", 0x9e, "int gidsetsize", "gid_t *grouplist", "-", "-", "-", "-"],
    [159, "setgroups", 0x9f, "int gidsetsize", "gid_t *grouplist", "-", "-", "-", "-"],
    [160, "uname", 0xa0, "struct old_utsname *", "-", "-", "-", "-", "-"],
    [161, "sethostname", 0xa1, "char *name", "int len", "-", "-", "-", "-"],
    [162, "setdomainname", 0xa2, "char *name", "int len", "-", "-", "-", "-"],
    [163, "getrlimit", 0xa3, "unsigned int resource", "struct rlimit *rlim", "-", "-", "-", "-"],
    [164, "setrlimit", 0xa4, "unsigned int resource", "struct rlimit *rlim", "-", "-", "-", "-"],
    [165, "getrusage", 0xa5, "int who", "struct rusage *ru", "-", "-", "-", "-"],
    [166, "umask", 0xa6, "int mask", "-", "-", "-", "-", "-"],
    [167, "prctl", 0xa7, "int option", "unsigned long arg2", "unsigned long arg3", "unsigned long arg4", "unsigned long arg5", "-"],
    [168, "getcpu", 0xa8, "unsigned *cpu", "unsigned *node", "struct getcpu_cache *cache", "-", "-", "-"],
    [169, "gettimeofday", 0xa9, "struct timeval *tv", "struct timezone *tz", "-", "-", "-", "-"],
    [170, "settimeofday", 0xaa, "struct timeval *tv", "struct timezone *tz", "-", "-", "-", "-"],
    [171, "adjtimex", 0xab, "struct __kernel_timex *txc_p", "-", "-", "-", "-", "-"],
    [172, "getpid", 0xac, "-", "-", "-", "-", "-", "-"],
    [173, "getppid", 0xad, "-", "-", "-", "-", "-", "-"],
    [174, "getuid", 0xae, "-", "-", "-", "-", "-", "-"],
    [175, "geteuid", 0xaf, "-", "-", "-", "-", "-", "-"],
    [176, "getgid", 0xb0, "-", "-", "-", "-", "-", "-"],
    [177, "getegid", 0xb1, "-", "-", "-", "-", "-", "-"],
    [178, "gettid", 0xb2, "-", "-", "-", "-", "-", "-"],
    [179, "sysinfo", 0xb3, "struct sysinfo *info", "-", "-", "-", "-", "-"],
    [180, "mq_open", 0xb4, "const char *name", "int oflag", "umode_t mode", "struct mq_attr *attr", "-", "-"],
    [181, "mq_unlink", 0xb5, "const char *name", "-", "-", "-", "-", "-"],
    [182, "mq_timedsend", 0xb6, "mqd_t mqdes", "const char *msg_ptr", "size_t msg_len", "unsigned int msg_prio", "const struct __kernel_timespec *abs_timeout", "-"],
    [183, "mq_timedreceive", 0xb7, "mqd_t mqdes", "char *msg_ptr", "size_t msg_len", "unsigned int *msg_prio", "const struct __kernel_timespec *abs_timeout", "-"],
    [184, "mq_notify", 0xb8, "mqd_t mqdes", "const struct sigevent *notification", "-", "-", "-", "-"],
    [185, "mq_getsetattr", 0xb9, "mqd_t mqdes", "const struct mq_attr *mqstat", "struct mq_attr *omqstat", "-", "-", "-"],
    [186, "msgget", 0xba, "key_t key", "int msgflg", "-", "-", "-", "-"],
    [187, "msgctl", 0xbb, "int msqid", "int cmd", "struct msqid_ds *buf", "-", "-", "-"],
    [188, "msgrcv", 0xbc, "int msqid", "struct msgbuf *msgp", "size_t msgsz", "long msgtyp", "int msgflg", "-"],
    [189, "msgsnd", 0xbd, "int msqid", "struct msgbuf *msgp", "size_t msgsz", "int msgflg", "-", "-"],
    [190, "semget", 0xbe, "key_t key", "int nsems", "int semflg", "-", "-", "-"],
    [191, "semctl", 0xbf, "int semid", "int semnum", "int cmd", "unsigned long arg", "-", "-"],
    [192, "semtimedop", 0xc0, "int semid", "struct sembuf *sops", "unsigned nsops", "const struct __kernel_timespec *timeout", "-", "-"],
    [193, "semop", 0xc1, "int semid", "struct sembuf *sops", "unsigned nsops", "-", "-", "-"],
    [194, "shmget", 0xc2, "key_t key", "size_t size", "int flag", "-", "-", "-"],
    [195, "shmctl", 0xc3, "int shmid", "int cmd", "struct shmid_ds *buf", "-", "-", "-"],
    [196, "shmat", 0xc4, "int shmid", "char *shmaddr", "int shmflg", "-", "-", "-"],
    [197, "shmdt", 0xc5, "char *shmaddr", "-", "-", "-", "-", "-"],
    [198, "socket", 0xc6, "int", "int", "int", "-", "-", "-"],
    [199, "socketpair", 0xc7, "int", "int", "int", "int *", "-", "-"],
    [200, "bind", 0xc8, "int", "struct sockaddr *", "int", "-", "-", "-"],
    [201, "listen", 0xc9, "int", "int", "-", "-", "-", "-"],
    [202, "accept", 0xca, "int", "struct sockaddr *", "int *", "-", "-", "-"],
    [203, "connect", 0xcb, "int", "struct sockaddr *", "int", "-", "-", "-"],
    [204, "getsockname", 0xcc, "int", "struct sockaddr *", "int *", "-", "-", "-"],
    [205, "getpeername", 0xcd, "int", "struct sockaddr *", "int *", "-", "-", "-"],
    [206, "sendto", 0xce, "int", "void *", "size_t", "unsigned", "struct sockaddr *", "int"],
    [207, "recvfrom", 0xcf, "int", "void *", "size_t", "unsigned", "struct sockaddr *", "int *"],
    [208, "setsockopt", 0xd0, "int fd", "int level", "int optname", "char *optval", "int optlen", "-"],
    [209, "getsockopt", 0xd1, "int fd", "int level", "int optname", "char *optval", "int *optlen", "-"],
    [210, "shutdown", 0xd2, "int", "int", "-", "-", "-", "-"],
    [211, "sendmsg", 0xd3, "int fd", "struct user_msghdr *msg", "unsigned flags", "-", "-", "-"],
    [212, "recvmsg", 0xd4, "int fd", "struct user_msghdr *msg", "unsigned flags", "-", "-", "-"],
    [213, "readahead", 0xd5, "int fd", "loff_t offset", "size_t count", "-", "-", "-"],
    [214, "brk", 0xd6, "unsigned long brk", "-", "-", "-", "-", "-"],
    [215, "munmap", 0xd7, "unsigned long addr", "size_t len", "-", "-", "-", "-"],
    [216, "mremap", 0xd8, "unsigned long addr", "unsigned long old_len", "unsigned long new_len", "unsigned long flags", "unsigned long new_addr", "-"],
    [217, "add_key", 0xd9, "const char *_type", "const char *_description", "const void *_payload", "size_t plen", "key_serial_t destringid", "-"],
    [218, "request_key", 0xda, "const char *_type", "const char *_description", "const char *_callout_info", "key_serial_t destringid", "-", "-"],
    [219, "keyctl", 0xdb, "int cmd", "unsigned long arg2", "unsigned long arg3", "unsigned long arg4", "unsigned long arg5", "-"],
    [220, "clone", 0xdc, "unsigned long", "unsigned long", "int *", "int *", "unsigned long", "-"],
    [221, "execve", 0xdd, "const char *filename", "const char *const *argv", "const char *const *envp", "-", "-", "-"],
    [222, "mmap", 0xde, "?", "?", "?", "?", "?", "?"],
    [223, "fadvise64", 0xdf, "int fd", "loff_t offset", "size_t len", "int advice", "-", "-"],
    [224, "swapon", 0xe0, "const char *specialfile", "int swap_flags", "-", "-", "-", "-"],
    [225, "swapoff", 0xe1, "const char *specialfile", "-", "-", "-", "-", "-"],
    [226, "mprotect", 0xe2, "unsigned long start", "size_t len", "unsigned long prot", "-", "-", "-"],
    [227, "msync", 0xe3, "unsigned long start", "size_t len", "int flags", "-", "-", "-"],
    [228, "mlock", 0xe4, "unsigned long start", "size_t len", "-", "-", "-", "-"],
    [229, "munlock", 0xe5, "unsigned long start", "size_t len", "-", "-", "-", "-"],
    [230, "mlockall", 0xe6, "int flags", "-", "-", "-", "-", "-"],
    [231, "munlockall", 0xe7, "-", "-", "-", "-", "-", "-"],
    [232, "mincore", 0xe8, "unsigned long start", "size_t len", "unsigned char * vec", "-", "-", "-"],
    [233, "madvise", 0xe9, "unsigned long start", "size_t len", "int behavior", "-", "-", "-"],
    [234, "remap_file_pages", 0xea, "unsigned long start", "unsigned long size", "unsigned long prot", "unsigned long pgoff", "unsigned long flags", "-"],
    [235, "mbind", 0xeb, "unsigned long start", "unsigned long len", "unsigned long mode", "const unsigned long *nmask", "unsigned long maxnode", "unsigned flags"],
    [236, "get_mempolicy", 0xec, "int *policy", "unsigned long *nmask", "unsigned long maxnode", "unsigned long addr", "unsigned long flags", "-"],
    [237, "set_mempolicy", 0xed, "int mode", "const unsigned long *nmask", "unsigned long maxnode", "-", "-", "-"],
    [238, "migrate_pages", 0xee, "pid_t pid", "unsigned long maxnode", "const unsigned long *from", "const unsigned long *to", "-", "-"],
    [239, "move_pages", 0xef, "pid_t pid", "unsigned long nr_pages", "const void * *pages", "const int *nodes", "int *status", "int flags"],
    [240, "rt_tgsigqueueinfo", 0xf0, "pid_t tgid", "pid_t pid", "int sig", "siginfo_t *uinfo", "-", "-"],
    [241, "perf_event_open", 0xf1, "struct perf_event_attr *attr_uptr", "pid_t pid", "int cpu", "int group_fd", "unsigned long flags", "-"],
    [242, "accept4", 0xf2, "int", "struct sockaddr *", "int *", "int", "-", "-"],
    [243, "recvmmsg", 0xf3, "int fd", "struct mmsghdr *msg", "unsigned int vlen", "unsigned flags", "struct __kernel_timespec *timeout", "-"],
    [244, "not implemented", 0xf4],
    [245, "not implemented", 0xf5],
    [246, "not implemented", 0xf6],
    [247, "not implemented", 0xf7],
    [248, "not implemented", 0xf8],
    [249, "not implemented", 0xf9],
    [250, "not implemented", 0xfa],
    [251, "not implemented", 0xfb],
    [252, "not implemented", 0xfc],
    [253, "not implemented", 0xfd],
    [254, "not implemented", 0xfe],
    [255, "not implemented", 0xff],
    [256, "not implemented", 0x100],
    [257, "not implemented", 0x101],
    [258, "not implemented", 0x102],
    [259, "not implemented", 0x103],
    [260, "wait4", 0x104, "pid_t pid", "int *stat_addr", "int options", "struct rusage *ru", "-", "-"],
    [261, "prlimit64", 0x105, "pid_t pid", "unsigned int resource", "const struct rlimit64 *new_rlim", "struct rlimit64 *old_rlim", "-", "-"],
    [262, "fanotify_init", 0x106, "unsigned int flags", "unsigned int event_f_flags", "-", "-", "-", "-"],
    [263, "fanotify_mark", 0x107, "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd", "const char *pathname", "-"],
    [264, "name_to_handle_at", 0x108, "int dfd", "const char *name", "struct file_handle *handle", "int *mnt_id", "int flag", "-"],
    [265, "open_by_handle_at", 0x109, "int mountdirfd", "struct file_handle *handle", "int flags", "-", "-", "-"],
    [266, "clock_adjtime", 0x10a, "clockid_t which_clock", "struct __kernel_timex *tx", "-", "-", "-", "-"],
    [267, "syncfs", 0x10b, "int fd", "-", "-", "-", "-", "-"],
    [268, "setns", 0x10c, "int fd", "int nstype", "-", "-", "-", "-"],
    [269, "sendmmsg", 0x10d, "int fd", "struct mmsghdr *msg", "unsigned int vlen", "unsigned flags", "-", "-"],
    [270, "process_vm_readv", 0x10e, "pid_t pid", "const struct iovec *lvec", "unsigned long liovcnt", "const struct iovec *rvec", "unsigned long riovcnt", "unsigned long flags"],
    [271, "process_vm_writev", 0x10f, "pid_t pid", "const struct iovec *lvec", "unsigned long liovcnt", "const struct iovec *rvec", "unsigned long riovcnt", "unsigned long flags"],
    [272, "kcmp", 0x110, "pid_t pid1", "pid_t pid2", "int type", "unsigned long idx1", "unsigned long idx2", "-"],
    [273, "finit_module", 0x111, "int fd", "const char *uargs", "int flags", "-", "-", "-"],
    [274, "sched_setattr", 0x112, "pid_t pid", "struct sched_attr *attr", "unsigned int flags", "-", "-", "-"],
    [275, "sched_getattr", 0x113, "pid_t pid", "struct sched_attr *attr", "unsigned int size", "unsigned int flags", "-", "-"],
    [276, "renameat2", 0x114, "int olddfd", "const char *oldname", "int newdfd", "const char *newname", "unsigned int flags", "-"],
    [277, "seccomp", 0x115, "unsigned int op", "unsigned int flags", "void *uargs", "-", "-", "-"],
    [278, "getrandom", 0x116, "char *buf", "size_t count", "unsigned int flags", "-", "-", "-"],
    [279, "memfd_create", 0x117, "const char *uname_ptr", "unsigned int flags", "-", "-", "-", "-"],
    [280, "bpf", 0x118, "int cmd", "union bpf_attr *attr", "unsigned int size", "-", "-", "-"],
    [281, "execveat", 0x119, "int dfd", "const char *filename", "const char *const *argv", "const char *const *envp", "int flags", "-"],
    [282, "userfaultfd", 0x11a, "int flags", "-", "-", "-", "-", "-"],
    [283, "membarrier", 0x11b, "int cmd", "int flags", "-", "-", "-", "-"],
    [284, "mlock2", 0x11c, "unsigned long start", "size_t len", "int flags", "-", "-", "-"],
    [285, "copy_file_range", 0x11d, "int fd_in", "loff_t *off_in", "int fd_out", "loff_t *off_out", "size_t len", "unsigned int flags"],
    [286, "preadv2", 0x11e, "unsigned long fd", "const struct iovec *vec", "unsigned long vlen", "unsigned long pos_l", "unsigned long pos_h", "rwf_t flags"],
    [287, "pwritev2", 0x11f, "unsigned long fd", "const struct iovec *vec", "unsigned long vlen", "unsigned long pos_l", "unsigned long pos_h", "rwf_t flags"],
    [288, "pkey_mprotect", 0x120, "unsigned long start", "size_t len", "unsigned long prot", "int pkey", "-", "-"],
    [289, "pkey_alloc", 0x121, "unsigned long flags", "unsigned long init_val", "-", "-", "-", "-"],
    [290, "pkey_free", 0x122, "int pkey", "-", "-", "-", "-", "-"],
    [291, "statx", 0x123, "int dfd", "const char *path", "unsigned flags", "unsigned mask", "struct statx *buffer", "-"]
];

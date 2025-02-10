#import <Foundation/Foundation.h>
#include <string.h>
#include <mach/mach.h>
#include <dirent.h>
#import "helpers.h"
#import <xpc/xpc.h>
#import <sys/sysctl.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>

char* get_temp_file_path(void) {
    @autoreleasepool {
        return strdup([[NSTemporaryDirectory() stringByAppendingPathComponent:@"AAAAs"] fileSystemRepresentation]);
    }
}

// create a read-only test file we can target:
char* set_up_tmp_file(void) {
    @autoreleasepool {
        char* path = get_temp_file_path();
        if (!path) {
            return NULL;
        }
        
        printf("path: %s\n", path);
        
        FILE* f = fopen(path, "w");
        if (!f) {
            printf("opening the tmp file failed...\n");
            free(path);
            return NULL;
        }
        
        char* buf = malloc(PAGE_SIZE * 10);
        if (!buf) {
            fclose(f);
            free(path);
            return NULL;
        }
        
        memset(buf, 'A', PAGE_SIZE * 10);
        size_t written = fwrite(buf, 1, PAGE_SIZE * 10, f);
        free(buf);
        
        if (written != PAGE_SIZE * 10) {
            fclose(f);
            free(path);
            return NULL;
        }
        
        fclose(f);
        return path;
    }
}

kern_return_t
bootstrap_look_up(mach_port_t bp, const char* service_name, mach_port_t *sp);

struct xpc_w00t {
  mach_msg_header_t hdr;
  mach_msg_body_t body;
  mach_msg_port_descriptor_t client_port;
  mach_msg_port_descriptor_t reply_port;
};

mach_port_t get_send_once(mach_port_t recv) {
  mach_port_t so = MACH_PORT_NULL;
  mach_msg_type_name_t type = 0;
  kern_return_t err = mach_port_extract_right(mach_task_self(), recv, MACH_MSG_TYPE_MAKE_SEND_ONCE, &so, &type);
  if (err != KERN_SUCCESS) {
    printf("port right extraction failed: %s\n", mach_error_string(err));
    return MACH_PORT_NULL;
  }
  printf("made so: 0x%x from recv: 0x%x\n", so, recv);
  return so;
}

// copy-pasted from an exploit I wrote in 2019...
// still works...

// (in the exploit for this: https://googleprojectzero.blogspot.com/2019/04/splitting-atoms-in-xnu.html )

void xpc_crasher(const char* service_name) {
    @autoreleasepool {
        // On iOS, we'll use a different approach to restart services
        pid_t pid = -1;
        
        // Get process ID
        int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
        struct kinfo_proc *info;
        size_t length;
        int count;
        
        if (sysctl(mib, 4, NULL, &length, NULL, 0) < 0) {
            return;
        }
        
        info = malloc(length);
        if (!info) {
            return;
        }
        
        if (sysctl(mib, 4, info, &length, NULL, 0) < 0) {
            free(info);
            return;
        }
        
        count = length / sizeof(struct kinfo_proc);
        for (int i = 0; i < count; i++) {
            if (strcmp(info[i].kp_proc.p_comm, service_name) == 0) {
                pid = info[i].kp_proc.p_pid;
                break;
            }
        }
        
        free(info);
        
        if (pid > 0) {
            kill(pid, SIGTERM);
            usleep(100000); // Wait 100ms
        }
    }
}

bool overwrite_file(int fd, NSData* data) {
    if (fd < 0 || !data) {
        return false;
    }
    
    off_t original_offset = lseek(fd, 0, SEEK_CUR);
    if (original_offset == -1) {
        return false;
    }
    
    if (lseek(fd, 0, SEEK_SET) == -1) {
        return false;
    }
    
    const uint8_t* bytes = data.bytes;
    size_t total_written = 0;
    size_t length = data.length;
    
    while (total_written < length) {
        ssize_t written = write(fd, bytes + total_written, length - total_written);
        if (written <= 0) {
            if (errno == EINTR) {
                continue;
            }
            lseek(fd, original_offset, SEEK_SET);
            return false;
        }
        total_written += written;
    }
    
    if (ftruncate(fd, length) == -1) {
        lseek(fd, original_offset, SEEK_SET);
        return false;
    }
    
    if (lseek(fd, original_offset, SEEK_SET) == -1) {
        return false;
    }
    
    return true;
}

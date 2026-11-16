// SPDX-License-Identifier: MIT
// Copyright (c) 2026 liaoyq / ASRT Contributors
//
//  calc_self.cpp
//  redis
//
//  Created by liaoyq on 2025/12/9.
//
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#ifdef _WIN32
int self_checksum_from_disk(uint8_t digest[32])
{
	memset(digest,0,32);
	return 0;
}
void swapSelf(char *argv[])
{
}
#else 
#include <MinoCrypt/sm3.h>
#include "calc_self.h"
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#ifdef __LINUX__
#define DLL_PUBLIC  __attribute__ ((visibility ("default")))
#else
#define DLL_PUBLIC
#endif

static int calculate_file_checksum(const char* filename,uint8_t result[32]) {
    FILE* file = fopen(filename, "rb");
    if (!file)         return 1;
    SM3 sm3;
    uint8_t buffer[4096];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) != 0)   sm3.update(buffer, bytes_read);
    sm3.finish(result);
    fclose(file);
    return 0;
}

// 获取当前共享库的文件路径
static int get_current_library_path(char* path, size_t max_size) {
    // 通过 /proc/self/maps 查找当前代码地址对应的文件路径
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) return 2;

    uintptr_t addr = (uintptr_t)self_checksum_from_disk; // 任意当前函数地址
    char line[1024];
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
            if ( addr >= start && addr < end) {
                char* path_start = strchr(line, '/');
                if (path_start) {
                    strncpy(path, path_start, max_size-1);
                    path[max_size - 1] = '\0';
                    // 移除换行符
                    char* newline = strchr(path, '\n');
                    if (newline) *newline = '\0';
                    break;
                }
            }
        }
    }
    fclose(maps);
    return 0;
}

// 在 DSO 中计算自身的磁盘文件校验和
DLL_PUBLIC int self_checksum_from_disk(uint8_t digest[32]) {
    char library_path[PATH_MAX];
    int err;
    memset(library_path,0,sizeof(library_path));
    if( (err=get_current_library_path(library_path, sizeof(library_path))) ) return err;
    
    if (strlen(library_path) == 0) return  3;

    printf("Library path: %s\n", library_path);
    return calculate_file_checksum(library_path,digest);
}

static int copy_file_atomic(const char *src, const char *dest)
{
    int src_fd, dest_fd;
    char buf[1024];
    ssize_t bytes_read;

    // 打开源文件（只读）
    src_fd = open(src, O_RDONLY);
    if (src_fd == -1) {
        perror("open source failed");
        printf("src file is %s\n",src);
        return -1;
    }

    // 创建目标文件（独占创建，避免覆盖已存在的文件）
    // 若需覆盖，可改为 O_WRONLY | O_CREAT | O_TRUNC
    dest_fd = open(dest, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (dest_fd == -1) {
        perror("open destination failed");
        printf("dest file is %s\n",src);
        close(src_fd);
        return -1;
    }

    // 复制文件内容
    while ((bytes_read = read(src_fd, buf, sizeof(buf))) > 0) {
        if (write(dest_fd, buf, bytes_read) != bytes_read) {
            perror("write failed");
            close(src_fd);
            close(dest_fd);
            unlink(dest); // 删除不完整的副本
            return -1;
        }
    }

    // 检查 read 错误
    if (bytes_read == -1) {
        perror("read failed");
        close(src_fd);
        close(dest_fd);
        unlink(dest);
        return -1;
    }

    // 同步文件元数据（可选，确保权限、时间戳等正确）
    if (fsync(dest_fd) == -1) {
        perror("fsync failed");
        close(src_fd);
        close(dest_fd);
        unlink(dest);
        return -1;
    }

    // 关闭文件描述符
    close(src_fd);
    close(dest_fd);

    return 0;
}
static char ori_path[1024];
static char newEnv1[1024];
static char pathEnv[1024];
static char * const envp[]={
    newEnv1,pathEnv,"HOME=/root","USER=root",NULL
};
DLL_PUBLIC void swapSelf(char *argv[])
{
    char path[800];
    memset(path,0,sizeof(path));
    if (readlink("/proc/self/exe", path, sizeof(path)) == -1) {
        perror("readlink");
        return ;
    }
    printf("current path:%s\n",path);
    if( ::strncmp(path,"/tmp/",5)==0 ){
        strcpy(ori_path,::getenv("NOTIFY_FILE"));
        printf("ori path:%s\n",ori_path);
        unlink(path);
        return;
    }
    sprintf(newEnv1,"NOTIFY_FILE=%s",path);
    sprintf(pathEnv,"PATH=%s",::getenv("PATH"));
    snprintf(ori_path, sizeof(ori_path), "/tmp/%s", ::strrchr(path,'/'));
    copy_file_atomic(path,ori_path);
    execve(ori_path, argv,envp);
}
#endif

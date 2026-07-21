// SPDX-License-Identifier: MIT
// Copyright (c) 2026 liaoyq / ASRT Contributors
//
//  PgFileClient.h
//
//  Created by liaoyq on 2026/4/27.
//
#ifndef PGFILE_CLIENT_H
#define PGFILE_CLIENT_H
#include <AsyncRuntime/asrt_socket.h>
//====================================
// 文件传输客户端
//====================================
class PgFileClient {
public:
    PgFileClient();
    ~PgFileClient();
    
    void setServer(const char* server);
    void setSilent(int isSilent){ mode = isSilent; };
    // 上传文件
    TransferResult uploadFile(const char * userKey, const char * filePath, const char * destPath);
    // 清空目录
    TransferResult clearPath(const char * userKey,const char * destPath);
    // 上传目录
    int uploadPath(const char * userKey, const char * srcPath, const char * destPath);
    // 执行远端目录下的 update.sh，并实时输出执行结果
    int deploy(const char * userKey, const char * destPath, const char * arg);
    // 管理命令
    AdminResult sendAdminCommand(const char * cmd);

    const char* getLastError() const { return m_lastError.data(); }
    void stop();
private:
    volatile int running;
    volatile int deployActive;
    int mode;
    AsrtSockStream m_server;
    DString m_svrAddr;
    DString m_lastError;
};

#endif

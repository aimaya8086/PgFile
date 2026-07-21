// SPDX-License-Identifier: MIT
// Copyright (c) 2026 liaoyq / ASRT Contributors
//
//  PgFileApp.h
//
//  文件加密传输 - 服务端+客户端融合
//

#ifndef PgFileApp_h
#define PgFileApp_h

#include "PgFileAuth.h"
#include <AsyncRuntime/SocketQueueService.h>
#include <AsyncRuntime/asrt_task.h>
#include <AsyncRuntime/asrt_socket.h>
#include <AsyncRuntime/DPtr.h>

class PgFileApp;
class PgFileAdminTask;

// 会话上下文
struct SessionContext {
    DString userKey;
    DString filePath;
    int64_t fileSize;
    uint8_t sharedKey[C25519_PUB_KEY_LEN];
    int64_t receivedBytes;
};



//====================================
// 文件传输 Runner (服务端处理)
//====================================
class PgFileRunner : public SocketClientRunner {
public:
    PgFileRunner(AsrtSock* handle, SocketQueueService* parent);
    virtual ~PgFileRunner();
    
    virtual int run() ;

protected:
    int handleFileRequest();
    int receiveFileData();
    int deploy(const char *arg);
    int replay(int code,const char * msg);
private:
   // SocketReader m_reader;
    DPtr m_buffer;
    SessionContext m_ctx;
    int jsonFmt;
};

//====================================
// 管理端口任务 (服务端)
//====================================
class PgFileAdminTask : public AsrtTask {
public:
    PgFileAdminTask(PgFileAuth* auth, int port);
    virtual ~PgFileAdminTask();
    
    /**
     * 接口初始化过程，在线程启动前运行，一般是读入配置等信息
     * 返回0表示成功，否则失败，对象将被删除。
     */
    virtual int onInit(void * arg);
    /**
     * 任务处理过程
     */
    virtual int run();
    /**
     * 清理资源
     */
    virtual int destory();
    /**
     *  结束通知函数
     */
    virtual int close();
protected:
    void handleAdminConnection();

    int handleCommand(char * cmd);
    
    int replay(int code,const char * msg);

private:
    char m_buffer[1024*16];
    AsrtSock client;
    PgFileAuth* m_auth;
    int m_port;
    int jsonFmt;
    AsrtSockAcceptor m_acceptor;
    
};

//====================================
// 文件传输服务端
//====================================
class PgFileServer : public SocketQueueService {
public:
    PgFileServer();
    virtual ~PgFileServer();
    
    int start(int port, int adminPort, const char* authFile);
    
    PgFileAuth* getAuth() { return &m_auth; }
    int getAdminPort() const { return m_adminPort; }
    virtual int close() override;
    virtual int destory() override;

protected:
    virtual SocketRunner* newClient(int index, AsrtSock* handle) override;
    
private:
    PgFileAuth  m_auth;
    int m_adminPort;
    PgFileAdminTask* m_adminTask;
};


#endif // PgFileApp_h

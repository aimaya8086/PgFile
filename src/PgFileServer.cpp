// SPDX-License-Identifier: MIT
// Copyright (c) 2026 liaoyq / ASRT Contributors
//
//  PgFileApp.cpp
//
//  文件加密传输 - 服务端+客户端融合实现
//

#include "PgFile.h"
#include "PgFileServer.h"
#include <AsyncRuntime/asrt_file.h>
#include <AsyncRuntime/asrt_socket.h>
#include <AsyncRuntime/SocketAddr.h>
#include <MinoCrypt/C25519.h>
#include <MinoCrypt/Utils.h>
#include <MinoCrypt/sm4.h>
#include <AsyncRuntime/asrt_path.h>
#include <AsyncRuntime/asrt_dirent.h>
#include <AsyncRuntime/asrt_shell.h>
#include <string.h>
#include <sys/types.h>
#ifndef WIN32
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif
#include "MapObject.h"
//====================================
// PgFileRunner 实现 (服务端处理)
//====================================

PgFileRunner::PgFileRunner(AsrtSock * handle, SocketQueueService* parent)
    :SocketClientRunner(handle,parent),m_buffer(TRANSFER_BUFFER_SIZE),jsonFmt(0){
}

PgFileRunner::~PgFileRunner() {
}
int PgFileRunner::replay(int code, const char *msg)
{
    DString tp ;
    if( jsonFmt ){
        tp= Response::fail(code, msg);
    } else {
        tp.AppendFormat("%s%s\r\n",code?CMD_BAD:CMD_OK,msg);
    }
    if( code ) APPWARN(tp.data());
    else APPINFO(tp.data());
    client_.send(tp,tp.length());
    return  code;
}
int PgFileRunner::run() {
    if (!client_.validate()) {
        APPERR("Invalid client connection");
        return -1;
    }
    client_.set_timeout(10000, 1000);

    int request = handleFileRequest();
    if (request) return request < 0 ? 0 : -1;
    
    if (receiveFileData()) return -1;
    
    APPINFO("File transfer completed for user: %s", m_ctx.userKey.data());
    return 0;
}

static void remove_dir_recursive(const char *path)
{
    AsrtDirent dirs;
    dirent *entry;
    char fullpath[1024];

    if( dirs.open(path)) return;
    while( (entry = dirs.select() )!=NULL){
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)  continue;

        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);
        if( AsrtFile::is_dir(fullpath,AsrtFile::READABLE) ) {
            remove_dir_recursive(fullpath);
        } else {
            if( strcmp(entry->d_name, "update.sh") != 0 ) unlink(fullpath);
        }
    }
    AsrtFile::rmdir(path);
}
static void empty_dir(const char * path)
{
    AsrtDirent dirs;
    dirent *entry;
    char fullpath[1024];

    if( dirs.open(path)) return;
    while( (entry = dirs.select() )!=NULL){
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)  continue;

        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);
        if( AsrtFile::is_dir(fullpath,AsrtFile::READABLE) ) {
            remove_dir_recursive(fullpath);
        } else {
            if( strcmp(entry->d_name, "update.sh") != 0 ) unlink(fullpath);
        }
    }
}
int PgFileRunner::handleFileRequest()
{
    int readLength = client_.recv(m_buffer, m_buffer.size());
    if(readLength <(C25519::SIZE_KEY*2+8)) return 1;
    char * base = m_buffer;
    base[readLength]=0;
    int k = readLength-1;
    if( base[k]!='\n' ) return 2;
    if( base[k-1]!='\r' ) return 2;
    base[k-1]=0;
    base[k]=0;
    while(base[0]==' ') base++;
    DString rs;
    APPINFO("Received request: %s", base);
    
    if( strstr(base, " --json")) jsonFmt = 1;
    C25519  localKey;
 
    localKey.generate();
    uint8_t pubKeyBytes[C25519_PUB_KEY_LEN];

    char * tmp = base + C25519::SIZE_KEY*2;
    if( (tmp[0]!=' ') || (Utils::unhex(base, pubKeyBytes, C25519::SIZE_KEY)!= C25519::SIZE_KEY) ){
        return replay(2,CMD_BAD_PARAMETER", bad c25519 public key");
    }
    localKey.agree(pubKeyBytes, m_ctx.sharedKey, C25519::SIZE_KEY);
    while(tmp[0]==' ') tmp++;
    base = tmp;
    if( base[0]==0 ){
        return replay(2, CMD_BAD_PARAMETER ", no user key");
    }
    //user key
    tmp = strstr(base," ");
    if( tmp==NULL) return replay(2,CMD_BAD_PARAMETER ", no user key");

    tmp[0]=0;
    m_ctx.userKey = base;
    tmp++;
    while(tmp[0]==' ') tmp++;
    base = tmp;
    //file path
    tmp = strstr(base," ");
    if( tmp == NULL ) return replay(2,CMD_BAD_PARAMETER ", no path");

    tmp[0] = 0;
    m_ctx.filePath = base;
    m_ctx.filePath = m_ctx.filePath.replace('\\', '/');
    m_ctx.filePath = m_ctx.filePath.replace("//", "/");

    if( m_ctx.filePath.indexOf(' ')>=0) return replay(4, CMD_BAD_PARAMETER ", file name can not ' '");
    if( m_ctx.filePath.indexOf("..")>=0)  return replay(4, CMD_BAD_PARAMETER ", file name can not '..'");

    PgFileServer* server = (PgFileServer*)parent_;
    PgFileAuth* auth = server->getAuth();
    if (auth->checkPermission(m_ctx.userKey, m_ctx.filePath))    return replay(3,CMD_BAD_PERMIT);

    tmp++;
    while(tmp[0]==' ') tmp++;
    base = tmp;
    if( base[0]==0 ) return replay(4, CMD_BAD_PARAMETER ", no file size");

    if( m_ctx.filePath.indexOf("/update.sh")>=0 )
        return replay(5, "update.sh is protected");

    if(strncmp(base,"deploy",6)==0 && (base[6]==0 || base[6]==' ') ){
        const char *arg = base + 6;
        while(arg[0]==' ') arg++;
        return deploy(arg[0] ? arg : NULL) == 0 ? -1 : 1;
    } else if(strcmp(base,"del")==0 ){
        if ( m_ctx.filePath.endsWith('/')) {
            empty_dir(m_ctx.filePath);
        } else {
            if( AsrtFile::delete_file(m_ctx.filePath) ) return replay(5,"can not delete file");
        }
        replay(0,"delete success");
        return 1;
    } else {
        m_ctx.fileSize = atoll(base);
        if (m_ctx.filePath.endsWith('/')) return replay(3,", can not save to path");
        if( m_ctx.fileSize>0 ){
            char response[77];
            memcpy(response, CMD_UPGRADE, 11);
            Utils::hex(localKey.pub, C25519_PUB_KEY_LEN, response + 11);
            response[75] = '\r';
            response[76] = '\n';
            client_.send(response, sizeof(response));
            
            APPINFO("Permission granted for user: %s, path: %s, continue....", m_ctx.userKey.data(), m_ctx.filePath.data());
        } else {
            AsrtPath parentDir(m_ctx.filePath);
            parentDir.create(0755);
            AsrtFile::delete_file(m_ctx.filePath.data());
            AsrtFile outFile;
            if (outFile.open(m_ctx.filePath.data(), O_WRONLY | O_CREAT | O_TRUNC,0644) != 0)
                return replay(4,"Cannot create file");

            APPINFO("Permission granted for user: %s, path: %s, file create success", m_ctx.userKey.data(), m_ctx.filePath.data());
            replay(0, "file created");
        }
    }
    return 0;
}

int PgFileRunner::deploy(const char *arg)
{
#ifdef WIN32
    return replay(5, "deploy is not supported on Windows");
#else
    DString script = m_ctx.filePath;
    if( !script.endsWith('/') ) script += "/";
    script += "update.sh";
    if( !AsrtFile::is_file(script.data(), AsrtFile::READABLE) )
        return replay(5, "update.sh not found");

    int output[2];
    if( pipe(output) != 0 ) return replay(5, "can not create deploy pipe");

    // AsrtRuntime 默认忽略 SIGCHLD；deploy 需要 waitpid 回收脚本进程。
    signal(SIGCHLD, SIG_DFL);
    pid_t pid = fork();
    if( pid < 0 ){
        ::close(output[0]);
        ::close(output[1]);
        return replay(5, "can not start update.sh");
    }
    if( pid == 0 ){
        // 独立进程组可确保取消时 update.sh 启动的子进程也被终止。
        setpgid(0, 0);
        ::close(output[0]);
        dup2(output[1], STDOUT_FILENO);
        dup2(output[1], STDERR_FILENO);
        ::close(output[1]);
        if( chdir(m_ctx.filePath.data()) != 0 ) _exit(126);
        if( arg ) execl("/bin/sh", "sh", "./update.sh", arg, (char *)NULL);
        else execl("/bin/sh", "sh", "./update.sh", (char *)NULL);
        _exit(126);
    }

    setpgid(pid, pid);
    ::close(output[1]);
    static const char response[] = "OK upgrade\r\n";
    if( client_.send(response, sizeof(response)-1) != (int)sizeof(response)-1 ){
        ::close(output[0]);
        kill(-pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return 1;
    }

    char buffer[4096];
    bool cancelled = false;
    bool outputOpen = true;
    while( outputOpen ){
        if( parent_->status() != AsrtTask::RUNNING ){
            cancelled = true;
            break;
        }
        ASRT_SOCKET readers[] = { output[0], client_.handle() };
        // 有限等待用于感知由其他线程处理的服务退出信号。
        int ready = AsrtSock::select(readers, 2, 1000);
        if( ready < 0 ){
            cancelled = true;
            break;
        }
        if( ready == 0 ) continue;
        if( readers[1] != ASRT_INVALID_SOCKET ){
            char control[32];
            int count = client_.recv(control, sizeof(control));
            if( count <= 0 || memchr(control, 3, count) ){
                cancelled = true;
                break;
            }
        }
        if( readers[0] != ASRT_INVALID_SOCKET ){
            ssize_t length = read(output[0], buffer, sizeof(buffer));
            if( length <= 0 ) outputOpen = false;
            else if( client_.send(buffer, (int)length) != length ){
                cancelled = true;
                break;
            }
        }
    }
    ::close(output[0]);

    int status = 0;
    if( cancelled ){
        AsrtShell::terminateProcessGroup(pid);
        return 0;
    }
    if( waitpid(pid, &status, 0) < 0 ) return 1;
    if( WIFEXITED(status) && WEXITSTATUS(status)==0 ) return 0;

    char result[64];
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
    int resultLen = snprintf(result, sizeof(result), "\nBAD update.sh exit code %d\r\n", code);
    client_.send(result, resultLen);
    return 1;
#endif
}

int PgFileRunner::receiveFileData()
{
    SM4 sm4;
    sm4.init(m_ctx.sharedKey, SM4_KEY_LEN);
    
    int padding = m_ctx.fileSize & 0x0F;
    if( padding ) padding = 16-padding;
    int64_t totalSize = m_ctx.fileSize+padding;
    uint8_t * base = m_buffer.base();
    AsrtPath parentDir(m_ctx.filePath);
    parentDir.create(0755);
    AsrtFile::delete_file(m_ctx.filePath.data());
    AsrtFile outFile;
    if (outFile.open(m_ctx.filePath.data(), O_WRONLY | O_CREAT | O_TRUNC,0644) != 0)
        return replay(4,"Cannot create file");

    int64_t remaining = totalSize;
    int lastProgress = 0;
    int lastBytes = 0;
    while (remaining > 0) {
        int bytesRead = client_.recv(base+lastBytes, m_buffer.size()-lastBytes);
        
        if (bytesRead <= 0)  return replay(4,"Connection closed unexpectedly");

        remaining -= bytesRead;

        bytesRead += lastBytes;
        lastBytes = bytesRead & 0x0F;
        int decryptedLen = sm4.decrypt(base, bytesRead-lastBytes, base);
        
        if (decryptedLen > 0) {
            outFile.write(m_buffer, decryptedLen);
        }
        if(lastBytes>0) memmove(base,base+decryptedLen,lastBytes);
        
        int progress = (int)((totalSize - remaining) * 100 / totalSize);
        if (progress / 10 != lastProgress / 10) {
            APPINFO("Progress: %d%%", progress);
            lastProgress = progress;
        }
    }
    
    outFile.close();
    
    if (padding > 0) {
        AsrtFile::truncate(m_ctx.filePath.data(), m_ctx.fileSize);
    }
    
    APPINFO("File received successfully: %s (%lld bytes)", m_ctx.filePath.data(), m_ctx.fileSize);
    return 0;
}

//====================================
// PgFileAdminTask 实现 (服务端管理)
//====================================

PgFileAdminTask::PgFileAdminTask(PgFileAuth* auth, int port)
    : m_auth(auth), m_port(port) {
        name("PgFileAdmin");
}

PgFileAdminTask::~PgFileAdminTask() {
    APPINFO("%s free...",name());
}

int PgFileAdminTask::onInit(void* args) {
    SocketAddr localAddr(m_port);
    if (m_acceptor.listen(localAddr, 1) != 0) {
        APPERR("Failed to open admin port %d", m_port);
        return -1;
    }
    return 0;
}

int PgFileAdminTask::close() {
    APPINFO("%s will be close...",name());
#ifndef WIN32
    m_acceptor.shutdown(2);
#endif
    m_acceptor.close();
    return 0;
}
int PgFileAdminTask::destory() {
    return 0;
}
int PgFileAdminTask::run() {
    AsrtSocketReader reader(NULL);

    while (status()==RUNNING) {        
        if (m_acceptor.accept(client,NULL) == -1) {
            APPINFO("PgFileAdminTask::run Accept failed on admin port");
            break;
        }
        client.set_timeout(5000, 1000);
        int readLength = client.recv(m_buffer, sizeof(m_buffer)-1);
        if( readLength<=0 ) {
            replay(2, CMD_BAD_PARAMETER ", empty command");
            client.close();
            continue;
        }
        m_buffer[readLength] = 0;
        char * base = m_buffer;
        int k = readLength-2;
        if( k<0 || base[k+1]!='\n' ) {
            replay(2, CMD_BAD_PARAMETER ", command must end with newline");
            client.close();
            continue;
        }
        if( base[k]=='\r' ) base[k]=0;
         else base[k+1]=0;

        APPINFO("Admin command: %s", base);
        
        handleCommand(base);
        client.close();
    }
    return 0;
}
int PgFileAdminTask::replay(int code, const char *msg)
{
    DString tp ;
    if( jsonFmt ){
        tp= Response::fail(code, msg);
    } else {
        tp.AppendFormat("%s%s\r\n",code?CMD_BAD:CMD_OK,msg);
    }
    if( code ) APPWARN(tp.data());
    else APPINFO(tp.data());
    client.send(tp,tp.length());
    return  code;
}
int PgFileAdminTask::handleCommand(char * cmd)
{
    jsonFmt = 0;
    if( strstr(cmd," --json")) jsonFmt = 1;
    size_t cmdLen = strlen(cmd);
    if( cmdLen<3 || cmd[3]!=' ') return  replay(1,"unknown command");
    
    int cmdIndx = 0;
    if (cmd[0]=='a' && cmd[1]=='d' && cmd[2]=='d' )  cmdIndx = 1;
    if ( cmd[0]=='d' && cmd[1]=='e' && cmd[2]=='l' ) cmdIndx = 2;
    if ( cmd[0]=='d' && cmd[1]=='i' && cmd[2]=='s' ) cmdIndx = 3;
    if ( cmd[0]=='d' && cmd[1]=='e' && cmd[2]=='s' ) cmdIndx = 3;
    if( cmdIndx==0 )   return  replay(1,"unknown command");
     
    cmd +=4;
    while(cmd[0]==' ') cmd++;
    if( cmd[0]==0){
        return replay(2, CMD_BAD_PARAMETER ", need user key");
    }
    const char * userKey = cmd;
    while(cmd[0]!=0 && cmd[0]!=' ') cmd++;
    
    if( cmd[0]!=0){
        cmd[0] = 0;
        cmd++;
        while(cmd[0]==' ') cmd++;
    }
    if(strcmp(userKey, "--json")==0){
        userKey = cmd;
        while(cmd[0]!=0 && cmd[0]!=' ') cmd++;
        if( cmd[0]!=0){
            cmd[0] = 0;
            cmd++;
            while(cmd[0]==' ') cmd++;
        }
    }
    const char * allowDir = cmd;
    if( allowDir[0]){
        if( allowDir[0]!='/' ) return replay(2,CMD_BAD_PARAMETER ", allowDir must start with '/'");
        while(cmd[0]!=0 && cmd[0]!=' ') cmd++;
        cmd[0]=0;
        cmd --;
        if(cmd[0]!='/' ) cmd[1] = '/';
        cmd[2] =0;
    }
    if(cmdIndx == 1 ){
        if( allowDir[0]==0 ) return replay(2,CMD_BAD_PARAMETER ", need path");
        m_auth->addUserDir(userKey, allowDir);
        APPINFO("Added user dir: %s -> %s", userKey, allowDir);
        return replay(0,"add success");
    }
    if( cmdIndx == 2){
        if(allowDir[0]){
            m_auth->delUserDir(userKey, allowDir);
            APPINFO("Deleted user dir: %s -> %s", userKey, allowDir);
            return replay(0, "delete rule success");
        } else {
            m_auth->delUser(userKey);
            APPINFO("Deleted user: %s", userKey);
            return replay(0,"delete user success");
        }
    }
    if( cmdIndx == 3 ){
        ArrayObject * tmp = NULL;
        if( strcmp("user",userKey) ==0 ){
            tmp = m_auth->getUserList();
        } else {
            tmp = m_auth->getUserDirs(userKey);
        }
        if( tmp ){
            DString tp ;
            if( jsonFmt ){
                tp = Response::success(tmp);
            } else {
                tp = "OK exec success\r\n";
                tp += tmp->toString();
            }
            client.send(tp,tp.length());
            delete tmp;
            return 0;
        }
        return replay(4,"not found");
    }
    return replay(1,"unknown command");
}

//====================================
// PgFileServer 实现
//====================================

PgFileServer::PgFileServer()
    : m_adminPort(0), m_adminTask(NULL) {
    name("PgFileServer");
}

PgFileServer::~PgFileServer() {
    destory();
}

int PgFileServer::start(int port, int adminPort, const char* authFile)
{
    if (authFile && authFile[0]) {
        if (!m_auth.loadFromFile(authFile)) {
            APPWARN("Auth file not found, creating new one");
        }
    } else APPWARN(("Run with no auth file, Persistence will not be available"));
    
    m_adminPort = adminPort;
    
    int params[3];
    params[0] = 16;
    params[1] = 1;
    params[2] = port;
    
    m_adminTask = new PgFileAdminTask(&m_auth, adminPort);
    if (m_adminTask->open(NULL) != 0) {
        APPERR("Failed to start admin task");
        delete m_adminTask;
        m_adminTask = NULL;
        return 1;
    }
    if (open(params) != 0) {
        APPERR("Failed to initialize SocketQueueService");
        return 1;
    }
    APPINFO("PgFileServer started: transfer port=%d, admin port=%d", port, adminPort);
    return 0;
}

int PgFileServer::close()
{
    if( m_adminTask ) m_adminTask->close();
    return SocketQueueService::close();
}
int PgFileServer::destory() {
    if( m_adminTask ){
        m_adminTask->destory();
        m_adminTask = NULL;
    }

    return SocketQueueService::destory();
}

SocketRunner* PgFileServer::newClient(int index, AsrtSock * handle) {
    return new PgFileRunner(handle, this);
}

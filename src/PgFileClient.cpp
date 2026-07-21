// SPDX-License-Identifier: MIT
// Copyright (c) 2026 liaoyq / ASRT Contributors
//
//  PgFileClient.cpp
//
//  Created by liaoyq on 2026/4/27.
//
#include "PgFile.h"
#include "PgFileClient.h"
#include <AsyncRuntime/asrt_file.h>
#include <AsyncRuntime/asrt_socket.h>
#include <AsyncRuntime/asrt_dirent.h>
#include <AsyncRuntime/asrt_string.h>
#include <MinoCrypt/C25519.h>
#include <MinoCrypt/Utils.h>
#include <MinoCrypt/sm4.h>
#include <sys/types.h>


//====================================
// PgFileClient 实现
//====================================

PgFileClient::PgFileClient(): running(1),deployActive(0),mode(0) {
}

PgFileClient::~PgFileClient() {
    m_server.close();
}

void PgFileClient::setServer(const char* server) {
    m_svrAddr = server;
}

void PgFileClient::stop()
{
    running = 0;
    if( deployActive ){
        const char ctrlC = 3;
        // deploy upgrade 后协议为双向通道；ETX 表示用户按下 Ctrl+C。
        m_server.send(&ctrlC, 1);
        m_server.shutdown(1);
    }
}

TransferResult PgFileClient::uploadFile(const char * userKey, const char * filePath, const char * destPath) {
    AsrtFile file;
    if (file.open(filePath, O_RDONLY) != 0) {
        m_lastError.Format("Cannot open file: %s", filePath);
        // APPERR("%s", m_lastError.data());
        return TransferResult::FileNotFound;
    }
    
    int64_t fileSize = file.filesize();   //file.seek(0, SEEK_END);
   
    
    if (fileSize <= 0) {
        m_lastError.Format("Invalid file size: %s", filePath);
        //  APPERR("%s", m_lastError.data());
        return TransferResult::FileNotFound;
    }
    
    
    SocketAddr addr;
    addr = m_svrAddr.c_str();
    if( addr.port() ==0 )    addr.port(DEFAULT_FILE_PORT);
    
    if (m_server.connect(addr) != 0) {
        m_lastError.Format("Cannot connect to server %s", m_svrAddr.data());
        //  APPERR("%s", m_lastError.data());
        return TransferResult::ConnectionFailed;
    }
    
    m_server.set_timeout(5000, 1000);
    
    C25519 localKey;
    localKey.generate();
    
    DPtr buffer(TRANSFER_BUFFER_SIZE);
    char * base = buffer;
    int offset = 0;
    Utils::hex(localKey.pub, C25519_PUB_KEY_LEN, base);
    offset += C25519_PUB_KEY_LEN * 2;
    base[offset++] = ' ';
    offset += snprintf(base+offset,2000,"%s %s %lld\r\n",userKey,destPath,(long long)fileSize);

    if (m_server.send(buffer, offset) != offset) {
        m_lastError = "Failed to send request";
        // APPERR("%s", m_lastError.data());
        return TransferResult::NetworkError;
    }
    
    AsrtSocketReader reader(&m_server);
    offset = reader.read(buffer, buffer.size());

    if ( offset <= 5) {
        m_lastError = "Failed to read server response";
        //APPERR("%s", m_lastError.data());
        return TransferResult::NetworkError;
    }
    base[offset--] = 0;
    if( base[offset]=='\n') base[offset--] = 0;
    if( base[offset]=='\r') base[offset--] = 0;
    if (strncmp(base,CMD_UPGRADE,strlen(CMD_UPGRADE))) {
        if ( strncmp(base,CMD_BAD,strlen(CMD_BAD))==0 ) {
            m_lastError = base + strlen(CMD_BAD);
          //  APPERR("%s", base);
            return TransferResult::PermissionDenied;
        }
        m_lastError = "Unknown server response";
        //APPERR("%s", m_lastError.data());
        return TransferResult::UnknownError;
    }
    base += strlen(CMD_UPGRADE);
    while( base[0]==' ' ) base++;
    
    if (base[0]==0) {
        m_lastError = "Invalid server response";
        //APPERR("%s", m_lastError.data());
        return TransferResult::UnknownError;
    }
    
    uint8_t serverPubKeyBytes[C25519_PUB_KEY_LEN];
    if( Utils::unhex(base, serverPubKeyBytes, C25519::SIZE_KEY)!=C25519::SIZE_KEY ){
        m_lastError = "Invalid server public key";
        //APPERR("%s", m_lastError.data());
        return TransferResult::UnknownError;
    }
    uint8_t sharedKey[C25519::SIZE_KEY ];
    localKey.agree(serverPubKeyBytes, sharedKey, C25519::SIZE_KEY );
    
    if (file.open(filePath, O_RDONLY) != 0) {
        m_lastError.Format("Cannot open file: %s", filePath);
        //APPERR("%s", m_lastError.data());
        return TransferResult::FileNotFound;
    }
    
    int64_t totalToSend = fileSize ;
    
    SM4 sm4;
    sm4.init(sharedKey, SM4_KEY_LEN);
    
    int64_t remaining = totalToSend;
    int lastProgress = 0;
    if( mode== 0 ){
        APPINFO("Tranfer '%s' start",filePath);
        AppLog::set_flags(AppLog::LM_NO_NEWLINE);
        APPINFO("*");
    }
    
    while (remaining > 0 && running) {
        int toRead = (int)(remaining > TRANSFER_BUFFER_SIZE ? TRANSFER_BUFFER_SIZE : remaining);
        int bytesRead = 0;
        
        if (toRead > 0) {
            bytesRead = file.read(buffer, toRead);
            if (bytesRead <= 0) {
                break;
            }
            remaining -= bytesRead;
        } else break;
        
        int encryptedLen = sm4.encrypt(buffer, bytesRead, buffer);
        
        if (m_server.send(buffer, encryptedLen) != encryptedLen) {
            //APPERR("Failed to send encrypted data");
            if( mode== 0 ) AppLog::LogRaw("\n");
            file.close();
            return TransferResult::NetworkError;
        }
        
        int progress = (int)((totalToSend - remaining) * 100 / totalToSend);
        if (progress / 10 != lastProgress / 10) {
            //APPINFO("Upload progress: %d%%", progress);
            if( mode== 0 ) AppLog::LogRaw("*");
            lastProgress = progress;
        }
    }
    if( mode== 0 ) AppLog::LogRaw("\n");
    file.close();
    m_server.close();
    
    APPINFO("File uploaded successfully: %s", filePath);
    return TransferResult::Success;
}
TransferResult PgFileClient::clearPath(const char * userKey,const char * destPath)
{
    SocketAddr addr;
    addr = m_svrAddr.c_str();
    if( addr.port() ==0 )    addr.port(DEFAULT_FILE_PORT);
    
    if (m_server.connect(addr) != 0) {
        m_lastError.Format("Cannot connect to server %s", m_svrAddr.data());
       // APPERR("%s", m_lastError.data());
        return TransferResult::ConnectionFailed;
    }
    
    m_server.set_timeout(5000, 1000);
    
    C25519 localKey;
    localKey.generate();
    
    DPtr buffer(TRANSFER_BUFFER_SIZE);
    char * base = buffer;
    int offset = strlen(destPath);
    char sChar = ' ';
    if( destPath[offset-1]!='/') sChar = '/';
    offset = 0;
    Utils::hex(localKey.pub, C25519_PUB_KEY_LEN, base);
    offset += C25519_PUB_KEY_LEN * 2;
    base[offset++] = ' ';
    offset += snprintf(base+offset,2000,"%s %s%c del\r\n",userKey,destPath,sChar);

    if (m_server.send(buffer, offset) != offset) {
        m_lastError = "Failed to send request";
        //APPERR("%s", m_lastError.data());
        return TransferResult::NetworkError;
    }

    offset = m_server.recv(buffer, buffer.size());

    if ( offset <= 5) {
        m_lastError = "Failed to read server response";
        //APPERR("%s", m_lastError.data());
        return TransferResult::NetworkError;
    }
    base[offset--] = 0;
    if( base[offset]=='\n') base[offset--] = 0;
    if( base[offset]=='\r') base[offset--] = 0;
    if (strncmp(base,CMD_OK,strlen(CMD_OK))) {
        if ( strncmp(base,CMD_BAD,strlen(CMD_BAD))==0 ) {
            m_lastError = base + strlen(CMD_BAD);
          //  APPERR("%s", base);
            return TransferResult::PermissionDenied;
        }
        m_lastError = "Unknown server response";
        //APPERR("%s", m_lastError.data());
        return TransferResult::UnknownError;
    }
    return TransferResult::Success;
}
int PgFileClient::uploadPath(const char * userKey, const char * srcPath, const char * destPath)
{
    AsrtDirent dirs;
    dirent *entry;
    char srcName[PATH_MAX*2];
    char destName[PATH_MAX*2];
    int nfiles = 0;
    if( dirs.open(srcPath) != 0) {
        m_lastError.Format("Cannot open directory: %s", srcPath);
        return -1;
    }
    while( (entry = dirs.select()) != NULL && running) {
        if (entry->d_type == DT_DIR) {
            if (ASRTString::strcmp(".",entry->d_name) != 0 && ASRTString::strcmp("..",entry->d_name) != 0) {
                snprintf(srcName, sizeof(srcName), "%s/%s", srcPath, entry->d_name);
                snprintf(destName, sizeof(destName), "%s/%s", destPath, entry->d_name);
                int k = uploadPath(userKey,srcName,destName);
                if( k<0 ) return k;
                nfiles+=k;
            }
        } else {
            snprintf(srcName, sizeof(srcName), "%s/%s", srcPath,entry->d_name);
            snprintf(destName, sizeof(destName), "%s/%s", destPath,entry->d_name);
            if( AsrtFile::is_file(srcName,AsrtFile::READABLE)){
                nfiles ++;
                if( uploadFile(userKey, srcName, destName)!= TransferResult::Success ) return -2;
            }
        }
    }
    return nfiles;
}
int PgFileClient::deploy(const char * userKey, const char * destPath, const char * arg)
{
    SocketAddr addr;
    addr = m_svrAddr.c_str();
    if( addr.port() == 0 ) addr.port(DEFAULT_FILE_PORT);
    if( m_server.connect(addr) != 0 ){
        m_lastError.Format("Cannot connect to server %s", m_svrAddr.data());
        return 1;
    }

    // deploy 脚本可能长时间没有输出，不能使用普通文件请求的 5 秒超时。
    m_server.set_timeout(5000, 0);
    C25519 localKey;
    localKey.generate();
    char request[PATH_MAX * 2];
    Utils::hex(localKey.pub, C25519_PUB_KEY_LEN, request);
    int length = C25519_PUB_KEY_LEN * 2;
    request[length++] = ' ';
    if( arg && (strchr(arg, '\r') || strchr(arg, '\n')) ){
        m_lastError = "Deploy argument cannot contain a newline";
        return 1;
    }
    int appended = snprintf(request+length, sizeof(request)-length, "%s %s deploy%s%s\r\n",
                            userKey, destPath, arg ? " " : "", arg ? arg : "");
    if( appended < 0 || appended >= (int)sizeof(request)-length ){
        m_lastError = "Deploy request is too long";
        return 1;
    }
    length += appended;
    if( m_server.send(request, length) != length ){
        m_lastError = "Failed to send deploy request";
        return 1;
    }

    char buffer[4096];
    int received = 0;
    int headerLength = 0;
    while( headerLength == 0 && received < (int)sizeof(buffer) ){
        int count = m_server.recv(buffer+received, sizeof(buffer)-received);
        if( count <= 0 ){
            m_lastError = "Failed to read deploy response";
            return 1;
        }
        received += count;
        char *newline = (char *)memchr(buffer, '\n', received);
        if( newline ) headerLength = (int)(newline-buffer)+1;
    }
    if( headerLength == 0 ){
        m_lastError = "Invalid deploy response";
        return 1;
    }
    if( strncmp(buffer, "OK upgrade\r\n", 12) != 0 ){
        int copyLength = headerLength;
        while(copyLength>0 && (buffer[copyLength-1]=='\r' || buffer[copyLength-1]=='\n')) copyLength--;
        buffer[copyLength] = 0;
        m_lastError = buffer;
        APPERR("%s", buffer);
        return 1;
    }
    deployActive = 1;
    if( received > headerLength ) fwrite(buffer+headerLength, 1, received-headerLength, stdout);
    fflush(stdout);
    APPINFO("Entry console mode, Press Ctrl+C to stop");
    while( (received = m_server.recv(buffer, sizeof(buffer))) > 0 ){
        fwrite(buffer, 1, received, stdout);
        fflush(stdout);
    }
    deployActive = 0;
    m_server.close();
    return running ? 0 : 130;
}
AdminResult PgFileClient::sendAdminCommand(const char * cmd) {
 
    SocketAddr addr;
    addr = m_svrAddr.c_str();
    if( addr.port() == 0 ) addr.port(DEFAULT_ADMIN_PORT);
    
    if (m_server.connect(addr) != 0) {
        m_lastError.Format("Cannot connect to admin %s", m_svrAddr.data());
        //APPERR("%s", m_lastError.data());
        return AdminResult::ConnectionFailed;
    }
    
    m_server.set_timeout(5000, 1000);
    char buffer[1024*16];
    int k = snprintf(buffer, sizeof(buffer), "%s\r\n",cmd);
    
    if (m_server.send(buffer, k) != k) {
        m_lastError = "Failed to send command";
        //APPERR("%s", m_lastError.data());
        return AdminResult::CommandFailed;
    }
    
    k = m_server.recv(buffer,sizeof(buffer)) ;
    if ( k<= 0) {
        m_lastError = "Failed to read response";
        //APPERR("%s", m_lastError.data());
        return AdminResult::CommandFailed;
    }
    buffer[k--]=0;
    if( buffer[k] == '\n' ) buffer[k--] = 0;
    if( buffer[k] == '\r' ) buffer[k--] = 0;
    char * base = buffer;
    while(base[0]==' ') base++;
    if (base[0]=='O' && base[1]=='K' && base[2]==' ') {
        APPERR("%s", base);
        return AdminResult::Success;
    }
    
    m_lastError.Format("%s", base+4);
    APPERR("%s", base);
    return AdminResult::CommandFailed;
}

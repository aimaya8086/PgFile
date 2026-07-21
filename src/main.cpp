// SPDX-License-Identifier: MIT
// Copyright (c) 2026 liaoyq / ASRT Contributors
//
//  main.cpp
//  PgFile
//
//  文件加密传输 - 统一入口
//  通过子命令选择 server 或 client 模式
//
#include "PgFile.h"
#include "PgFileClient.h"
#include "PgFileServer.h"
#include "AsyncRuntime/asrt_base.h"
#include "AsyncRuntime/DString.h"
#include "AsyncRuntime/asrt_option.h"
#include "AsyncRuntime/asrt_string.h"
#include "AsyncRuntime/asrt_runtime.h"
#include "AsyncRuntime/asrt_file.h"
#include "calc_self.h"

#ifdef __APPLE__
#if defined(__x86_64__)
#define ARCH x86_64
#elif defined(__i386__)
#define ARCH x86
#elif defined(__arm64__) || defined(__aarch64__)
#define ARCH  ARM64
#elif defined(__arm__)
#define ARCH ARM
#endif
#endif

PgFileServer server;
PgFileClient client;
PgFileAdminTask* m_adminTask;
static const char * serverAddr = "127.0.0.1";
static const char * userKey = NULL;
static char filePath[PATH_MAX];
static char destPath[PATH_MAX];
static int transferPort = DEFAULT_FILE_PORT;
static int adminPort = DEFAULT_ADMIN_PORT;
static uint8_t self_digest[32];


static void signal_handle()
{
    client.stop();
    server.close();
}

void printUsage() {
    printf("Usage: %s <command> [options] [params]\n", AsrtRuntime::program_name);
    printf("\nCommands:\n");
    printf("  server                        Start file transfer server\n");
    printf("  file                          Upload file or directory, use -u set userKey, use -f set src filePath, -d  set dest filePath.\n");
    printf("  path                          clear  under path, use -u set userKey, use -d set dest filePath to be clean. \n");
    printf("  deploy [argument]             Run update.sh under -d directory and stream its output\n");
    printf("  admin  params....             Exec admin command\n");
    printf("         add <userKey> <directory>     Add user directory permission\n");
    printf("         del <userKey> [directory]     Delete user or user directory\n");
    printf("         dis user                      List all user \n");
    printf("         dis <userKey>                 List user allow path\n");
    printf("\nOptions:\n");
    printf("  -s <ip>:<port>    Server Addr (default: 127.0.0.1), and Port (Transfer  default: 9100, Admin default 9101)\n");
    printf("  -p <port>         File port for server (default: 9101), server only\n");
    printf("  -a <port>         Admin port for server (default: 9101), servder only\n");
    printf("  -u <userKey>      userKey, client only\n");
    printf("  -f <file>         Auth file  (default: auth.txt, server only) or file to uplaod\n");
    printf("  -d <path>         Path for file to be stored\n");
    printf("  -l <level>        Log level: DEBUG, INFO, WARN, ERROR (default: INFO)\n");
    printf("  -h                Show this help\n");
}
struct option long_options[] = {
    {"server",  required_argument, NULL, 's'},
    {"port",    required_argument, NULL, 'p'},
    {"admin",    required_argument, NULL, 'a'},
    {"user",    required_argument, NULL, 'u'},
    {"file",    required_argument, NULL, 'f'},
    {"dest",    required_argument, NULL, 'd'},
    {"level",    required_argument, NULL, 'l'},
    {"silent",    no_argument, NULL, 256},
    {"help",    no_argument, NULL, 'h'},
    {"version",    no_argument, NULL, 'v'},
};

#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION 1.2
#endif
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
static void setLogLevel(const char* logLevel) {
    if (strcmp(logLevel, "DEBUG") == 0) {
        AppLog::priority(AppLog::LM_DEBUG);
    } else if (strcmp(logLevel, "INFO") == 0) {
        AppLog::priority(AppLog::LM_INFO);
    } else if (strcmp(logLevel, "WARN") == 0) {
        AppLog::priority(AppLog::LM_WARNING);
    } else if (strcmp(logLevel, "ERROR") == 0) {
        AppLog::priority(AppLog::LM_ERROR);
    }
}
static int setOption(int optkey, char *optarg)
{
    switch(optkey) {
        case 's':
        case 'S':
            serverAddr = optarg;
            break;
        case 'p':
            transferPort = atoi(optarg);
            break;
        case 'a':
            adminPort = atoi(optarg);
            break;
        case 'u':
            userKey = optarg;
            break;
        case 'f':
            ASRTString::strncpy(filePath , optarg,sizeof(filePath));
            break;
        case 'd':
            ASRTString::strncpy(destPath , optarg,sizeof(destPath));
            break;
        case 'l':
            setLogLevel(optarg);
            break;
        case 256:
            client.setSilent(1);
            break;
        case 'V':
        case 'v':
            printf("%s %s v.%s - (C) 2026-04 atdm\n\n",AsrtRuntime::program_name,TOSTRING(ARCH),TOSTRING(PACKAGE_VERSION) );
            return -1;
        case 'h':
        case 'H':
            printUsage();
            return -1;
        default:
            return -1;
        }
    return 0;
}


static int runServer() {
    if( filePath[0]==0 ) ASRTString::strcpy(filePath , "auth.txt");

    APPINFO("Starting PgFileServer...");
    APPINFO("  Transfer port: %d", transferPort);
    APPINFO("  Admin port: %d", adminPort);
    APPINFO("  Auth file: %s", filePath);
    

    if (server.start(transferPort, adminPort, filePath)) {
        APPERR("Failed to start server");
        return 1;
    }
    
    APPINFO("PgFileServer is running. Press Ctrl+C to stop.");
    AsrtRuntime::signal_init(signal_handle);
    AsrtRuntime::wait_threads();
    APPINFO("PgFileServer stopped.");
    return 0;
}
int clearPath()
{

    if( userKey == NULL ){
        APPERR("missing user key");
        return -1;
    }

    if( destPath[0] == 0 ) {
        APPERR("missing destination file parameter");
        return -1;
    }
    if( destPath[0]!='/'){
        APPERR("the destination file must start with a '/'");
        return -1;
    }

    APPINFO("Uploading file: %s", filePath);
    APPINFO("User: %s", userKey);
    APPINFO("Server: %s", serverAddr);
    APPINFO("dest file: %s", destPath);

    TransferResult result = client.clearPath(userKey,destPath);
    
    switch (result) {
        case TransferResult::Success:
            APPINFO("Upload completed successfully!");
            return 0;
        case TransferResult::ConnectionFailed:
            APPERR("Connection failed: %s", client.getLastError());
            return 1;
        case TransferResult::PermissionDenied:
            APPERR("Permission denied: %s", client.getLastError());
            return 1;
        case TransferResult::FileNotFound:
            APPERR("File not found: %s", client.getLastError());
            return 1;
        case TransferResult::NetworkError:
            APPERR("Network error: %s", client.getLastError());
            return 1;
        default:
            APPERR("Unknown error: %s", client.getLastError());
            return 1;
    }
}
int uploadFile()
{

    if( userKey == NULL ){
        APPERR("missing user key");
        return -1;
    }
    if( filePath[0] == 0 ){
        APPERR("missing local file parameterd");
        return -1;
    }
    if( destPath[0] == 0 ) {
        APPERR("missing destination file parameter");
        return -1;
    }
    if( destPath[0]!='/'){
        APPERR("the destination file must start with a '/'");
        return -1;
    }
 
    if (AsrtFile::is_dir(filePath, AsrtFile::READABLE) ) {
        // filePath is a directory, destPath must end with '/'
        if ( destPath[strlen(destPath)-1] != AsrtFile::PATH_SEP_CHAR) {
            APPERR("the destination path must end with a '/' when uploading a directory");
            return 1;
        }
        if( filePath[strlen(filePath)-1] == AsrtFile::PATH_SEP_CHAR ) filePath[strlen(filePath)-1] =0;
        APPINFO("Uploading directory: %s", filePath);
        APPINFO("User: %s", userKey);
        APPINFO("Server: %s", serverAddr);
        APPINFO("dest path: %s", destPath);
        client.clearPath(userKey,destPath);
        destPath[strlen(destPath)-1]  =0;
        int nfiles = client.uploadPath(userKey, filePath, destPath);
        if (nfiles >= 0) {
            APPINFO("Upload completed successfully! %d files transferred.", nfiles);
            return 0;
        }
        APPERR("Directory upload failed (code: %d): %s", nfiles, client.getLastError());
        return 1;
    }

    APPINFO("Uploading file: %s", filePath);
    APPINFO("User: %s", userKey);
    APPINFO("Server: %s", serverAddr);
    APPINFO("dest file: %s", destPath);

    TransferResult result = client.uploadFile(userKey, filePath,destPath);
    
    switch (result) {
        case TransferResult::Success:
            APPINFO("Upload completed successfully!");
            return 0;
        case TransferResult::ConnectionFailed:
            APPERR("Connection failed: %s", client.getLastError());
            return 1;
        case TransferResult::PermissionDenied:
            APPERR("Permission denied: %s", client.getLastError());
            return 1;
        case TransferResult::FileNotFound:
            APPERR("File not found: %s", client.getLastError());
            return 1;
        case TransferResult::NetworkError:
            APPERR("Network error: %s", client.getLastError());
            return 1;
        default:
            APPERR("Unknown error: %s", client.getLastError());
            return 1;
    }
}
int runClient(int argc,char * argv[])
{
    if( argc<1){
        APPERR("no admin command");
        return -1;
    }
    int paramCount = 0;
    for(int i=1;i<argc;i++){
        if( strcmp(argv[i],"--json") ) paramCount++;
    }
    if( strcmp(argv[0],"add")==0 ){
        if( paramCount<2 ){
            APPERR("admin add need user key and directory");
            return -1;
        }
    } else if( strcmp(argv[0],"del")==0 ){
        if( paramCount<1 ){
            APPERR("admin del need user key");
            return -1;
        }
    } else if( strcmp(argv[0],"dis")==0 || strcmp(argv[0],"des")==0 ){
        if( paramCount<1 ){
            APPERR("admin dis need user key or user");
            return -1;
        }
    } else {
        APPERR("unknown admin command: %s", argv[0]);
        return -1;
    }
    DString cmd=argv[0];
    for(int i=1;i<argc;i++){ cmd.Append(" "); cmd.Append(argv[i]); }
    APPINFO("CMD: %s...",cmd.data());
    return (int)client.sendAdminCommand(cmd.data());
}

int runDeploy(int argc, char *argv[])
{
    if( userKey == NULL ){
        APPERR("missing user key");
        return 1;
    }
    if( destPath[0] != '/' ){
        APPERR("destination directory must start with a '/'");
        return 1;
    }
    if( argc > 1 ){
        APPERR("deploy accepts only one argument");
        return 1;
    }
    AsrtRuntime::signal_init(signal_handle);
    return client.deploy(userKey, destPath, argc == 1 ? argv[0] : NULL);
}

int main(int argc, char* argv[]) {
    AsrtRuntime runtime;
    if( runtime.init(argv[0])<0 ) return -1;
    if (argc < 2) {
        printUsage();
        return 1;
    }

    if( AsrtOption::load(argc-1,argv+1,"hHvs:S:p:a:u:f:d:",setOption,long_options )<0) return -2;
    if (strcmp(argv[1], "server") == 0) {
        APPINFO("Compiled on: %s at %s build for %s",__DATE__,__TIME__,TOSTRING(ARCH));
        self_checksum_from_disk(self_digest);
        APPINFO("self digest:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                self_digest[0],self_digest[1],self_digest[2],self_digest[3],self_digest[4],self_digest[5],self_digest[6],self_digest[7],
                self_digest[8],self_digest[9],self_digest[10],self_digest[11],self_digest[12],self_digest[13],self_digest[14],self_digest[15],
                self_digest[16],self_digest[17],self_digest[18],self_digest[19],self_digest[20],self_digest[21],self_digest[22],self_digest[23],
                self_digest[24],self_digest[25],self_digest[26],self_digest[27],self_digest[28],self_digest[29],self_digest[30],self_digest[31]);
        swapSelf(argv);
        return runServer();
    }
    client.setServer(serverAddr);
    if (strcmp(argv[1], "file") == 0) return uploadFile();
    if (strcmp(argv[1], "path") == 0) return clearPath();
    if (strcmp(argv[1], "deploy") == 0) return runDeploy(argc-optind-1, argv+optind+1);
    // client 子命令: /add/del/dis
    if( strcmp(argv[1],"admin") == 0 ) return runClient(argc-optind-1,argv+optind+1);
    printUsage();
    return 1;
}

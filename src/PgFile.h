// SPDX-License-Identifier: MIT
// Copyright (c) 2026 liaoyq / ASRT Contributors
//
//  PgFile.h
//
//  文件加密传输模块
//

#ifndef PgFile_h
#define PgFile_h

#include <AsyncRuntime/asrt_core.h>
#include <AsyncRuntime/DString.h>
#include <AsyncRuntime/AppLog.h>


// 用户Key前缀和长度定义
#define USER_KEY_PREFIX "acc"
#define USER_KEY_RANDOM_LEN 21
#define USER_KEY_CHARS "abcdefghijklmnopqrstuvwxyz0123456789-#%&!"
#define USER_KEY_TOTAL_LEN (sizeof(USER_KEY_PREFIX) - 1 + USER_KEY_RANDOM_LEN)
 
#define DEFAULT_FILE_PORT  8100
#define DEFAULT_ADMIN_PORT 8101
// 传输缓冲区大小 (1MB)
#define TRANSFER_BUFFER_SIZE (1024 * 1024)

// SM4 密钥长度
#define SM4_KEY_LEN 16

// C25519 公钥长度
#define C25519_PUB_KEY_LEN 32

// 协议命令
#define CMD_UPGRADE "OK upgrade "
#define CMD_OK "OK "
#define CMD_BAD "BAD "
#define CMD_BAD_PERMIT "Permission denied"
#define CMD_BAD_PARAMETER "Invalid parameter"

// 传输结果
enum class TransferResult {
    Success = 0,
    ConnectionFailed = 1,
    PermissionDenied = 2,
    FileNotFound = 3,
    NetworkError = 4,
    UnknownError = 5
};

// 管理命令结果
enum class AdminResult {
    Success = 0,
    ConnectionFailed = 1,
    CommandFailed = 2,
    UnknownError = 3
};

// 生成随机用户Key
inline DString generateUserKey() {
    DString key = USER_KEY_PREFIX;
    const char* chars = USER_KEY_CHARS;
    int charCount = strlen(chars);
    for (int i = 0; i < USER_KEY_RANDOM_LEN; i++) {
        int idx = rand() % charCount;
        key += chars[idx];
    }
    return key;
}

// Base64 编码
inline DString base64Encode(const uint8_t* data, int len) {
    static const char* base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    DString result;
    int i = 0;
    int j = 0;
    uint8_t charArray3[3];
    uint8_t charArray4[4];
    
    while (len--) {
        charArray3[i++] = *(data++);
        if (i == 3) {
            charArray4[0] = (charArray3[0] & 0xfc) >> 2;
            charArray4[1] = ((charArray3[0] & 0x03) << 4) + ((charArray3[1] & 0xf0) >> 4);
            charArray4[2] = ((charArray3[1] & 0x0f) << 2) + ((charArray3[2] & 0xc0) >> 6);
            charArray4[3] = charArray3[2] & 0x3f;
            
            for(i = 0; i < 4; i++)
                result += base64Chars[charArray4[i]];
            i = 0;
        }
    }
    
    if (i) {
        for(j = i; j < 3; j++)
            charArray3[j] = '\0';
        charArray4[0] = (charArray3[0] & 0xfc) >> 2;
        charArray4[1] = ((charArray3[0] & 0x03) << 4) + ((charArray3[1] & 0xf0) >> 4);
        charArray4[2] = ((charArray3[1] & 0x0f) << 2) + ((charArray3[2] & 0xc0) >> 6);
        
        for (j = 0; j < i + 1; j++)
            result += base64Chars[charArray4[j]];
        
        while((i++ < 3))
            result += '=';
    }
    
    return result;
}

// Base64 解码
inline int base64Decode(const DString& encoded, uint8_t* output, int maxLen) {
    static const unsigned char base64DecodeTable[256] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 0, 0, 0, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 0, 0, 0, 0, 0, 0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
        39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 0, 0, 0, 0, 0
    };
    
    int len = encoded.length();
    int i = 0;
    int j = 0;
    unsigned char charArray4[4], charArray3[3];
    int outputLen = 0;
    
    while (len-- && (encoded[j] != '=') && isalnum(encoded[j])) {
        charArray4[i++] = encoded[j]; j++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                charArray4[i] = base64DecodeTable[charArray4[i]];
            
            charArray3[0] = (charArray4[0] << 2) + ((charArray4[1] & 0x30) >> 4);
            charArray3[1] = ((charArray4[1] & 0xf) << 4) + ((charArray4[2] & 0x3c) >> 2);
            charArray3[2] = ((charArray4[2] & 0x3) << 6) + charArray4[3];
            
            for (i = 0; i < 3; i++) {
                if (outputLen < maxLen)
                    output[outputLen++] = charArray3[i];
            }
            i = 0;
        }
    }
    
    return outputLen;
}
// 路径是否以指定前缀开头


#endif /* PgFile_h */

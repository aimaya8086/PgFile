// SPDX-License-Identifier: MIT
// Copyright (c) 2026 liaoyq / ASRT Contributors
//
//  PgFileAuth.h
//
//  权限管理模块 - 用户索引 + 双Buffer
//  checkPermission: O(1) 查找用户 + O(D) 检查目录 (D=该用户目录数)
//

#ifndef PgFileAuth_h
#define PgFileAuth_h

#include "PgFile.h"
#include "MapObject.h"
#include <AsyncRuntime/DPtr.h>
// 最大用户数
#define AUTH_MAX_USERS 1024

// 每用户最大目录数
#define AUTH_MAX_DIRS 64

// 哈希表容量 (2的幂次)
#define AUTH_HASH_SIZE 2048

// 用户权限数据
class UserAuth {
    DString userKey;
    DStringArray dirs;
    int refs;
protected:
    UserAuth();
    UserAuth(const char * key);
    ~UserAuth(){  };
public:
    static UserAuth * getInstance(const char * key) { return new UserAuth(key); };
    static UserAuth * getInstance(UserAuth * ua){
        UserAuth * p = new UserAuth(ua->userKey);
        for(int i=0;i<ua->dirs.count();i++)p->dirs.add(ua->dirs[i]);
        return p;
    }
    const DString& operator [](int nIndex) const  { return dirs[nIndex]; }  ;
    const DString& getAt(int nIndex) const { return dirs[nIndex]; };
    int count() { return dirs.count(); };
    const char * name() { return userKey.data(); };
    void addPath(const char * path);
    void delPath(const char * path);
    UserAuth * clone(){ refs++; return this; };
    void release() { refs--; if( refs==0 ) delete this;};
    int compare(const char * key){ return userKey.Compare(key); }
    ArrayObject * toArray();
    void toFile(FILE * fp);
};

// AuthData: 持有一组用户权限数据 + 哈希索引
class AuthData {
    ValueArray<UserAuth * > users;
public:
    AuthData();
    ~AuthData();
    AuthData * clone();
    void clear() ;
    int count() { return users.count(); };
    // 查找用户在 users 数组中的下标, -1 表示未找到
    UserAuth * findUser(const char * userKey);
    int findIndex(const char * userKey) const;
    UserAuth * get(int index){ return users[index]; };
    // 添加用户, 返回下标, -1 表示失败
    int addPermit(const char * userKey,const char * path);
    
    // 删除用户
    void delPermit(const char * userKey,const char * path);
    void delUser(const char * userKey);
    ListObject * toArray();
    void toFile(FILE * fp);
};

// 权限管理器 - 使用双Buffer实现线程安全
class PgFileAuth {
public:
    PgFileAuth();
    ~PgFileAuth();
    
    // 加载权限文件
    int loadFromFile(const char* filePath);
    
    // 检查用户是否存在
    int hasUser(const char * userKey);
    
    // 添加用户和允许的目录
    void addUserDir(const char *userKey, const char *allowDir);
    
    // 删除用户的所有目录
    void delUser(const char * userKey);
    
    // 删除用户的特定目录
    void delUserDir(const char * userKey, const char * allowDir);
    
    // 检查用户是否有权限访问指定路径
    int checkPermission(const char * userKey, const char * filePath);
    
    // 获取所有用户列表
    ListObject * getAllUsers();
    
    // 获取用户的目录列表
    ArrayObject * getUserDirs(const char * userKey);

    ArrayObject * getUserList();
private:

    // 保存到文件（私有，每次修改后自动保存）
    int saveToFile();

private:
    // 文件路径
    DString m_filePath;
    
    // 双Buffer
    AuthData * m_current;
    AuthData * m_old;
};

#endif // PgFileAuth_h

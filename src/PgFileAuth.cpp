// SPDX-License-Identifier: MIT
// Copyright (c) 2026 liaoyq / ASRT Contributors
//
//  PgFileAuth.cpp
//
//  权限管理模块实现 - 用户索引 + 双Buffer
//

#include "PgFileAuth.h"
#include <AsyncRuntime/LineFile.h>
///////////////////////////////
///
///
UserAuth::UserAuth():refs(1)
{
    
}
UserAuth::UserAuth(const char * key): refs(1)
{
    userKey = key;
}
void UserAuth::addPath(const char * path)
{
    int len = (int)strlen(path);
    for(int i=0;i<dirs.count();i++){
        if( len!= dirs[i].length() ) continue;
        if( strcmp(dirs[i],path)==0 ) return ;
    }
    dirs.add(path);
}
void UserAuth::delPath(const char * path)
{
    for(int i=0;i<dirs.count();i++) if( strcmp(dirs[i],path)==0 ){
        dirs.remove(i, 1);
        break;
    }
}
ArrayObject * UserAuth::toArray()
{
    ArrayObject * result = new ArrayObject();
    for(int k=0;k< dirs.count();k++){
        result->add( new ValueObject(dirs[k].data()));
    }
    return result;
}
void UserAuth::toFile(FILE * fp)
{
    for(int k=0;k< dirs.count();k++){
        fprintf(fp,"%s:%s\n",userKey.data(),dirs[k].data());
    }
}
/////////////////////////////////////////////
///
///
AuthData::AuthData()
{
    
}
AuthData::~AuthData()
{
    for(int i=0;i<users.count();i++) users[i]->release();
    users.empty();
}
AuthData * AuthData::clone()
{
    AuthData * rs = new AuthData();
    for(int i=0;i<users.count();i++) rs->users.add(users[i]->clone());
    return rs;
}
void AuthData::clear()
{
    for (int i = 0; i < users.count(); i++) users[i]->release();
    users.empty();
}
UserAuth * AuthData::findUser(const char * userKey) 
{
    int lo = 0, hi = users.count() - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int cmp = users[mid]->compare(userKey);
        if (cmp > 0)
            lo = mid + 1;
        else if (cmp < 0)
            hi = mid - 1;
        else {
            return users[mid];
        }
    }
    return NULL;
}
int AuthData::findIndex(const char * userKey) const
{
    int lo = 0, hi = users.count() - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int cmp = users[mid]->compare(userKey);
        if (cmp > 0)
            lo = mid + 1;
        else if (cmp < 0)
            hi = mid - 1;
        else {
            return mid;
        }
    }
    return -1;
}
int AuthData::addPermit(const char * userKey,const char * path)
{
    int lo = 0, hi = users.count() - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int cmp = users[mid]->compare(userKey);
        if (cmp > 0)
            lo = mid + 1;
        else if (cmp < 0)
            hi = mid - 1;
        else {
            UserAuth * old = users[mid];
            UserAuth * newNode = UserAuth::getInstance(old);
            newNode->addPath(path);
            users[mid] = newNode;
            old->release();
            return mid;
        }
    }
    // add at lo
    UserAuth * newNode = UserAuth::getInstance(userKey);
    newNode->addPath(path);
    users.insertAt(lo, newNode);
    return lo;
}
void AuthData::delPermit(const char * userKey,const char * path)
{
    int lo = 0, hi = users.count() - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int cmp = users[mid]->compare(userKey);
        if (cmp > 0)
            lo = mid + 1;
        else if (cmp < 0)
            hi = mid - 1;
        else {
            UserAuth * old = users[mid];
            UserAuth * newNode = UserAuth::getInstance(old->name());
            for(int i=0;i<old->count();i++){
                if( strcmp(path,old->getAt(i)) ) newNode->addPath(old->getAt(i));
            }
            users[mid] = newNode;
            old->release();
            return ;
        }
    }
}
void AuthData::delUser(const char * userKey)
{
    int lo = 0, hi = users.count() - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int cmp = users[mid]->compare(userKey);
        if (cmp > 0)
            lo = mid + 1;
        else if (cmp < 0)
            hi = mid - 1;
        else {
            UserAuth * old = users[mid];
            users.remove(mid, 1);
            old->release();
            return ;
        }
    }
}
ListObject * AuthData::toArray()
{
    ListObject * result = new ListObject();
    for(int i=0;i<users.count();i++){
        result->add(users[i]->name(), users[i]->toArray());
    }
    return result;
}
void AuthData::toFile(FILE *fp)
{
    for(int i=0;i<users.count();i++){
       users[i]->toFile(fp);
    }
}
///////////////////////////////////////////
///
PgFileAuth::PgFileAuth():m_old(NULL)
{
    m_current = new AuthData();
}

PgFileAuth::~PgFileAuth() {
    if( m_current ) delete m_current;
    if( m_old ) delete m_old;
}



int PgFileAuth::hasUser(const char * userKey)
{
    return m_current->findIndex(userKey) <0 ? 0 : 1;
}

void PgFileAuth::addUserDir(const char * userKey, const char * allowDir) {
    // 切换到备用缓冲区
    AuthData * newData = m_current->clone();
    newData->addPermit(userKey, allowDir);
    AuthData * tmp = m_old;
    m_old = m_current;
    m_current = newData;
    if( tmp ) delete tmp;
    
    // 同步保存到文件
    saveToFile();
}

void PgFileAuth::delUserDir(const char * userKey, const char * allowDir) {
    AuthData * newData = m_current->clone();
    newData->delPermit(userKey, allowDir);
    AuthData * tmp = m_old;
    m_old = m_current;
    m_current = newData;
    if( tmp ) delete tmp;

    // 同步保存到文件
    saveToFile();

}

void PgFileAuth::delUser(const char * userKey) {
    AuthData * newData = m_current->clone();
    newData->delUser(userKey);
    AuthData * tmp = m_old;
    m_old = m_current;
    m_current = newData;
    if( tmp ) delete tmp;

    // 同步保存到文件
    saveToFile();
}

int PgFileAuth::loadFromFile(const char* filePath) {
    m_filePath = filePath;
    
    LineFile lf;
    int max = lf.fromFile(filePath, 2000);
    if ( max <1  ) {
        APPERR("Cannot open auth file: %s", filePath);
        return -1;
    }
    m_current->clear();
    if( m_old ) delete m_old;
    m_old = NULL;
   ;
    for(int i=0;i<max;i++){
        DString line = lf[i];
        line = line.trim();
        if (line.isEmpty() || line.startsWith("#")) {
            continue;
        }
        
        // 格式: userKey:目录
        int sepPos = line.indexOf(':');
        if (sepPos > 0) {
            DString userKey = line.substring(0, sepPos);
            DString allowDir = line.substring(sepPos + 1);
            
            if (!userKey.isEmpty() && !allowDir.isEmpty()) {
                m_current->addPermit(userKey, allowDir);
            }
        }
    }
    APPINFO("Loaded %d users from %s", m_current->count(), filePath);
    return true;
}

int PgFileAuth::saveToFile()
{
    if (m_filePath.isEmpty())        return 0;
    FILE * fp = fopen(m_filePath.data(),"w");
    if( fp ){
        for(int i=0;i<m_current->count();i++){
            UserAuth *ua = m_current->get(i);
            ua->toFile(fp);
        }
        fclose(fp);
    }
    return true;
}

int PgFileAuth::checkPermission(const char * userKey, const char * filePath)
{
    
    // O(1) 查找用户
    UserAuth * user = m_current->findUser(userKey);
    if ( user == NULL ) return -1;
    int len = (int)strlen(filePath);
    // O(D) 检查目录权限 (D = 该用户的目录数)
    for (int i = 0; i < user->count(); i++) {
        DString allow = user->getAt(i);
        if( len < allow.length() ) continue;
        if( strncmp(filePath,allow.data(),allow.length())==0 ){
            return 0;
        } 
    }
    return 1;
}

ListObject * PgFileAuth::getAllUsers() {
    return m_current->toArray();
}
ArrayObject * PgFileAuth::getUserList() {
    ArrayObject * result = new ArrayObject();
    for(int i=0;i<m_current->count();i++){
        result->add(new ValueObject(m_current->get(i)->name()));
    }
    return result;
}
ArrayObject * PgFileAuth::getUserDirs(const char * userKey) {
    UserAuth * data = m_current->findUser(userKey);
    if( data ){
        return data->toArray();
    }
    return NULL;
}

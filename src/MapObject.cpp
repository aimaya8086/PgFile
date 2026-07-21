// SPDX-License-Identifier: MIT
// Copyright (c) 2026 liaoyq / ASRT Contributors
//
//  MapObject.cpp
//
//  Created by liaoyq on 2026/4/29.
//
#include <AsyncRuntime/asrt_core.h>
#include "MapObject.h"

Value::Value()
{
    
}
Value::~Value()
{
}

ListObject::ListObject()
{
    
}
ListObject::~ListObject()
{
    
}
DString ListObject::toString()
{
    if( names.count()<1 ) return "{}";
    DString tmp = "{";
    tmp.AppendFormat("\"%s\":%s",names[0].data(),values[0]->toString().data());
    for(int i=1;i<names.count();i++){
        tmp.AppendFormat(",\"%s\":%s",names[i].data(),values[i]->toString().data());
    }
    tmp += "}";
    return tmp;
}
ArrayObject::ArrayObject()
{
    
}
ArrayObject::~ArrayObject()
{
    
}
DString ArrayObject::toString()
{
    if( values.count()<1 ) return "[]";
    DString tmp = "[";
    tmp.Append(values[0]->toString());
    for(int i=1;i<values.count();i++){
        tmp.Append(",");
        tmp.Append(values[i]->toString());
    }
    tmp += "]";
    return tmp;
}
/////////////////////////////////
///
///
Response::Response():code(0),data(NULL)
{
    
}

Response::~Response()
{
    if( data ) delete data;
}

DString Response::toString()
{
    DString tmp;
    tmp.Format("{\"code\":%d",code);
    if( msg.length()>0 ) tmp.AppendFormat(",\"msg\":\"%s\"",msg.data());
    if( data ) tmp.AppendFormat(",\"data\":%s",data->toString().data());
    tmp.Append("}");
    return tmp;
}
DString Response::success(Value * data)
{
    DString tmp="{\"code\": 0";
    if( data ) tmp.AppendFormat(",\"data\":%s",data->toString().data());
    tmp.Append("}");
    return tmp;
}
DString Response::fail(int code,const char * msg)
{
    DString tmp;
    tmp.Format("{\"code\":%d",code);
    tmp.AppendFormat(",\"msg\":\"%s\"",msg);
    tmp.Append("}");
    return tmp;
}

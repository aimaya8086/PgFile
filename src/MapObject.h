// SPDX-License-Identifier: MIT
// Copyright (c) 2026 liaoyq / ASRT Contributors
//
//  MapObject.h
//
//  Created by liaoyq on 2026/4/29.
//

#ifndef MAP_OBJECT_H
#define MAP_OBJECT_H

#include <AsyncRuntime/DPtr.h>
#include <AsyncRuntime/DString.h>

class Value
{
protected:
    Value();
public:
    virtual ~Value();
    virtual DString toString() = 0;
};

class ValueObject: public Value
{
protected:
    DString name;
public:
    ValueObject(int value){ name.Format("%d",value); };
    ValueObject(double value){ name.Format("%f",value); };
    ValueObject(const char * value){ name.Format("\"%s\"",value); };
    virtual ~ValueObject() {};
    virtual DString toString() { return name; }
};


class ListObject: public Value
{
    MutableArray<DString> names;
    MutableArray<Value *> values;
public:
    ListObject();
    virtual ~ListObject();
    virtual DString toString();
    void add(const char * name, Value * value){ names.add(name); values.add(value); };
};

class ArrayObject: public Value
{
    MutableArray<Value *> values;
public:
    ArrayObject();
    virtual ~ArrayObject();
    virtual DString toString();
    void add(Value * value){ values.add(value); }
};

class Response: public Value
{
public:
    int code;
    DString msg;
    Value * data;
public:
    Response();
    virtual ~Response();
    virtual DString toString();
    static DString success(Value * data);
    static DString fail(int code,const char * msg);
};
#endif

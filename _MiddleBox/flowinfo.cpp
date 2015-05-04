#include "flowinfo.h"

FlowInfo::FlowInfo(FlowKey* key)
    :key(key->getIP1(), key->getPort1(), key->getIP2(), key->getPort2())
{
    //ctor
}

FlowInfo::~FlowInfo()
{
    //dtor
}

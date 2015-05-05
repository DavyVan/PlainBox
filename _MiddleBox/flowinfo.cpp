#include "flowinfo.h"

FlowInfo::FlowInfo(FlowKey &key)
    :key(key.getIP1(), key.getPort1(), key.getIP2(), key.getPort2())
    , status(TCP_HANDSHAKING)
{
    //ctor
}

FlowInfo::~FlowInfo()
{
    //dtor
}

FlowKey* FlowInfo::getFlowKey()
{
    return &key;
}

FlowStatus FlowInfo::getStatus()
{
    return status;
}

void FlowInfo::statusChange(FlowStatus newStatus)
{
    status = newStatus;
}

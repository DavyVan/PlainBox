#include"flowmgr.h"

FlowMgr::FlowMgr()
{
    //ctor
}

FlowMgr::~FlowMgr()
{
    //dtor
}

FlowInfoPtr FlowMgr::findFlow(FlowKey &key)
{
    map_it it = mp.find(key);
    if(it == mp.end())
        return FlowInfoPtr();
    else
    {
        return it->second;
    }
}

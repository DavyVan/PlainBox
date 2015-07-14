#include"flowmgr.h"
#include<iostream>

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
    map_it it = mp.find(key.map_key_gen());
    if(it == mp.end())
    {
        //std::cout<<"it end\n";
        return FlowInfoPtr();
    }
    else
    {
        return it->second;
    }
}

FlowInfoPtr FlowMgr::addNewFlow(FlowKey &key)
{
    FlowInfoPtr info_ptr(new FlowInfo(key));
    mp[key.map_key_gen()] = info_ptr;
    return info_ptr;
}

void FlowMgr::deleteFlow(FlowKey &key)
{
    mp.erase(key.map_key_gen());
    //std::cout<<mp.size()<<endl;
}

#include<memory.h>
#include "applayerhandler.h"

AppLayerHandler::AppLayerHandler()
{
    //ctor
}

TLSHandler::TLSHandler()
{
    memset(temp, 0, 20000);
    temp_length = 0;
    status = INITIAL;
}

void* TLSHandler::parse(TCPDataNode* head, TCPDataDirection direction)
{
    while(head != NULL)
    {
        if(temp_length[direction] == 0)
        {
            uint8_t tlshdr[5] = {0};
            memcpy(tlshdr, head_->tcp_payload, 5);
        }
        else
        {
            //TODO: temp_length!=0, that means it has imcompleted TLSRec in cache.
        }
        //TODO: delete and move head on
    }
}

#include<memory.h>
#include<iostream>
#include "applayerhandler.h"

using namespace std;

AppLayerHandler::AppLayerHandler()
{
    //ctor
}

AppLayerHandler::~AppLayerHandler()
{
    //dtor
}

TLSHandler::TLSHandler()
{
    memset(temp, 0, 70000*2);
    memset(temp_length, 0, 2);
    status = INITIAL;
}

TLSHandler::~AppLayerHandler()
{

}

void* TLSHandler::parse(TCPDataNode* head, TCPDataDirection direction)
{
    while(head != NULL)     //pick a TCP payload
    {
        unsigned int tcp_length = head->length;
        unsigned int offset = 0;
        if(temp_length[direction] == 0)     //if there is a imcompleted TLS record in cache
        {
            //nothing in cache
            while(tcp_length > 0)
            {
                //inspect TLS header
                uint8_t content_type = 0;
                uint16_t version = 0;
                uint16_t length = 0;
                memcpy(&content_type, head->tcp_payload + offset, 1);
                memcpy(&version, head->tcp_payload + offset +1, 2);
                version = ntohs(version);
                memcpy(&length, head->tcp_payload + offset +3, 2);
                length = ntohs(length);

                //Check if there is a completed TLS record in this TCP payload
                if(length+5 <= tcp_length)
                {
                    TLSRec rec;
                    rec.content_type = content_type;
                    rec.version = version;
                    rec.length = length;
                    memcpy(rec.tls_payload, head->tcp_payload + offset +5, length);
                    //Process the new TLS record
                    process(&rec);

                    tcp_length -= 5+length;
                    offset += 5+length;
                }
                else
                {
                    //TODO: No completed TLS record in this TCP payload, put it in cache
                    memcpy(temp[direction], head->tcp_payload + offset, tcp_length);
                    temp_length[direction] = tcp_length;

                    tcp_length = 0;     //end the loop, continue to next tcp payload
                }
            }
        }
        else
        {
            //it has imcompleted TLSRec in cache.
            //inspect TLS header that stored in cache.
            uint8_t content_type = 0;
            uint16_t version = 0;
            uint16_t length = 0;
            memcpy(&content_type, temp[direction], 1);
            memcpy(&version, temp[direction] +1, 2);
            version = ntohs(version);
            memcpy(&length, temp[direction] +3, 2);
            length = ntohs(length);

            //Check if there is a completed TLS record including current TCP payload.
            if(length+5 <= temp_length[direction]+tcp_length)
            {
                //it can be a completed TLS record
                TLSRec rec;
                rec.content_type = content_type;
                rec.version = version;
                rec.length = length;
                memcpy(rec.tls_payload, temp[direction]+5, temp_length[direction]-5);
                memcpy(rec.tls_payload+temp_length[direction]-5, head->tcp_payload, length-temp_length[direction]+5);
                tcp_length -= length-temp_length[direction]+5;
                offset += length-temp_length[direction]+5;
                temp_length[direction] = 0;

                //processing TLS record
                process(&rec);

                while(tcp_length > 0)
                {
                    //inspect TLS header
                    uint8_t content_type = 0;
                    uint16_t version = 0;
                    uint16_t length = 0;
                    memcpy(&content_type, head->tcp_payload + offset, 1);
                    memcpy(&version, head->tcp_payload + offset +1, 2);
                    version = ntohs(version);
                    memcpy(&length, head->tcp_payload + offset +3, 2);
                    length = ntohs(length);

                    //Check if there is a completed TLS record in this TCP payload
                    if(length+5 <= tcp_length)
                    {
                        TLSRec rec;
                        rec.content_type = content_type;
                        rec.version = version;
                        rec.length = length;
                        memcpy(rec.tls_payload, head->tcp_payload + offset +5, length);
                        //Process the new TLS record
                        process(&rec);

                        tcp_length -= 5+length;
                        offset += 5+length;
                    }
                    else
                    {
                        //TODO: No completed TLS record in this TCP payload, put it in cache
                        memcpy(temp[direction], head->tcp_payload + offset, tcp_length);
                        temp_length[direction] = tcp_length;

                        tcp_length = 0;     //end the loop, continue to next tcp payload
                    }
                }
            }
            else
            {
                //still not a completed TLS record, put current TCP payload into cache.
                memcpy(temp[direction]+temp_length[direction], head->tcp_payload, tcp_length);
            }
        }
        //delete and move head on
        TCPDataNode *p = head->next;
        delete(head);
        head = p;
    }
}

void TLSHandler::process(void *record)
{
    TLSRec *rec = (TLSRec*) record;

    switch(rec->version)
    {
        case 0x0303:
            cout<<"TLS v1.2 ";
            break;
        case 0x0301:
            cout<<"TLS v1.0 ";
            break;
        default:
            cout<<"TLS v"<<hex<<rec->version<<dec<<" ";
            break;
    }

    if(rec->content_type == 20)
    {
        cout<<"CHANGE_CIPHER_SPEC"<<endl;
    }
    else if(rec->content_type == 21)
    {
        cout<<"ALERT"<<endl;
    }
    else if(rec->content_type == 22)
    {
        cout<<"HANDSHAKE"<<endl;
    }
    else if(rec->content_type == 23)
    {
        cout<<"APPLICATION_DATA"<<endl;
    }
    else
    {
        cout<<"Unknown Content Type"<<endl;
    }
    //TLS record is no need to delete.
}

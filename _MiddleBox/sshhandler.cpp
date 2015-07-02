#include<memory.h>
#include<iostream>
#include<cstring>
#include<cstdio>
#include "sshhandler.h"
using namespace std;

SSHHandler::SSHHandler()
{
    memset(temp, 0, 70000*2);
    memset(temp_length, 0, 2);
    status = SSH_INITIAL;
    clientIs = 0;
    mac_length[0] = mac_length[1] = 0;
    isEncrypted[0] = isEncrypted[1] = false;
}

SSHHandler::~SSHHandler()
{
    //dtor
}

void* SSHHandler::parse(TCPDataNode *head, TCPDataDirection direction, FlowKey* flowkey)
{
    while(head != NULL)
    {
        unsigned int tcp_length = head->length;
        unsigned int offset = 0;
        if(temp_length[direction] == 0)     //nothing in cache
        {
            while(tcp_length > 0)   //start parse SSH record
            {
                //SSH header
                uint32_t packet_length = 0;
                uint8_t padding_length = 0;
                uint32_t total_length = 0;      //including packet_length, padding_length, payload, padding data, MAC(namely, all of SSH data)
                memcpy(&packet_length, head->tcp_payload + offset, 4);
                packet_length = ntohl(packet_length);
                memcpy(&padding_length, head->tcp_payload + offset + 4, 1);

                //handle the Protocol Version Exchange string
                if(packet_length == 0x5353482d && *(head->tcp_payload+tcp_length-2) == 0x0d && *(head->tcp_payload+tcp_length-1) == 0x0a)
                {
                    cout<<"Protocol Version Exchange: ";
                    for(int i = 0; i < tcp_length-2; i++)   //skip \r\n
                        cout<<(char)head->tcp_payload[i];
                    cout<<endl;
                    break;  //Protocol Version Exchange is always alone.
                }
                printf("packet_length:%04x\n", packet_length);

                //calculate total_length
                total_length = packet_length + 4;
                if(isEncrypted[direction])
                    total_length += mac_length[direction];

                //Check if there is a completed SSH record in this TCP payload.
                if(total_length <= tcp_length)
                {
                    SSHRec rec;
                    memset(rec.ssh_payload_padding_mac, 0, 70000);
                    //memset(rec.mac, 0, 200);
                    rec.packet_length = packet_length;
                    rec.padding_length = padding_length;
                    memcpy(rec.ssh_payload_padding_mac, head->tcp_payload + offset + 5, total_length-5);

                    process(&rec, direction, flowkey);

                    tcp_length -= total_length;
                    offset += total_length;
                }
                else    //No completed SSH record in this TCP payload, cache it.
                {
                    memcpy(temp[direction], head->tcp_payload + offset, tcp_length);
                    temp_length[direction] = tcp_length;
                    cout<<"No completed TLS record in this TCP payload, put it in cache, and temp_length:"<<temp_length[direction]<<endl;

                    tcp_length = 0;
                }
            }
        }
        else    //it has imcompleted SSH record in cache.
        {
            uint32_t packet_length = 0;
            uint8_t padding_length = 0;
            uint32_t total_length = 0;
            memcpy(&packet_length, temp[direction], 4);
            packet_length = ntohl(packet_length);
            memcpy(&padding_length, temp[direction] + 4, 1);

            //calculate total_length
            total_length = packet_length + 4;
            if(isEncrypted[direction])
                total_length += mac_length[direction];

            //Check there is a completed TLS record including current TCP payload and cache.
            if(total_length <= temp_length[direction] + tcp_length)     //it can be a completed SSH record.
            {
                SSHRec rec;
                rec.packet_length = packet_length;
                rec.padding_length = padding_length;
                memcpy(rec.ssh_payload_padding_mac, temp[direction] + 5, temp_length[direction]-5);
                memcpy(rec.ssh_payload_padding_mac+temp_length[direction]-5, head->tcp_payload, total_length-temp_length[direction]);
                tcp_length -= total_length-temp_length[direction];
                offset += total_length-temp_length[direction];
                temp_length[direction] = 0;

                process(&rec, direction, flowkey);

                while(tcp_length > 0)   //start parse SSH record
                {
                    //SSH header
                    uint32_t packet_length = 0;
                    uint8_t padding_length = 0;
                    uint32_t total_length = 0;      //including packet_length, padding_length, payload, padding data, MAC(namely, all of SSH data)
                    memcpy(&packet_length, head->tcp_payload + offset, 4);
                    packet_length = ntohl(packet_length);
                    memcpy(&padding_length, head->tcp_payload + offset + 4, 1);

                    //calculate total_length
                    total_length = packet_length + 4;
                    if(isEncrypted[direction])
                        total_length += mac_length[direction];

                    //Check if there is a completed SSH record in this TCP payload.
                    if(total_length <= tcp_length)
                    {
                        SSHRec rec;
                        memset(rec.ssh_payload_padding_mac, 0, 70000);
                        //memset(rec.mac, 0, 200);
                        rec.packet_length = packet_length;
                        rec.padding_length = padding_length;
                        memcpy(rec.ssh_payload_padding_mac, head->tcp_payload + offset + 5, total_length-5);

                        process(&rec, direction, flowkey);

                        tcp_length -= total_length;
                        offset += total_length;
                    }
                    else    //No completed SSH record in this TCP payload, cache it.
                    {
                        memcpy(temp[direction], head->tcp_payload + offset, tcp_length);
                        temp_length[direction] = tcp_length;
                        cout<<"No completed TLS record in this TCP payload, put it in cache, and temp_length:"<<temp_length[direction]<<endl;

                        tcp_length = 0;
                    }
                }
            }
            else    //still not a completed SSH record, put current TCP payload into cache as well.
            {
                memcpy(temp[direction]+temp_length[direction], head->tcp_payload, tcp_length);
                temp_length[direction] += tcp_length;
            }
        }
        //delete current TCPDataNode and move ahead
        TCPDataNode *p = head->next;
        head->next = NULL;
        delete(head);
        head = p;
    }
}

void SSHHandler::process(void *record, TCPDataDirection direction, FlowKey* flowkey)
{
    SSHRec *rec = (SSHRec*) record;

    //check if it needs to be decrypted.
    uint32_t packet_length;
    uint8_t padding_length;
    uint32_t payload_length;
    uint8_t ssh_payload[70000] = {0};
    uint8_t ssh_mac[200] = {0};
    if(isEncrypted[direction])
    {
        //TODO: decrypt,mac,don't forget padding_length
    }
    else    //no need to decrypt
    {
        packet_length = rec->packet_length;
        padding_length = rec->padding_length;
        payload_length = packet_length-padding_length-1;
        memcpy(ssh_payload, rec->ssh_payload_padding_mac, packet_length-padding_length-1);
        //No MAC
    }

    uint8_t message_code;
    memcpy(&message_code, ssh_payload, 1);

    if(message_code == 20)
    {
        cout<<"Key Exchange Init\n";
    }
    else if(message_code == 21)
    {
        cout<<"New Keys\n";
        isEncrypted[direction] = true;
        mac_length[direction] = 16;     //I assume that mac is 16 bytes long
    }
    else if(message_code == 30)
    {
        cout<<"Diffie-Hellman Key Exchange Init\n";
        clientIs = direction == _1to2 ? 1 : 2;
        cout<<"client is: "<<clientIs<<endl;
    }
    else if(message_code == 31)
    {
        cout<<"Diffie-Hellman Key Exchange Reply\n";
    }

}

AppLayerDataDirection SSHHandler::getAppLayerDataDirection(TCPDataDirection tcpdirection)
{
    if(clientIs == 0)
        return PLACEHOLDER;
    else if(clientIs == 1)
    {
        if(tcpdirection == _1to2)
            return CLIENT_TO_SERVER;
        else if(tcpdirection == _2to1)
            return SERVER_TO_CLIENT;
    }
    else if(clientIs == 2)
    {
        if(tcpdirection == _1to2)
            return SERVER_TO_CLIENT;
        else if(tcpdirection == _2to1)
            return CLIENT_TO_SERVER;
    }
}

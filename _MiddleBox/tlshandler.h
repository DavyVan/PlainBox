#ifndef TLSHANDLER_H
#define TLSHANDLER_H

#include<arpa/inet.h>


struct TLSRec
{
    unsigned int full_length;
    uint8_t *tls_payload;
};

//More status to be added/modified
enum TLSStatus
{
    HANDSHAKE_CLIENTHELLO,
    HANDSHAKE_SERVERHELLO,
    HANDSHAKE_NEGOTIATING,
    WORKING
};

/*
* This class aims to trace TLS connection status and re-assamble/analyze TLS Record.
* This class should have a instance in FlowInfo, so that it can trace the status of the TLS connection.
*/
class TLSHandler
{
    public:
        TLSHandler();

        //loop inside until no complete TLS record any more
        void run_analyze();

        //re-assamble a TLS record to be analyzed. Called by run_analyze().
        TLSRec* nextRec();

        //do something with TLS record, like printing some info. to standard output. Called by run_analyze().
        void analyze(TLSRec* rec);

        //Called by run_analyze().
        void statusChange(int newStatus);

        ~TLSHandler();
    private:
        int status;
};


#endif // TLSHANDLER_H

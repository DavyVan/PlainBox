#ifndef ESPHANDLER_H
#define ESPHANDLER_H

#include<boost/enable_shared_from_this.hpp>
#include<netinet/in.h>
#include<map>
using namespace std;
struct KeyMaterial_ESP
{
    char encalg[50];
    unsigned int enckeylen;
    unsigned char enckey[100];

    char authalg[50];
    unsigned int authkeylen;
    unsigned char authkey[100];
};
typedef boost::shared_ptr<KeyMaterial_ESP> KeyMaterial_ESP_Ptr;

static map<unsigned int, KeyMaterial_ESP_Ptr> espKeyMap;
typedef map<unsigned int, KeyMaterial_ESP_Ptr>::iterator espKeyMap_it;

class ESPHandler
{
    public:
        ESPHandler();

        ///@brief parse ESP header, then decrypt it.
        ///@param   length      ESP length, including header and trailer and auth code
        ///@param   payload
        ///@param   dest        where to hold plaintext
        ///@return  bool        true if decrypted successfully.
        static bool parseAndDecrypt(unsigned int length, const uint8_t* payload, uint8_t* dest, unsigned int &plaintlen);


        virtual ~ESPHandler();
    private:
        ///@brief   get keys from client, for now, from file, and save it to a map.
        ///         Called by parse().
        ///@param   spi     whose key you want to get
        ///@return  KeyMaterial_ESP_Ptr    return the keys' pointer if success
        static KeyMaterial_ESP_Ptr getKeys(unsigned int spi);

        ///@brief   decrypt payload and return the plaintext. Called by parseAndDecrypt().
        static void decrypt(unsigned int length, const uint8_t* payload, KeyMaterial_ESP_Ptr km, uint8_t* iv, uint8_t* dest);


};

#endif // ESPHANDLER_H

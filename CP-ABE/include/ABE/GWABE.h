#ifndef SECRETSHARING_GWABE_H
#define SECRETSHARING_GWABE_H

#include <vector>
#include <unordered_map>
#include <bitset>
#include <string>
#include <openssl/sha.h>
#include "../pbc/pbc.h"
#include "../PicoSHA2/picosha2.h"

#include "utilities.h"
#include "LSSS.h"

using namespace std;


namespace GWABESPACE
{


    struct MPK
    {
        element_t g;
        element_t gb;
        element_t egga;
    };

    struct MSK
    {
        element_t ga;
    };

    struct KeyTuple
    {
        struct TK
        {
            string attributes;
            element_t tk_1;
            element_t tk_2;
            unordered_map<string, element_s> tk_att;
        };
        struct SK
        {
            element_t r_2;
        };

        TK tk;
        SK sk;
    };

    struct Cipher
    {
        LSSS *policy;
        vector<element_s> lambda;

        element_t c_1;
        string c_2;
        element_t c_3;
        vector<element_s> dot_c;
        vector<element_s> ddot_c;
    };


    struct CT
    {
        element_t ct_1;
        string ct_2;
        element_t ct_3;
    };


    class GWABE
    {
    public:
        MPK mpk;
        MSK msk;

        // constructor and destructor
        GWABE();

        ~GWABE();

        void Setup(pairing_t _pairing);

        void KeyGen(KeyTuple &keytuple, const string _attributes, pairing_t _pairing);

        void Encrypt(Cipher &cipher, string ek, LSSS &lsss, pairing_t _pairing);

        void Transform(CT &ct, KeyTuple::TK &tk, Cipher &cipher, pairing_t _pairing);

        void Decrypt(string &ek, KeyTuple::SK &sk, CT &ct, pairing_t _pairing);

        /*
         * DEBUG functions
         */
        void showKeys();

        void showKeytuple(KeyTuple &ktuple);

        void showCipher(Cipher &cipher);

        void showCT(CT &ct);

    };

}


#endif //SECRETSHARING_GWABE_H

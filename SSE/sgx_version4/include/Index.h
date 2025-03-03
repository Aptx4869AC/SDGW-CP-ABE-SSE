#pragma once

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iomanip>

#include "utilities.h"

using namespace std;

namespace INDEXSPACE {
    struct cipher_number {
        unsigned char *content;
        unsigned char *tag;
        int len;

    };

    struct cipher_keyword {
        unsigned char *content;
        unsigned char *tag;
        int len;

        bool operator==(const cipher_keyword &other) const {
            return (len == other.len && memcmp(content, other.content, len) == 0);
        }

        bool operator<(const cipher_keyword &other) const {
            if (len != other.len)
                return len < other.len;
            else
                return memcmp(content, other.content, len) < 0;
        }
    };


    struct CipherKeywordHasher {
        std::size_t operator()(const cipher_keyword &keyword) const {
            std::size_t seed = 0;
            for (int i = 0; i < keyword.len; ++i) {
                seed ^= keyword.content[i] + 0x9e3779b9 + (seed << 6) + (seed >> 2);
            }
            return seed;
        }
    };

    class Index {

    private:
        /**
         * encrypted inverted index
        */

    public:
        unordered_map<cipher_keyword, vector<cipher_number>, CipherKeywordHasher> cipher_wordMap;
	vector<cipher_keyword> cipherWordList;
        Index();

        ~Index();

        /**
     * given an file_path, convert the word:[num1,num2,...] in the file to an unordered_map<string,vector<string>> mp
    */
        unordered_map<string, vector<string>> readFile(const string &file_path);

        /**
         * given an inverted index, initialzie algorithm outputs the encrypted inverted index; 
         *  e.g., for each pair (keyword, document list)
         *              output a pair (Enc(sk1, keyword), Enc(sk2, document list))
        */
        void initialzie(string file_path);

        /**
         * given an encrypted keyword Enc(sk1, keyword), it outputs Enc(sk2, document list)
        */
        void query(vector<cipher_number> &vec_num, cipher_keyword cipher_word);


    };
}

void INDEXSPACE::Index::initialzie(string file_path) {

    /* get map from file */
    unordered_map<string, vector<string>> wordMap = readFile(file_path);

    unsigned char *sk_1 = (unsigned char *) "D370E2422FD0C2EAF33AD884341BB4F72F7908D04AAE9EDA3B7E6FE307249DA1";
    unsigned char *sk_2 = (unsigned char *) "4DC72209C099B8C9B6DC857C4CA2C658E4E7D8B51EC5DF62770911C860581E61";
    unsigned char* iv = (unsigned char *) "BF40624F935E3256DCB6165CD005BCDC"; 
    unsigned char* additional = (unsigned char *) "The five boxing wizards jump quickly.";
    
    for (const auto &entry: wordMap) {
   	unsigned char tag_word[16];
        	
	string word = entry.first;
        const char *cstr = word.c_str();
	unsigned char* wordPtr = (unsigned char*)cstr;
        unsigned char ciphertext_word[128];

        /* Encrypt the word */
        int ciphertext_word_len = gcm_encrypt(wordPtr, strlen((char *)wordPtr),
                                              additional, strlen((char *)additional),
                                              sk_1,
                                              iv, strlen((char *)iv),
                                              ciphertext_word, tag_word);

        ciphertext_word[ciphertext_word_len]='\0';
        cipher_keyword cipher_word;
        cipher_word.content = new unsigned char[128];
        memcpy(cipher_word.content, ciphertext_word, 128);
        cipher_word.tag = new unsigned char[16];
        memcpy(cipher_word.tag, tag_word, 16);
        cipher_word.len = ciphertext_word_len; 
        cipherWordList.push_back(cipher_word);        
         

        for (string num: entry.second) {
            unsigned char tag_num[16];  
            unsigned char* numbersPtr =  reinterpret_cast<unsigned char *>(const_cast<char *>(num.c_str()));
            unsigned char ciphertext_num[128];

            /* Encrypt every num */
            int ciphertext_num_len = gcm_encrypt(numbersPtr, strlen((char *) numbersPtr),
                                                 additional, strlen((char *) additional),
                                                 sk_2,
                                                 iv, strlen((char *) iv),
                                                 ciphertext_num, tag_num);


            ciphertext_num[ciphertext_num_len]='\0';
            cipher_number cipher_num;
            cipher_num.content = new unsigned char[128];
            memcpy(cipher_num.content, ciphertext_num, 128);
            cipher_num.tag = new unsigned char[16];
            memcpy(cipher_num.tag, tag_num, 16);
            cipher_num.len = ciphertext_num_len;
            cipher_wordMap[cipher_word].push_back(cipher_num);
            
        }

    }


}

void INDEXSPACE::Index::query(vector<cipher_number> &vec_num, cipher_keyword cipher_word) {
    if (cipher_wordMap.count(cipher_word) > 0) {
        /* contains the cipher_word */
        vec_num = cipher_wordMap[cipher_word];
        cout << "success!\n";
    } else {
        /* Does not contain */
        cout << "failed!\n";
        exit(-1);

    }
}


/* get the mapping of keyword and its doc_id*/
unordered_map<string, vector<string>> INDEXSPACE::Index::readFile(const string &file_path) {
    unordered_map<string, vector<string>> wordMap;

    ifstream file(file_path);
    string line;
    string currentWord;
    int i = 0;
    while (getline(file, line)) {
        stringstream ss(line);
        string word;
        ss >> word;
        if (word[word.size() - 1] == ':') {
            // Extracting words
            currentWord = word.substr(1, word.size() - 3);
            //cout<<"currentWord: "<< currentWord<<'\n';
        } else if (!currentWord.empty()) {
            // Extracting numbers
            if (word[0] == ']') {
                currentWord = "";
                continue;
            }
            word.erase(remove_if(word.begin(), word.end(), [](char c) {
                return !isdigit(c);
            }), word.end());
            //cout<<word<<'\n';
            try {
	         wordMap[currentWord].push_back(word);
            }
            catch (const invalid_argument &e) {
                cerr << "Invalid number format: " << word << endl;
            }

        }
    }

    cout << "keyword number:" << wordMap.size() << endl;

    return wordMap;
}

INDEXSPACE::Index::Index() {}

INDEXSPACE::Index::~Index() {}



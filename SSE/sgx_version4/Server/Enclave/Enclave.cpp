#include <stdio.h>      /* vsnprintf */
#include <stdarg.h>

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include "tSgxSSL_api.h"
#include <vector>
#include <cstdio>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <vector>
#include <string.h>

using namespace std;


struct cipher_number {
    unsigned char *content;
    unsigned char *tag;
    int len;

};

struct WordDistance{
    unsigned char* word;
    int distance;
    int loc;
};

int printf(const char *fmt, ...) {
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int) strnlen(buf, BUFSIZ - 1) + 1;
}

int openssl_printf(const char *fmt, int len, ...) {
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_openssl(buf, len);
    return (int) strnlen(buf, BUFSIZ - 1) + 1;
}


unsigned char *sk_0;
unsigned char *sk_1 = (unsigned char *) "D370E2422FD0C2EAF33AD884341BB4F72F7908D04AAE9EDA3B7E6FE307249DA1";
unsigned char *sk_2 = (unsigned char *) "4DC72209C099B8C9B6DC857C4CA2C658E4E7D8B51EC5DF62770911C860581E61";
unsigned char *iv = (unsigned char *) "BF40624F935E3256DCB6165CD005BCDC";
unsigned char *additional = (unsigned char *) "The five boxing wizards jump quickly.";
unsigned char *wordTable[10000];

const unsigned char *publicKeyStr = (unsigned char *) "-----BEGIN PUBLIC KEY-----\n"
                                                      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApuQMsdqlYZuZ5A3ipnih\n"
                                                      "N5AN+SPUgAfhndhioydXTpXvB1/bB55pc6X5HmaeUvF64LePqVPLUfMyeKfsGbwY\n"
                                                      "/T/Z66lg1TANP8oH2JucYraym3lvlmrCdwxwS+Wy/afEUpn/NaCQXW7QrWnDu+nk\n"
                                                      "UbC/hXvxxA8+GyautDbReL7BuH5NzhVO5pxSyYNgOlAGxo3vX0Z/PCl8F0KijD38\n"
                                                      "qtBruF2iSqDh6/GmaCM19TRREVhn2faVumYvlRRrB/zmtwocpgwVmFzvmpzWczd5\n"
                                                      "9DBfYmFwKoIunyyfCSnYAxRMahuffO0jogscoxtIjYfxkbByPnc973+1kc7gkEQ7\n"
                                                      "XQIDAQAB\n-----END PUBLIC KEY-----";

const unsigned char *privateKeyStr = (unsigned char *) "-----BEGIN PRIVATE KEY-----\n"
                                                       "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCm5Ayx2qVhm5nk\n"
                                                       "DeKmeKE3kA35I9SAB+Gd2GKjJ1dOle8HX9sHnmlzpfkeZp5S8Xrgt4+pU8tR8zJ4\n"
                                                       "p+wZvBj9P9nrqWDVMA0/ygfYm5xitrKbeW+WasJ3DHBL5bL9p8RSmf81oJBdbtCt\n"
                                                       "acO76eRRsL+Fe/HEDz4bJq60NtF4vsG4fk3OFU7mnFLJg2A6UAbGje9fRn88KXwX\n"
                                                       "QqKMPfyq0Gu4XaJKoOHr8aZoIzX1NFERWGfZ9pW6Zi+VFGsH/Oa3ChymDBWYXO+a\n"
                                                       "nNZzN3n0MF9iYXAqgi6fLJ8JKdgDFExqG5987SOiCxyjG0iNh/GRsHI+dz3vf7WR\n"
                                                       "zuCQRDtdAgMBAAECggEAXMbwa7siL1YCQi6Z7nOnJC1YJ0WM77Px7/8ILq1DMvPV\n"
                                                       "EuNt7xlYhCsjh4wCvhdyeRRyr+5eXGt3hm3Lqi7QMZFag1EA/OMeqnSU0g0H7jSk\n"
                                                       "rBvhNdyZyPbIQtkqHSszz7u+jcB6IQbmyVC/uGp5PBSnE/zoVVcn7o4dlx/WaWm0\n"
                                                       "g/7oKJTIxjmWLlDTJX96+OzYFRGW2oqCQ8Fv0Qoes4NKVXHCQ1G3PJHclNCTFjQO\n"
                                                       "YCEDp7P1geMuUBvv+eKiDd+qfY/1NrY6WUkwQ/4iuHSlTtVgAKqWXtXkyYlljCXw\n"
                                                       "t3/3mUb0XRIo67r1MRHJIv60PQ34cqNW+eFnIqyoIQKBgQDTtoIISnBUzdlRU3CJ\n"
                                                       "rSmqARtmi+RGIEMGBd1a2jE6b1DFs35abfRhWaZkRvPs6PUyGkvjfc27SJ7Y/SM1\n"
                                                       "eIc44/WxsSlvEmqLDlY69ND167k9d7pNclfPXjtho3wAqe8i691fK4I1w6g1I+5Y\n"
                                                       "EE35v/FKHKqlD/b/AnEL4UD2aQKBgQDJzUMMozVUL0W9Xf5PZkgGBJ/0T+saCyHZ\n"
                                                       "8vySneQXMY5ZZyN0bmCjodYL7cGGCIHlzWgTOgxUs4daR8uLysKHgUOXgOwaUujZ\n"
                                                       "qBjsciZ4aCwMRXW2MX1XhX3xbC81EK0reoOm+ZMGhI/KTVKcCxf1NsiDubSrBo+t\n"
                                                       "36SKEVLG1QKBgDIrK4EfcqMF7Jty9FYLrLXWcVHJkJx1hKxms1+WGNhKDI/syuJO\n"
                                                       "7/wprF5S2fan9YKb7KPJ6fiZatrskW1YVGLM0in7W2AwswKksRZjcSj1ZP4F4yX7\n"
                                                       "FIfVQqkOfpIBsuNJlTm6K67l4HRHQXGo23F1ZI41YNKgh91CDNvN0wERAoGBALih\n"
                                                       "C48sY0Y6Wdv/ewS513tqD84+sCKLvNTi8yJRQrXVqR8ytcV4lwIetu8C/+PZNL9D\n"
                                                       "Rs0QduenuVZoCVpEj+XZ5jVexqTu5gr9OJBbf8b5yBMSGbgvXzYL9EZFbItoTodQ\n"
                                                       "99J01IdKESRNyh7qJ2k6Tgn2hc1Tm3DBBJEteEZhAoGAOa0W/wehmDfRIh1sdWKY\n"
                                                       "jTJmz/ThUfhg19S9tizKGKOtqWJg1Sv1QeIy7kOovHqHdZ/YprkcoyPh9EEn0Vri\n"
                                                       "svLorB+IEZ+toDdvKBQ8lM7r7kJeBEpuPy47vvPS6BOcoz//6pOg0k6dfHBC0kna\n"
                                                       "Dw9GfEGW8R5pSFITYsc3q0Y=\n-----END PRIVATE KEY-----";

// Encrypt a string using a public key
unsigned char *rsaEncrypt(const unsigned char *publicKey, const unsigned char *plaintext, size_t plaintextLength,
                          size_t &encryptedLength) {
    BIO *bio = BIO_new_mem_buf(publicKey, -1); // Create a memory BIO object
    if (!bio) {
        printf("errors");
    }

    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL); // Read the public key from the BIO object
    BIO_free(bio); // Free the BIO object
    if (!pkey) {
        printf("errors");
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL); // Create an EVP_PKEY_CTX object
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0)   // Initialize public key encryption
    {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        printf("errors");
    }

    encryptedLength = EVP_PKEY_size(pkey); // Get the RSA key length
    unsigned char *ciphertext = new unsigned char[encryptedLength]; // Create an array to store the ciphertext

    // Encrypt the plaintext using the RSA public key
    if (EVP_PKEY_encrypt(ctx, ciphertext, &encryptedLength, plaintext, plaintextLength) <= 0)   // If encryption fails
    {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        printf("errors");
    }

    EVP_PKEY_free(pkey); // Free the EVP_PKEY object
    EVP_PKEY_CTX_free(ctx); // Free the EVP_PKEY_CTX object
    return ciphertext;
}

// Decrypt a string using a private key
unsigned char *rsaDecrypt(const unsigned char *privateKey, const unsigned char *ciphertext, size_t ciphertextLength,
                          size_t &decryptedLength) {
    BIO *bio = BIO_new_mem_buf(privateKey, -1); // Create a memory BIO object
    if (!bio) {
        printf("errors");
    }

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL); // Read the private key from the BIO object
    BIO_free(bio); // Free the BIO object
    if (!pkey) {
        printf("errors");
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL); // Create an EVP_PKEY_CTX object
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0)   // Initialize private key decryption
    {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        printf("errors");
    }

    decryptedLength = EVP_PKEY_size(pkey); // Get the RSA key length
    unsigned char *decryptedtext = new unsigned char[decryptedLength]; // Create an array to store the decrypted plaintext

    // Decrypt the ciphertext using the RSA private key
    if (EVP_PKEY_decrypt(ctx, decryptedtext, &decryptedLength, ciphertext, ciphertextLength) <=
        0)   // If decryption fails
    {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        printf("errors");
    }

    EVP_PKEY_free(pkey); // Free the EVP_PKEY object
    EVP_PKEY_CTX_free(ctx); // Free the EVP_PKEY_CTX object
    return decryptedtext;
}

int compare(const WordDistance& wordA, const WordDistance& wordB) {
    return wordA.distance < wordB.distance;
}

int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        printf("errors");

    /* Initialise the encryption operation. */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        printf("errors");

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        printf("errors");

    /* Initialise key and IV */
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        printf("errors");

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        printf("errors");

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        printf("errors");
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        printf("errors");
    ciphertext_len += len;

    /* Get the tag */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        printf("errors");

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        printf("errors");

    /* Initialise the decryption operation. */
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        printf("errors");

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        printf("errors");

    /* Initialise key and IV */
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        printf("errors");

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        printf("errors");

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        printf("errors");
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        printf("errors");

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}

// string -> vector<>
void deserl_vec(std::vector<struct cipher_number> &vec, unsigned char *content_str, size_t content_str_count,
                unsigned char *tag_str, size_t tag_str_count) {
    int num_elements = content_str_count / 128;

    unsigned char *content_pointer = content_str;
    unsigned char *tag_pointer = tag_str;
    for (size_t i = 0; i < num_elements; i++) {
        struct cipher_number cipherNum;

        cipherNum.content = (unsigned char *) malloc(128);
        memcpy(cipherNum.content, content_pointer, 128);
        content_pointer = content_pointer + 128;

        cipherNum.tag = (unsigned char *) malloc(16);
        memcpy(cipherNum.tag, tag_pointer, 16);
        tag_pointer = tag_pointer + 16;

        cipherNum.len = 8;// specially for num

        vec.push_back(cipherNum);

        // openssl_printf((const char *) cipherNum.content, cipherNum.len);
        // openssl_printf((const char *) cipherNum.tag, 16);
    }

    printf("[Enclave] deserl_vec is ok!\n");
}


int calculateEditDistance(const unsigned char *word1, const unsigned char *word2) {
    int m = strlen((const char *) word1);
    int n = strlen((const char *) word2);

    std::vector<std::vector<int>> dp(m + 1, std::vector<int>(n + 1, 0));

    for (int i = 1; i <= m; ++i) {
        dp[i][0] = i;
    }

    for (int j = 1; j <= n; ++j) {
        dp[0][j] = j;
    }

    for (int i = 1; i <= m; ++i) {
        for (int j = 1; j <= n; ++j) {
            if (word1[i - 1] == word2[j - 1]) {
                dp[i][j] = dp[i - 1][j - 1];
            } else {
                dp[i][j] = std::min({dp[i - 1][j - 1], dp[i][j - 1], dp[i - 1][j]}) + 1;
            }
        }
    }

    return dp[m][n];
}


void fetch_table(cipherKeyword table[10000], int tableSize) {
    // printf("[Enclave] OpenSSL Version: %s\n", SSLeay_version(SSLEAY_VERSION));
    printf("[Enclave] executes fetch_table\n");
    printf("[Enclave] sk_1: %s\n", sk_1);
    for (int i = 0; i < tableSize; i++) {

        unsigned char decrypted_keyword[128];
        int decrypted_keyword_len = gcm_decrypt(table[i].content, table[i].len,
                                                additional, strlen((char *) additional),
                                                table[i].tag,
                                                sk_1,
                                                iv, strlen((char *) iv),
                                                decrypted_keyword);

        if (decrypted_keyword_len >= 0) {
            decrypted_keyword[decrypted_keyword_len] = '\0';
            wordTable[i] = new unsigned char(decrypted_keyword_len);
            memcpy(wordTable[i], decrypted_keyword, decrypted_keyword_len);
            wordTable[i][decrypted_keyword_len] = '\0';
        } else {
            printf("[Enclave] Decryption failed\n");
        }
    }
    printf("[Enclave] tableSize: %d\n", tableSize);
    printf("[Enclave] decrypt all the plaintext keyword is ok\n");
}


void step_1(cipherKeyword word, size_t **location, size_t *location_len, size_t **distance_vtr) {

    // openssl_printf((const char *) *cipher_content, *cipher_len);
    printf("[Enclave] executes step 1\n");
    printf("[Enclave] pk_TEE: \n%s\n", publicKeyStr);
    printf("[Enclave] sk_TEE: \n%s\n", privateKeyStr);

    /* RSA decryption*/
    size_t decryptedLength;
    unsigned char *decrypted_combined_str = rsaDecrypt(privateKeyStr, word.content, word.len, decryptedLength);
    decrypted_combined_str[decryptedLength] = '\0';
    printf("[Enclave] (RSA decryption) client combined_str: %s\n", decrypted_combined_str);
    printf("[Enclave] decryptedLength: %ld\n", decryptedLength);

    // get sk_0
    sk_0 = (unsigned char *) malloc(sizeof(unsigned char) * 64);
    memcpy(sk_0, decrypted_combined_str + (decryptedLength - 64), 64);
    sk_0[64] = '\0';
    printf("[Enclave] get client sk_0: %s\n", sk_0);

    // get keyword
    unsigned char *decrypted_keyword = (unsigned char *) malloc(sizeof(unsigned char) * decryptedLength - 64);
    memcpy(decrypted_keyword, decrypted_combined_str, decryptedLength - 64);
    decrypted_keyword[decryptedLength - 64] = '\0';
    printf("[Enclave] get client keyword: %s\n", decrypted_keyword);

    printf("[Enclave] compute LevenshteinDistance\n");
    WordDistance* distances = (WordDistance*)malloc(500 * sizeof(WordDistance));
    int numDistances = 0;
    int flag = 0, threshold = 2;
    printf("[Enclave] threshold: %d\n", threshold);
    int minDistance = INT_MAX;
    vector<int> record_index;
    for (int i = 0; i < 10000; i++) {
        if (wordTable[i] != nullptr) {
            int distance = calculateEditDistance(decrypted_keyword, wordTable[i]);
            if (distance <= threshold) {
                // printf("[Enclave] %s %s %d\n", decrypted_keyword, wordTable[i], distance);
                distances[numDistances].word = wordTable[i];
                distances[numDistances].distance = distance;
                distances[numDistances].loc = i;
                numDistances++;
            }
            if (distance < minDistance) {
                minDistance = distance;
            }
            if (distance == 0) {
                (*location)[0] = i;
                *location_len = 1;
                (*distance_vtr)[0] = 0;
            }
            wordTable[i] = nullptr;
        }
    }
    printf("[Enclave] The count of keywords that match the threshold Levenshtein Distance: %d\n", numDistances);
    
    std::sort(distances, distances+numDistances, compare);
    for (int i = 0; i < numDistances; i++) {
        printf("[Enclave] %s %s %d %d\n", decrypted_keyword, distances[i].word, distances[i].distance, distances[i].loc);
        record_index.push_back(distances[i].loc);
        (*distance_vtr)[i] = distances[i].distance;
    }
    
    
    if (minDistance != 0) {
        for (int i = 0; i < record_index.size(); i++) {
            (*location)[i] = record_index[i];
        }
        *location_len = record_index.size();
        printf("[Enclave] Due to minDistance != 0, so return fuzzy match results\n");
    } else {
        printf("[Enclave] Due to minDistance = 0, so return exact match results\n");
    }

    printf("[Enclave] send location to server\n");
}


void step_3(cipherKeyword response_word,
            unsigned char **response_cipher_vector, size_t *response_cipher_vector_len,
            unsigned char **response_tag_vector, size_t *response_tag_vector_len,
            cipherKeyword *result_word,
            unsigned char **result_cipher_vector, size_t *result_cipher_vector_len,
            unsigned char **result_tag_vector, size_t *result_tag_vector_len) {

    printf("[Enclave] executes step 3\n");
    printf("[Enclave] sk_0: %s\n", sk_0);
    printf("[Enclave] sk_1: %s\n", sk_1);
    printf("[Enclave] sk_2: %s\n", sk_2);

    /* Re-enc keyword */
    unsigned char decrypted_keyword[128];
    int decrypted_keyword_len = gcm_decrypt(response_word.content, response_word.len,
                                            additional, strlen((char *) additional),
                                            response_word.tag,
                                            sk_1,
                                            iv, strlen((char *) iv),
                                            decrypted_keyword);
    if (decrypted_keyword_len >= 0) {
        decrypted_keyword[decrypted_keyword_len] = '\0';
        printf("[Enclave] (queried) server keyword: %s\n", decrypted_keyword);
        /* EncK0(Result keyword) */
        unsigned char *Word = decrypted_keyword;
        unsigned char cipher[128];
        unsigned char tag[16];
        int len = gcm_encrypt(Word, strlen((char *) Word),
                              additional, strlen((char *) additional),
                              sk_0,
                              iv, strlen((char *) iv),
                              cipher, tag);


        cipher[len] = '\0';
        memcpy((*result_word).content, cipher, len);
        memcpy((*result_word).tag, tag, 16);
        (*result_word).len = len;

        printf("[Enclave] Re-encrypt keyword\n");
    } else {
        printf("[Enclave] Decryption failed\n");
    }

    /* Re-enc index */
    std::vector<cipher_number> response_vec_num;
    deserl_vec(response_vec_num, *response_cipher_vector, *response_cipher_vector_len, *response_tag_vector,
               *response_tag_vector_len);
    printf("[Enclave] num_elements: %d\n", response_vec_num.size());


    unsigned char *content = new unsigned char[response_vec_num.size() * 128];
    unsigned char *tag = new unsigned char[response_vec_num.size() * 16];
    unsigned char *content_pointer = content;
    unsigned char *tag_pointer = tag;
    int content_len = 0;
    int tag_len = 0;

    printf("[Enclave] decrypted index: [ ");
    for (auto num: response_vec_num) {
        /* Decrypting Results */
        unsigned char decrypted_index[128];
        int decrypted_index_len = gcm_decrypt(num.content, 8,
                                              additional, strlen((char *) additional),
                                              num.tag,
                                              sk_2,
                                              iv, strlen((char *) iv),
                                              decrypted_index);
        if (decrypted_index_len >= 0) {
            decrypted_index[decrypted_index_len] = '\0';
            printf("%s ", decrypted_index);


            /* EncK0(Results index) */
            unsigned char *Index = decrypted_index;
            unsigned char cipher[128];
            unsigned char tag[16];
            int len = gcm_encrypt(Index, strlen((char *) Index),
                                  additional, strlen((char *) additional),
                                  sk_0,
                                  iv, strlen((char *) iv),
                                  cipher, tag);


            cipher[len] = '\0';
            //serl
            memcpy(content_pointer, cipher, 128);
            content_pointer = content_pointer + 128;
            content_len += 128;

            memcpy(tag_pointer, tag, 16);
            tag_pointer = tag_pointer + 16;
            tag_len += 16;

        } else {
            printf("[Enclave] Decryption failed\n");
        }

    }
    printf("]\n");

    memcpy(*result_cipher_vector, content, content_len);
    memcpy(*result_tag_vector, tag, tag_len);

    *result_tag_vector_len = tag_len;
    *result_cipher_vector_len = content_len;
    printf("\n[Enclave] serl_vec is ok!\n");
    printf("[Enclave] send Encrypted Result to server\n");

}






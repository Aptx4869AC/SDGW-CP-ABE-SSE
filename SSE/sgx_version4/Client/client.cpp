#include "../include/Index.h"
#include <unordered_map>

#include <chrono>
#include <omp.h>

using namespace INDEXSPACE;

#define PORT 8080
#define EVP_MAX_SALT_LEN 8 // Manually define the length of salt

char * generateAESParams()
{
    unsigned char *key = new unsigned char[EVP_MAX_KEY_LENGTH];
    unsigned char *salt = new unsigned char[EVP_MAX_SALT_LEN];
    unsigned char *iv = new unsigned char[EVP_MAX_IV_LENGTH];

    // Generate salt
    RAND_bytes(salt, EVP_MAX_SALT_LEN);

    // Set password and iteration count
    const char *password = "secret";
    const int iteration = 1000;

    // Use PBKDF2 to generate the key
    PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), salt, EVP_MAX_SALT_LEN, iteration, EVP_CIPHER_key_length(EVP_aes_256_cbc()), key);

    // Generate IV
    RAND_bytes(iv, EVP_CIPHER_iv_length(EVP_aes_256_cbc()));

    // Convert key to hexadecimal string
    stringstream ss;
    for (int i = 0; i < EVP_CIPHER_key_length(EVP_aes_256_cbc()); ++i)
        ss << hex << setw(2) << setfill('0') << (int)key[i];
    char * key_str = new char[ss.str().length() + 1];
    strcpy(key_str, ss.str().c_str());
    return key_str;

}

int main(int argc, char *argv[]) {
    const char *openssl_version = OpenSSL_version(OPENSSL_VERSION);
    // cout << "OpenSSL Version: " << openssl_version << std::endl;

    /* Client create ssecret keys - 256 bit key */
    unsigned char *sk_0 = (unsigned char *) generateAESParams();
    unsigned char *iv = (unsigned char *) "BF40624F935E3256DCB6165CD005BCDC";    /* A 128 bit IV */
    unsigned char *additional = (unsigned char *) "The five boxing wizards jump quickly.";    /* Additional data */
    unsigned char *publicKeyStr = (unsigned char *) "-----BEGIN PUBLIC KEY-----\n"
                                                    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApuQMsdqlYZuZ5A3ipnih\n"
                                                    "N5AN+SPUgAfhndhioydXTpXvB1/bB55pc6X5HmaeUvF64LePqVPLUfMyeKfsGbwY\n"
                                                    "/T/Z66lg1TANP8oH2JucYraym3lvlmrCdwxwS+Wy/afEUpn/NaCQXW7QrWnDu+nk\n"
                                                    "UbC/hXvxxA8+GyautDbReL7BuH5NzhVO5pxSyYNgOlAGxo3vX0Z/PCl8F0KijD38\n"
                                                    "qtBruF2iSqDh6/GmaCM19TRREVhn2faVumYvlRRrB/zmtwocpgwVmFzvmpzWczd5\n"
                                                    "9DBfYmFwKoIunyyfCSnYAxRMahuffO0jogscoxtIjYfxkbByPnc973+1kc7gkEQ7\n"
                                                    "XQIDAQAB\n"
                                                    "-----END PUBLIC KEY-----";

    printf("pk_TEE: \n%s\n\n", publicKeyStr);
    printf("sk_0: %s\n", sk_0);

    /* Encrypt the plain_word */
    string word = argv[1];
    unsigned char *plain_word = (unsigned char *) word.c_str();
    size_t plaintextLength = strlen((const char *) plain_word);

    size_t combinedLength = strlen((const char *) plain_word) + strlen((const char *) sk_0);
    unsigned char *combined_str = (unsigned char *) malloc(combinedLength);
    memcpy(combined_str, plain_word, strlen((const char *) plain_word));
    memcpy(combined_str + strlen((const char *) plain_word), sk_0, strlen((const char *) sk_0));
    printf("combined_str: %s\n", combined_str);
    printf("combinedLength: %ld\n", combinedLength);


    size_t encryptedLength;
    unsigned char *ciphertext = rsaEncrypt(publicKeyStr, combined_str, combinedLength, encryptedLength);

    printf("encryptedLength: %ld\n", encryptedLength);

    cipher_keyword cipher_word;
    cipher_word.content = new unsigned char[encryptedLength];
    memcpy(cipher_word.content, ciphertext, encryptedLength);
    cipher_word.len = encryptedLength;

    printf("Client request keyword: %s\n", plain_word);
    // BIO_dump_fp(stdout, (const char *) cipher_word.content, cipher_word.len);

    int server_socket;
    struct sockaddr_in serverAddr;

    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

    if (connect(server_socket, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) == 0)
        std::cout << "Connected to server" << std::endl;
    else {
        std::cout << "Failed to connect to server" << std::endl;
        return -1;
    }

    int n = 1; //query times
    for (int epoch = 0; epoch < n; epoch++) {
        write(server_socket, &(cipher_word.len), sizeof(int) * 1);
        write(server_socket, cipher_word.content, sizeof(unsigned char) * cipher_word.len);

        printf("\nServer return results\n");


        // The number of keywords to be processed
        size_t byte_stream_size_keyword = 0;
        read(server_socket, &byte_stream_size_keyword, sizeof(size_t));
        printf("The count of keywords that need to receive: %ld\n", byte_stream_size_keyword);
        for (size_t i = 0; i < byte_stream_size_keyword; i++) {
            /* accept result EncK0(keyword) */
            int distance;
            struct cipher_keyword received_cipher_word;
            received_cipher_word.content = (unsigned char *) malloc(sizeof(unsigned char) * 128);
            received_cipher_word.tag = (unsigned char *) malloc(sizeof(unsigned char) * 16);
            
            read(server_socket, &(distance), sizeof(int));
            read(server_socket, &(received_cipher_word.len), sizeof(int));
            read(server_socket, received_cipher_word.content, sizeof(unsigned char) * 128);
            read(server_socket, received_cipher_word.tag, sizeof(unsigned char) * 16);

            cout << "Client accept result EncK0(keyword)\n";
            /* decrypted */
            unsigned char decrypted_word[128];
            int decrypted_word_len = gcm_decrypt(received_cipher_word.content, received_cipher_word.len,
                                                 additional, strlen((char *) additional),
                                                 received_cipher_word.tag,
                                                 sk_0,
                                                 iv, strlen((char *) iv),
                                                 decrypted_word);
            if (decrypted_word_len >= 0) {
                decrypted_word[decrypted_word_len] = '\0';
            } else {
                printf("Decryption num failed\n");
                exit(-1);
            }


            // The number of index to be processed
            size_t byte_stream_size_index = 0;
            read(server_socket, &byte_stream_size_index, sizeof(byte_stream_size_index));

            /* accept result EncK0(index) */
            vector <cipher_number> vec_num;
            for (size_t i = 0; i < byte_stream_size_index / sizeof(cipher_number); i++) {
                cipher_number num;
                read(server_socket, &num.len, sizeof(int) * 1);
                num.content = new unsigned char[128];
                num.tag = new unsigned char[16];
                read(server_socket, num.content, 128);
                read(server_socket, num.tag, 16);
                vec_num.push_back(num);
            }
            cout << "Client accept result EncK0(index)\n\n";

            if (strcmp(reinterpret_cast<const char *>(decrypted_word), reinterpret_cast<const char *>(plain_word)) !=
                0) {
                cout << "Enclave has internally corrected keyword\n";
                cout << "request: " << plain_word << '\n';
                cout << "return(Has been decrypted by Client): " << decrypted_word << '\n';
            }


            /* decrypted */
            printf("distance:%d, %s: [ ", distance, decrypted_word);
            for (auto num: vec_num) {

                unsigned char decrypted_num[128];
                int decrypted_num_len = gcm_decrypt(num.content, num.len,
                                                    additional, strlen((char *) additional),
                                                    num.tag,
                                                    sk_0,
                                                    iv, strlen((char *) iv),
                                                    decrypted_num);
                if (decrypted_num_len >= 0) {
                    decrypted_num[decrypted_num_len] = '\0';
                    cout << decrypted_num << " ";
                } else {
                    printf("Decryption num failed\n");
                    exit(-1);
                }

            }
            cout << "] \n\n";

            cout << "-------------------------------------------------------\n\n";
            sleep(1);
        }
    }

    close(server_socket);


    return 0;
}


#include "../include/Index.h"
#include <unordered_map>

#include <chrono>
#include <omp.h>

using namespace INDEXSPACE;

#define PORT 8080

int main(int argc, char *argv[])
{
    const char *openssl_version = OpenSSL_version(OPENSSL_VERSION);
    // cout << "OpenSSL Version: " << openssl_version << std::endl;

    /* Client create ssecret keys - 256 bit key */
    // ek = 011011001111001101011111110100101001110111011010000011110100101101110010100110010111001110
    // 11100111100001011110100101111110110100010100000011100001101011001101001001010010001101110110111001111010
    // 10001001111100011011000101011000001010110011100011101001100010
    unsigned char *sk_3 = (unsigned char *) "6CF35FD29DDA0F4B729973B9E17A5FB450386B34948DDB9EA27C6C560ACE3A62";
    unsigned char *iv = (unsigned char *) "BF40624F935E3256DCB6165CD005BCDC";    /* A 128 bit IV */
    unsigned char *additional = (unsigned char *) "The five boxing wizards jump quickly.";
    printf("sk_3: %s\n", sk_3);

    /* Encrypt the plain_word */
    string word = argv[1];
    const char *cstr = word.c_str();
    unsigned char tag[16];
    unsigned char *plain_word = (unsigned char *) cstr;
    unsigned char cipher[128];
    // 陷门生成
    auto begin = std::chrono::high_resolution_clock::now();
    int cipher_len = gcm_encrypt(plain_word, strlen((char *) plain_word),
                                 nullptr, 0,
                                 sk_3,
                                 iv, strlen((char *) iv),
                                 cipher, tag);

    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    printf("\ntime of generate the trapdoor (ms):\t %.3f\n\n", elapsed.count() * 1e-6);


    cipher[cipher_len] = '\0';
    cipher_keyword cipher_word;
    cipher_word.content = new unsigned char[128];
    memcpy(cipher_word.content, cipher, 128);
    cipher_word.tag = new unsigned char[16];
    memcpy(cipher_word.tag, tag, 16);
    cipher_word.len = cipher_len;


    printf("Client request keyword: %s\n", plain_word);
    BIO_dump_fp(stdout, (const char *) cipher_word.content, cipher_word.len);
    BIO_dump_fp(stdout, (const char *) cipher_word.tag, 16);

    int server_socket;
    struct sockaddr_in serverAddr;

    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

    if (connect(server_socket, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) == 0)
        std::cout << "Connected to server" << std::endl;
    else
    {
        std::cout << "Failed to connect to server" << std::endl;
        return -1;
    }

    int n = 1;
    for (int epoch = 0; epoch < n; epoch++)
    {
        write(server_socket, &(cipher_word.len), sizeof(int) * 1);
        write(server_socket, cipher_word.content, sizeof(unsigned char) * 128);
        write(server_socket, cipher_word.tag, sizeof(unsigned char) * 16);

        printf("\nServer return results\n");

        // 待接收关键词数量
        size_t byte_stream_size_keyword = 0;
        read(server_socket, &byte_stream_size_keyword, sizeof(size_t));
        printf("The count of keywords that need to receive: %ld\n", byte_stream_size_keyword);
        for (size_t i = 0; i < byte_stream_size_keyword; i++)
        {
            /* accept result EncK0(keyword) */
            int distance;
            struct cipher_keyword received_cipher_word;
            received_cipher_word.content = (unsigned char *) malloc(sizeof(unsigned char) * 128);
            received_cipher_word.tag = (unsigned char *) malloc(sizeof(unsigned char) * 16);

            read(server_socket, &(distance), sizeof(int));
            read(server_socket, &(received_cipher_word.len), sizeof(int));
            read(server_socket, received_cipher_word.content, sizeof(unsigned char) * 128);
            read(server_socket, received_cipher_word.tag, sizeof(unsigned char) * 16);

            cout << "[Client] accept result EncK3(keyword)\n";
            /* decrypted */
            unsigned char decrypted_word[128];
            int decrypted_word_len = gcm_decrypt(received_cipher_word.content, received_cipher_word.len,
                                                 nullptr, 0,
                                                 received_cipher_word.tag,
                                                 sk_3,
                                                 iv, strlen((char *) iv),
                                                 decrypted_word);
            if (decrypted_word_len >= 0)
            {
                decrypted_word[decrypted_word_len] = '\0';
            } else
            {
                printf("Decryption num failed\n");
                exit(-1);
            }


            // The number of index to be processed
            size_t byte_stream_size_index = 0;
            read(server_socket, &byte_stream_size_index, sizeof(byte_stream_size_index));

            /* accept result EncK0(index) */
            vector <cipher_number> vec_num;
            for (size_t i = 0; i < byte_stream_size_index / sizeof(cipher_number); i++)
            {
                cipher_number num;
                read(server_socket, &num.len, sizeof(int) * 1);
                num.content = new unsigned char[128];
                num.tag = new unsigned char[16];
                read(server_socket, num.content, 128);
                read(server_socket, num.tag, 16);
                vec_num.push_back(num);
            }
            cout << "[Client] accept result EncK3(index)\n\n";

            if (strcmp(reinterpret_cast<const char *>(decrypted_word), reinterpret_cast<const char *>(plain_word)) !=
                0)
            {
                cout << "Enclave has internally corrected keyword\n";
                cout << "request: " << plain_word << '\n';
                cout << "return(Has been decrypted by Client): " << decrypted_word << '\n';
            }


            /* decrypted */
            printf("distance:%d, %s: [ ", distance, decrypted_word);
            for (auto num: vec_num)
            {

                unsigned char decrypted_num[128];
                int decrypted_num_len = gcm_decrypt(num.content, num.len,
                                                    nullptr, 0,
                                                    num.tag,
                                                    sk_3,
                                                    iv, strlen((char *) iv),
                                                    decrypted_num);
                if (decrypted_num_len >= 0)
                {
                    decrypted_num[decrypted_num_len] = '\0';
                    cout << decrypted_num << " ";
                } else
                {
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


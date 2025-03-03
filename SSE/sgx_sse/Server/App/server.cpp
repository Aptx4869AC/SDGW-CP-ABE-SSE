#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#include <libgen.h>
#include <stdlib.h>
#include <pthread.h>
#include <cstdio>>
#include <chrono>
#include <thread>
#include <omp.h>
#include <iomanip>

#include <sgx_urts.h>
#include "server.h"
#include "Enclave_u.h"
#include "../../include/Index.h"

#define PORT 8080
#define MAX_PATH FILENAME_MAX
using namespace INDEXSPACE;
using namespace std;

unsigned char *sk_1 = (unsigned char *) "D370E2422FD0C2EAF33AD884341BB4F72F7908D04AAE9EDA3B7E6FE307249DA1";
unsigned char *sk_2 = (unsigned char *) "4DC72209C099B8C9B6DC857C4CA2C658E4E7D8B51EC5DF62770911C860581E61";
unsigned char *iv = (unsigned char *) "BF40624F935E3256DCB6165CD005BCDC";
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t
{
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] =
        {
                {
                        SGX_ERROR_UNEXPECTED, "Unexpected error occurred.", NULL
                }, {
                SGX_ERROR_INVALID_PARAMETER, "Invalid parameter.", NULL
        }, {
                SGX_ERROR_OUT_OF_MEMORY, "Out of memory.", NULL
        }, {
                SGX_ERROR_ENCLAVE_LOST, "Power transition occurred.", "Please refer to the sample \"PowerTransition\" for details."
        }, {
                SGX_ERROR_INVALID_ENCLAVE, "Invalid enclave image.", NULL
        }, {
                SGX_ERROR_INVALID_ENCLAVE_ID, "Invalid enclave identification.", NULL
        }, {
                SGX_ERROR_INVALID_SIGNATURE, "Invalid enclave signature.", NULL
        }, {
                SGX_ERROR_OUT_OF_EPC, "Out of EPC memory.", NULL
        }, {
                SGX_ERROR_NO_DEVICE, "Invalid Intel® Software Guard Extensions device.", "Please make sure Intel® Software Guard Extensions module is enabled in the BIOS, and install Intel® Software Guard Extensions driver afterwards."
        }, {
                SGX_ERROR_MEMORY_MAP_CONFLICT, "Memory map conflicted.", NULL
        }, {
                SGX_ERROR_INVALID_METADATA, "Invalid enclave metadata.", NULL
        }, {
                SGX_ERROR_DEVICE_BUSY, "Intel® Software Guard Extensions device was busy.", NULL
        }, {
                SGX_ERROR_INVALID_VERSION, "Enclave version was invalid.", NULL
        }, {
                SGX_ERROR_INVALID_ATTRIBUTE, "Enclave was not authorized.", NULL
        }, {
                SGX_ERROR_ENCLAVE_FILE_ACCESS, "Can't open enclave file.", NULL
        },};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++)
    {
        if (ret == sgx_errlist[idx].err)
        {
            if (NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error: Unexpected error occurred [0x%x].\n", ret);
}

/* Initialize the enclave:
 *   Step 1: retrive the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    /* Step 1: retrive the launch token saved by last transaction */

    /* try to get the token saved in $HOME */
    char cwd[1024];
    const char *home_dir = getcwd(cwd, sizeof(cwd));
    if (home_dir != NULL &&
        (strlen(home_dir) + strlen("/") + sizeof(TOKEN_FILENAME) + 1) <= MAX_PATH)
    {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME) + 1);
    } else
    {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL)
    {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }
    printf("token_path: %s\n", token_path);
    if (fp != NULL)
    {
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t))
        {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
        }
    }

    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);

    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);

        return -1;
    }

    /* Step 3: save the launch token if it is updated */

    if (updated == FALSE || fp == NULL)
    {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);

    return 0;
}


/* OCall functions */
void ocall_print_string(const char *str)
{
    printf("%s", str);
}

void ocall_print_openssl(const char *str, int len)
{
    BIO_dump_fp(stdout, str, len);
}


/* Other functions */
int compare(const INDEXSPACE::cipher_keyword &server_word, const INDEXSPACE::cipher_keyword &client_word)
{

    cout << "[Server] Matches the ciphertext keyword\n";
    int flag1 = 0, flag2 = 0;
    if (server_word.len == client_word.len)
    {
        if (memcmp(server_word.content, client_word.content, server_word.len) == 0)
        {
            cout << "[Server] The two content areas are equal\n";
            flag1 = 1;
        } else
        {
            cout << "[Server] The two content areas are not equal\n";
        }
    } else cout << "[Server] content_len are not equal\n";

    if (memcmp(server_word.tag, client_word.tag, 16) == 0)
    {
        cout << "[Server] The two tag areas are equal\n";
        flag2 = 1;
    } else
    {
        cout << "[Server] The two tag areas are not equal\n";
    }

    if (flag1 && flag2) return 1;
    else return 0;
}


// vector<> -> string
void serl_vec(unsigned char **content_str, size_t *content_str_count, unsigned char **tag_str, size_t *tag_str_count,
              std::vector<struct cipher_number> &vec)
{
    unsigned char *content_pointer = *content_str;
    unsigned char *tag_pointer = *tag_str;

    for (size_t i = 0; i < vec.size(); i++)
    {
        memcpy(content_pointer, vec[i].content, 128);
        content_pointer = content_pointer + 128;

        memcpy(tag_pointer, vec[i].tag, 16);
        tag_pointer = tag_pointer + 16;

    }

    std::cout << "[Server] serl_vec is ok!\n";
}


// string -> vector<>
void deserl_vec(std::vector<struct cipher_number> &vec, unsigned char *content_str, size_t content_str_count,
                unsigned char *tag_str, size_t tag_str_count)
{
    int num_elements = content_str_count / 128;
    cout << "[Server] num_elements: " << num_elements << '\n';

    unsigned char *content_pointer = content_str;
    unsigned char *tag_pointer = tag_str;
    for (size_t i = 0; i < num_elements; i++)
    {
        struct cipher_number cipherNum;
        cipherNum.content = (unsigned char *) malloc(128);
        memcpy(cipherNum.content, content_pointer, 128);
        content_pointer = content_pointer + 128;

        cipherNum.tag = (unsigned char *) malloc(16);
        memcpy(cipherNum.tag, tag_pointer, 16);
        tag_pointer = tag_pointer + 16;

        cipherNum.len = 8;

        vec.push_back(cipherNum);
    }

    cout << "[Server] deserl_vec is ok!\n";


}


void compare_serl_deserl(std::vector<struct cipher_number> &origin_vec, std::vector<struct cipher_number> &deserl_vec)
{
    for (int i = 0; i < origin_vec.size(); i++)
    {
        if (origin_vec[i].len == deserl_vec[i].len)
        {
            if (memcmp(origin_vec[i].content, deserl_vec[i].content, origin_vec[i].len) == 0)
            {
                //cout << i<<" The two content areas are equal\n";
            } else
            {
                cout << i << "[Server] The two content areas are not equal\n";
                return;
            }
        } else cout << i << "[Server] content_len are not equal\n";

        if (memcmp(origin_vec[i].tag, deserl_vec[i].tag, 16) == 0)
        {
            // cout << i<<" The two tag areas are equal\n";
        } else
        {
            cout << i << "[Server] The two tag areas are not equal\n";
            return;
        }

    }
}


/* Application entry */
int main(int argc, char **argv)
{
    (void) (argc);
    (void) (argv);

    // printf("OpenSSL Version: %s\n", SSLeay_version(SSLEAY_VERSION));

    /* Initialize the enclave */
    if (initialize_enclave() < 0)
        return 1;

    Index index;
    printf("sk_1: %s\n", sk_1);
    printf("sk_2: %s\n", sk_2);


    string file = (argc > 1) ? argv[1] : "invIndex_data.txt";
    file = "Enron/" + file;
    cout << "input file name is: " << file << endl;

    /* initialize the Inverted_Index mapping */
    index.initialzie(file);
    printf("initialzie is ok!\n");

    int server_socket, client_socket;
    struct sockaddr_in serverAddr;
    struct sockaddr_storage serverStorage;
    socklen_t addr_size;

    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

    bind(server_socket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));

    if (listen(server_socket, 5) == 0)
        std::cout << "Listening..." << std::endl;
    else
        std::cout << "Error in listening" << std::endl;

    addr_size = sizeof serverStorage;

    while (true)
    {
        client_socket = accept(server_socket, (struct sockaddr *) &serverStorage, &addr_size);

        char clientAddress[INET_ADDRSTRLEN];
        if (serverStorage.ss_family == AF_INET)
        {
            struct sockaddr_in *s = (struct sockaddr_in *) &serverStorage;
            inet_ntop(AF_INET, &s->sin_addr, clientAddress, INET_ADDRSTRLEN);
        } else if (serverStorage.ss_family == AF_INET6)
        {
            struct sockaddr_in6 *s = (struct sockaddr_in6 *) &serverStorage;
            inet_ntop(AF_INET6, &s->sin6_addr, clientAddress, INET_ADDRSTRLEN);
        } else
        {
            cerr << "Unknown address family" << std::endl;
            return -1;
        }

        cout << "Received request from client at " << clientAddress << '\n';

        int n = 1; //query times
        auto time1 = 0.0;
        auto time2 = 0.0;
        auto time3 = 0.0;
        for (int epoch = 0; epoch < n; epoch++)
        {
            
            printf("\n[Server] receives EncK0(W)\n");
            cipherKeyword word;
            word.content = (unsigned char *) malloc(sizeof(unsigned char) * 128);
            word.tag = (unsigned char *) malloc(sizeof(unsigned char) * 16);
            read(client_socket, &(word.len), sizeof(int) * 1);
            read(client_socket, word.content, sizeof(unsigned char) * 128);
            read(client_socket, word.tag, sizeof(unsigned char) * 16);


            size_t *location = (size_t *) malloc(sizeof(size_t) * 200);
            size_t *distance_vtr = (size_t *) malloc(sizeof(size_t) * 200);
            size_t location_len;
            cipherKeyword *abc = new cipherKeyword[index.cipherWordList.size()];
            vector <cipher_keyword> table;
            int loc = 0;
            for (auto trapdoor: index.cipherWordList)
            {
                table.push_back(trapdoor);

                abc[loc].content = (unsigned char *) malloc(sizeof(unsigned char) * 128);
                abc[loc].tag = (unsigned char *) malloc(sizeof(unsigned char) * 16);

                memcpy(abc[loc].content, trapdoor.content, trapdoor.len);
                memcpy(abc[loc].tag, trapdoor.tag, 16);
                abc[loc].len = trapdoor.len;
                loc++;
            }

            // SGX Ecall
            auto begin = std::chrono::high_resolution_clock::now();
            printf("[Server] send EncK1(table) to TEE\n");
            fetch_table(global_eid, abc, index.cipherWordList.size());
            printf("[Server] send EncK3(W) to TEE\n");
            step_1(global_eid, word, &location, &location_len, &distance_vtr);

            auto end = std::chrono::high_resolution_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
            printf("\ntime of match the trapdoor (ms):\t %.3f\n\n", elapsed.count() * 1e-6);
            time1 += elapsed.count() * 1e-6;

            // Tell the Client to process multiple requests
            write(client_socket, &location_len, sizeof(size_t));
            for (int i = 0; i < location_len; i++)
            {
                int loc = location[i];
                struct cipher_keyword query_cipher_word;
                query_cipher_word.content = (unsigned char *) malloc(sizeof(unsigned char) * 128);
                query_cipher_word.tag = (unsigned char *) malloc(sizeof(unsigned char) * 16);
                query_cipher_word.len = table[loc].len;
                memcpy(query_cipher_word.content, table[loc].content, table[loc].len);
                memcpy(query_cipher_word.tag, table[loc].tag, 16);

                printf("[Server] executes step 2\n");
                begin = std::chrono::high_resolution_clock::now();
                auto it = index.cipher_wordMap.find(query_cipher_word);

                if (it != index.cipher_wordMap.end())
                {
                    if (compare(it->first, query_cipher_word))
                    {
                        end = std::chrono::high_resolution_clock::now();
                        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
                        printf("\ntime of queryting (ms):\t %.3f\n\n", elapsed.count() * 1e-6);
                        time2 += elapsed.count() * 1e-6;

                        cout << "[Server] Successful search!\n";

                        cipherKeyword response_word;
                        response_word.content = (unsigned char *) malloc(sizeof(unsigned char) * 128);
                        response_word.tag = (unsigned char *) malloc(sizeof(unsigned char) * 16);

                        memcpy(response_word.content, it->first.content, it->first.len);
                        memcpy(response_word.tag, it->first.tag, 16);
                        response_word.len = it->first.len;

                        cipherKeyword result_word;
                        result_word.content = (unsigned char *) malloc(sizeof(unsigned char) * 128);
                        result_word.tag = (unsigned char *) malloc(sizeof(unsigned char) * 16);
                        result_word.len = 0;


                        int indexMapSize = index.cipher_wordMap[query_cipher_word].size();
                        cout << "[Server] Number of indexes: " << indexMapSize << '\n';
                        vector <cipher_number> vec_num = index.cipher_wordMap[query_cipher_word];

                        size_t response_cipher_vector_len = 128 * vec_num.size();
                        unsigned char *response_cipher_vector = (unsigned char *) malloc(response_cipher_vector_len);
                        size_t response_tag_vector_len = 16 * vec_num.size();
                        unsigned char *response_tag_vector = (unsigned char *) malloc(response_tag_vector_len);

                        serl_vec(&response_cipher_vector, &response_cipher_vector_len, &response_tag_vector,
                                 &response_tag_vector_len, vec_num);
                        response_cipher_vector[response_cipher_vector_len] = '\0';
                        response_tag_vector[response_tag_vector_len] = '\0';


                        vector <cipher_number> test_vec_num;
                        unsigned char *result_cipher_vector = (unsigned char *) malloc(
                                sizeof(unsigned char) * response_cipher_vector_len);
                        unsigned char *result_tag_vector = (unsigned char *) malloc(
                                sizeof(unsigned char) * response_tag_vector_len);
                        size_t result_cipher_vector_len;
                        size_t result_tag_vector_len;


                        printf("[Server] send query_result to enclave\n");
                        // SGX Ecall
                        begin = std::chrono::high_resolution_clock::now();
                        step_3(global_eid, response_word, &response_cipher_vector, &response_cipher_vector_len,
                               &response_tag_vector,
                               &response_tag_vector_len, &result_word, &result_cipher_vector, &result_cipher_vector_len,
                               &result_tag_vector, &result_tag_vector_len);


                        end = std::chrono::high_resolution_clock::now();
                        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
                        printf("\ntime of RE-ecrypting result (ms):\t %.3f\n\n", elapsed.count() * 1e-6);
                        time3 += elapsed.count() * 1e-6;

                        vector <cipher_number> result_vec_num;
                        deserl_vec(result_vec_num, result_cipher_vector, result_cipher_vector_len, result_tag_vector,
                                   result_tag_vector_len);

                        /* send result EncK3(keyword) */
                        write(client_socket, &(distance_vtr[i]), sizeof(int));
                        write(client_socket, &(result_word.len), sizeof(int));
                        write(client_socket, result_word.content, sizeof(unsigned char) * 128);
                        write(client_socket, result_word.tag, sizeof(unsigned char) * 16);


                        /* send result EncK3(index) */
                        size_t byte_stream_size = indexMapSize * sizeof(cipher_number);
                        write(client_socket, &byte_stream_size, sizeof(byte_stream_size));

                        for (auto &num: result_vec_num)
                        {
                            write(client_socket, &(num.len), sizeof(int) * 1);
                            write(client_socket, num.content, sizeof(unsigned char) * 128);
                            write(client_socket, num.tag, sizeof(unsigned char) * 16);

                        }

                        cout << "[Server] Return results!\n";
                    }
                } else
                {
                    end = std::chrono::high_resolution_clock::now();
                    elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
                    printf("\ntime of queryting (ms):\t %.3f\n\n", elapsed.count() * 1e-6);


                    /* Does not contain */
                    cout << "[Server] Failed Search!\n";
                    cout << "program forcefully terminated\n";
                    exit(-1);
                }
                cout << "-------------------------------------------------------\n\n";
                sleep(1);
            }

        }
        cout << "time of match the trapdoor: " << fixed << setprecision(4) << time1 / n << " ms\n";
        cout << "time of queryting: " << fixed << setprecision(4) << time2 / n << " ms\n";
        cout << "time of RE-ecrypting result: " << fixed << setprecision(4) << time3 / n << " ms\n";

        close(client_socket);
    }
    close(server_socket);

    // destroy Encalve
    sgx_destroy_enclave(global_eid);


    return 0;
}


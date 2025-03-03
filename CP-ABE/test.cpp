#include <iostream>
#include <omp.h>
#include <time.h>
#include <random>
#include "include/ABE/GWABE.h"
#include "include/pbc/pbc_test.h"
#include "include/PicoSHA2/picosha2.h"

using namespace std;
using namespace GWABESPACE;


/**
 * 生成随机的01二进制字符串
 * @param length
 * @return
 */
string generateRandomBinaryString(size_t length)
{
    // 创建随机数引擎
    random_device rd;  // 获取随机数种子
    mt19937 gen(rd());  // 使用梅森旋转算法生成随机数
    uniform_int_distribution<> dis(0, 1); // 定义均匀分布，生成 0 或 1

    string randomString;
    for (size_t i = 0; i < length; ++i)
    {
        randomString += to_string(dis(gen)); // 生成 0 或 1，并添加到字符串
    }

    return randomString;
}

int main(int argc, char *argv[])
{
    int epoch = 20;
    double start_time, end_time;
    double average_time_Setup = 0, average_time_Encrypt = 0, average_time_Keygen = 0, average_time_Transform = 0, average_time_Decrypt = 0;

    for (int i = 0; i < epoch; i++)
    {

        pbc_param_t param;
        pbc_param_init_a_gen(param, 512, 1024);
        pairing_t pairing;
        pairing_init_pbc_param(pairing, param);

        /* Setup 初始化 */
        GWABE gwabe;
        start_time = omp_get_wtime();
        gwabe.Setup(pairing);
        end_time = omp_get_wtime();
        average_time_Setup += (end_time - start_time) * 1000;

//        gwabe.showKeys();
        printf("-------------------------------------------------------------------------\n");


        /* KeyGen */
//        string attribute_str = "(A,B,C,D,F)";
//        string attribute_str = "(A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,10)";
//        string attribute_str = "(A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20,20)";
//        string attribute_str = "(A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20,A21,A22,A23,A24,A25,A26,A27,A28,A29,A30,30)";
//        string attribute_str = "(A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20,A21,A22,A23,A24,A25,A26,A27,A28,A29,A30,A31,A32,A33,A34,A35,A36,A37,A38,A39,A40,40)";
        string attribute_str = "(A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20,A21,A22,A23,A24,A25,A26,A27,A28,A29,A30,A31,A32,A33,A34,A35,A36,A37,A38,A39,A40,A41,A42,A43,A44,A45,A46,A47,A48,A49,A50,50)";
        KeyTuple keytuple;

        start_time = omp_get_wtime();
        gwabe.KeyGen(keytuple, attribute_str, pairing);
        end_time = omp_get_wtime();
        average_time_Keygen += (end_time - start_time) * 1000;

//        gwabe.showKeytuple(keytuple);
        printf("-------------------------------------------------------------------------\n");


        /* Encrypt */
        // 生成LSSS矩阵
//        string access_policy = "(A1,A2,A3,A4,A5,A6,A7,A8,A9,A10)";
//        string access_policy = "(A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20)";
//        string access_policy = "(A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20,A21,A22,A23,A24,A25,A26,A27,A28,A29,A30)";
//        string access_policy = "(A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20,A21,A22,A23,A24,A25,A26,A27,A28,A29,A30,A31,A32,A33,A34,A35,A36,A37,A38,A39,A40)";
        string access_policy = "(A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20,A21,A22,A23,A24,A25,A26,A27,A28,A29,A30,A31,A32,A33,A34,A35,A36,A37,A38,A39,A40,A41,A42,A43,A44,A45,A46,A47,A48,A49,A50)";

        cout << "access_policy = " << access_policy << '\n';
        LSSS lsss(access_policy);

        // 生成消息ek
        string ek = generateRandomBinaryString(256); // 随机生成k=256长度的01二进制字符串
        cout << ek.size() << ", ek = " << ek << '\n';

        Cipher cipher;
        start_time = omp_get_wtime();
        gwabe.Encrypt(cipher, ek, lsss, pairing);
        end_time = omp_get_wtime();
        average_time_Encrypt += (end_time - start_time) * 1000;

//        gwabe.showCipher(cipher);
        printf("-------------------------------------------------------------------------\n");

        //Transform
        CT ct;
        start_time = omp_get_wtime();
        gwabe.Transform(ct, keytuple.tk, cipher, pairing);
        end_time = omp_get_wtime();
        average_time_Transform += (end_time - start_time) * 1000;

//        gwabe.showCT(ct);
        printf("-------------------------------------------------------------------------\n");


        // Decrypt
        string dec_ek;
        start_time = omp_get_wtime();
        gwabe.Decrypt(dec_ek, keytuple.sk, ct, pairing);
        end_time = omp_get_wtime();
        average_time_Decrypt += (end_time - start_time) * 1000;
        cout << dec_ek.size() << ", ek' = " << dec_ek << '\n';

        // 判断M和M1是否一致
        if (ek != dec_ek)
        {
            cout << "i = " << i << '\n';
            cout << ek.size() << ", ek = " << ek << '\n';
            cout << dec_ek.size() << ", ek' = " << dec_ek << '\n';
            cout << "错误：ek 与 ek' 不一致" << '\n';
            return -1;  // 返回非零值表示出错
        }

        printf("-------------------------------------------------------------------------\n");
    }

    printf("[KGC，步骤一] %d次 Setup平均耗时 %.6f ms\n", epoch, average_time_Setup / epoch);
    printf("[KGC，步骤二] %d次 Keygen平均耗时 %.6f ms\n", epoch, average_time_Keygen / epoch);
    printf("[数据所有者，步骤三] %d次 Encrypt平均耗时 %.6f ms\n", epoch, average_time_Encrypt / epoch);
    printf("[区块链，步骤四] %d次 Transform平均耗时 %.6f ms\n", epoch, average_time_Transform / epoch);
    printf("[数据请求者，步骤五] %d次 Decrypt平均耗时 %.6f ms\n", epoch, average_time_Decrypt / epoch);

    printf("Info: exp successfully returned.\n");
    return 0;
}


#include "../include/ABE/GWABE.h"

using namespace GWABESPACE;


string xorHashes(const std::string &hash1, const std::string &hash2)
{
    // 确保两个哈希具有相同的位数
    size_t bitLength = std::max(hash1.size(), hash2.size());
    std::string paddedHash1 = hash1;
    std::string paddedHash2 = hash2;
    if (hash1.size() < bitLength)
    {
        paddedHash1.insert(0, bitLength - hash1.size(), '0');
    }
    if (hash2.size() < bitLength)
    {
        paddedHash2.insert(0, bitLength - hash2.size(), '0');
    }

    // 对两个哈希进行异或操作
    bitset<256> bitset1(paddedHash1);
    bitset<256> bitset2(paddedHash2);
    bitset<256> result = bitset1 ^ bitset2;
    string resultString = result.to_string();

//    //剔除result字符串前缀中的连续0
//    size_t firstNonZero = resultString.find_first_not_of('0');
//    if (firstNonZero != string::npos)
//    {
//        resultString = resultString.substr(firstNonZero);
//    } else
//    {
//        resultString = "0";
//    }

    // 将结果转换为字符串
    return resultString;
}


string elementToHash(element_t &element)
{
    // 获取元素R的字节表示
    size_t byteLength = element_length_in_bytes(element);
    unsigned char *bytes = new unsigned char[byteLength];
    element_to_bytes(bytes, element);

    // 使用SHA-256进行哈希计算
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(bytes, byteLength, hash);

    // 将哈希值转换为01字符串
    std::string hashString;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        for (int j = 7; j >= 0; j--)
        {
            hashString += ((hash[i] >> j) & 1) ? '1' : '0';
        }
    }

    delete[] bytes;

    return hashString;
}


void GWABE::Setup(pairing_t pairing)
{
    // random,
    element_t a, b;
    element_init_Zr(a, pairing);
    element_init_Zr(b, pairing);
    element_random(a);
    element_random(b);

    // public key
    element_init_G1(mpk.g, pairing);
    element_init_G1(mpk.gb, pairing);
    element_init_GT(mpk.egga, pairing);  //e(g,g)^a, G*G->GT

    element_random(mpk.g);
    element_pow_zn(mpk.gb, mpk.g, b); // g^b

    pairing_apply(mpk.egga, mpk.g, mpk.g, pairing);
    element_pow_zn(mpk.egga, mpk.egga, a);

    //  secret key
    element_init_G1(msk.ga, pairing);
    element_pow_zn(msk.ga, mpk.g, a); // g^a


    element_clear(a);
    element_clear(b);
}


void GWABE::KeyGen(KeyTuple &keytuple, const string _attributes, pairing_t _pairing)
{
    keytuple.tk.attributes = _attributes;
    vector <string> attributes;
    string2attribute_Set(attributes, _attributes);

    element_init_Zr(keytuple.sk.r_2, _pairing);
    element_init_G1(keytuple.tk.tk_1, _pairing);
    element_init_G1(keytuple.tk.tk_2, _pairing);

    // randomness
    element_t r_1, r_2;
    element_init_Zr(r_1, _pairing);
    element_init_Zr(r_2, _pairing);
    element_random(r_1);
    element_random(r_2);

    // decryption key
    element_set(keytuple.sk.r_2, r_2);

    // transformation key
    element_t left, right, inv_r_2;
    element_init_G1(left, _pairing);
    element_init_G1(right, _pairing);
    element_init_Zr(inv_r_2, _pairing);
    element_invert(inv_r_2, r_2);

    // tk_1
    element_set(left, msk.ga);
    element_pow_zn(left, left, inv_r_2);
    element_pow_zn(right, mpk.gb, r_1);
    element_pow_zn(right, right, inv_r_2);
    element_mul(keytuple.tk.tk_1, left, right);

    // tk_2
    element_pow_zn(keytuple.tk.tk_2, mpk.g, r_1);
    element_pow_zn(keytuple.tk.tk_2, keytuple.tk.tk_2, inv_r_2);

    // tk_3
    for (auto e: attributes)
    {
        element_s temp_tk_att;
        element_init_G1(&temp_tk_att, _pairing);
        element_from_hash(&temp_tk_att, (void *) e.c_str(), e.length());
        element_pow_zn(&temp_tk_att, &temp_tk_att, r_1);
        element_pow_zn(&temp_tk_att, &temp_tk_att, inv_r_2);
        keytuple.tk.tk_att.emplace(e, temp_tk_att);
    }

    element_clear(left);
    element_clear(right);
    element_clear(inv_r_2);
    element_clear(r_1);
    element_clear(r_2);


}


void GWABE::Encrypt(Cipher &cipher, string ek, LSSS &lsss, pairing_t _pairing)
{

    int lsss_row = lsss.M.size();
    int lsss_col = lsss.M[0].size();
    cipher.policy = &lsss;


    /* El Gamal layer */

    // c_1
    element_t R;
    element_init_GT(R, _pairing);
    element_random(R);
    element_printf("R = %B\n", R);

    string hash_R = elementToHash(R);
    string splice_string = hash_R + ek;
    element_s s;
    element_init_Zr(&s, _pairing);
    element_from_hash(&s, (void *) splice_string.c_str(), splice_string.length());

    element_init_GT(cipher.c_1, _pairing);
    element_pow_zn(cipher.c_1, mpk.egga, &s);
    element_mul(cipher.c_1, cipher.c_1, R);

    // c_2
    cipher.c_2 = xorHashes(hash_R, ek);


    // c_3
    element_init_G1(cipher.c_3, _pairing);
    element_pow_zn(cipher.c_3, mpk.g, &s);


    /* access policy layer */
    // 随机元 v 与 phi
    vector <element_s> v;
    v.push_back(s);
    for (int i = 0; i < lsss_col - 1; i++)
    {
        element_s temp_y;
        element_init_Zr(&temp_y, _pairing);
        element_random(&temp_y);
        v.push_back(temp_y);
    }
    vector <element_s> phi;
    for (int i = 0; i < lsss_row; i++)
    {
        element_s tmp_phi;
        element_init_Zr(&tmp_phi, _pairing);
        element_random(&tmp_phi);
        phi.push_back(tmp_phi);
    }


    lsss.generateShares(cipher.lambda, v, _pairing);
    assert(cipher.lambda.size() == lsss.M.size());

    // ct_0 ct_1
    for (int i = 0; i < phi.size(); ++i)
    {
        element_s dot_c_i;
        element_s ddot_c_i;
        element_init_G1(&dot_c_i, _pairing);
        element_init_G1(&ddot_c_i, _pairing);

        // ct_0
        element_pow_zn(&dot_c_i, mpk.g, &phi[i]);

        // ct_1
        element_t left, right;
        element_init_G1(left, _pairing);
        element_init_G1(right, _pairing);
        element_pow_zn(left, mpk.gb, &cipher.lambda[i]);

        element_t hash_label, neg_phi;
        element_init_G1(hash_label, _pairing);
        element_init_Zr(neg_phi, _pairing);
        element_from_hash(hash_label, (void *) lsss.rho[i].c_str(), lsss.rho[i].size());
        element_neg(neg_phi, &phi[i]);

        element_pow_zn(right, hash_label, neg_phi);
        element_mul(&ddot_c_i, left, right);

        cipher.dot_c.push_back(dot_c_i);
        cipher.ddot_c.push_back(ddot_c_i);

        element_clear(left);
        element_clear(right);
        element_clear(hash_label);
        element_clear(neg_phi);
    }
}

void GWABE::Transform(CT &ct, KeyTuple::TK &tk, Cipher &cipher, pairing_t _pairing)
{

    element_init_GT(ct.ct_1, _pairing);
    element_init_GT(ct.ct_3, _pairing);

    // ct_1
    element_set(ct.ct_1, cipher.c_1);

    // ct_2
    ct.ct_2 = cipher.c_2;

    // e(c_3, tk_1)
    element_t numerator, denominator;
    element_init_GT(numerator, _pairing);
    element_init_GT(denominator, _pairing);
    pairing_apply(numerator, cipher.c_3, tk.tk_1, _pairing);
    element_set1(denominator);

    // find vector
    vector <element_s> lambda;
    vector <element_s> ddot_c;
    vector <element_s> dot_c;
    vector <element_s> tk_att;
    cipher.policy->getValidSharesExt(lambda, ddot_c, dot_c, tk_att,
                                     cipher.lambda, cipher.ddot_c, cipher.dot_c, tk.tk_att,
                                     tk.attributes, _pairing);


    vector <element_s> w;
    cipher.policy->findVector(w, tk.attributes, _pairing);


    for (int i = 0; i < w.size(); i++)
    {
        element_t left, right;
        element_init_GT(left, _pairing);
        element_init_GT(right, _pairing);

        // CP1 part
        pairing_apply(left, &ddot_c[i], tk.tk_2, _pairing);
        pairing_apply(right, &dot_c[i], &tk_att[i], _pairing);
        element_mul(left, left, right);
        element_pow_zn(left, left, &w[i]);
        element_mul(denominator, denominator, left);

        element_clear(left);
        element_clear(right);
    }


    element_div(ct.ct_3, numerator, denominator);

    element_clear(numerator);
    element_clear(denominator);

    for (auto it = ddot_c.begin(); it != ddot_c.end(); ++it)
    {
        element_clear(&(*it));
    }
    ddot_c.clear();
    for (auto it = dot_c.begin(); it != dot_c.end(); ++it)
    {
        element_clear(&(*it));
    }
    dot_c.clear();
    for (auto it = lambda.begin(); it != lambda.end(); ++it)
    {
        element_clear(&(*it));
    }
    lambda.clear();
    for (auto it = tk_att.begin(); it != tk_att.end(); ++it)
    {
        element_clear(&(*it));
    }
    tk_att.clear();
    for (auto it = w.begin(); it != w.end(); ++it)
    {
        element_clear(&(*it));
    }
    w.clear();


}


void GWABE::Decrypt(string &ek, KeyTuple::SK &sk, CT &ct, pairing_t _pairing)
{

    /* R */
    element_t R, denominator;
    element_init_GT(R, _pairing);
    element_init_GT(denominator, _pairing);
    element_pow_zn(denominator, ct.ct_3, sk.r_2);
    element_div(R, ct.ct_1, denominator);

    /* ek */
    string hash_R = elementToHash(R);
    ek = xorHashes(hash_R, ct.ct_2);


    /* s */
    string splice_string = hash_R + ek;
    element_s s;
    element_init_Zr(&s, _pairing);
    element_from_hash(&s, (void *) splice_string.c_str(), splice_string.length());


    element_t result_1, result_2;
    element_init_GT(result_1, _pairing);
    element_init_GT(result_2, _pairing);

    element_pow_zn(result_1, mpk.egga, &s);
    element_set(result_2, result_1);
    element_mul(result_1, result_1, R);

    if (element_cmp(result_1, ct.ct_1) != 0)
    {
        cout << "error!\n";
        exit(-1);
    }


    if (element_cmp(result_2, denominator) != 0)
    {
        cout << "error!\n";
        exit(-1);
    }


    element_clear(result_1);
    element_clear(result_2);
    element_clear(R);
    element_clear(denominator);
}


void GWABE::showKeys()
{
    element_printf("Master Public Key:\n g = %B\n g_b = %B\n e(g,g)^a = %B\n\n", mpk.g, mpk.gb, mpk.egga);
    element_printf("Master Secret Key:\n g_a = %B\n", msk.ga);
}

void GWABE::showKeytuple(KeyTuple &keytuple)
{
    element_printf("Decryption key sk.r_2 = %B\n", keytuple.sk.r_2);

    cout << "attribute_str = " << keytuple.tk.attributes << '\n';
    element_printf("Transformation key: \ntk_1 = %B\ntk_2 = %B\n\n", keytuple.tk.tk_1, keytuple.tk.tk_2);
    for (auto e: keytuple.tk.tk_att)
    {
        element_printf("tk_att: %s \t %B\n", e.first.c_str(), &e.second);
    }
}

void GWABESPACE::GWABE::showCipher(GWABESPACE::Cipher &cipher)
{
    element_printf("c_1 = %B\n", cipher.c_1);
    cout << "c_2 = " << cipher.c_2 << '\n';
    element_printf("c_3 = %B\n", cipher.c_3);

    assert(cipher.dot_c.size() == cipher.ddot_c.size());
    assert(cipher.dot_c.size() == cipher.lambda.size());

    for (int i = 0; i < cipher.dot_c.size(); i++)
    {
        element_printf("dot_c_%d = %B\n", i, &cipher.dot_c[i]);
        element_printf("ddot_c_%d = %B\n", i, &cipher.ddot_c[i]);
        element_printf("lambda%d = %B\n", i, &cipher.lambda[i]);
    }
}

void GWABE::showCT(GWABESPACE::CT &ct)
{
    element_printf("ct_1 = %B\n", ct.ct_1);
    cout << "ct_2 = " << ct.ct_2 << '\n';
    element_printf("ct_3 = %B\n", ct.ct_3);
}


GWABE::GWABE()
{}

GWABE::~GWABE()
{}
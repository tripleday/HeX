#include "CryptoEnclave_t.h"

#include "EnclaveUtils.h"

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "stdlib.h"
#include <stdarg.h>
#include <stdio.h>
#include <string>
#include <unordered_map>
#include <algorithm> // for std::find
#include <iterator> // for std::begin, std::end
#include <vector>
#include <list>
#include "../common/data_type.h"
#include <bitset> 
#include <random>
#include <vector>
#include <algorithm>
// using std::bitset;  
using std::string;  

//change to malloc for tokens , run ulimit -s 65536 to set stack size to
//65536 KB in linux

// local variables inside Enclave
unsigned char K[ENTRY_HASH_KEY_LEN_128] = {0};
// unsigned char KC[ENC_KEY_SIZE] = {0};
// unsigned char KF[ENC_KEY_SIZE] = {0};

// total file amount
const int id_max = total_file_no;
// constexpr size_t N = id_max;
int in_amt = 1;
int CK_max = 10;
int out_srch_amt = 1;
int out_upd_amt = 2;
// int CK_max = 2*in_amt;
// int out_srch_amt = in_amt;
// int out_upd_amt = 2*in_amt;
int dummy_value = 0;
// key version state
std::unordered_map<string, int> KVS;
std::vector<string> words_KVS; 
// cached keyword
std::unordered_map<string,std::bitset<id_max>> CK;

/*** setup */
void ecall_init(unsigned char *keyF, size_t len){ 

    // memcpy(KF,keyF,len);
    sgx_read_rand(K, ENTRY_HASH_KEY_LEN_128);
    // sgx_read_rand(KC, ENC_KEY_SIZE);
}

/*** update with op */
void ecall_updateDoc(char *doc_id, size_t id_length, char *content, size_t content_length, const int* op, size_t op_len){             
    //parse content to keywords splited by comma
    std::vector<string> wordList;
    wordList = wordTokenize(content,content_length);
    size_t pair_no = wordList.size();

    int id_int = atoi(doc_id);
    // string id_str(doc_id,id_length);
    // printf("%d \n", CK.size());

    for(std::vector<string>::iterator it = wordList.begin(); it != wordList.end(); ++it) {     
        // printf("\nCK size %d", CK.size());     
        // for (auto it = CK.begin(); it != CK.end(); ++it) {
        //     printf("%s ", it->first);
        // }
        string word = (*it);
        // printf("keyword %s", (char*)word.c_str());

        if (CK.size() == 0) { // just fill
            std::bitset<id_max> bm;
            if (*op==ADD) { bm[id_int-1]=1; } else { bm[id_int-1]=0; }
            CK.insert(std::pair<string,std::bitset<id_max>>(word, bm));
            KVS.insert(std::pair<string,int>(word, 0)); words_KVS.push_back(word);
            continue;
        }
        else if (CK.size() < CK_max) { // just fill based on CK
            std::unordered_map<string,std::bitset<id_max>>::const_iterator ck_got = CK.find(word);
            if (ck_got == CK.end()) {
                std::unordered_map<string,int>::const_iterator kvs_got = KVS.find(word);
                if (kvs_got == KVS.end()) {
                    std::bitset<id_max> bm;
                    if (*op==ADD) { bm[id_int-1]=1; } else { bm[id_int-1]=0; }
                    CK.insert(std::pair<string,std::bitset<id_max>>(word, bm));
                    KVS.insert(std::pair<string,int>(word, 0)); words_KVS.push_back(word);
                }
            }
            else{
                std::bitset<id_max> bm = ck_got->second;
                if (*op==ADD) { bm[id_int-1]=1; } else { bm[id_int-1]=0; }
                CK.erase(word);
                CK.insert(std::pair<string,std::bitset<id_max>>(word, bm));
            }
            if (CK.size() <= CK_max) {
                continue;
            }
        }
        else { // CK is full and KVS >= 3, need to read index
            if ( KVS.size() == CK_max ) {
                std::unordered_map<string,std::bitset<id_max>>::const_iterator ck_got = CK.find(word);
                if (ck_got == CK.end()) {
                    std::unordered_map<string,int>::const_iterator kvs_got = KVS.find(word);
                    if (kvs_got == KVS.end()) {
                        std::bitset<id_max> bm;
                        if (*op==ADD) { bm[id_int-1]=1; } else { bm[id_int-1]=0; }
                        CK.insert(std::pair<string,std::bitset<id_max>>(word, bm));
                        KVS.insert(std::pair<string,int>(word, 0)); words_KVS.push_back(word);
                    }
                }
                else{
                    std::bitset<id_max> bm = ck_got->second;
                    if (*op==ADD) { bm[id_int-1]=1; } else { bm[id_int-1]=0; }
                    CK.erase(word);
                    CK.insert(std::pair<string,std::bitset<id_max>>(word, bm));
                }
            } 
            else {
                string word_in;
                std::unordered_map<string,std::bitset<id_max>>::const_iterator ck_got = CK.find(word);
                if (ck_got == CK.end()) { // not cached
                    std::unordered_map<string,int>::const_iterator kvs_got = KVS.find(word);
                    if (kvs_got == KVS.end()) { // first update                        
                        // std::vector<string> words_CK;               
                        // for (auto it = CK.begin(); it != CK.end(); ++it) {
                        //     words_CK.push_back(it->first);
                        // }
                        // std::sort(words_CK.begin(), words_CK.end(), std::less<string>());
                        // for (auto it = words_CK.begin(); it != words_CK.end(); ++it) {
                        //     printf("CK: %s ", *it);
                        // }
                        // std::vector<string> words_KVS;               
                        // for (auto it = KVS.begin(); it != KVS.end(); ++it) {
                        //     words_KVS.push_back(it->first);
                        // }
                        // std::sort(words_KVS.begin(), words_KVS.end(), std::less<string>());
                        // for (auto it = words_KVS.begin(); it != words_KVS.end(); ++it) {
                        //     printf("KVS: %s ", *it);
                        // }
                        // std::vector<string> words_without_CK;
                        // std::set_difference(words_KVS.begin(), words_KVS.end(),
                        //         words_CK.begin(), words_CK.end(),
                        //         std::back_inserter(words_without_CK));       
                        // for (auto it = words_without_CK.begin(); it != words_without_CK.end(); ++it) {
                        //     printf("without: %s ", *it);
                        // }
                        // std::vector<string>::iterator words_without_CK=words_KVS.end();
                        // for (auto it = CK.begin(); it != CK.end(); ++it) {
                        //     words_without_CK = std::remove(words_KVS.begin(), words_without_CK, it->first);
                        // }
                        // std::vector<string> temp; 
                        // std::sample(words_KVS.begin(), words_without_CK, std::back_inserter(temp), 1, std::mt19937{std::random_device{}()});
                        // word_in = temp[0];
                        bool find = false;
                        while (!find) {
                            int r = std::mt19937{std::random_device{}()}() % words_KVS.size();
                            find = true;   
                            for (auto it = CK.begin(); it != CK.end(); ++it) {
                                if (words_KVS[r]==it->first) {
                                    find = false;
                                    break;
                                }
                            }
                            if (find) {
                                word_in = words_KVS[r];
                            }
                        }
                        // bool find = false;
                        // while (!find) {
                        //     std::vector<string> temp; 
                        //     std::sample(words_KVS.begin(), words_KVS.end(), std::back_inserter(temp), 1, std::mt19937{std::random_device{}()}); 
                        //     find = true;   
                        //     for (auto it = CK.begin(); it != CK.end(); ++it) {
                        //         if (temp[0]==it->first) {
                        //             find = false;
                        //             break;
                        //         }
                        //     }
                        //     if (find) {
                        //         word_in = temp[0];
                        //     }
                        // }
                    }
                    else{ // exists
                        word_in = word;
                    }
                }
                else{ // cached
                    // std::vector<string> words_KVS;               
                    // for (auto it = KVS.begin(); it != KVS.end(); ++it) {
                    //     words_KVS.push_back(it->first);
                    // }
                    bool find = false;
                    while (!find) {
                        int r = std::mt19937{std::random_device{}()}() % words_KVS.size();
                        find = true;   
                        for (auto it = CK.begin(); it != CK.end(); ++it) {
                            if (words_KVS[r]==it->first) {
                                find = false;
                                break;
                            }
                        }
                        if (find) {
                            word_in = words_KVS[r];
                        }
                    }
                }
                
                label_struct *ins = (label_struct*) malloc(sizeof(label_struct)); // label
                string msg = word_in + std::to_string(KVS[word_in]) + std::to_string(0);
                unsigned char *label =  (unsigned char *) malloc(HASH_VALUE_LEN_128); 
                hash_SHA128(K, msg.c_str(), msg.length(), label);
                memcpy(ins->content,label,HASH_VALUE_LEN_128);
                ins->content_length = HASH_VALUE_LEN_128;
                free(label);
                string enc_key_msg = word_in + std::to_string(KVS[word_in]) + std::to_string(1); // encryption key
                unsigned char *enc_key =  (unsigned char *) malloc(HASH_VALUE_LEN_128); 
                hash_SHA128(K, enc_key_msg.c_str(), enc_key_msg.length(), enc_key);
                cipher_struct *ins_res = (cipher_struct*) malloc(sizeof(cipher_struct));   
                // printf("%s",word_in.c_str());
                ocall_retrieve_edb(ins, ins_res, sizeof(label_struct), sizeof(cipher_struct));
                free(ins);

                size_t temp_plain_len = ins_res->content_length-AESGCM_MAC_SIZE-AESGCM_IV_SIZE;
                uint8_t* temp_plain = (uint8_t*) malloc(temp_plain_len);
                dec_aes_gcm(enc_key, ins_res->content, ins_res->content_length, temp_plain, temp_plain_len);
                free(enc_key);
                free(ins_res);
                // string bm_in_str((char*) temp_plain, temp_plain_len);
                // printf("%d",bm_in_str.length());
                // std::reverse(bm_in_str.begin(),bm_in_str.end()); // reverse to convert to bitset
                // printf("%d",bm_in_str.length());
                // std::bitset<id_max> bm_in(bm_in_str, bm_in_str.size()-id_max);
                std::bitset<id_max> bm_in = uint8ArrayToBitset<id_max>(temp_plain);
                free(temp_plain);

                
                // std::unordered_map<string,std::bitset<id_max>>::const_iterator ck_got = CK.find(word);
                if (ck_got == CK.end()) { // not cached
                    std::unordered_map<string,int>::const_iterator kvs_got = KVS.find(word);
                    if (kvs_got == KVS.end()) { // first update
                        CK.insert(std::pair<string,std::bitset<id_max>>(word_in, bm_in));
                        std::bitset<id_max> bm;
                        if (*op==ADD) { bm[id_int-1]=1; } else { bm[id_int-1]=0; }
                        CK.insert(std::pair<string,std::bitset<id_max>>(word, bm));
                        KVS.insert(std::pair<string,int>(word, 0)); words_KVS.push_back(word);
                    }
                    else{ // exists
                        if (*op==ADD) { bm_in[id_int-1]=1; } else { bm_in[id_int-1]=0; }
                        CK.insert(std::pair<string,std::bitset<id_max>>(word_in, bm_in));
                        string dummy = "dummy" + std::to_string(dummy_value);   
                        dummy_value++; 
                        std::bitset<id_max> dummy_bm;
                        CK.insert(std::pair<string,std::bitset<id_max>>(dummy, dummy_bm));
                        KVS.insert(std::pair<string,int>(dummy, 0)); words_KVS.push_back(dummy);
                    }
                }
                else{ // cached
                    CK.insert(std::pair<string,std::bitset<id_max>>(word_in, bm_in));
                    std::bitset<id_max> bm = ck_got->second;
                    if (*op==ADD) { bm[id_int-1]=1; } else { bm[id_int-1]=0; }
                    CK.erase(word);
                    CK.insert(std::pair<string,std::bitset<id_max>>(word, bm));
                    string dummy = "dummy" + std::to_string(dummy_value);    
                    dummy_value++; 
                    std::bitset<id_max> dummy_bm;
                    CK.insert(std::pair<string,std::bitset<id_max>>(dummy, dummy_bm));
                    KVS.insert(std::pair<string,int>(dummy, 0)); words_KVS.push_back(dummy);
                }
            }
        }
        int out_amt = CK.size()-CK_max;
        // printf("out amt %d",out_amt);
        std::vector<string> words_without_w;               
        for (auto it = CK.begin(); it != CK.end(); ++it) {
            if (it->first!=word) {words_without_w.push_back(it->first);}
        }
        std::vector<string> words_out; 
        std::sample(words_without_w.begin(), words_without_w.end(), std::back_inserter(words_out), out_amt, std::mt19937{std::random_device{}()});
        label_struct *outs = (label_struct*) malloc(out_amt * sizeof(label_struct)); // labels
        cipher_struct *outs_res = (cipher_struct*) malloc(out_amt * sizeof(cipher_struct));   
        for (int i=0; i < out_amt; i++) {     
            // printf("out word %s", words_out[i]);
            string msg = words_out[i] + std::to_string(KVS[words_out[i]]+1) + std::to_string(0);
            unsigned char *label =  (unsigned char *) malloc(HASH_VALUE_LEN_128); 
            hash_SHA128(K, msg.c_str(), msg.length(), label);
            memcpy(outs[i].content,label,HASH_VALUE_LEN_128);
            outs[i].content_length = HASH_VALUE_LEN_128;
            free(label);
            string enc_key_msg = words_out[i] + std::to_string(KVS[words_out[i]]+1) + std::to_string(1);
            unsigned char *enc_key =  (unsigned char *) malloc(HASH_VALUE_LEN_128); 
            hash_SHA128(K, enc_key_msg.c_str(), enc_key_msg.length(), enc_key);
            // string bm_str = CK[words_out[i]].to_string();
            // printf("out bm %s",bm_str.c_str());
            uint8_t* bm_p = (uint8_t*) malloc(int(id_max/8));
            bitsetToUint8Array(CK[words_out[i]], bm_p);
            // cipher_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + bm_str.length(); 
            int cipher_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + int(id_max/8); 
	        unsigned char * cipher = (unsigned char *) malloc(cipher_length);
            enc_aes_gcm(enc_key, bm_p, int(id_max/8), cipher, cipher_length);
            // enc_aes_gcm(enc_key, bm_str.c_str(), bm_str.length(), cipher, cipher_length);
            memcpy(outs_res[i].content, (unsigned char*)cipher, cipher_length);
            outs_res[i].content_length = cipher_length;
            free(enc_key);
            free(bm_p);
            free(cipher);
            // int vn = KVS[words_out[i]]+1;
            // KVS.erase(words_out[i]);
            // KVS.insert(std::pair<string,int>(words_out[i], vn)); 
            KVS[words_out[i]] = KVS[words_out[i]]+1;
            CK.erase(words_out[i]);
        }
        ocall_add_edbs(outs, outs_res, out_amt, sizeof(label_struct), sizeof(cipher_struct));
        free(outs);
        free(outs_res);

        //printf("State c: %d \n", c);
    }

    // //call Server to update
    // ocall_transfer_edbs(labels, ciphers, pair_no, sizeof(rand_t));
}


/*** search for a keyword */
void ecall_search(const char *keyword, size_t keyword_len){
    //init keys
    string word(keyword,keyword_len);

    std::unordered_map<string,int>::const_iterator kvs_got = KVS.find(word);
    if (kvs_got == KVS.end()) { // not exists
        printf("Keyword does not exist for search");
        if (dummy_value > 0) {
            int d = std::mt19937{std::random_device{}()}() % dummy_value;
            word = "dummy" + std::to_string(d);
        }
        else return;
    }
    // else{ // exists
        string word_in;
        std::unordered_map<string,std::bitset<id_max>>::const_iterator ck_got = CK.find(word);
        if (ck_got == CK.end()) { // not cached
            word_in = word;
        }
        else { // cached
            printf("total file number: %d \n", ck_got->second.count());
            // ck_got->second.count();
            // std::vector<string> words_KVS;               
            // for (auto it = KVS.begin(); it != KVS.end(); ++it) {
            //     words_KVS.push_back(it->first);
            // }
            bool find = false;
            while (!find) {
                int r = std::mt19937{std::random_device{}()}() % words_KVS.size();
                find = true;   
                for (auto it = CK.begin(); it != CK.end(); ++it) {
                    if (words_KVS[r]==it->first) {
                        find = false;
                        break;
                    }
                }
                if (find) {
                    word_in = words_KVS[r];
                }
            }
        }
        label_struct *ins = (label_struct*) malloc(sizeof(label_struct)); // label
        string msg = word_in + std::to_string(KVS[word_in]) + std::to_string(0);
        unsigned char *label =  (unsigned char *) malloc(HASH_VALUE_LEN_128); 
        hash_SHA128(K, msg.c_str(), msg.length(), label);
        memcpy(ins->content,label,HASH_VALUE_LEN_128);
        ins->content_length = HASH_VALUE_LEN_128;
        free(label);
        string enc_key_msg = word_in + std::to_string(KVS[word_in]) + std::to_string(1); // encryption key
        unsigned char *enc_key =  (unsigned char *) malloc(HASH_VALUE_LEN_128); 
        hash_SHA128(K, enc_key_msg.c_str(), enc_key_msg.length(), enc_key);
        cipher_struct *ins_res = (cipher_struct*) malloc(sizeof(cipher_struct));   
        // printf("%s",word_in.c_str());
        ocall_retrieve_edb(ins, ins_res, sizeof(label_struct), sizeof(cipher_struct));
        free(ins);

        size_t temp_plain_len = ins_res->content_length-AESGCM_MAC_SIZE-AESGCM_IV_SIZE;
        uint8_t* temp_plain = (uint8_t*) malloc(temp_plain_len);
        dec_aes_gcm(enc_key, ins_res->content, ins_res->content_length, temp_plain, temp_plain_len);
        free(enc_key);
        free(ins_res);
        std::bitset<id_max> bm_in = uint8ArrayToBitset<id_max>(temp_plain);
        free(temp_plain);
        if (ck_got == CK.end()) { // not cached
            printf("total file number: %d \n", bm_in.count());
        }
        // bm_in.count();
        CK.insert(std::pair<string,std::bitset<id_max>>(word_in, bm_in));
    // }

    int out_amt = CK.size()-CK_max;
    std::vector<string> words_without_w;               
    for (auto it = CK.begin(); it != CK.end(); ++it) {
        if (it->first!=word) {words_without_w.push_back(it->first);}
    }
    std::vector<string> words_out; 
    std::sample(words_without_w.begin(), words_without_w.end(), std::back_inserter(words_out), out_amt, std::mt19937{std::random_device{}()});
    label_struct *outs = (label_struct*) malloc(out_amt * sizeof(label_struct)); // labels
    cipher_struct *outs_res = (cipher_struct*) malloc(out_amt * sizeof(cipher_struct));   
    for (int i=0; i < out_amt; i++) {
        string msg = words_out[i] + std::to_string(KVS[words_out[i]]+1) + std::to_string(0);
        unsigned char *label =  (unsigned char *) malloc(HASH_VALUE_LEN_128); 
        hash_SHA128(K, msg.c_str(), msg.length(), label);
        memcpy(outs[i].content,label,HASH_VALUE_LEN_128);
        outs[i].content_length = HASH_VALUE_LEN_128;
        free(label);
        string enc_key_msg = words_out[i] + std::to_string(KVS[words_out[i]]+1) + std::to_string(1);
        unsigned char *enc_key =  (unsigned char *) malloc(HASH_VALUE_LEN_128); 
        hash_SHA128(K, enc_key_msg.c_str(), enc_key_msg.length(), enc_key);
        // string bm_str = CK[words_out[i]].to_string();
        // printf("out bm %s",bm_str.c_str());
        uint8_t* bm_p = (uint8_t*) malloc(int(id_max/8));
        bitsetToUint8Array(CK[words_out[i]], bm_p);
        // cipher_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + bm_str.length(); 
        int cipher_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + int(id_max/8); 
        unsigned char * cipher = (unsigned char *) malloc(cipher_length);
        enc_aes_gcm(enc_key, bm_p, int(id_max/8), cipher, cipher_length);
        // enc_aes_gcm(enc_key, bm_str.c_str(), bm_str.length(), cipher, cipher_length);
        memcpy(outs_res[i].content, (unsigned char*)cipher, cipher_length);
        outs_res[i].content_length = cipher_length;
        free(enc_key);
        free(bm_p);
        free(cipher);
        // int vn = KVS[words_out[i]]+1;
        // KVS.erase(words_out[i]);
        // KVS.insert(std::pair<string,int>(words_out[i], vn)); 
        KVS[words_out[i]] = KVS[words_out[i]]+1;
        CK.erase(words_out[i]);
    }
    ocall_add_edbs(outs, outs_res, out_amt, sizeof(label_struct), sizeof(cipher_struct));
    free(outs);
    free(outs_res);

    //printf("State c: %d \n", c);
}

void ecall_printMem(){
    printf("%d", (sizeof(string)+sizeof(int))*KVS.size()+(sizeof(string)+total_file_no/8)*CK.size());
}

// // vector implementation
// void ecall_addDoc(char *doc_id, size_t id_length,char *content,int content_length){             
//     //parse content to keywords splited by comma
//     std::vector<string> wordList;
//     wordList = wordTokenize(content,content_length);
//     size_t pair_no = wordList.size();

//     rand_t labels[pair_no];
//     rand_t ciphers[pair_no];

//     int id_int = atoi(doc_id);
//     // string id_str(doc_id,id_length);
//     int index=0;

//     for(std::vector<string>::iterator it = wordList.begin(); it != wordList.end(); ++it) {
      
//         string word = (*it);
//         //printf("keyword %s", (char*)word.c_str());

//         if (CK.size() == 0) { // just fill
//             std::bitset<id_max> bm;
//             bm[id_int-1]=1;
//             CK.insert(std::pair<string,std::bitset<id_max>>(word, bm));
//             KVS.insert(std::pair<string,int>(word, 0));
//         }
//         else if (CK.size() < CK_max) { // just fill based on CK
//             std::unordered_map<string,std::bitset<id_max>>::const_iterator ck_got = CK.find(word);
//             if (ck_got == CK.end()) {
//                 std::unordered_map<string,int>::const_iterator kvs_got = KVS.find(word);
//                 if (kvs_got == KVS.end()) {
//                     std::bitset<id_max> bm;
//                     bm[id_int-1]=1;
//                     CK.insert(std::pair<string,std::bitset<id_max>>(word, bm));
//                     KVS.insert(std::pair<string,int>(word, 0)); 
//                 }
//             }
//             else{
//                 std::bitset<id_max> bm = ck_got->second;
//                 if (bm[id_int-1]==0) {
//                     bm[id_int-1] = 1;
//                 }
//             }
//         }
//         else { // == CK_max
//             std::vector<string> word_in;
//             int word_in_amt = 0;
//             std::unordered_map<string,std::bitset<id_max>>::const_iterator ck_got = CK.find(word);
//             if (ck_got == CK.end()) { // not cached
//                 word_in.push_back();
//                 std::unordered_map<string,int>::const_iterator kvs_got = KVS.find(word);
//                 if (kvs_got == KVS.end()) {
//                 }
//                 else{
//                 }
//             }
//             else{ // cached
//                 std::vector<string> words_KVS;               
//                 for (auto it = CK.begin(); it != CK.end(); ++it) {
//                     words_KVS.push_back(it->first);
//                 }
//                 std::vector<string> words_KVS;               
//                 for (auto it = KVS.begin(); it != KVS.end(); ++it) {
//                     words_KVS.push_back(it->first);
//                 }
//                 std::vector<string> words_without_CK;
//                 std::set_difference(words_KVS.begin(), words_KVS.end(),
//                         words_KVS.begin(), words_KVS.end(),
//                         std::back_inserter(words_without_CK));
//                 if (words_without_CK.size() < in_amt) { // take in KVS.szie-CK.size entries
//                     word_in = words_without_CK;
//                     word_in_amt = words_without_CK.size();
//                 }
//                 else{ // take in in_amt entries
//                     std::sample(words_without_CK.begin(), words_without_CK.end(), std::back_inserter(word_in), in_amt, std::mt19937{std::random_device{}()});
//                     word_in_amt = in_amt;
//                 }
//             }
//             label_struct *ins = (label_struct*) malloc(word_in_amt * sizeof(label_struct)); // labels
//             std::vector<string> enc_keys(word_in_amt); // encryption keys
//             for (int i=0; i < word_in_amt; i++) {
//                 string msg = word_in[i] + std::to_string(KVS[word_in[i]]) + std::to_string(0);
//                 enc_keys[i] = word_in[i] + std::to_string(KVS[word_in[i]]) + std::to_string(1);
//                 unsigned char *label =  (unsigned char *) malloc(HASH_VALUE_LEN_128); 
//                 hash_SHA128(K, msg.c_str(), msg.length(), label);
//                 memcpy(&ins[i].content,label,HASH_VALUE_LEN_128);
//                 free(label);
//             }
//             cipher_struct *ins_res = (cipher_struct*) malloc(word_in_amt * sizeof(cipher_struct));   
//             ocall_retrieve_edbs(ins, ins_res, word_in_amt, sizeof(label_struct), sizeof(cipher_struct));
//             for (int i=0; i < word_in_amt; i++) {
//                 unsigned char* temp_plain;
//                 size_t temp_plain_len;
//                 dec_aes_gcm(&enc_keys[i], ins_res[i].content, ins_res[i].content_length, temp_plain, temp_plain_len);
//                 string bm_str((char*) temp_plain, temp_plain_len);
//                 std::reverse(bm_str.begin(),bm_str.end()); // reverse to convert to bitset
//                 std::bitset<id_max> bm(bm_str);
//                 CK.insert(std::pair<string,std::bitset<id_max>>(word_in[i], bm));
//             }
//         }
//     }
// }

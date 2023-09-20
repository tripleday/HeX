#ifndef ENCLAVE_UTILS_H
#define ENCLAVE_UTILS_H

#include "stdlib.h"
#include <stdarg.h>
#include <stdio.h>
#include <string>
#include <unordered_map>
#include <iterator>
#include <vector>
#include <cstring>
#include <bitset> 
#include "../common/data_type.h"


void printf( const char *fmt, ...);
void print_bytes(uint8_t *ptr, uint32_t len);
int  cmp(const uint8_t *value1, const uint8_t *value2, uint32_t len);
void clear(uint8_t *dest, uint32_t len);
std::vector<std::string>  wordTokenize(char *content,int content_length);

void enc_aes_gcm(const void *key, const void *plaintext, size_t plaintext_len, void *ciphertext, size_t ciphertext_len);
void dec_aes_gcm(const void *key, const void *ciphertext, size_t ciphertext_len, void *plaintext, size_t plaintext_len);
int hash_SHA128(const void *key, const void *msg, int msg_len, void *value);
int hash_SHA128_key(const void *key, int key_len, const void *msg, int msg_len, void *value);

template <size_t N>
std::bitset<N> uint8ArrayToBitset(const unsigned char* array) {
    std::bitset<N> bits;
    for (size_t i = 0; i < N / 8; ++i) {
        for (size_t j = 0; j < 8; ++j) {
            bits[i * 8 + j] = (array[i] >> (7 - j)) & 1;
        }
    }
    return bits;
}

template <size_t N>
void bitsetToUint8Array(const std::bitset<N>& bits, unsigned char* array) {
    for (size_t i = 0; i < N / 8; ++i) {
        array[i] = 0;
        for (size_t j = 0; j < 8; ++j) {
            array[i] |= (bits[i * 8 + j] << (7 - j));
        }
    }
}

//improved
//void prf_F_improve(const void *key,const void *plaintext,size_t plaintext_len, entryKey *k );
//void prf_Enc_improve(const void *key,const void *plaintext,size_t plaintext_len, entryValue *v);
//void prf_Dec_Improve(const void *key,const void *ciphertext,size_t ciphertext_len, entryValue *value );

#endif

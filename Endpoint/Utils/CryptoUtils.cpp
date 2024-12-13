/*
 *  Copyright (C) 2024 Fraunhofer AISEC
 *  Authors: Andrei-Cosmin Aprodu <andrei-cosmin.aprodu@aisec.fraunhofer.de>
 *
 *  CryptoUtils.cpp
 *
 *  Provides access to cryptographic functionalities inspired by Intel SGX SDK.
 *
 *  All Rights Reserved.
 */

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <cstring>

#include "../KeyMaterial.h"

#define NULL_BREAK(x) if (!x) break
#define BN_CHECK_BREAK(x) if (!x || BN_is_zero(x)) break
#define AES_GCM_KEY_SIZE 16
#define AES_GCM_MAC_SIZE 16
#define AES_GCM_IV_SIZE 12
#define SHA256_HASH_SIZE 32


typedef unsigned char byte;
typedef uint8_t aes_gcm_128bit_t[16];


// Inspired from: https://github.com/intel/linux-sgx/blob/master/sdk/tlibcrypto/sgxssl/sgx_rsa_encryption.cpp
int generatePrivKeyRSA(void **new_priv_key) {
    if (new_priv_key == nullptr) {
        return -1;
    }

    auto *p_e = (byte *) &KeyMaterial::pub_e;
    int ret_code = -1;
    bool rsa_memory_manager = false;
    EVP_PKEY *rsa_key = nullptr;
    RSA *rsa_ctx;
    BIGNUM *n = nullptr;
    BIGNUM *e = nullptr;
    BIGNUM *d = nullptr;
    BIGNUM *dmp1 = nullptr;
    BIGNUM *dmq1 = nullptr;
    BIGNUM *iqmp = nullptr;
    BIGNUM *q = nullptr;
    BIGNUM *p = nullptr;
    BN_CTX *tmp_ctx;

    do {
        tmp_ctx = BN_CTX_new();
        NULL_BREAK(tmp_ctx);
        n = BN_new();
        NULL_BREAK(n);

        p = BN_lebin2bn(KeyMaterial::p_p, (KeyMaterial::n_byte_size / 2), p);
        BN_CHECK_BREAK(p);
        q = BN_lebin2bn(KeyMaterial::p_q, (KeyMaterial::n_byte_size / 2), q);
        BN_CHECK_BREAK(q);
        dmp1 = BN_lebin2bn(KeyMaterial::p_dmp1, (KeyMaterial::n_byte_size / 2), dmp1);
        BN_CHECK_BREAK(dmp1);
        dmq1 = BN_lebin2bn(KeyMaterial::p_dmq1, (KeyMaterial::n_byte_size / 2), dmq1);
        BN_CHECK_BREAK(dmq1);
        iqmp = BN_lebin2bn(KeyMaterial::p_iqmp, (KeyMaterial::n_byte_size / 2), iqmp);
        BN_CHECK_BREAK(iqmp);
        e = BN_lebin2bn(p_e, sizeof(KeyMaterial::pub_e), e);
        BN_CHECK_BREAK(e);

        if (!BN_mul(n, p, q, tmp_ctx)) {
            break;
        }

        d = BN_dup(n);
        NULL_BREAK(d);

        BN_set_flags(d, BN_FLG_CONSTTIME);
        BN_set_flags(e, BN_FLG_CONSTTIME);

        if (!BN_sub(d, d, p) || !BN_sub(d, d, q) || !BN_add_word(d, 1) || !BN_mod_inverse(d, e, d, tmp_ctx)) {
            break;
        }

        rsa_ctx = RSA_new();
        rsa_key = EVP_PKEY_new();

        if (rsa_ctx == nullptr || rsa_key == nullptr || !EVP_PKEY_assign_RSA(rsa_key, rsa_ctx)) {
            RSA_free(rsa_ctx);
            rsa_key = nullptr;
            break;
        }

        if (!RSA_set0_factors(rsa_ctx, p, q)) {
            break;
        }
        rsa_memory_manager = true;
        if (!RSA_set0_crt_params(rsa_ctx, dmp1, dmq1, iqmp)) {
            BN_clear_free(n);
            BN_clear_free(e);
            BN_clear_free(d);
            BN_clear_free(dmp1);
            BN_clear_free(dmq1);
            BN_clear_free(iqmp);
            break;
        }

        if (!RSA_set0_key(rsa_ctx, n, e, d)) {
            BN_clear_free(n);
            BN_clear_free(e);
            BN_clear_free(d);
            break;
        }

        *new_priv_key = rsa_key;
        ret_code = 0;
    } while (false);

    BN_CTX_free(tmp_ctx);

    if (ret_code != 0) {
        if (!rsa_memory_manager) {
            BN_clear_free(n);
            BN_clear_free(e);
            BN_clear_free(d);
            BN_clear_free(dmp1);
            BN_clear_free(dmq1);
            BN_clear_free(iqmp);
            BN_clear_free(q);
            BN_clear_free(p);
        }
        EVP_PKEY_free(rsa_key);
    }

    return ret_code;
}

// Inspired from: https://github.com/intel/linux-sgx/blob/master/sdk/tlibcrypto/sgxssl/sgx_rsa_encryption.cpp
int decryptRSA_SHA256(byte *pout_data, size_t *pout_len, const byte *pin_data, size_t pin_len) {
    if (pout_len == nullptr || pin_data == nullptr || pin_len < 1 || pin_len >= INT_MAX) {
        return -1;
    }

    void *private_key = nullptr;
    if (generatePrivKeyRSA(&private_key)) {
        return -1;
    }

    EVP_PKEY_CTX *ctx;
    size_t data_len = 0;
    int ret_code = -1;

    do {
        ctx = EVP_PKEY_CTX_new((EVP_PKEY *) private_key, nullptr);
        if (ctx == nullptr || EVP_PKEY_decrypt_init(ctx) < 1) {
            break;
        }

        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());

        if (pout_data == nullptr) {
            *pout_len = data_len;
            ret_code = 0;
            break;
        } else if (*pout_len < data_len) {
            ret_code = -1;
            break;
        }

        if (EVP_PKEY_decrypt(ctx, pout_data, pout_len, pin_data, pin_len) <= 0) {
            break;
        }
        ret_code = 0;
    } while (false);

    EVP_PKEY_CTX_free(ctx);

    return ret_code;
}

// Inspired from: https://github.com/intel/linux-sgx/blob/master/sdk/tlibcrypto/sgxssl/sgx_aes_gcm.cpp
int decryptAES128GCM(const aes_gcm_128bit_t *p_key, const uint8_t *p_src,
                     uint32_t src_len, uint8_t *p_dst, const uint8_t *p_iv, uint32_t iv_len,
                     const uint8_t *p_aad, uint32_t aad_len, const aes_gcm_128bit_t *p_in_mac) {
    uint8_t l_tag[AES_GCM_MAC_SIZE];

    if (src_len >= INT_MAX || aad_len >= INT_MAX || p_key == nullptr || (src_len > 0 && p_dst == nullptr) ||
        (src_len > 0 && p_src == nullptr) || p_in_mac == nullptr || iv_len != AES_GCM_IV_SIZE ||
        (aad_len > 0 && p_aad == nullptr) || p_iv == nullptr || (p_src == nullptr && p_aad == nullptr)) {
        return -1;
    }
    int len = 0;
    int ret = -1;
    EVP_CIPHER_CTX *pState;

    std::memset(&l_tag, 0, AES_GCM_MAC_SIZE);
    memcpy(l_tag, p_in_mac, AES_GCM_MAC_SIZE);

    do {
        if (!(pState = EVP_CIPHER_CTX_new())) {
            ret = -2;
            break;
        }

        if (!EVP_DecryptInit_ex(pState, EVP_aes_128_gcm(), nullptr, (unsigned char *) p_key, p_iv)) {
            break;
        }

        if (nullptr != p_aad) {
            if (!EVP_DecryptUpdate(pState, nullptr, &len, p_aad, static_cast<int>(aad_len))) {
                break;
            }
        }

        if (!EVP_DecryptUpdate(pState, p_dst, &len, p_src, static_cast<int>(src_len))) {
            break;
        }

        if (!EVP_CIPHER_CTX_ctrl(pState, EVP_CTRL_GCM_SET_TAG, AES_GCM_MAC_SIZE, l_tag)) {
            break;
        }

        if (EVP_DecryptFinal_ex(pState, p_dst + len, &len) <= 0) {
            ret = -3;
            break;
        }
        ret = 0;
    } while (false);

    if (pState != nullptr) {
        EVP_CIPHER_CTX_free(pState);
    }
    std::memset(&l_tag, 0, AES_GCM_MAC_SIZE);
    return ret;
}

int generateSHA256(byte *message, uint32_t message_len, byte *digest) {
    if (message == nullptr || digest == nullptr) {
        return -1;
    }

    if (SHA256(const_cast<const byte *>(message), message_len, digest) == nullptr) {
        return -1;
    }
    return 0;
}

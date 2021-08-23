//
// Created by 朱凇 on 2021/8/18.
//

#ifndef ANDROIDZ_HELPER_H
#define ANDROIDZ_HELPER_H

#include <android/log.h>
#include <string.h>
#include "zcrypto.h"
#include <stdlib.h>
#include "base64.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "NDK_LOG", __VA_ARGS__)
#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, "NDK_LOG", __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "NDK_LOG", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "NDK_LOG", __VA_ARGS__)
#define ASSERT(cond, fmt, ...)                                \
  if (!(cond)) {                                              \
    __android_log_assert(#cond, "AG_APM", fmt, ##__VA_ARGS__); \
  }

#endif //ANDROIDZ_HELPER_H

const int noise_words_index = 88;
const int noise_words_size = 6;

// 记录服务端返回的加密后的原始公钥信息, 需要返回服务端用来获取对应私钥解密
char *c_key_b64_origin;
// 用来加密的实际公钥
char *c_key;

RSA *public_key_rsa;
int rsa_len;
// 设置加密key
JNIEXPORT void JNICALL Java_cn_com_lasong_utils_ZCrypto_validateClientKey
        (JNIEnv *env, jclass clz, jstring key) {
    int len_key = (*env)->GetStringUTFLength(env, key);
    const char *tmp = (*env)->GetStringUTFChars(env, key, 0);
    if (c_key) {
        free(c_key);
        c_key = NULL;
    }
    if (c_key_b64_origin) {
        free(c_key_b64_origin);
        c_key_b64_origin = NULL;
    }

    if (public_key_rsa) {
        RSA_free(public_key_rsa);
        public_key_rsa = NULL;
    }
    c_key_b64_origin = malloc(len_key * sizeof(char));
    strcpy(c_key_b64_origin, tmp);
    (*env)->ReleaseStringUTFChars(env, key, tmp);
    int key_b64_length = Base64decode_len(c_key_b64_origin);
    // get noise key
    char *key_noise = malloc(key_b64_length * sizeof(char));
    int key_noise_len = Base64decode(key_noise, c_key_b64_origin);
    // get real key
    int invalid_len = noise_words_size + 1;
    int key_real_len = key_noise_len - invalid_len;
    c_key = malloc(key_real_len * sizeof(char));
    strncpy(c_key, key_noise, noise_words_index);
    int real_rlt_start_index = noise_words_index + invalid_len;
    strncpy(c_key + noise_words_index, key_noise + real_rlt_start_index,
            key_noise_len - real_rlt_start_index);
    free(key_noise);
    key_noise = NULL;
    // get crypto public key
    BIO *public_key_bio = BIO_new_mem_buf(c_key, -1);
    public_key_rsa = PEM_read_bio_RSA_PUBKEY(public_key_bio, NULL, NULL, NULL);
    BIO_free(public_key_bio);
    // get crypto result len
    rsa_len = RSA_size(public_key_rsa);
}

// 加密数据
JNIEXPORT jstring JNICALL
Java_cn_com_lasong_utils_ZCrypto_encode(JNIEnv *env, jclass clazz, jstring content) {
    const char *tmp = (*env)->GetStringUTFChars(env, content, 0);
    LOGE("content : %s\n, key_orgin : %s\n, key : %s\n", tmp, c_key_b64_origin, c_key);
    char *p_en = malloc(rsa_len * sizeof(unsigned char));
    int p_len = RSA_public_encrypt(strlen(tmp), (unsigned char *) tmp, (unsigned char *) p_en,
                                 public_key_rsa, RSA_PKCS1_PADDING);
    (*env)->ReleaseStringUTFChars(env, content, tmp);

    if (p_len < 0) {
        LOGE("encode error: %d", p_len);
        return NULL;
    }
    int len = Base64encode_len(p_len);
    char *p_en_b64 = malloc(len * sizeof(char));
    Base64encode(p_en_b64, p_en, p_len);
    return (*env)->NewStringUTF(env, p_en_b64);

    // 解密实现
//    char *p_key = "-----BEGIN RSA PRIVATE KEY-----\n"
//                  XXX
//                  "-----END RSA PRIVATE KEY-----";
//    BIO *private_key_bio = BIO_new_mem_buf(p_key, -1);
//
//
//    unsigned char *p_dec = malloc(字符长度 * sizeof(unsigned char));
//    RSA *private_key_rsa = PEM_read_bio_RSAPrivateKey(private_key_bio, NULL, NULL, NULL);
//    返回解码后的字符长度
//    int len = RSA_private_decrypt(rsa_len, p_en, p_dec, private_key_rsa, RSA_PKCS1_PADDING);
}


// 返回原始key
JNIEXPORT jstring JNICALL
Java_cn_com_lasong_utils_ZCrypto_originKey(JNIEnv *env, jclass clazz) {
    return (*env)->NewStringUTF(env, c_key_b64_origin);
}
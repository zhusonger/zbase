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
    c_key_b64_origin = malloc(len_key * sizeof(char));
    strcpy(c_key_b64_origin, tmp);
    (*env)->ReleaseStringUTFChars(env, key, tmp);
    int key_b64_length = Base64decode_len(c_key_b64_origin);
    // get noise key
    char* key_noise = malloc(key_b64_length * sizeof(char));
    int key_noise_len = Base64decode(key_noise, c_key_b64_origin);
    // get real key
    int invalid_len = noise_words_size + 1;
    int key_real_len = key_noise_len - invalid_len;
    c_key = malloc(key_real_len * sizeof(char));
    strncpy(c_key, key_noise, noise_words_index);
    int real_rlt_start_index = noise_words_index + invalid_len;
    strncpy(c_key + noise_words_index, key_noise + real_rlt_start_index, key_noise_len - real_rlt_start_index);
    free(key_noise);
    key_noise = NULL;
}

// 加密数据
JNIEXPORT jstring JNICALL
Java_cn_com_lasong_utils_ZCrypto_encode(JNIEnv *env, jclass clazz, jstring content) {
    const char *tmp = (*env)->GetStringUTFChars(env, content, 0);
    LOGE("content : %s, key_orgin : %s, key : %s", tmp, c_key_b64_origin, c_key);
    (*env)->ReleaseStringUTFChars(env, content, tmp);

    return NULL;
}


// 返回原始key
JNIEXPORT jstring JNICALL
Java_cn_com_lasong_utils_ZCrypto_originKey(JNIEnv *env, jclass clazz) {

}
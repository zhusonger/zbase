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

const size_t noise_word_index = 66;
const size_t noise_word_size = 6;
const size_t aes_size = 32;

const char *client_key = NULL;
// ras key
char *rsa_key = NULL;
// aes key
char *aes_key = NULL;
// sign
char *signature = NULL;
// rsa key instance
RSA *public_key_rsa;
RSA *private_key_rsa;
int public_rsa_len;
int private_rsa_len;

// release instance
void _release() {
    public_rsa_len = 0;
    private_rsa_len = 0;
    if (rsa_key) {
        free(rsa_key);
        rsa_key = NULL;
    }
    if (aes_key) {
        free(aes_key);
        aes_key = NULL;
    }
    if (signature) {
        free(signature);
        signature = NULL;
    }
    if (public_key_rsa) {
        RSA_free(public_key_rsa);
        public_key_rsa = NULL;
    }
    if (private_key_rsa) {
        RSA_free(private_key_rsa);
        private_key_rsa = NULL;
    }
}

// alloc & init
void *malloc_z(size_t size) {
    void *ptr = malloc(size);
    if (ptr)
        memset(ptr, 0, size);
    return ptr;
}

JNIEXPORT int JNICALL Java_cn_com_lasong_utils_ZCrypto_validateClientKey
        (JNIEnv *env, jclass clz, jstring key, jstring sign) {

    _release();

    const char *rsa_aes_origin_b64 = (*env)->GetStringUTFChars(env, key, /*copy*/JNI_FALSE);
    int len_sign_index = (*env)->GetStringUTFLength(env, sign);
    signature = malloc_z(len_sign_index * sizeof(char));
    const char *sign_index_b64 = (*env)->GetStringUTFChars(env, sign, /*copy*/JNI_FALSE);
    strlcpy(signature, sign_index_b64, len_sign_index);
    char *noise_rsa_aes = malloc_z(Base64decode_len(rsa_aes_origin_b64) * sizeof(char));
    int len_noise_rsa_aes = Base64decode(noise_rsa_aes, rsa_aes_origin_b64);

    // get aes key
    int aes_offset = noise_word_size;
    // aes index
    size_t aes_index = noise_word_index - aes_offset;
    aes_key = malloc_z((aes_size + 1) * sizeof(char));
    strncpy(aes_key, noise_rsa_aes + aes_index, aes_size);
    aes_key[aes_size] = '\0';
    // get real public rsa key
    rsa_key = malloc_z((len_noise_rsa_aes - noise_word_size - aes_size + 1) * sizeof(char));
    // XXXXX  		 AES_KEY(32)  XXXX(6) 			NOISE(6) XXXXX
    //          ↑                              ↑
    //	     AES_INDEX					  NOISE_INDXE
    // part1
    strncpy(rsa_key, noise_rsa_aes, aes_index);
    // part2
    strncpy(rsa_key + aes_index, noise_rsa_aes + aes_index + aes_size, aes_offset);
    // part3
    strncpy(rsa_key + aes_index + aes_offset,
            noise_rsa_aes + aes_index + aes_size + aes_offset + noise_word_size,
            len_noise_rsa_aes - noise_word_size - aes_size - aes_index - aes_offset);
    rsa_key[len_noise_rsa_aes - noise_word_size - aes_size] = '\0';
    // get crypto public key
    BIO *public_key_bio = BIO_new_mem_buf(rsa_key, -1);
    public_key_rsa = PEM_read_bio_RSA_PUBKEY(public_key_bio, NULL, NULL, NULL);
    BIO_free_all(public_key_bio);
    // get crypto result len
    public_rsa_len = RSA_size(public_key_rsa);

    // sign verify
    char *sign_b64 = malloc_z((len_sign_index - 1) * sizeof(char));
    strncpy(sign_b64, signature, noise_word_index);
    unsigned int real_rs_start_index = noise_word_index + 1;
    strncpy(sign_b64 + noise_word_index, signature + real_rs_start_index,
            (len_sign_index - real_rs_start_index));
    char *de_sign = malloc_z((Base64decode_len(sign_b64) + 1) * sizeof(char));
    int len_de_sign = Base64decode(de_sign, sign_b64);
    de_sign[len_de_sign] = '\0';
    //sha256 digest
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *) rsa_aes_origin_b64, strlen(rsa_aes_origin_b64), md);
    int ret = RSA_verify(NID_sha256, md, SHA256_DIGEST_LENGTH, (const unsigned char *) de_sign,
                         len_de_sign, public_key_rsa);
    if (!ret) {
        _release();
    }
    (*env)->ReleaseStringUTFChars(env, key, rsa_aes_origin_b64);
    (*env)->ReleaseStringUTFChars(env, sign, sign_index_b64);
    free(noise_rsa_aes);
    noise_rsa_aes = NULL;
    free(sign_b64);
    sign_b64 = NULL;
    free(de_sign);
    de_sign = NULL;
//    LOGE("ret: %d\nAES_KEY:\n%s\n\nRSA_KEY:\n%s\nSIGNATURE\n:%s\n", ret, aes_key, rsa_key, signature);
    return ret;
}

JNIEXPORT jstring JNICALL
Java_cn_com_lasong_utils_ZCrypto_encryptRSA(JNIEnv *env, jclass clazz, jstring content) {
    if (!public_key_rsa) {
        return NULL;
    }
    const char *message = (*env)->GetStringUTFChars(env, content, 0);
    char *p_en = malloc_z(public_rsa_len * sizeof(unsigned char));
    int p_len = RSA_public_encrypt(strlen(message), (unsigned char *) message, (unsigned char *) p_en,
                                   public_key_rsa, RSA_PKCS1_PADDING);
    (*env)->ReleaseStringUTFChars(env, content, message);

    if (p_len < 0) {
        LOGE("encode error: %d", p_len);
        return NULL;
    }
    int len = Base64encode_len(p_len);
    char *p_en_b64 = malloc_z(len * sizeof(char));
    Base64encode(p_en_b64, p_en, p_len);
    return (*env)->NewStringUTF(env, p_en_b64);
}

JNIEXPORT jstring JNICALL
Java_cn_com_lasong_utils_ZCrypto_decryptRSA(JNIEnv *env, jclass clazz, jstring content) {
    if (!client_key || !content) {
        return NULL;
    }
    if (!private_key_rsa) {
        // get crypto private key
        BIO *private_key_bio = BIO_new_mem_buf((void *) client_key, -1);
        private_key_rsa = PEM_read_bio_RSAPrivateKey(private_key_bio, NULL, NULL, NULL);
        BIO_free_all(private_key_bio);
        // get crypto result len
        private_rsa_len = RSA_size(private_key_rsa);
    }

    char *encrypt_message = NULL;
    char *decrypt_result = NULL;
    char *part_text = NULL;
    char *part_decrypt_text = NULL;

    if (private_key_rsa) {
        const char *message_b64 = (*env)->GetStringUTFChars(env, content, JNI_FALSE);
        encrypt_message = malloc_z(Base64decode_len(message_b64) * sizeof(char));
        int len_encrypt_message = Base64decode(encrypt_message, message_b64);
        (*env)->ReleaseStringUTFChars(env, content, message_b64);
        // encrypt message length > decrypt message length, so use the length of encrypt message is enough
        decrypt_result = malloc_z(len_encrypt_message * sizeof(char));
        if (!decrypt_result) {
            goto error;
        }
        memset(decrypt_result, '\0', len_encrypt_message);
        int len_encrypt = len_encrypt_message;
        int offset = 0;
        int decrypt_offset = 0;
        while (len_encrypt > 0) {
            int rsa_len = len_encrypt >= private_rsa_len ? private_rsa_len : len_encrypt;
            part_text = malloc_z(rsa_len * sizeof(char));
            if (part_text) {
                memset(part_text, '\0', rsa_len);
                strncpy(part_text, encrypt_message + offset, rsa_len);
            }
            part_decrypt_text = malloc_z(rsa_len * sizeof(char));
            if (!part_decrypt_text) {
                goto error;
            }
            RSA_private_decrypt(private_rsa_len, (const unsigned char *) encrypt_message + offset,
                                (unsigned char *) part_decrypt_text,
                                private_key_rsa, RSA_PKCS1_PADDING);
            strncpy(decrypt_result + decrypt_offset, part_decrypt_text, rsa_len);
//            LOGE("part_decrypt_text : %s\n", part_decrypt_text);
            len_encrypt -= rsa_len;
            offset += rsa_len;
            decrypt_offset += strlen(part_decrypt_text);
            if (part_text) {
                free(part_text);
                part_text = NULL;
            }
            free(part_decrypt_text);
            part_decrypt_text = NULL;
        }
//        LOGE("decrypt_result : %s\n", decrypt_result);
        jstring j_decrypt = (*env)->NewStringUTF(env, decrypt_result);
        free(encrypt_message);
        encrypt_message = NULL;
        free(decrypt_result);
        decrypt_result = NULL;
        return j_decrypt;
    }
    error:
    if (part_text) {
        free(part_text);
        part_text = NULL;
    }
    if (part_decrypt_text) {
        free(part_decrypt_text);
        part_decrypt_text = NULL;
    }
    if (encrypt_message) {
        free(encrypt_message);
        encrypt_message = NULL;
    }
    if (decrypt_result) {
        free(decrypt_result);
        decrypt_result = NULL;
    }
    return NULL;

}

JNIEXPORT void JNICALL
Java_cn_com_lasong_utils_ZCrypto_release(JNIEnv *env, jclass clazz) {
    _release();
}
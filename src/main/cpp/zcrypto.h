//
// Created by 朱凇 on 2021/8/18.
//

/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class cn_com_lasong_utils_ZCrypto */

#ifndef _Included_cn_com_lasong_utils_ZCrypto
#define _Included_cn_com_lasong_utils_ZCrypto
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     cn_com_lasong_utils_ZCrypto
 * Method:    validateClientKey
 * Signature: (Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_cn_com_lasong_utils_ZCrypto_validateClientKey
(JNIEnv *, jclass, jstring);

JNIEXPORT jstring JNICALL
Java_cn_com_lasong_utils_ZCrypto_encode(JNIEnv *, jclass, jstring);

JNIEXPORT jstring JNICALL
Java_cn_com_lasong_utils_ZCrypto_originKey(JNIEnv *, jclass);
#ifdef __cplusplus
}
#endif
#endif


package cn.com.lasong.utils;

import org.json.JSONObject;

/**
 * Author: zhusong
 * Email: song.zhu@lasong.com.cn
 * Date: 2021/8/18
 * Description:
 * 加密相关native方法
 */
public class ZCrypto {
    static {
        System.loadLibrary("ssl");
        System.loadLibrary("crypto");
        System.loadLibrary("zcrypto");
    }

    /**
     * 验证服务端返回的密钥与签名
     * @param key 密钥
     * @param sign 签名
     * @return 0为成功, <0 为失败, 失败会清空所有加解密相关的对象
     */
    public static native int validateClientKey(String key, String sign);

    /**
     * 使用服务端公钥RSA加密
     * @param content 需要加密的内容
     * @return 加密结果
     */
    public static native String encryptRSA(String content);

    /**
     * 使用客户端私钥RSA解密
     * @param content 需要解密的内容
     * @return 解密结果
     */
    public static native String decryptRSA(String content);

    /**
     * AES加密
     * @param content 需要加密的内容
     * @return 加密结果
     */
    public static native String encryptAES(String content);

    /**
     * AES解密
     * @param content 需要解密的内容
     * @return 解密结果
     */
    public static native String decryptAES(String content);

    /**
     * 对内容签名
     * @param content 加密的内容
     * @return 签名
     */
    public static native String signature(String content);

    /**
     * 释放加解密相关的对象
     */
    public static native void release();


    /**
     * 解密与验证客户端
     * @param content 加密的内容
     * @return 成功0, 其他失败
     */
    public static int decryptAndValidClient(String content) {
        if (null != content) {
            String key_sign = ZCrypto.decryptRSA(content);
            try {
                JSONObject json = new JSONObject(key_sign);
                return ZCrypto.validateClientKey(json.optString("key"),
                        json.optString("signature"));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return -1;
    }
}

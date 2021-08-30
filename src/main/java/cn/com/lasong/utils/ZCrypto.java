package cn.com.lasong.utils;

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
     * @return 1为成功, 0为失败, 失败会清空所有加解密相关的对象
     */
    public static native int validateClientKey(String key, String sign);

    /**
     * 使用服务端公钥RSA加密
     * @param content 需要解密的内容
     * @return 加密结果
     */
    public static native String encryptRSA(String content);

    /**
     * 使用客户端私钥RSA解密
     * @param content 需要加密的内容
     * @return 解密结果
     */
    public static native String decryptRSA(String content);

    /**
     * 释放加解密相关的对象
     */
    public static native void release();
}

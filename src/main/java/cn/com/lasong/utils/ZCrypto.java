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
    public static native void validateClientKey(String clientKey);

    public static native String encode(String content);

    public static native String originKey();
}

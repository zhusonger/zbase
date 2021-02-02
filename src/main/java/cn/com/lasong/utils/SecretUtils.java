package cn.com.lasong.utils;

import java.util.UUID;

/**
 * Author: zhusong
 * Email: song.zhu@lasong.com.cn
 * Date: 2021/2/2
 * Description: 安全相关工具类
 */
public class SecretUtils {

    /**
     * 获取唯一码UUID
     * @param origin
     * @return
     */
    public static String uuid(String origin) {
        return UUID.nameUUIDFromBytes(origin.getBytes()).toString();
    }
}

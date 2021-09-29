package cn.com.lasong.utils;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;

import java.security.MessageDigest;
import java.util.Locale;
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
     *
     * @param origin
     * @return
     */
    public static String uuid(String origin) {
        return UUID.nameUUIDFromBytes(origin.getBytes()).toString();
    }

    /**
     * @param context
     * @return 获取应用签名
     */
    @SuppressLint("PackageManagerGetSignatures")
    public static String getSignature(Context context) {
        try {
            String pkgName = context.getPackageName();
            PackageManager manager = context.getPackageManager();
            PackageInfo packageInfo = manager.getPackageInfo(pkgName, PackageManager.GET_SIGNATURES);
            Signature[] signatures = packageInfo.signatures;
            byte[] bytes = signatures[0].toByteArray();
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] publicKey = md.digest(bytes);
            StringBuilder hexString = new StringBuilder();
            for (byte b : publicKey) {
                String appendString = Integer.toHexString(0xFF & b)
                        .toUpperCase(Locale.US);
                if (appendString.length() == 1)
                    hexString.append("0");
                hexString.append(appendString);
                hexString.append(":");
            }
            return hexString.toString();
        } catch (Exception e) {
            return null;
        }
    }
}

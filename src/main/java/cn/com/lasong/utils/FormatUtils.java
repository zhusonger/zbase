package cn.com.lasong.utils;

import java.util.Locale;
import java.util.concurrent.TimeUnit;

/**
 * Author: zhusong
 * Email: song.zhu@lasong.com.cn
 * Date: 2019/10/27
 * Description:
 */
public class FormatUtils {

    public static String getDurationHms(long duration) {
        if (duration <= 0) {
            return "00:00:00";
        }
        long hours = TimeUnit.MILLISECONDS.toHours(duration);
        long minutes = TimeUnit.MILLISECONDS.toMinutes(duration - TimeUnit.HOURS.toMillis(hours));
        long seconds = TimeUnit.MILLISECONDS.toSeconds(duration - TimeUnit.HOURS.toMillis(hours)
                - TimeUnit.MINUTES.toMillis(minutes));
        return String.format(Locale.CHINA, "%02d:%02d:%02d", hours, minutes, seconds);
    }

    public static String getDurationMs(long duration) {
        if (duration <= 0) {
            return "00:00";
        }
        long minutes = TimeUnit.MILLISECONDS.toMinutes(duration);
        long seconds = TimeUnit.MILLISECONDS.toSeconds(duration - TimeUnit.MINUTES.toMillis(minutes));
        return String.format(Locale.CHINA, "%02d:%02d", minutes, seconds);
    }

    /**
     * 获取时间间隔文本
     */
    public static String getDuration(/*ms*/long duration) {
        long hours = TimeUnit.MILLISECONDS.toHours(duration);
        if (hours > 0) {
            return getDurationHms(duration);
        } else {
            return getDurationMs(duration);
        }
    }
}

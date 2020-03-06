package cn.com.lasong.utils;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.Point;
import android.os.Build;
import android.view.WindowManager;

/**
 * Author: zhusong
 * Email: song.zhu@kascend.com
 * Date: 2019/10/23
 * Description:
 */
public class DeviceUtils {
    /**
     * 获取屏幕宽高
     */
    private static Point sSize = new Point();
    public static Point getRealScreenSize(Context context) {
        if (null != context) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                WindowManager manager = (WindowManager) context.getSystemService(Context.WINDOW_SERVICE);
                manager.getDefaultDisplay().getRealSize(sSize);
            } else {
                WindowManager manager = (WindowManager) context.getSystemService(Context.WINDOW_SERVICE);
                manager.getDefaultDisplay().getSize(sSize);
            }
        }

        return sSize;
    }

    /**
     * @param context context
     * @return a point which contains the width and height of the screen
     */
    public static Point getScreenSize(Context context) {
        WindowManager manager = (WindowManager) context.getSystemService(Context.WINDOW_SERVICE);
        Point pt = new Point();
        manager.getDefaultDisplay().getSize(pt);
        return pt;
    }

    /**
     * Value of dp to value of px.
     *
     * @param dpValue The value of dp.
     * @return value of px
     */
    public static int dp2px(final float dpValue) {
        final float scale = Resources.getSystem().getDisplayMetrics().density;
        return (int) (dpValue * scale + 0.5f);
    }

    /**
     * Value of px to value of dp.
     *
     * @param pxValue The value of px.
     * @return value of dp
     */
    public static int px2dp(final float pxValue) {
        final float scale = Resources.getSystem().getDisplayMetrics().density;
        return (int) (pxValue / scale + 0.5f);
    }

    /**
     * Value of sp to value of px.
     *
     * @param spValue The value of sp.
     * @return value of px
     */
    public static int sp2px(final float spValue) {
        final float fontScale = Resources.getSystem().getDisplayMetrics().scaledDensity;
        return (int) (spValue * fontScale + 0.5f);
    }

    /**
     * Value of px to value of sp.
     *
     * @param pxValue The value of px.
     * @return value of sp
     */
    public static int px2sp(final float pxValue) {
        final float fontScale = Resources.getSystem().getDisplayMetrics().scaledDensity;
        return (int) (pxValue / fontScale + 0.5f);
    }
}

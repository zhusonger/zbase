package cn.com.lasong.utils;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Looper;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckedTextView;
import android.widget.FrameLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.StringRes;

import cn.com.lasong.base.AppManager;
import cn.com.lasong.base.R;

/**
 * Created by zhusong on 17/5/19.
 */

public class TN {
    private static Toast sToast = null;
    private static int sTextSize = 14;
    private static int sHorizontal = DeviceUtils.dp2px(10);
    private static int sVertical = DeviceUtils.dp2px(10);
    private static int sMargin = DeviceUtils.dp2px(28);

    /**
     * 设置字体大小
     * @param textSize
     */
    public static void setTextSize(int textSize) {
        if (textSize <= 0) {
            return;
        }
        sTextSize = textSize;
    }

    /**
     * 设置内间距
     */
    public static void setPadding(int horizontal, int vertical) {
        sHorizontal = horizontal;
        sVertical = vertical;
    }

    /**
     * 设置左右外间距
     * @param margin
     */
    public static void setMargin(int margin) {
        sMargin = margin;
    }

    public static void show(@StringRes int tipId) {
        Context context = AppManager.getInstance().current();
        if (null == context) {
            return;
        }
        show(context.getString(tipId));
    }

    public static void show(String tip) {
        show(tip, false, false);
    }

    @SuppressLint("ShowToast")
    public static void show(String tip, boolean checked, boolean enable) {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            ILog.e("T", "T is not show on MainThread");
            return;
        }
        if (TextUtils.isEmpty(tip)) {
            return;
        }
        Context context = AppManager.getInstance().current();
        if (null == context) {
            return;
        }
        if (null == sToast) {
            sToast = Toast.makeText(context, tip, Toast.LENGTH_SHORT);
            View customView = LayoutInflater.from(context).inflate(R.layout.view_t_default, null);
            TextView toast_custom_tv = customView.findViewById(R.id.toast_custom_tv);
            toast_custom_tv.setTextSize(TypedValue.COMPLEX_UNIT_SP, sTextSize);
            sToast.setView(customView);
            sToast.setGravity(Gravity.BOTTOM|Gravity.FILL_HORIZONTAL, 0, DeviceUtils.dp2px(240));
        }
        View customView = sToast.getView();
        if (null != customView) {
            CheckedTextView toast_custom_tv = customView.findViewById(R.id.toast_custom_tv);
            FrameLayout flToast = customView.findViewById(R.id.fl_toast);
            ViewGroup.MarginLayoutParams lp = (ViewGroup.MarginLayoutParams) flToast.getLayoutParams();
            lp.leftMargin = sMargin;
            lp.rightMargin = sMargin;
            flToast.setLayoutParams(lp);
            toast_custom_tv.setTextSize(TypedValue.COMPLEX_UNIT_SP, sTextSize);
            toast_custom_tv.setPadding(sHorizontal, sVertical, sHorizontal, sVertical);
            toast_custom_tv.setText(tip);
            toast_custom_tv.setEnabled(enable);
            toast_custom_tv.setChecked(checked);
        }
        sToast.show();
    }

    public static void showNew(String tip) {
        Context context = AppManager.getInstance().current();
        if (null == context) {
            return;
        }
        Toast toast = Toast.makeText(context, tip, Toast.LENGTH_SHORT);
        View customView = LayoutInflater.from(context).inflate(R.layout.view_t_default, null);
        TextView toast_custom_tv = customView.findViewById(R.id.toast_custom_tv);
        toast_custom_tv.setTextSize(TypedValue.COMPLEX_UNIT_SP, sTextSize);
        toast_custom_tv.setPadding(sHorizontal, sVertical, sHorizontal, sVertical);
        FrameLayout flToast = customView.findViewById(R.id.fl_toast);
        ViewGroup.MarginLayoutParams lp = (ViewGroup.MarginLayoutParams) flToast.getLayoutParams();
        lp.leftMargin = sMargin;
        lp.rightMargin = sMargin;
        flToast.setLayoutParams(lp);
        toast.setView(customView);
        toast.setGravity(Gravity.BOTTOM|Gravity.FILL_HORIZONTAL, 0, DeviceUtils.dp2px(240));
        toast.show();
    }

    /**
     * 显示居中红色背景提示
     */
    public static void showError(@StringRes int tipId) {
        Context context = AppManager.getInstance().current();
        if (null == context) {
            return;
        }
        showError(context.getString(tipId));
    }
    public static void showError(String str) {
        show(str, true, false);
    }
}

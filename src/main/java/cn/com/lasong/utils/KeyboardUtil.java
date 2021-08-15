package cn.com.lasong.utils;

import android.content.Context;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;

import androidx.annotation.NonNull;

/**
 * Author: zhusong
 * Email: song.zhu@lasong.com.cn
 * Date: 2021/8/15
 * Description:
 * 键盘工具类
 */
public class KeyboardUtil {
    /**
     * hide soft input
     *
     * @param view any view
     */
    public static void hideSoftInput(@NonNull View view) {
        InputMethodManager imm = (InputMethodManager) view.getContext().getApplicationContext().getSystemService(Context.INPUT_METHOD_SERVICE);
        if (imm != null) {
            imm.hideSoftInputFromWindow(view.getWindowToken(), 0);
            view.clearFocus();
        }
    }

    /**
     * show soft input
     *
     * @param view edit text view
     */
    public static void showSoftInput(@NonNull EditText view) {
        view.setFocusable(true);
        InputMethodManager imm = (InputMethodManager) view.getContext().getApplicationContext().getSystemService(Context.INPUT_METHOD_SERVICE);
        if (imm != null) {
            view.requestFocus();
            imm.showSoftInput(view, 0);
        }
    }
}

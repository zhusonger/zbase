package cn.com.lasong.base;

import android.os.Bundle;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.ViewModel;
import androidx.lifecycle.ViewModelProvider;

import cn.com.lasong.base.result.PERCallback;
import cn.com.lasong.base.result.PERCaller;
import cn.com.lasong.base.result.PERLifecycleObserver;

/**
 * Author: zhusong
 * Email: song.zhu@lasong.com.cn
 * Date: 2020-03-04
 * Description: activity基类
 */
public class BaseActivity extends AppCompatActivity implements PERCaller {

    private PERLifecycleObserver mPERObserver;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mPERObserver = new PERLifecycleObserver(getActivityResultRegistry());
        getLifecycle().addObserver(mPERObserver);
    }


    /**
     * 权限请求
     * @param callback
     * @param permissions
     */
    @Override
    public void requestPermissions(PERCallback callback, String... permissions) {
        mPERObserver.requestPermissions(callback, permissions);
    }
}

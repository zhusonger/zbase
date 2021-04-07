package cn.com.lasong.base;

import android.os.Bundle;

import androidx.activity.result.ActivityResultRegistry;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import cn.com.lasong.base.result.PERCallback;
import cn.com.lasong.base.result.PERCaller;
import cn.com.lasong.base.result.PERLifecycleObserver;

/**
 * Author: zhusong
 * Email: song.zhu@lasong.com.cn
 * Date: 2021/2/2
 * Description: 基类Fragment
 */
public class BaseFragment extends Fragment implements PERCaller {

    private PERLifecycleObserver mPERObserver;
    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mPERObserver = new PERLifecycleObserver(requireActivity().getActivityResultRegistry());
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

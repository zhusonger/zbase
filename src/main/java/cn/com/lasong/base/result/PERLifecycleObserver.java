package cn.com.lasong.base.result;

import android.util.Log;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.ActivityResultRegistry;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.lifecycle.Lifecycle;
import androidx.lifecycle.LifecycleEventObserver;
import androidx.lifecycle.LifecycleOwner;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.atomic.AtomicInteger;

import cn.com.lasong.utils.ILog;
import cn.com.lasong.utils.SecretUtils;

/**
 * Author: zhusong
 * Email: song.zhu@lasong.com.cn
 * Date: 2021/2/1
 * Description: 由Activity管理的生命周期监听类
 */
public class PERLifecycleObserver implements LifecycleEventObserver {

    private final AtomicInteger mNextLocalRequestCode = new AtomicInteger();
    private final ActivityResultRegistry mRegistry;

    // 处理权限请求
    private Map<String, Queue<PERCallback>> mCallbacks = new HashMap<>();
    private ActivityResultLauncher<String[]> mLauncher;
    private String TAG = "PERLifecycleObserver";

    public PERLifecycleObserver(@NonNull ActivityResultRegistry registry) {
        this.mRegistry = registry;
    }


    public void onCreate(@NonNull LifecycleOwner owner) {
        mLauncher = mRegistry.register(
                "fragment_rq_"+owner.getClass().getSimpleName()+"#" + mNextLocalRequestCode.getAndIncrement(),
                owner, new ActivityResultContracts.RequestMultiplePermissions(),
                result -> {
                    List<String> keys = new ArrayList<>(result.keySet());
                    Collections.sort(keys);
                    StringBuilder builder = new StringBuilder();
                    Boolean isGrant = true;
                    for (String permission : keys) {
                        builder.append(permission);
                        isGrant &= result.get(permission);
                    }
                    String key = SecretUtils.uuid(builder.toString());
                    Queue<PERCallback> queue = mCallbacks.remove(key);
                    if (null != queue) {
                        for (PERCallback callback: queue) {
                            if (null != callback) {
                                try {
                                    callback.onResult(isGrant, result);
                                } catch (Exception e) {
                                    Log.e(TAG, "Permissions Result Error, Check it!", e);
                                }
                            }
                        }

                    }
                });
    }

    public void onDestroy(@NonNull LifecycleOwner owner) {
        mCallbacks.clear();
    }


    /**
     * 请求权限
     * @param callback 回调
     * @param permissions 权限数组
     */
    public void requestPermissions(PERCallback callback, String... permissions) {
        if (null != callback) {
            List<String> keys = Arrays.asList(permissions);
            Collections.sort(keys);
            StringBuilder builder = new StringBuilder();
            for (String permission : keys) {
                builder.append(permission);
            }
            String key = SecretUtils.uuid(builder.toString());
            // 使用数组是为了处理相同权限在不同位置的请求
            Queue<PERCallback> queue = mCallbacks.get(key);
            if (queue == null) {
                queue = new LinkedList<>();
                mCallbacks.put(key, queue);
            }
            queue.offer(callback);
        }
        mLauncher.launch(permissions);

    }

    @Override
    public void onStateChanged(@NonNull LifecycleOwner owner, @NonNull Lifecycle.Event event) {
        switch (event) {
            case ON_CREATE:
                onCreate(owner);
                break;
            case ON_DESTROY:
                onDestroy(owner);
                break;
        }
    }
}

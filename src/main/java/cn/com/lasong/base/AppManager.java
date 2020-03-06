package cn.com.lasong.base;

import android.app.Activity;

import androidx.annotation.NonNull;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Author: zhusong
 * Email: song.zhu@lasong.com.cn
 * Date: 2020-03-04
 * Description: activity管理类
 */
public class AppManager {

    private static class Holder {
        private static final AppManager INSTANCE = new AppManager();
    }

    private AppManager(){}

    public static AppManager getInstance() {
        return Holder.INSTANCE;
    }

    private Map<String, List<WeakReference<Activity>>> mLifeActivities = new HashMap<>();
    // 一般情况 mCurrent 跟 mCurrentVisible 相同, 但是在启动新Activity, 可能出现mCurrent是正准备展示的Activity
    // 当前显示activity
    private WeakReference<Activity> mCurrent;
    public void onCreate(@NonNull Activity activity) {
        String name = activity.getClass().getName();
        List<WeakReference<Activity>> list = mLifeActivities.get(name);
        if (null == list) {
            list = new ArrayList<>();
            mLifeActivities.put(name, list);
        }
        list.add(new WeakReference<Activity>(activity));
        mCurrent = new WeakReference<>(activity);
    }

    public void onStart(@NonNull Activity activity) {
    }

    public void onResume(@NonNull Activity activity) {
    }

    public void onPause(@NonNull Activity activity) {
    }
    public void onStop(Activity activity) {
    }

    public void onDestroy(@NonNull Activity activity) {
        String name = activity.getClass().getName();
        List<WeakReference<Activity>> list = mLifeActivities.get(name);
        if (null == list) {
            return;
        }
        WeakReference<Activity> removeRef = null;
        for (WeakReference<Activity> ref : list) {
            Activity value = ref.get();
            if (value == activity) {
                removeRef = ref;
                break;
            }
        }
        if (null != removeRef) {
            list.remove(removeRef);
        }
    }

    public Activity current() {
        if (null == mCurrent || mCurrent.get() == null) {
            return null;
        }
        return mCurrent.get();
    }

    public Activity getActivity(@NonNull String key){
        List<WeakReference<Activity>> list = mLifeActivities.get(key);
        if (null == list || list.isEmpty()) {
            return null;
        }
        for(WeakReference<Activity> weakActivity :list){
            Activity activity = weakActivity.get();
            if(activity == null){
                continue;
            }
            if(activity.getClass().getName().equals(key)){
                return activity;
            }
        }
        return null;
    }

    public void finishRecent(@NonNull String key) {
        List<WeakReference<Activity>> list = mLifeActivities.get(key);
        if (null == list || list.isEmpty()) {
            return;
        }
        WeakReference<Activity> last = list.get(list.size() - 1);
        Activity activity = last.get();
        if (null == activity) {
            return;
        }
        activity.finish();
    }

    public void finishAll(@NonNull String key) {
        List<WeakReference<Activity>> list = mLifeActivities.get(key);
        if (null == list || list.isEmpty()) {
            return;
        }
        for (WeakReference<Activity> ref : list) {
            Activity activity = ref.get();
            if (activity == null) {
                continue;
            }
            activity.finish();
        }
        list.clear();
    }

    public void finishCurrent() {
        if (null != mCurrent && mCurrent.get() != null) {
            Activity activity = mCurrent.get();
            activity.finish();
        }
    }

    public void exit() {
        Set<String> keys = mLifeActivities.keySet();
        for (String key : keys) {
            finishAll(key);
        }
    }
}

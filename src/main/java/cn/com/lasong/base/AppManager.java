package cn.com.lasong.base;

import android.app.Activity;

import androidx.annotation.NonNull;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;

/**
 * Author: zhusong
 * Email: song.zhu@lasong.com.cn
 * Date: 2020-03-04
 * Description: activity管理类
 */
public class AppManager {

    private static class Holder {
       public static final AppManager INSTANCE = new AppManager();
    }

    private AppManager(){}

    public static AppManager getInstance() {
        return Holder.INSTANCE;
    }

    private List<Activity> mActivities = Collections.synchronizedList(new LinkedList<>());

    public void onCreate(@NonNull Activity activity) {
        mActivities.add(activity);
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
        mActivities.remove(activity);
    }

    /**
     * 获取当前的activity
     * @return
     */
    public Activity current() {
        if (mActivities.isEmpty()) {
            return null;
        }
        return mActivities.get(mActivities.size() - 1);

    }

    /**
     * 获取最后一个指定类的activity
     * @param clz
     * @param <A>
     * @return
     */
    public <A extends Activity> A getLastActivity(@NonNull Class<A> clz){
        if (mActivities.isEmpty()) {
            return null;
        }

        ListIterator<Activity> iterator = mActivities.listIterator(mActivities.size());
        while (iterator.hasPrevious()) {
            Activity activity = iterator.previous();
            if (clz.isInstance(activity)) {
                return (A) activity;
            }
        }
        return null;
    }

    /**
     * 移除最后一个指定类的activity
     * @param clz
     * @param <A>
     */
    public <A extends Activity> void finishLastActivity(@NonNull Class<A> clz) {
        if (mActivities.isEmpty()) {
            return;
        }

        ListIterator<Activity> iterator = mActivities.listIterator(mActivities.size());
        while (iterator.hasPrevious()) {
            Activity activity = iterator.previous();
            if (clz.isInstance(activity)) {
                activity.finish();
                break;
            }
        }
    }
}

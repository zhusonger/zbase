package cn.com.lasong.buffer;

import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;

/**
 * Author: zhusong
 * Email: song.zhu@lasong.com.cn
 * Date: 2020/9/2
 * Description:
 * 缓冲任务
 */
public class Buffer {

    private static Handler sHandler = new Handler(Looper.getMainLooper());


    /**
     * 缓冲队列, BufferStream的token必须是同一个才会进行同一个缓冲
     * 没有token就直接运行
     * @param stream
     */
    public static void doIt(BufferStream stream) {
        if (null == stream) {
            return;
        }
        Object token = stream.get();
        // 没有token, 直接运行
        if (token == null) {
            stream.run();
            return;
        }
        // 移除token相关的延时任务
        sHandler.removeCallbacksAndMessages(token);
        // 延时执行
        long delayMillis = stream.delay;
        if (delayMillis < 0) {
            delayMillis = 0;
        }
        sHandler.postAtTime(stream, token, SystemClock.uptimeMillis() + delayMillis);
    }
}

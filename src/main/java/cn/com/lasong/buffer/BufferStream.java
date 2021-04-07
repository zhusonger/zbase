package cn.com.lasong.buffer;

import java.lang.ref.WeakReference;

/**
 * Author: zhusong
 * Email: song.zhu@lasong.com.cn
 * Date: 2020/9/2
 * Description:
 */
public abstract class BufferStream extends WeakReference<Object> implements Runnable {

    // 缓冲时长,ms
    long delay = 300;

    public BufferStream(Object token) {
        super(token);
    }

    public BufferStream(Object token, long delay) {
        super(token);
        this.delay = delay;
    }
}

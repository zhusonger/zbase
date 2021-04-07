package cn.com.lasong.base.result;

/**
 * Author: zhusong
 * Email: song.zhu@lasong.com.cn
 * Date: 2021/3/5
 * Description:
 */
public interface PERCaller {
    void requestPermissions(PERCallback callback, String... permissions);
}

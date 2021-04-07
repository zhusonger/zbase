package cn.com.lasong.base.result;

import java.util.Map;

/**
 * Author: zhusong
 * Email: song.zhu@lasong.com.cn
 * Date: 2021/2/2
 * Description: 权限请求结果
 */
public interface PERCallback {
    void onResult(boolean isGrant, Map<String, Boolean> result);
}

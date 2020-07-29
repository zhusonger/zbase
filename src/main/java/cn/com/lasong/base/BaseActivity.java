package cn.com.lasong.base;

import android.content.pm.PackageManager;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

/**
 * Author: zhusong
 * Email: song.zhu@lasong.com.cn
 * Date: 2020-03-04
 * Description: activity基类
 */
public class BaseActivity extends AppCompatActivity {

    protected final int REQ_PERMISSION = 0x007;

    protected boolean requestAllPermissions(String... permissions) {
        int length = permissions.length;
        for (int i = 0; i < length; i++) {
            if(ContextCompat.checkSelfPermission(this, permissions[i]) != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this, permissions,
                        REQ_PERMISSION);
                return false;
            }
        }
        return true;
    }
}

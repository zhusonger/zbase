package cn.com.lasong.utils;

import android.util.Log;

import java.util.Collection;
import java.util.Map;

/**
 * Author: zhusong
 * Email: song.zhu@kascend.com
 * Date: 2019/10/22
 * Description:
 */
public class ILog {

    private static final String TAG = "ILog";
    private static int sLogLevel = Log.ERROR;

    public static void setLogLevel(int level) {
        sLogLevel = level;
    }

    public static void d(Map<? extends Object, ? extends Collection> map) {
        d(TAG, map);
    }
    public static void d(String tag, Map<? extends Object, ? extends Collection> map) {
        if (sLogLevel <= Log.DEBUG) {
            if (null != map && !map.isEmpty()) {
                StringBuilder sb = new StringBuilder("[");
                for (Map.Entry<? extends Object, ? extends Collection> item : map.entrySet()) {
                    Object key = item.getKey();
                    Collection value = item.getValue();
                    sb.append("{");
                    sb.append("\"").append(key).append("\":");
                    sb.append(formatCollection(value));
                    sb.append("}").append(",");
                }
                sb.deleteCharAt(sb.length() - 1);
                sb.append("]");
                Log.d(tag, sb.toString());
            }
        }
    }

    public static void d(String tag, String msg, Collection collection) {
        if (sLogLevel <= Log.DEBUG) {
            Log.d(tag, msg + formatCollection(collection));
        }
    }
    public static void d(String tag, Collection collection) {
        d(tag, "", collection);
    }

    private static String formatCollection(Collection collection) {
        if (null != collection && !collection.isEmpty()) {
            StringBuilder sb = new StringBuilder("[");
            for (Object item : collection) {
                sb.append(item).append(",");
            }
            sb.deleteCharAt(sb.length() - 1);
            sb.append("]");
            return sb.toString();
        }

        return null;
    }
    public static void d(Collection collection) {
        d(TAG, collection);
    }

    public static void d(String msg) {
        if (sLogLevel <= Log.DEBUG) {
            StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
            String nameILog = ILog.class.getName();
            String tag = TAG;
            for (int i = 0; i < stackTrace.length; i++) {
                String classname = stackTrace[i].getClassName();
                if (classname.equals(nameILog)) {
                    String srcClzName = stackTrace[i+1].getClassName();
                    int start = srcClzName.lastIndexOf(".");
                    srcClzName = srcClzName.substring(start+1);
                    tag = srcClzName;
                    break;
                }
            }
            Log.d(tag, msg);
        }
    }

    public static void ds(String tag, String msg, Object... args) {
        if (sLogLevel <= Log.DEBUG) {
            Log.d(tag, getContent(msg, 4, args));
        }
    }

    public static void ds(String msg, Object... args) {
        if (sLogLevel <= Log.DEBUG) {
            Log.d(TAG, getContent(msg, 4, args));
        }
    }



    public static void d(String tag, String msg) {
        if (sLogLevel <= Log.DEBUG) {
            Log.d(tag, msg);
        }
    }

    public static void d(String tag, String msg, Throwable tr) {
        if (sLogLevel <= Log.DEBUG) {
            Log.d(tag, msg, tr);
        }
    }

    public static void e(Throwable tr) {
        if (sLogLevel <= Log.ERROR) {
            StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
            String nameILog = ILog.class.getName();
            String tag = TAG;
            for (int i = 0; i < stackTrace.length; i++) {
                String classname = stackTrace[i].getClassName();
                if (classname.equals(nameILog)) {
                    String srcClzName = stackTrace[i+1].getClassName();
                    int start = srcClzName.lastIndexOf(".");
                    srcClzName = srcClzName.substring(start+1);
                    tag = srcClzName;
                    break;
                }
            }
            Log.e(tag, "", tr);
        }
    }

    public static void e(String tag, Throwable tr) {
        if (sLogLevel <= Log.ERROR) {
            Log.e(tag, "", tr);
        }
    }

    public static void e(String msg) {
        if (sLogLevel <= Log.ERROR) {
            StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
            String nameILog = ILog.class.getName();
            String tag = TAG;
            for (int i = 0; i < stackTrace.length; i++) {
                String classname = stackTrace[i].getClassName();
                if (classname.equals(nameILog)) {
                    String srcClzName = stackTrace[i+1].getClassName();
                    int start = srcClzName.lastIndexOf(".");
                    srcClzName = srcClzName.substring(start+1);
                    tag = srcClzName;
                    break;
                }
            }
            Log.e(tag, msg);
        }
    }

    public static void e(String tag, String msg) {
        if (sLogLevel <= Log.ERROR) {
            Log.e(tag, msg);
        }
    }

    public static void e(String tag, String msg, Throwable tr) {
        if (sLogLevel <= Log.ERROR) {
            Log.e(tag, msg, tr);
        }
    }

    public static void i(String tag, String msg) {
        if (sLogLevel <= Log.INFO) {
            Log.i(tag, msg);
        }
    }

    public static void w(String msg) {
        if (sLogLevel <= Log.WARN) {
            StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
            String nameILog = ILog.class.getName();
            String tag = TAG;
            for (int i = 0; i < stackTrace.length; i++) {
                String classname = stackTrace[i].getClassName();
                if (classname.equals(nameILog)) {
                    String srcClzName = stackTrace[i+1].getClassName();
                    int start = srcClzName.lastIndexOf(".");
                    srcClzName = srcClzName.substring(start+1);
                    tag = srcClzName;
                    break;
                }
            }
            Log.w(tag, msg);
        }
    }

    public static void w(String tag, String msg) {
        if (sLogLevel <= Log.WARN) {
            Log.w(tag, msg);
        }
    }

    private static String getContent(String msg, int place, Object... args) {
        try {
            String sourceLinks = getNameFromTrace(Thread.currentThread().getStackTrace(), place);
            return String.format(msg, args)+ sourceLinks;
        } catch (Throwable throwable) {
            return msg;
        }
    }

    private static String getNameFromTrace(StackTraceElement[] traceElements, int place) {
        StringBuilder taskName = new StringBuilder();
        int end = traceElements != null ? Math.min(traceElements.length, place + 3) : place;
        int start = place;
        for (int i = start; i < end; i++) {
            StackTraceElement traceElement = traceElements[i];
            taskName.append("\n\tat ").append(traceElement.toString());
        }
//        //判断调用栈的层级，大于place的才打印Log输出
//        if (traceElements != null && traceElements.length > place) {
//            StackTraceElement traceElement = traceElements[place];
//            taskName.append(traceElement.getMethodName());
//            taskName.append("(").append(traceElement.getFileName()).append(":").append(traceElement.getLineNumber()).append(")");
//        }
        return taskName.toString();
    }
}

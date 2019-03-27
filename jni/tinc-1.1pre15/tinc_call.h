#ifndef _TINC_CALL_H_
#define _TINC_CALL_H_
// 引入log头文件
#include  <android/log.h>
// log标签
#define  TAG    "这里填写日志的TAG"
// 定义info信息
//#define LOGI(...)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,TAG,__VA_ARGS__)
// 定义debug信息
//#define LOGD(...)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
// 定义error信息

//#define LOGE(...)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,TAG,__VA_ARGS__)
int set_supernode(char *confbase);
int prepare_tinc(char *confbase);
int start_tinc();
int stop_tinc();
int status_tinc(int retry_max);
int udpsocket_tinc();
int tcpsocket_tinc();
int get_in_KB();
int get_out_KB();
void reset_in_out_bytes();
#endif

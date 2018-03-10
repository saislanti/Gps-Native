LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := libss
LOCAL_LDLIBS	:= -llog 

LOCAL_SRC_FILES := hook_ioctl.c \
	hook.c

include $(BUILD_SHARED_LIBRARY)

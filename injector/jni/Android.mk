LOCAL_PATH := $(call my-dir)    
    
include $(CLEAR_VARS)    
LOCAL_MODULE := injector_ss     
LOCAL_SRC_FILES := inject.c     
    
#shellcode.s    
    
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog  

LOCAL_CFLAGS += -fPIE

LOCAL_LDFLAGS += -fPIE -pie  
    
#LOCAL_FORCE_STATIC_EXECUTABLE := true    
    
include $(BUILD_EXECUTABLE)    
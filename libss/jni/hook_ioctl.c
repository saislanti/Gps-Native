#include <unistd.h>
#include <sys/types.h>
#include <android/log.h>
#include <linux/binder.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>


#include <android/log.h>


#include <sys/un.h>


#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hook.h"


#define BWR_SIZE sizeof(struct binder_write_read)
#define BTD_SIZE sizeof(struct binder_transaction_data)
#define VALID_SIZE (BTD_SIZE + sizeof(unsigned long))
#define MSG_LEN 15

#define LOCATION_KEY 	"ILocationManager"
#define GPS_KEY			"gps"
#define NETWORK_KEY		"network"
#define READ_SMS_KEY 	"content://sms"
#define RECV_SMS_KEY	"SmsReceiverService"
#define SEND_SMS_KEY	"ISms"
#define CONTACTS_KEY 	"content://contacts"
#define BOOKMARKS_KEY	"content://browser"
#define PHONEINFO_KEY	"IPhoneSubInfo"
#define MAKE_CALL_KEY 	"ITelephony"
#define CAMERA_KEY		"ICamera"
#define RECORDING_KEY	"IMediaRecorder"
#define SM_SEND_SMS_KEY "isms"

#define LOCATION_VAL 	1
#define GPS_VAL			12
#define NETWORK_VAL		11
#define READ_SMS_VAL 	2
#define RECV_SMS_VAL	3
#define SEND_SMS_VAL	4
#define CONTACTS_VAL 	5
#define BOOKMARKS_VAL	6
#define PHONEINFO_VAL	7
#define MAKE_CALL_VAL 	8
#define CAMERA_VAL	9
#define RECORDING_VAL	10

#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "hook-ioctl", __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, "hook-ioctl", __VA_ARGS__))


void _init(char *args)
{
    LOGI("[+] lib loaded ...");
}

long (*orig_ioctl)(long, long, ...);
long num ;
extern long global_entry_addr;

int  get_time(char* tmbuf) {

    
        struct timeval tv;
    long  nowtime,nownanotime;
    //char tmbuf[30];


        gettimeofday(&tv, NULL);
        double time_second = (tv.tv_sec) * 1000.0;
        long time_nanosecond = (tv.tv_usec) / 1000;
    double time_in_mill =  time_second + time_nanosecond ;
         
         long long time_to_return = (long long)time_in_mill ;
         sprintf(tmbuf,"%lld",time_to_return);
         //LOGI("time: %s\n",tmbuf);
         return 0;



}
 
void unhook()
{
	memcpy((long *)global_entry_addr, &orig_ioctl, sizeof(long));	
}

//==============================================================
int init_socket(const char *sock_name, struct sockaddr_un *addr)
{
    int sockfd;
    
	if ( (sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0 ) {
		perror("socket");
		exit(-1);
	}
	
	memset(addr, 0, sizeof(struct sockaddr_un));
	
	addr->sun_family = AF_UNIX;
	
	addr->sun_path[0] = 0;   // Linux abstract namespace
	strcpy(addr->sun_path + 1, sock_name);
	
	return sockfd;
}

//==============================================================
int send_msg(const char *msg)
{
	struct sockaddr_un remote_addr;
	char *sock_name = "SENDDATALocation";
	int sockfd = init_socket(sock_name, &remote_addr);
	int res = 0;
	
	socklen_t len = strlen(sock_name) + offsetof(struct sockaddr_un, sun_path) + 1;

	if ( connect(sockfd, (struct sockaddr *)&remote_addr, len) == -1 ) {
		perror("connect");
		return -1;
	}


	LOGI("connect ok\n");

	if ( send(sockfd, msg, strlen(msg), 0) == -1 ) {
		perror("send");
		close(sockfd);
		return -1;
	}

	LOGI("sendmsg: %s\n",msg);


	close(sockfd);

	return res;
    
}

//==================================================================

void read_transaction_data(long addr) 
{
	//LOGI("read_transaction_data\n");
	struct binder_transaction_data 	*btd = addr;
	
	pid_t pid = btd->sender_pid;
	uid_t uid = btd->sender_euid;
    unsigned int codeFunc=btd->code;
	
	char *data 	= (char *) btd->data.ptr.buffer;
	char *buf ,*temp;
	
	temp =0;
	buf =0;
	if (btd->data_size>8)
	{
		buf=temp= (char *) malloc(btd->data_size + 5);	// remember to free
		unsigned i, k;
		for (i = k = 0; i < btd->data_size; i++) {
			if ( data[i] > 23 && data[i] < 123 )
				buf[k++] = data[i];
			else
				continue;
		}
		buf[k] = 0;
	}
    else{
		buf = (char *) btd->data.buf;
	}    	
	//LOGI("pid: %d uid: %d buf: %s data_size:%d\n",pid,uid,buf,btd->data_size);
	
	char msg[MSG_LEN];
	memset(msg, 0, MSG_LEN);


	char* timenow;
    char msgback[70];
	
	if ( strstr(buf,"ILocationManager") && strlen(buf) > 45){
 
            if(pid != 0 || uid != 0)   
            {   
				if(codeFunc == 5){
				LOGI("system_server: %s pid: %d uid: %d code: %d buf: %s buflen:%d\n",time,pid,uid,codeFunc,buf,strlen(buf));
				char timenow[30];
                 get_time(timenow);		
                 char* code="-";
				 
				char* packageName = "FromNative";
                 char* functionName = "SystemServer_ioctl";
                 char pidstring[7];
                 memset(msgback,0,sizeof(msgback));

                 sprintf(pidstring,"%ld", pid);
				char uidstring[7];
                 sprintf(uidstring,"%ld",uid);

                 strcpy(msgback,packageName);
                // LOGI("msgback: %s\n",msgback);
                 strcat(msgback,code);
                // LOGI("msgback: %s\n",msgback);
                 strcat(msgback,functionName);
                // LOGI("msgback: %s\n",msgback);
                 strcat(msgback,code);
                 strcat(msgback,pidstring);
                 strcat(msgback,code);
                 strcat(msgback,uidstring);
                 strcat(msgback,code);
                 strcat(msgback,timenow);
                // LOGI("msgback: %s\n",msgback);
                 int len = strlen(msgback);
                 msgback[len] = '\n';
				LOGI("msgbackxx: %s %d\n",msgback,codeFunc);
                

                 send_msg(msgback);
				}
            }

    }
	
	if (temp )
		free(temp);	
	
}


void locate_transaction_data(long start, long size, unsigned long type) 
{
	unsigned long _type 	= 0;	// used to store the type that has been read	
  	long end		= start + size;
  	while ( start < end ) {				// loop to find BR_TRANSACTION
  	if (sizeof(BR_TRANSACTION) == 4)
		_type = *(uint32_t *)start;		// get the type of transaction data
	else 
		_type = *(unsigned long *)start;
  		start += sizeof(BR_TRANSACTION);		// point to binder_transaction_data
  		
  		if ( _type == type ) {                        
  			read_transaction_data(start);	// self-explanatory :-)
  			start += sizeof(struct binder_transaction_data); // point to next type
		}
  	}
}



long hooked_ioctl(long fd, unsigned cmd, void *data)
{

	if ( BINDER_WRITE_READ != (unsigned)cmd ) 	
		return (*orig_ioctl)(fd, cmd, data);
	/*
	 * The third parameter data points to struct binder_write_read.
	 * Create a pointer bwr pointing to struct binder_write_read with type cast.
	 */
	struct binder_write_read* bwr = (struct binder_write_read *)data;
	
  	/*
  	 * Before original ioctl is invoked, read BR_TRANSACTION
  	 */  	
  	if ( bwr->read_size > 0 ) {
		locate_transaction_data(bwr->read_buffer, bwr->read_size, BR_TRANSACTION);
	}
  	  	
	long retval = (*orig_ioctl)(fd, cmd, data);	// invoking original ioctl
	
	/*
	 * After original ioctl is invoked, read BC_REPLY
	 */
	
	if ( bwr->write_size >= VALID_SIZE ) {
		locate_transaction_data(bwr->write_buffer, bwr->write_size, BC_REPLY);
	}
	
	return retval;
}

void hook_entry(char *p)
{
    char *sym = "ioctl";
    LOGI("Hook Information:%s\n",p);
	num=0;
    // servicemanager does not use /system/lib/libbinder.so
    // therefore, if you want to hook ioctl of servicemanager
    // please change module_path to /system/bin/servicemanager
#if defined(__LP64__)   
	char *module_path = "/system/lib64/libbinder.so";
#else
	char *module_path = "/system/lib/libbinder.so";
#endif

    orig_ioctl = do_hook(module_path, (long)hooked_ioctl, sym);	
    if ( orig_ioctl == 0 )
    {
        LOGE("[-] hook %s failed", sym);
        return ;
    }
    LOGI("[+] orignal ioctl: 0x%llx", orig_ioctl);
}


#include <stdio.h>    
#include <stdlib.h>    
#include <sys/user.h>    
#include <asm/ptrace.h>    
#include <sys/ptrace.h>    
#include <sys/wait.h>    
#include <sys/mman.h>    
#include <dlfcn.h>    
#include <dirent.h>    
#include <unistd.h>    
#include <string.h>    
#include <elf.h>    
#include <android/log.h>    
#include <sys/uio.h>
    
#if defined(__i386__)    
#define pt_regs         user_regs_struct    
#elif defined(__aarch64__)
#define pt_regs         user_pt_regs  
#define uregs	regs
#define ARM_pc	pc
#define ARM_sp	sp
#define ARM_cpsr	pstate
#define ARM_lr		regs[30]
#define ARM_r0		regs[0]  
#define PTRACE_GETREGS PTRACE_GETREGSET
#define PTRACE_SETREGS PTRACE_SETREGSET
#endif    
    
#define ENABLE_DEBUG 1    
    
#if ENABLE_DEBUG    
#define  LOG_TAG "INJECT"    
#define  LOGD(fmt, args...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG, fmt, ##args)    
#define DEBUG_PRINT(format,args...) \    
    LOGD(format, ##args)    
#else    
#define DEBUG_PRINT(format,args...)    
#endif    
    
#define CPSR_T_MASK     ( 1u << 5 )    
    
#if defined(__aarch64__)    
const char *libc_path = "/system/lib64/libc.so";    
const char *linker_path = "/system/bin/linker64";    
#else
const char *libc_path = "/system/lib/libc.so";    
const char *linker_path = "/system/bin/linker";    
#endif
    
int ptrace_readdata(pid_t pid,  uint8_t *src, uint8_t *buf, size_t size)    
{    
    long i, j, remain;    
    uint8_t *laddr;       
    size_t bytes_width = sizeof(long);
	
    union u {    
        long val;    
        char chars[bytes_width];    
    } d;    
    
    j = size / bytes_width;    
    remain = size % bytes_width;    
    
    laddr = buf;    
    
    for (i = 0; i < j; i ++) {    
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);    
        memcpy(laddr, d.chars, bytes_width);    
        src += bytes_width;    
        laddr += bytes_width;    
    }    
    
    if (remain > 0) {    
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);    
        memcpy(laddr, d.chars, remain);    
    }    
    
    return 0;    
}    

/*
Func : ��size�ֽڵ�data����д�뵽pid���̵�dest��ַ��
@param dest: Ŀ�Ľ��̵�ջ��ַ
@param data: ��Ҫд������ݵ���ʼ��ַ
@param size: ��Ҫд������ݵĴ�С�����ֽ�Ϊ��λ
*/
int ptrace_writedata(pid_t pid, uint8_t *dest, uint8_t *data, size_t size)    
{    
    long i, j, remain;    
    uint8_t *laddr;    
    size_t bytes_width = sizeof(long);
	
	//������������壬�����Ϳ��Է�������ֽ�Ϊ��λд��4�ֽ����ݣ�����longΪ��λptrace_poketext��ջ��  
    union u {    
        long val;    
        char chars[bytes_width];    
    } d;    
    
    j = size / bytes_width;    
    remain = size % bytes_width;    
    
    laddr = data;

	//����4�ֽ�Ϊ��λ��������д��
    
    for (i = 0; i < j; i ++) {    
        memcpy(d.chars, laddr, bytes_width);    
        ptrace(PTRACE_POKETEXT, pid, dest, d.val);    
    
        dest  += bytes_width;    
        laddr += bytes_width;    
    }    
    
    if (remain > 0) {
		//Ϊ�����̶ȵı���ԭջ�����ݣ��ȶ�ȡdest��long���ݣ�Ȼ��ֻ�������е�ǰremain�ֽڣ���д��
        d.val = ptrace(PTRACE_PEEKTEXT, pid, dest, 0);    
        for (i = 0; i < remain; i ++) {    
            d.chars[i] = *laddr ++;    
        }    
    
        ptrace(PTRACE_POKETEXT, pid, dest, d.val);   
    }    
    
    return 0;    
}    

/*
�����ܽ᣺
1����Ҫִ�е�ָ��д��Ĵ����У�ָ��ȴ���4��long�Ļ�����Ҫ��ʣ���ָ��ͨ��ptrace_writedata����д��ջ�У�
2��ʹ��ptrace_continue��������Ŀ�Ľ��̣�ֱ��Ŀ�Ľ��̷���״ֵ̬0xb7f���Ը�ֵ�ķ�����������֣���
3������ִ����֮��Ŀ����̹���ʹ��ptrace_getregs������ȡ��ǰ�����мĴ���ֵ���������ʹ��ptrace_retval������ȡ�����ķ���ֵ��
*/
#if defined(__arm__) || defined(__aarch64__)
int ptrace_call(pid_t pid, uintptr_t addr, long *params, int num_params, struct pt_regs* regs)    
{    
    int i;   
#if defined(__arm__) 
    int num_param_registers = 4;
#elif defined(__aarch64__) 
    int num_param_registers = 8;
#endif

    for (i = 0; i < num_params && i < num_param_registers; i ++) {    
        regs->uregs[i] = params[i];    
    }    
    
    //    
    // push remained params onto stack    
    //    
    if (i < num_params) {    
        regs->ARM_sp -= (num_params - i) * sizeof(long) ;    
        ptrace_writedata(pid, (void *)regs->ARM_sp,(uint8_t *)& params[i], (num_params - i) * sizeof(long));    
    }    
    //��PC�Ĵ���ֵ��ΪĿ�꺯���ĵ�ַ
    regs->ARM_pc = addr; 
	//����ָ��ж� 
    if (regs->ARM_pc & 1) {    
        /* thumb */    
        regs->ARM_pc &= (~1u);    
		// #define CPSR_T_MASK  ( 1u << 5 )  CPSRΪ����״̬�Ĵ���
        regs->ARM_cpsr |= CPSR_T_MASK;    
    } else {    
        /* arm */    
        regs->ARM_cpsr &= ~CPSR_T_MASK;    
    }    
	
    //�����ӳ���ķ��ص�ַΪ�գ��Ա㺯��ִ����󣬷��ص�null��ַ������SIGSEGV������ϸ���ü�����ĺ��ַ���
    regs->ARM_lr = 0;    
    
	/*
    *Ptrace_setregs���ǽ��޸ĺ��regsд��Ĵ����У�Ȼ�����ptrace_continue��ִ������ָ���Ĵ���
    */
    if (ptrace_setregs(pid, regs) == -1     
            || ptrace_continue(pid) == -1) {    
        printf("error\n");    
        return -1;    
    }    
    
    int stat = 0;  
    waitpid(pid, &stat, WUNTRACED);  
	/* WUNTRACED����waitpid������ӽ��̽�����ͣ״̬����ô���������ء�����Ǳ�ptrace���ӽ��̣���ô��ʹ���ṩWUNTRACED������Ҳ�����ӽ��̽�����ͣ״̬��ʱ���������ء�
	����ʹ��ptrace_cont���е��ӽ��̣�������3������½�����ͣ״̬������һ��ϵͳ���ã����ӽ����˳������ӽ��̵�ִ�з������������0xb7f�ͱ�ʾ�ӽ��̽�������ͣ״̬���ҷ��͵Ĵ����ź�Ϊ11(SIGSEGV)������ʾ��ͼ����δ������Լ����ڴ�, ����ͼ��û��дȨ�޵��ڴ��ַд���ݡ���ôʲôʱ��ᷢ�����ִ����أ���Ȼ�����ӽ���ִ����ע��ĺ���������������ǰ��������regs->ARM_lr = 0�����ͻ᷵�ص�0��ַ������ִ�У������ͻ����SIGSEGV�ˣ�*/
    
	//���ѭ���Ƿ�����һ���ȷ������ΪĿǰÿ��ptrace_call���ñض��᷵��0xb7f����������Ҳ���������ݴ��԰�~
	
	//ͨ����ndk��Դ��sys/wait.h�Լ�man waitpid����֪�����0xb7f�ľ������á�����˵һ��stat��ֵ����2�ֽ����ڱ�ʾ�����ӽ��̵��˳�����ͣ״̬�ź�ֵ����2�ֽڱ�ʾ�ӽ������˳�(0x0)������ͣ(0x7f)״̬��0xb7f�ͱ�ʾ�ӽ���Ϊ��ͣ״̬����������ͣ���ź���Ϊ11��sigsegv����
	while (stat != 0xb7f) {  
        if (ptrace_continue(pid) == -1) {  
            printf("error\n");  
            return -1;  
        }  
        waitpid(pid, &stat, WUNTRACED);  
    }  
    
    return 0;    
}    

#elif defined(__i386__)    
long ptrace_call(pid_t pid, uintptr_t addr, long *params, int num_params, struct user_regs_struct * regs)    
{    
    regs->esp -= (num_params) * sizeof(long) ;    
    ptrace_writedata(pid, (void *)regs->esp, (uint8_t *)params, (num_params) * sizeof(long));    
    
    long tmp_addr = 0x00;    
    regs->esp -= sizeof(long);    
    ptrace_writedata(pid, regs->esp, (char *)&tmp_addr, sizeof(tmp_addr));     
    
    regs->eip = addr;    
    
    if (ptrace_setregs(pid, regs) == -1     
            || ptrace_continue( pid) == -1) {    
        printf("error\n");    
        return -1;    
    }    
    
    int stat = 0;  
    waitpid(pid, &stat, WUNTRACED);  
    while (stat != 0xb7f) {  
        if (ptrace_continue(pid) == -1) {  
            printf("error\n");  
            return -1;  
        }  
        waitpid(pid, &stat, WUNTRACED);  
    }  
    
    return 0;    
}    
#else     
#error "Not supported"    
#endif    
    
int ptrace_getregs(pid_t pid, struct pt_regs * regs)    
{    
#if defined (__aarch64__)
		int regset = NT_PRSTATUS;
		struct iovec ioVec;
		
		ioVec.iov_base = regs;
		ioVec.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_GETREGSET, pid, (void*)regset, &ioVec) < 0) {    
        perror("ptrace_getregs: Can not get register values");   
        printf(" io %llx, %d", ioVec.iov_base, ioVec.iov_len); 
        return -1;    
    }    
    
    return 0;   
#else
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {    
        perror("ptrace_getregs: Can not get register values");    
        return -1;    
    }    
    
    return 0;   
#endif     
}    
    
int ptrace_setregs(pid_t pid, struct pt_regs * regs)    
{     
#if defined (__aarch64__)
		int regset = NT_PRSTATUS;
		struct iovec ioVec;
		
		ioVec.iov_base = regs;
		ioVec.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_SETREGSET, pid, (void*)regset, &ioVec) < 0) {    
        perror("ptrace_setregs: Can not get register values");    
        return -1;    
    }    
    
    return 0;   
#else
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {    
        perror("ptrace_setregs: Can not set register values");    
        return -1;    
    }    
    
    return 0;   
#endif     
}    
    
int ptrace_continue(pid_t pid)    
{    
    if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {    
        perror("ptrace_cont");    
        return -1;    
    }    
    
    return 0;    
}    
    
int ptrace_attach(pid_t pid)    
{    
    if (ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0) {    
        perror("ptrace_attach");    
        return -1;    
    }    
    
    int status = 0;    
    waitpid(pid, &status , WUNTRACED);    
    
    return 0;    
}    
    
int ptrace_detach(pid_t pid)    
{    
    if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) {    
        perror("ptrace_detach");    
        return -1;    
    }    
    
    return 0;    
}


//��Ȼ����������ĵľ���get_module_base������
/*
�˺����Ĺ��ܾ���ͨ������/proc/pid/maps�ļ������ҵ�Ŀ��module_name���ڴ�ӳ����ʼ��ַ��
�����ڴ��ַ�ı��﷽ʽ��startAddrxxxxxxx-endAddrxxxxxxx�ģ����Ի��ں���ʹ��strtok(line,"-")���ָ��ַ���
���pid = -1,��ʾ��ȡ���ؽ��̵�ĳ��ģ��ĵ�ַ��
�������pid���̵�ĳ��ģ��ĵ�ַ��
*/    
    
void* get_module_base(pid_t pid, const char* module_name)    
{    
    FILE *fp;    
    long addr = 0;    
    char *pch;    
    char filename[32];    
    char line[1024];    
    
    if (pid < 0) {    
        /* self process */    
        snprintf(filename, sizeof(filename), "/proc/self/maps", pid);    
    } else {    
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);    
    }    
    
    fp = fopen(filename, "r");    
    
    if (fp != NULL) {    
        while (fgets(line, sizeof(line), fp)) {    
            if (strstr(line, module_name)) {
				//�ֽ��ַ���Ϊһ���ַ�����lineΪҪ�ֽ���ַ�����"-"Ϊ�ָ����ַ�����
                pch = strtok( line, "-" );
				//������pch�ַ������ݲ���base(��ʾ����)��ת�����޷��ŵĳ�������  
                addr = strtoull( pch, NULL, 16 );   
    
                if (addr == 0x8000)    
                    addr = 0;    
    
                break;    
            }    
        }    
    
        fclose(fp) ;    
    }    
    
    return (void *)addr;    
}    

/*
�ú���Ϊһ����װ������ͨ������get_module_base��������ȡĿ�Ľ��̵�ĳ��ģ�����ʼ��ַ��Ȼ��ͨ����ʽ�����ָ��������Ŀ�Ľ��̵���ʼ��ַ��
*/
void* get_remote_addr(pid_t target_pid, const char* module_name, void* local_addr)    
{    
    void* local_handle, *remote_handle; 
    
	//��ȡ����ĳ��ģ�����ʼ��ַ
    local_handle = get_module_base(-1, module_name);
    //��ȡԶ��pid��ĳ��ģ�����ʼ��ַ
    remote_handle = get_module_base(target_pid, module_name);    
    
    DEBUG_PRINT("[+] get_remote_addr: local[%llx], remote[%llx]\n", local_handle, remote_handle);    
    /*����Ҫ���Ǻú����⣺local_addr - local_handle��ֵΪָ������(��mmap)�ڸ�ģ���е�ƫ������Ȼ���ټ���rempte_handle�������Ϊָ��������Ŀ�Ľ��̵������ַ*/
    void * ret_addr = (void *)((uintptr_t)local_addr + (uintptr_t)remote_handle - (uintptr_t)local_handle);    
    
#if defined(__i386__)    
    if (!strcmp(module_name, libc_path)) {    
        ret_addr += 2;    
    }    
#endif    
    return ret_addr;    
}    

//����name�ҵ�pid
int find_pid_of(const char *process_name)    
{    
    int id;    
    pid_t pid = -1;    
    DIR* dir;    
    FILE *fp;    
    char filename[32];    
    char cmdline[256];    
    
    struct dirent * entry;    
    
    if (process_name == NULL)    
        return -1;    
    
    dir = opendir("/proc");    
    if (dir == NULL)    
        return -1;    
    
    while((entry = readdir(dir)) != NULL) {    
        id = atoi(entry->d_name);    
        if (id != 0) {    
            sprintf(filename, "/proc/%d/cmdline", id);    
            fp = fopen(filename, "r");    
            if (fp) {    
                fgets(cmdline, sizeof(cmdline), fp);    
                fclose(fp);    
    
                if (strcmp(process_name, cmdline) == 0) {    
                    /* process found */    
                    pid = id;    
                    break;    
                }    
            }    
        }    
    }    
    
    closedir(dir);    
    return pid;    
}    
    
uint64_t ptrace_retval(struct pt_regs * regs)    
{    
#if defined(__arm__) || defined(__aarch64__)
    return regs->ARM_r0;    
#elif defined(__i386__)    
    return regs->eax;    
#else    
#error "Not supported"    
#endif    
}    
    
uint64_t ptrace_ip(struct pt_regs * regs)    
{    
#if defined(__arm__) || defined(__aarch64__) 
    return regs->ARM_pc;   
#elif defined(__i386__)    
    return regs->eip;    
#else    
#error "Not supported"    
#endif    
}    

//�ܽ�һ��ptrace_call_wrapper����������������ܣ�
//һ�ǵ���ptrace_call������ִ��ָ��������ִ������ӽ��̹���
//���ǵ���ptrace_getregs������ȡ���мĴ�����ֵ����Ҫ��Ϊ�˻�ȡr0�������ķ���ֵ��  
int ptrace_call_wrapper(pid_t target_pid, const char * func_name, void * func_addr, long * parameters, int param_num, struct pt_regs * regs)     
{    
    DEBUG_PRINT("[+] Calling %s in target process.\n", func_name);    
    if (ptrace_call(target_pid, (uintptr_t)func_addr, parameters, param_num, regs) == -1)    
        return -1;    
    
    if (ptrace_getregs(target_pid, regs) == -1)    
        return -1;    
    DEBUG_PRINT("[+] Target process returned from %s, return value=%llx, pc=%llx \n",     
            func_name, ptrace_retval(regs), ptrace_ip(regs));    
    return 0;    
}    

//Զ��ע��
int inject_remote_process(pid_t target_pid, const char *library_path, const char *function_name, const char *param, size_t param_size)    
{    
    int ret = -1;    
    void *mmap_addr, *dlopen_addr, *dlsym_addr, *dlclose_addr, *dlerror_addr;    
    void *local_handle, *remote_handle, *dlhandle;    
    uint8_t *map_base = 0;    
    uint8_t *dlopen_param1_ptr, *dlsym_param2_ptr, *saved_r0_pc_ptr, *inject_param_ptr, *remote_code_ptr, *local_code_ptr;    
    
    struct pt_regs regs, original_regs;     
    long parameters[10];    
    
    DEBUG_PRINT("[+] Injecting process: %d\n", target_pid);    
	
    //��ATTATCH��ָ��Ŀ����̣���ʼ����
    if (ptrace_attach(target_pid) == -1)    
        goto exit;   
	
    //��GETREGS����ȡĿ����̵ļĴ����������ֳ�
    if (ptrace_getregs(target_pid, &regs) == -1)    
        goto exit;    
    
    /* save original registers */    
    memcpy(&original_regs, &regs, sizeof(regs));    
	
	//��ͨ��get_remote_addr������ȡĿ�Ľ��̵�mmap�����ĵ�ַ���Ա�Ϊlibxxx.so�����ڴ�
    
	/*
		��Ҫ��(void*)mmap����˵��������ȡ��inject�������̵�mmap�����ĵ�ַ������mmap������libc.so  
		���У�Ϊ�˽�libxxx.so���ص�Ŀ�Ľ����У�����Ҫʹ��Ŀ�Ľ��̵�mmap������������Ҫ���ҵ�libc.so����Ŀ�Ľ��̵���ʼ��ַ��
	*/
    mmap_addr = get_remote_addr(target_pid, libc_path, (void *)mmap);    
    DEBUG_PRINT("[+] Remote mmap address: %llx\n", mmap_addr);

	/* call mmap (null, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC,
	                         MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
	��������һ��0x4000��С���ڴ�
	*/
    parameters[0] = 0;  // addr    
    parameters[1] = 0x4000; // size    
    parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot    
    parameters[3] = MAP_ANONYMOUS | MAP_PRIVATE; // flags    
    parameters[4] = 0; //fd    
    parameters[5] = 0; //offset    
    
    if (ptrace_call_wrapper(target_pid, "mmap", mmap_addr, parameters, 6, &regs) == -1)    
        goto exit;    
    
	//�ݴӼĴ����л�ȡmmap�����ķ���ֵ����������ڴ��׵�ַ��
    map_base = ptrace_retval(&regs);  
    
	//�����λ�ȡlinker��dlopen��dlsym��dlclose��dlerror�����ĵ�ַ:
    dlopen_addr = get_remote_addr( target_pid, linker_path, (void *)dlopen );    
    dlsym_addr = get_remote_addr( target_pid, linker_path, (void *)dlsym );    
    dlclose_addr = get_remote_addr( target_pid, linker_path, (void *)dlclose );    
    dlerror_addr = get_remote_addr( target_pid, linker_path, (void *)dlerror );    
    
    DEBUG_PRINT("[+] Get imports: dlopen: %llx, dlsym: %llx, dlclose: %llx, dlerror: %llx\n",    
            dlopen_addr, dlsym_addr, dlclose_addr, dlerror_addr);    
    
    printf("library path = %s\n", library_path);    
	//�ߵ���dlopen������
	/*
	�ٽ�Ҫע���so��д��ǰ��mmap�������ڴ�
	��д��dlopen����
	��ִ��dlopen("libxxx.so", RTLD_NOW ! RTLD_GLOBAL) 
	RTLD_NOW֮��Ĳ������ÿɲο���
	http://baike.baidu.com/view/2907309.htm?fr=aladdin 
	��ȡ��dlopen�ķ���ֵ�������sohandle������
	*/
    ptrace_writedata(target_pid, map_base, library_path, strlen(library_path) + 1);  
        
    parameters[0] = map_base;       
    parameters[1] = RTLD_NOW| RTLD_GLOBAL;     
    
    if (ptrace_call_wrapper(target_pid, "dlopen", dlopen_addr, parameters, 2, &regs) == -1)    
        goto exit;    
    
    void * sohandle = ptrace_retval(&regs);    
    if(!sohandle) {
    		if (ptrace_call_wrapper(target_pid, "dlerror", dlerror_addr, 0, 0, &regs) == -1)    
      	  goto exit;    
        
    		uint8_t *errret = ptrace_retval(&regs);  
    		uint8_t errbuf[100];
    		ptrace_readdata(target_pid, errret, errbuf, 100);
  	}
    
    //�����dlsym����
	/*
	��ͬ��hook_entry_addr = (void *)dlsym(sohandle, "hook_entry");
	*/ 
#define FUNCTION_NAME_ADDR_OFFSET       0x100    
    ptrace_writedata(target_pid, map_base + FUNCTION_NAME_ADDR_OFFSET, function_name, strlen(function_name) + 1);    
    parameters[0] = sohandle;       
    parameters[1] = map_base + FUNCTION_NAME_ADDR_OFFSET;     
    
    if (ptrace_call_wrapper(target_pid, "dlsym", dlsym_addr, parameters, 2, &regs) == -1)    
        goto exit;    
    
    void * hook_entry_addr = ptrace_retval(&regs);    
    DEBUG_PRINT("hook_entry_addr = %p\n", hook_entry_addr);    
    
	//�����hook_entry������
#define FUNCTION_PARAM_ADDR_OFFSET      0x200    
    ptrace_writedata(target_pid, map_base + FUNCTION_PARAM_ADDR_OFFSET, param, strlen(param) + 1);    
    parameters[0] = map_base + FUNCTION_PARAM_ADDR_OFFSET;      
  
    if (ptrace_call_wrapper(target_pid, "hook_entry", hook_entry_addr, parameters, 1, &regs) == -1)    
        goto exit;        
    
    printf("Press enter to dlclose and detach\n");    
    getchar();    
    parameters[0] = sohandle;       
    
	//�����dlclose�ر�lib:
    if (ptrace_call_wrapper(target_pid, "dlclose", dlclose, parameters, 1, &regs) == -1)    
        goto exit;    
    
    /* restore */    
	//?�ָ��ֳ����˳�ptrace:
    ptrace_setregs(target_pid, &original_regs);    
    ptrace_detach(target_pid);    
    ret = 0;    
    
exit:    
    return ret;    
}    
    
int main(int argc, char** argv) {    
    pid_t target_pid;    
    target_pid = find_pid_of("system_server");
    if (-1 == target_pid) {  
        printf("Can't find the process\n");  
        return -1;  
    }  
    //target_pid = find_pid_of("/data/test");    
    inject_remote_process(target_pid, "/data/local/libss.so", "hook_entry",  "I'm parameter!", strlen("I'm parameter!"));    
    return 0;  
}
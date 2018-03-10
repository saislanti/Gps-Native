/**
 * filename     : hook.c
 * description  : elf hook engine
 * author       : shaoyuru@whu.edu.cn
 */

#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <android/log.h>
#include <sys/ioctl.h>

#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "hook-engine", __VA_ARGS__))
#define LOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, "hook-engine", __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, "hook-engine", __VA_ARGS__))

#define PAGE_START(addr, size) ~((size) - 1) & (addr)

/*ELF MARCO*/
#if defined(__LP64__)//<---------------------Elf64
#define ElfW(type) 		Elf64_ ## type
#define ELF_R_SYM 		ELF64_R_SYM
#define ELF_R_TYPE    	ELF64_R_TYPE
#else		//<------------------------------Elf32
#define ElfW(type)	 	Elf32_ ## type
#define ELF_R_SYM 		ELF32_R_SYM
#define ELF_R_TYPE    	ELF32_R_TYPE
#endif	

#define RELFLAG_REL_PLT  (1<<0)
#define RELFLAG_RELA_PLT (1<<1)


/**
 * lookup the start address of a specific module
 * return 0 if FAILED
 */
long get_module_base(pid_t pid, const char *module_path) 
{
    FILE *fp = NULL;
    char *pch = NULL;
    char filename[32];
    char line[512];
    long addr = 0;

    if ( pid < 0 ) 
        snprintf(filename, sizeof(filename), "/proc/self/maps");
    else 
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);

    if ( (fp = fopen(filename, "r")) == NULL ) 
    {
        LOGE("open %s failed!", filename);
        return 0;
    }

    while ( fgets(line, sizeof(line), fp) ) 
    {
        if ( strstr(line, module_path) ) 
        {
            pch = strtok(line, "-");
            addr = strtoull(pch, NULL, 16);
            break;
        }
    }

    fclose(fp);

    return addr;
}


long get_offset_from_rel(int fd, long targetNdx, ElfW(Shdr) *shdr, long elf_rel_size)
{
	long rel_sh_offset = shdr->sh_offset;
	long rel_sh_size = shdr->sh_size;
	int i;
	long offset=0;
    ElfW(Rel) *rel_ent = (ElfW(Rel) *)malloc(elf_rel_size);
    lseek(fd, rel_sh_offset, SEEK_SET);
    if ( read(fd, rel_ent, elf_rel_size) != elf_rel_size ) 
    {
        LOGE("[get_offset_from_rel]  error1 !");
        return 0;
    }
	
    for ( i = 0; i < rel_sh_size / elf_rel_size; i++ ) 
    {
        long ndx = ELF_R_SYM(rel_ent->r_info);
		long rtype = ELF_R_TYPE(rel_ent->r_info);
			
        if (ndx == targetNdx) 
        {
            offset = rel_ent->r_offset;
			break;
        }
        if ( read(fd, rel_ent, elf_rel_size) != elf_rel_size ) 
        {
            LOGE("[get_offset_from_rel]  error2 !");
            return 0;
        }
    }
	LOGI("return offset = %llx\n",offset);
	free (rel_ent);
	return offset;
} 


void dumpMem(long MemStart,long dumpsize,char *filepath)
{
	long page_size = getpagesize();
	long mpsize = dumpsize;
    long entry_page_start = PAGE_START(MemStart, page_size);
	mpsize += MemStart-entry_page_start;
	long remain = mpsize % page_size;
	mpsize = (mpsize / page_size)*page_size;
	if (remain)
		mpsize += page_size;
    mprotect((long *)entry_page_start, mpsize, PROT_READ | PROT_WRITE  | PROT_EXEC);
	FILE* fp = fopen (filepath,"wb");
	if (fp==NULL)
	{
		LOGE("[dumpMem] fopen failed!\n");
	}
	LOGI("dumpsize=%d\n",dumpsize);
	fwrite(MemStart,dumpsize,1,fp);	
	fclose(fp);
		
}

ElfW(Addr) caculate_bias_addr(int fd,const ElfW(Ehdr)* elf,ElfW(Addr) module_base)
{
    ElfW(Addr) offset = elf->e_phoff;
	ElfW(Phdr)* phdr=(ElfW(Phdr)*)malloc(sizeof(ElfW(Phdr)));
	lseek(fd, offset, SEEK_SET);
	if ( read(fd, phdr, sizeof(ElfW(Phdr))) != sizeof(ElfW(Phdr)) ) 
    {
            LOGI("[caculate_bias_addr] Read phdr error!\n");
            return 0;
	}
	int i=0;
    for (i = 0; i < elf->e_phnum; i++)
    {
        if (phdr->p_type == PT_LOAD)
        {
			LOGI("[caculate_bias_addr] PT_LOAD found\n");
            return module_base + phdr->p_offset - phdr->p_vaddr;
        }
		if ( read(fd, phdr, sizeof(ElfW(Phdr))) != sizeof(ElfW(Phdr)) ) 
        {
            LOGI("[caculate_bias_addr] Read phdr error!\n");
            return 0;
        }
    }
	LOGI("[caculate_bias_addr] PT_LOAD not found\n");
    return 0;
}

/**
 * lookup symbol's GOT entry address 
 *
 * module_path, absolute path of the module which imports symbol
 * symbol_name, name of the target symbol
 */
long find_got_entry_address(const char *module_path, const char *symbol_name) 
{
    long module_base = get_module_base(-1, module_path);
    if ( module_base == 0 ) 
    {
        LOGE("[-] it seems that process %d does not dependent on %s", getpid(), module_path);
        return 0;
    }
    
    LOGI("[+] base address of %s: 0x%x", module_path, module_base);
	
    int fd = open(module_path, O_RDONLY);
    if ( fd == -1 ) 
    {
        LOGE("[-] open %s error!", module_path);
        return 0;
    }

    ElfW(Ehdr) *elf_header = (ElfW(Ehdr) *)malloc(sizeof(ElfW(Ehdr)));
    if ( read(fd, elf_header, sizeof(ElfW(Ehdr))) != sizeof(ElfW(Ehdr)) ) 
    {
        LOGE("[-] read %s error! in %s at line %d", module_path, __FILE__, __LINE__);
        return 0;
    }
	/*get bias_addr*/
	ElfW(Addr)  bias_addr = caculate_bias_addr(fd,elf_header,module_base);
	
    long sh_base = elf_header->e_shoff;
    long ndx = elf_header->e_shstrndx;
    long shstr_base = sh_base + ndx * sizeof(ElfW(Shdr));
    LOGI("[+] start of section headers: 0x%llx", sh_base);
    LOGI("[+] section header string table index: %d", ndx);
    LOGI("[+] section header string table offset: 0x%llx", shstr_base);

    lseek(fd, shstr_base, SEEK_SET);
    ElfW(Shdr) *shstr_shdr = (ElfW(Shdr) *)malloc(sizeof(ElfW(Shdr)));
    if ( read(fd, shstr_shdr, sizeof(ElfW(Shdr))) != sizeof(ElfW(Shdr)) ) 
    {
        LOGE("[-] read %s error! in %s at line %d", module_path, __FILE__, __LINE__);
        return 0;
    }
    LOGI("[+] section header string table offset: 0x%llx", shstr_shdr->sh_offset);

    char *shstrtab = (char *)malloc(sizeof(char) * shstr_shdr->sh_size);
    lseek(fd, shstr_shdr->sh_offset, SEEK_SET);
    if ( read(fd, shstrtab, shstr_shdr->sh_size) != shstr_shdr->sh_size ) 
    {
        LOGE("[-] read %s error! in %s at line %d", module_path, __FILE__, __LINE__);
        return 0;
    }
	
	
    ElfW(Shdr) *shdr = (ElfW(Shdr) *)malloc(sizeof(ElfW(Shdr)));
    ElfW(Shdr) *relplt_shdr  = (ElfW(Shdr) *)malloc(sizeof(ElfW(Shdr)));
    ElfW(Shdr) *dynsym_shdr  = (ElfW(Shdr) *)malloc(sizeof(ElfW(Shdr)));
    ElfW(Shdr) *dynstr_shdr  = (ElfW(Shdr) *)malloc(sizeof(ElfW(Shdr)));
    ElfW(Shdr) *relaplt_shdr = (ElfW(Shdr) *)malloc(sizeof(ElfW(Shdr)));
    lseek(fd, sh_base, SEEK_SET);
    if ( read(fd, shdr, sizeof(ElfW(Shdr))) != sizeof(ElfW(Shdr)) ) 
    {
        LOGE("[-] read %s error! in %s at line %d", module_path, __FILE__, __LINE__);
        perror("Error");
        return 0;
    }
    int i = 1;
    char *s = NULL;
	int relflag = 0;
    for ( ; i < elf_header->e_shnum; i++ ) 
    {
        s = shstrtab + shdr->sh_name;
        if ( strcmp(s, ".rel.plt") == 0 )
		{
            memcpy(relplt_shdr, shdr, sizeof(ElfW(Shdr)));
			relflag |= RELFLAG_REL_PLT;
		}
        else if ( strcmp(s, ".dynsym") == 0 ) 
		{
            memcpy(dynsym_shdr, shdr, sizeof(ElfW(Shdr)));
		}
        else if ( strcmp(s, ".dynstr") == 0 ) 
		{
            memcpy(dynstr_shdr, shdr, sizeof(ElfW(Shdr)));
		}
		else if (strcmp(s,".rela.plt") == 0)
		{
			memcpy(relaplt_shdr,shdr, sizeof(ElfW(Shdr)));
			relflag |= RELFLAG_RELA_PLT;
		}
		
        if ( read(fd, shdr, sizeof(ElfW(Shdr))) != sizeof(ElfW(Shdr)) ) 
        {
            LOGE("[-] read %s error! i = %d, in %s at line %d", module_path, i, __FILE__, __LINE__);
            return 0;
        }
    }
	
    // read dynmaic symbol string table
    char *dynstr = (char *)malloc(sizeof(char) * dynstr_shdr->sh_size);
    lseek(fd, dynstr_shdr->sh_offset, SEEK_SET);
    if ( read(fd, dynstr, dynstr_shdr->sh_size) != dynstr_shdr->sh_size ) 
    {
        LOGE("[-] read %s error!", module_path);
        return 0;
    }
	
    // read dynamic symbol table
    ElfW(Sym) *dynsymtab = (ElfW(Sym) *)malloc(dynsym_shdr->sh_size);
    lseek(fd, dynsym_shdr->sh_offset, SEEK_SET);
    if ( read(fd, dynsymtab, dynsym_shdr->sh_size) != dynsym_shdr->sh_size ) 
    {
        LOGE("[-] read %s error!", module_path);
        return 0;
    }
	
	long targetNdx=0;
	for (i=0;i<dynsym_shdr->sh_size/sizeof(ElfW(Sym));i++)
	if ( strcmp(dynstr + dynsymtab[i].st_name, symbol_name) == 0 ) 
        {
            targetNdx = i;
			LOGI("[+]targetNdx = %d \n",targetNdx );
            break;
        }

	if (targetNdx == 0)
		return 0;
    long offset=0,tmpoffset;
	if (relflag & RELFLAG_RELA_PLT)
	{
		tmpoffset = get_offset_from_rel( fd, targetNdx, relaplt_shdr,sizeof(ElfW(Rela)));
		if (tmpoffset) offset = tmpoffset;
    }

	if (relflag & RELFLAG_REL_PLT)
	{
		tmpoffset	= get_offset_from_rel( fd, targetNdx, relplt_shdr,sizeof(ElfW(Rel)));
		if (tmpoffset) offset = tmpoffset;
	}
	
	ElfW(Half) type = elf_header->e_type; // ET_EXEC or ET_DYN
    free(elf_header);
    free(shstr_shdr);
    free(shstrtab);
    free(shdr);
	
    free(relplt_shdr);
	free(relaplt_shdr);
	
    free(dynsym_shdr);
    free(dynstr_shdr);
    free(dynstr);
    free(dynsymtab);
	
	LOGI("offset=%llx, module_base =%llx,bias_addr=%llx\n",offset,module_base,bias_addr);
    // GOT entry offset is different between ELF executables and shared libraries
    if ( type == ET_EXEC )
	{
        return offset;
	}
    else if ( type == ET_DYN )
	{
		return offset + bias_addr;
	}
	else
	{
		LOGI("[-]It's not ELF executables or shared libraries\n");
	}
    return 0;
}

/**
 * replace GOT entry content of the function indicated by symbol name
 * with the address of hook_func
 *
 * return original name if SUCC
 * return 0 if FAILED
 */
 
long global_entry_addr;
long do_hook(const char *module_path, long hook_func, const char *symbol_name) 
{
    long entry_addr = find_got_entry_address(module_path, symbol_name);
	
    if ( entry_addr == 0 )
        return 0;
	
    long original_addr = 0;	
	long page_size = getpagesize();
    long entry_page_start = PAGE_START(entry_addr, page_size);
    LOGI("[+] page size: 0x%llx", page_size);
    LOGI("[+] entry page start: 0x%llx", entry_page_start);

    // change the property of current page to writeable
    mprotect((long *)entry_page_start, page_size, PROT_READ | PROT_WRITE  | PROT_EXEC);
	
    // save original GOT entry content
    memcpy(&original_addr, (long *)entry_addr, sizeof(long));
    LOGI("[+] hook_fun addr: 0x%llx", hook_func);
    LOGI("[+] got entry addr: 0x%llx", entry_addr);
    LOGI("[+] original addr: 0x%llx", original_addr);

    // replace GOT entry content with hook_func's address
	global_entry_addr = entry_addr;
	LOGI("entry_addr =%llx\n",entry_addr);
    memcpy((long *)entry_addr, &hook_func, sizeof(long));
    return original_addr;
}

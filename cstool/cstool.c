#include <stdio.h>
#include <inttypes.h>
#include <String.h>

#include <capstone/capstone.h>

//#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"
static void usage(char * prog){
    printf("Syntax: %s <arch+mode> <assembler-string>", prog);
    printf("\nThe following <arch+mode> options are supported:\n");
    
    if(cs_support(CS_ARCH_ARM)){
        printf("        arm:      32-bit ARM\n");
        printf("        armb:     arm + big endian\n");
        printf("        thumb:    Thumb - little endian\n");
        printf("        thumbbe:  Thumb - big endian\n");
        
        
        
        
    }
    if(cs_support(CS_ARCH_ARM64)){
         printf("        arm64:     AArch64 - little endian\n");
        
    }
    if(cs_support(CS_ARCH_MIPS)){
        printf("        mips:          mips32 + little endian\n");
        printf("        mipsbe:        mips32 + big endian\n");
        printf("        mips64:        mips64 + little endian\n");
        printf("        mips64be:      mips64 + big endian\n");
        
        
    }
    if(cs_support(CS_ARCH_X86)){
         printf("        x16:         16-bit mode (X86)\n");
         printf("        x32:         32-bit mode (X86)\n");
         printf("        x64:         64-bit mode (X86)\n");
         printf("        x16att:      16-bit mode (X86) syntax-att\n");
         printf("        x32att:      32-bit mode (X86) syntax-att\n");
         printf("        x64att:      64-bit mode (X86) syntax-att\n");
         printf("        x16noregname:     16-bit mode (X86) syntax-noregname\n");
         printf("        x32noregname:     32-bit mode (X86) syntax-noregname\n");
         printf("        x64noregname:     64-bit mode (X86) syntax-noregname\n");
        
        
        
    }
    if(cs_support(CS_ARCH_PPC)){
        
        printf("        ppc64:        ppc64 + little endian\n");
        printf("        ppc64be:      ppc64 + big endian\n");
        
    }
    if(cs_support(CS_ARCH_SPARC)){
        printf("         sparcv9:        sparcv9\n");
  
    }
    if(cs_support(CS_ARCH_SYSZ)){
       printf("        systemz:   SystemZ (S390x)\n");
    }
    if(cs_support(CS_ARCH_XCORE)){
        printf("       xcore:     XCORE\n");
    }
    
    printf("\n");

}
       int main(int argc, char ** argv){
           csh handle;
           char * mode;
           uint8_t * disassembleCode = NULL;
           size_t size;
           uint64_t *address;
           cs_insn *insn;
           cs_err err;
           
           if(argc == 1 && !strcmp(argv[0],"cstool")){
               usage(argv[0]);
               return -1;
               
           }
           //cstool x64 "\x55\x48\x8b\x05\xb8\x13\x00\x00"
           
           if(argc == 3){
               mode = argv[1];
               disassembleCode = (uint8_t *)argv[2];
               printf("%s",disassembleCode);
               
           }
           //在获取命令行的参数后，可以初始化啦
           //strcmp 相等则返回零
           if(!strcmp(mode,"arm")){
               err = cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle);
               
           }
           if(!strcmp(mode,"armb")){
               err = cs_open(CS_ARCH_ARM, CS_MODE_ARM+CS_MODE_LITTLE_ENDIAN, &handle);
               
           }
           if(!strcmp(mode,"thumb")){
               err = cs_open(CS_ARCH_ARM, CS_MODE_THUMB+CS_MODE_LITTLE_ENDIAN, &handle);
               
           }
           if(!strcmp(mode,"thumbbe")){
               err = cs_open(CS_ARCH_ARM, CS_MODE_THUMB+CS_MODE_BIG_ENDIAN, &handle);
               
           }
           if(!strcmp(mode,"armb64")){
               err = cs_open(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN, &handle);
               
           }
           if(!strcmp(mode,"mips")){
               err = cs_open(CS_ARCH_MIPS,CS_MODE_MIPS32+CS_MODE_LITTLE_ENDIAN, &handle);
               
           }
           if(!strcmp(mode,"mipsbe")){
               err = cs_open(CS_ARCH_MIPS,CS_MODE_MIPS64+CS_MODE_LITTLE_ENDIAN, &handle);
               
           }
           if(!strcmp(mode,"mips64be")){
               err = cs_open(CS_ARCH_MIPS,CS_MODE_MIPS64+CS_MODE_BIG_ENDIAN, &handle);
               
           }
           if(!strcmp(mode,"x16")){
               err = cs_open(CS_ARCH_X86,CS_MODE_16, &handle);
               
           }
           if(!strcmp(mode,"x32")){
               err = cs_open(CS_ARCH_X86,CS_MODE_32, &handle);
               
           }
           if(!strcmp(mode,"x64")){
               err = cs_open(CS_ARCH_X86,CS_MODE_16, &handle);
               
           }
           if(!strcmp(mode,"x16att")){
               err = cs_open(CS_ARCH_X86,CS_MODE_16,&handle);
               if(!err){
                   cs_option(handle,CS_OPT_SYNTAX,CS_OPT_SYNTAX_ATT);
               }
           }
           if(!strcmp(mode,"x32att")){
               err = cs_open(CS_ARCH_X86,CS_MODE_32,&handle);
               if(!err){
                   cs_option(handle,CS_OPT_SYNTAX,CS_OPT_SYNTAX_ATT);
               }
           }
           if(!strcmp(mode,"x64att")){
               err = cs_open(CS_ARCH_X86,CS_MODE_64,&handle);
               if(!err){
                   cs_option(handle,CS_OPT_SYNTAX,CS_OPT_SYNTAX_ATT);
               }
           }
           if(!strcmp(mode,"x64noregname")){
               err = cs_open(CS_ARCH_X86,CS_MODE_64,&handle);
               if(!err){
                   cs_option(handle,CS_OPT_SYNTAX,CS_OPT_SYNTAX_NOREGNAME);
               }
           }
           if(!strcmp(mode,"x64noregname")){
               err = cs_open(CS_ARCH_X86,CS_MODE_64,&handle);
               if(!err){
                   cs_option(handle,CS_OPT_SYNTAX,CS_OPT_SYNTAX_NOREGNAME);
               }
           }
           if(!strcmp(mode,"x64noregname")){
               err = cs_open(CS_ARCH_X86,CS_MODE_64,&handle);
               if(!err){
                   cs_option(handle,CS_OPT_SYNTAX,CS_OPT_SYNTAX_NOREGNAME);
               }
           }
           if(!strcmp(mode,"ppc64")){
               err = cs_open(CS_ARCH_PPC,CS_MODE_64+CS_MODE_LITTLE_ENDIAN,&handle);
           }
           if(!strcmp(mode,"ppc64be")){
               err = cs_open(CS_ARCH_PPC,CS_MODE_64+CS_MODE_BIG_ENDIAN,&handle);
           }
           if(!strcmp(mode,"sparcv9")){
               err = cs_open(CS_ARCH_SPARC,CS_MODE_V9,&handle);
           }
           
           if (!strcmp(mode, "systemz") || !strcmp(mode, "sysz") || !strcmp(mode, "s390x")) {
                err = cs_open(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN, &handle);
           }
           if(!strcmp(mode,"xcore")){
               err = cs_open(CS_ARCH_XCORE, CS_MODE_BIG_ENDIAN,&handle);
               
           }
           
           if(err){
               printf("ERROR: Failed on cs_open()\n");
               usage(argv[0]);
               return -1;
           }
           //初始化成功以后，调用函数
           size = cs_disasm(handle,disassembleCode, sizeof(disassembleCode)-1,
                                         0x1000,//这个地址需要给出吗？
                                         0,//0表示获得所有指令
                                         &insn);
           if(size>0){
               size_t j;
               printf("\n");
               for(j=0;j<size;j++){
                   printf("\t%s\t%s\t%s\n", insn[j].bytes,insn[j].mnemonic,insn[j].op_str);
               }
            cs_free(insn, size);
           }
           
           cs_close(&handle);
           
           return 0;
       }



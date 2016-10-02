#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include <capstone/capstone.h>

static uint8_t converth(char c)//convert cahr A of AB to 0xA0
{
    uint8_t result,intc;
    intc = (int) c;
    switch (intc){
        case 97: result = 0xa0; break;
        case 98: result = 0xb0; break;
        case 99: result = 0xc0; break;
        case 100: result = 0xd0; break;
        case 101: result = 0xe0; break;
        case 48: result = 0x00; break;
        case 49: result = 0x10; break;
        case 50: result = 0x20; break;
        case 51: result = 0x30; break;
        case 52: result = 0x40; break;
        case 53: result = 0x50; break;
        case 54: result = 0x60; break;
        case 55: result = 0x70; break;
        case 56: result = 0x80; break;
        case 57: result = 0x90; break;
        default: result = 0x00;
    }
    printf("this high char is %c and the (int)c is %d, and the result is %x \n",c,intc,result);//just for testing
    return result;
}

static uint8_t convertl(char c)//convert char B of AB to 0xB 
{
    uint8_t result,intc;
    intc = (int) c;
    switch (intc) {
        case 97: result = 0x0a; break;
        case 98: result = 0x0b; break;
        case 99: result = 0x0c; break;
        case 100: result = 0x0d; break;
        case 101: result = 0x0e; break;
        case 48: result = 0x00; break;
        case 49: result = 0x01; break;
        case 50: result = 0x02; break;
        case 51: result = 0x03; break;
        case 52: result = 0x04; break;
        case 53: result = 0x05; break;
        case 54: result = 0x06; break;
        case 55: result = 0x07; break;
        case 56: result = 0x08; break;
        case 57: result = 0x09; break;
        default: result = 0x00;
    }
    printf("this low char is %c and the (int)c is %d,and the convert result is %x\n",c,intc,result);
    return result;
}

static uint8_t * preprocess(char * code)
{
    uint8_t * result;
    result = (uint8_t *)malloc( strlen(code)*sizeof(uint8_t));
    int i,j=0, high, low;
    
    for (i = 0; i<strlen(code); i++) {
        if (i%3 == 0) {
            high = converth(code[i]);
            low = convertl(code[i+1]);
            result[j] = high + low;
            j++;
        }
    }

    return result;
}

static void usage(char * prog)
{
    printf("Syntax: %s <arch+mode> <assembler-string>", prog);
    printf("\nThe following <arch+mode> options are supported:\n");
    
    if (cs_support(CS_ARCH_ARM)) {
        printf("        arm:       32-bit ARM\n");
        printf("        armb:      arm + big endian\n");
        printf("        thumb:     Thumb - little endian\n");
        printf("        thumbbe:   Thumb - big endian\n");
    }
    
    if (cs_support(CS_ARCH_ARM64)) {
         printf("        arm64:     AArch64 - little endian\n");
    }
    
    if (cs_support(CS_ARCH_MIPS)) {
        printf("        mips:      mips32 + little endian\n");
        printf("        mipsbe:    mips32 + big endian\n");
        printf("        mips64:    mips64 + little endian\n");
        printf("        mips64be:  mips64 + big endian\n");
    }
    
    if (cs_support(CS_ARCH_X86)) {
         printf("        x16:       16-bit mode (X86)\n");
         printf("        x32:       32-bit mode (X86)\n");
         printf("        x64:       64-bit mode (X86)\n");
         printf("        x16att:    16-bit mode (X86) syntax-att\n");
         printf("        x32att:    32-bit mode (X86) syntax-att\n");
         printf("        x64att:    64-bit mode (X86) syntax-att\n");
    }
    
    if (cs_support(CS_ARCH_PPC)) {
        printf("        ppc64:     ppc64 + little endian\n");
        printf("        ppc64be:   ppc64 + big endian\n");
    }
    
    if (cs_support(CS_ARCH_SPARC)) {
        printf("        sparcv9:   sparcv9\n");
    }
    
    if (cs_support(CS_ARCH_SYSZ)) {
       printf("        systemz:   SystemZ (S390x)\n");
    }
    
    if (cs_support(CS_ARCH_XCORE)) {
        printf("        xcore:     XCORE\n");
    }
    
    printf("\n");
}

int main(int argc, char ** argv)
{
    csh handle;
    char *mode;
    uint8_t *assembly;
    size_t size;
    uint64_t *address;
    cs_insn *insn;
    cs_err err;
    
    if (argc != 3) {
        usage(argv[0]);
        return -1;
    }
    
    mode = argv[1];
    assembly = preprocess(argv[2]);
    
    if (!strcmp(mode,"arm")) {
        err = cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle);
    }
    
    if (!strcmp(mode,"armb")) {
        err = cs_open(CS_ARCH_ARM, CS_MODE_ARM+CS_MODE_LITTLE_ENDIAN, &handle);
    }
    
    if (!strcmp(mode,"thumb")) {
        err = cs_open(CS_ARCH_ARM, CS_MODE_THUMB+CS_MODE_LITTLE_ENDIAN, &handle);
    }
    
    if (!strcmp(mode,"thumbbe")) {
        err = cs_open(CS_ARCH_ARM, CS_MODE_THUMB+CS_MODE_BIG_ENDIAN, &handle);
    }
    
    if (!strcmp(mode,"armb64")) {
        err = cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle);
    }
    
    if (!strcmp(mode,"mips")) {
        err = cs_open(CS_ARCH_MIPS, CS_MODE_MIPS32+CS_MODE_LITTLE_ENDIAN, &handle);
    }
    
    if (!strcmp(mode,"mipsbe")) {
        err = cs_open(CS_ARCH_MIPS, CS_MODE_MIPS64+CS_MODE_LITTLE_ENDIAN, &handle);
    }
    
    if (!strcmp(mode,"mips64be")) {
        err = cs_open(CS_ARCH_MIPS, CS_MODE_MIPS64+CS_MODE_BIG_ENDIAN, &handle);
    }
    
    if (!strcmp(mode,"x16")) {
        err = cs_open(CS_ARCH_X86, CS_MODE_16, &handle);
    }
    
    if (!strcmp(mode,"x32")) {
        err = cs_open(CS_ARCH_X86, CS_MODE_32, &handle);
    }
    
    if (!strcmp(mode,"x64")) {
        err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    }
    
    if (!strcmp(mode,"x16att")) {
        err = cs_open(CS_ARCH_X86, CS_MODE_16, &handle);
        if (!err) {
            cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
        }
    }
    
    if (!strcmp(mode,"x32att")) {
        err = cs_open(CS_ARCH_X86, CS_MODE_32, &handle);
        if (!err) {
            cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
        }
    }
    
    if (!strcmp(mode,"x64att")) {
        err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
        if (!err) {
            cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
        }
    }
    
    if (!strcmp(mode,"ppc64")) {
        err = cs_open(CS_ARCH_PPC,CS_MODE_64+CS_MODE_LITTLE_ENDIAN,&handle);
    }
    
    if (!strcmp(mode,"ppc64be")) {
        err = cs_open(CS_ARCH_PPC,CS_MODE_64+CS_MODE_BIG_ENDIAN,&handle);
    }
    
    if (!strcmp(mode,"sparcv9")) {
        err = cs_open(CS_ARCH_SPARC,CS_MODE_V9,&handle);
    }
           
    if (!strcmp(mode, "systemz") || !strcmp(mode, "sysz") || !strcmp(mode, "s390x")) {
        err = cs_open(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN, &handle);
    }
    
    if (!strcmp(mode,"xcore")) {
        err = cs_open(CS_ARCH_XCORE, CS_MODE_BIG_ENDIAN,&handle);
    }
           
    if (err) {
        printf("ERROR: Failed on cs_open()\n");
        usage(argv[0]);
        return -1;
    }
    //test
    int k;
    for (k=0;  k <= strlen((char *)assembly); k++) {
        printf("%x ",assembly[k]);
    }
    printf("the strlen of assembly is %lu\n",strlen((char *)assembly));
    //end test
    size = cs_disasm(handle, assembly, strlen((char *)assembly),
                                         0x1000,//Is this address necessary?
                                         0,
                                         &insn);
    if (size>0) {
        size_t j;
        printf("\n");
        for (j=0;j<size;j++) {
            printf("\t%s\t%s\t%s\n", insn[j].bytes,insn[j].mnemonic,insn[j].op_str);
        }
        cs_free(insn, size);
    }
           
    cs_close(&handle);
    return 0;
}



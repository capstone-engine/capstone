#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include <capstone/capstone.h>

static uint8_t converth(char c)//convert cahr A of AB to 0xA0
{
    uint8_t result,intc;
    intc = (int) c;
    
    if (intc >= '0' && intc <= '9') {
        result = 16 * (intc - '0');
    }
    
    if (intc >= 'a' && intc <= 'f') {
        result = 16 *(10 + intc - 'a');
    }
    
    if (intc >= 'A' && intc <= 'F') {
        result = 16 * (10 + intc - 'A');
    }
    
    printf("this high char is %c and the (int)c is %d, and the result is %x \n",c,intc,result);//just for testing
    return result;
}

static uint8_t convertl(char c)//convert char B of AB to 0xB
{
    uint8_t result,intc;
    intc = (int) c;
    
    if (intc >= '0' && intc <= '9') {
        result = intc - '0';
    }
    
    if (intc >= 'a' && intc <= 'f') {
        result = 10 + intc - 'a';
    }
    
    if (intc >= 'A' && intc <= 'F') {
        result = 10 + intc - 'A';
    }
    
    printf("this low char is %c and the (int)c is %d,and the convert result is %x\n",c,intc,result);
    return result;
}

static uint8_t * preprocess(char * code)
{
    uint8_t * result;
    result = (uint8_t *)malloc(strlen(code));
    int i,j=0;
    uint8_t intc, high, low;
    
    for (i = 0; i<strlen(code); i++) {
        intc = (int)code[i];
        if ((intc >= '0' && intc <= '9') || (intc >= 'a' && intc <= 'f') || (intc >= 'A' && intc <= 'F')) {//Skip the character not in set A = {'a'~'f','A'~'F','0'~'9'}.
            printf("the %d code char is %c\n",i,code[i]);
            uint8_t ints = (int)code[i+1];
            if ((ints >= '0' && ints <= '9') || (ints >= 'a' && ints <= 'f') || (ints >= 'A' && ints <= 'F')) {//Valid hexadecimal must be AB, A can't represent 0A.
                high = converth(code[i]);
                low = convertl(code[i+1]);
                result[j] = high + low;
                j++;
                i++;
            }
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
    printf("strlen of assembly is %lu",strlen((char *)assembly));
    
    if (strlen((char *)assembly) == 0) {
        printf("Please inpute complete hexadecimal number.\n");
        return -1;
    }
    
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
    printf("the result of converting is :");
    for (k=0;  k <= strlen((char *)assembly); k++) {
        printf("%x ",assembly[k]);
    }
    printf("\n the strlen of assembly is %lu\n",strlen((char *)assembly));
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



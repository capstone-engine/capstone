# CS_ARCH_ALPHA, CS_MODE_LITTLE_ENDIAN, None
0x03,0x00,0x22,0x40 = addl   $1,$2,$3
0x03,0xd0,0x3b,0x40 = addl   $1,0xde,$3
0x03,0x04,0x22,0x40 = addq   $1,$2,$3
0x03,0xd4,0x3b,0x40 = addq   $1,0xde,$3
0x03,0xb0,0x22,0x58 = adds/su        $f1,$f10,$f11
0x03,0xb4,0x22,0x58 = addt/su        $f1,$f10,$f11
0x03,0x00,0x22,0x44 = and    $1,$2,$3
0x03,0xd0,0x3b,0x44 = and    $1,0xde,$3
0xfc,0x3f,0x20,0xe4 = beq    $1,0xfffffffffffffff4
0xfc,0x3f,0x20,0xf8 = bge    $1,0xfffffffffffffff4
0xfc,0x3f,0x20,0xfc = bgt    $1,0xfffffffffffffff4
0x03,0x01,0x22,0x44 = bic    $1,$2,$3
0x03,0xd1,0x3b,0x44 = bic    $1,0xde,$3
0x03,0x04,0x22,0x44 = bis    $1,$2,$3
0x03,0xd4,0x3b,0x44 = bis    $1,0xde,$3
0xfc,0x3f,0x20,0xe0 = blbc   $1,0xfffffffffffffff4
0xfc,0x3f,0x20,0xf0 = blbs   $1,0xfffffffffffffff4
0xfc,0x3f,0x20,0xec = ble    $1,0xfffffffffffffff4
0xfc,0x3f,0x20,0xe8 = blt    $1,0xfffffffffffffff4
0xfc,0x3f,0x20,0xf4 = bne    $1,0xfffffffffffffff4
0xfc,0x3f,0xe0,0xc3 = br     $31,0xfffffffffffffff4
0xfc,0x3f,0x40,0xd3 = bsr    $26,$0xfffffffffffffff4 ..ng
0x83,0x04,0x22,0x44 = cmoveq $1,$2,$3
0xc3,0x08,0x22,0x44 = cmovge $1,$2,$3
0xc3,0x0c,0x22,0x44 = cmovgt $1,$2,$3
0xc3,0x02,0x22,0x44 = cmovlbc        $1,$2,$3
0x83,0x02,0x22,0x44 = cmovlbs        $1,$2,$3
0x83,0x0c,0x22,0x44 = cmovle $1,$2,$3
0x83,0x08,0x22,0x44 = cmovlt $1,$2,$3
0xc3,0x04,0x22,0x44 = cmovne $1,$2,$3
0xe3,0x01,0x22,0x40 = cmpbge $1,$2,$3
0xe3,0xd1,0x3b,0x40 = cmpbge $1,0xde,$3
0xa3,0x05,0x22,0x40 = cmpeq  $1,$2,$3
0xa3,0xd5,0x3b,0x40 = cmpeq  $1,0xde,$3
0xa3,0x0d,0x22,0x40 = cmple  $1,$2,$3
0xa3,0xdd,0x3b,0x40 = cmple  $1,0xde,$3
0xa3,0x09,0x22,0x40 = cmplt  $1,$2,$3
0xa3,0xd9,0x3b,0x40 = cmplt  $1,0xde,$3
0xa3,0xb4,0x22,0x58 = cmpteq/su      $f1,$f10,$f11
0xe3,0xb4,0x22,0x58 = cmptle/su      $f1,$f10,$f11
0xc3,0xb4,0x22,0x58 = cmptlt/su      $f1,$f10,$f11
0x83,0xb4,0x22,0x58 = cmptun/su      $f1,$f10,$f11
0xa3,0x07,0x22,0x40 = cmpule $1,$2,$3
0xa3,0xd7,0x3b,0x40 = cmpule $1,0xde,$3
0xa3,0x03,0x22,0x40 = cmpult $1,$2,$3
0xa3,0xd3,0x3b,0x40 = cmpult $1,0xde,$3
0x43,0x04,0x22,0x5c = cpyse  $f1,$f10,$f11
0x23,0x04,0x22,0x5c = cpysn  $f1,$f10,$f11
0x03,0x04,0x22,0x5c = cpys   $f1,$f10,$f11
0x42,0x06,0xe1,0x73 = ctlz   $1,$2
0x02,0x06,0xe1,0x73 = ctpop  $1,$2
0x62,0x06,0xe1,0x73 = cttz   $1,$2
0x82,0xf7,0xe1,0x5b = cvtqs/sui      $f1,$f10
0xc2,0xf7,0xe1,0x5b = cvtqt/sui      $f1,$f10
0x82,0xd5,0xe1,0x5b = cvtst/s        $f1,$f10
0xe2,0xa5,0xe1,0x5b = cvttq/svc      $f1,$f10
0x82,0xf5,0xe1,0x5b = cvtts/sui      $f1,$f10
0x63,0xb0,0x22,0x58 = divs/su        $f1,$f10,$f11
0x63,0xb4,0x22,0x58 = divt/su        $f1,$f10,$f11
0x00,0xe8,0xe1,0x63 = ecb    ($1)
0x03,0x09,0x22,0x44 = eqv    $1,$2,$3
0x03,0xd9,0x3b,0x44 = eqv    $1,0xde,$3
0x00,0x04,0x00,0x60 = excb
0xc3,0x00,0x22,0x48 = extbl  $1,$2,$3
0xc3,0xd0,0x3b,0x48 = extbl $1,0xde,$3
0x43,0x0d,0x22,0x48 = extlh $1,$2,$3
0x43,0xdd,0x3b,0x48 = extlh $1,0xde,$3
0xc3,0x04,0x22,0x48 = extll $1,$2,$3
0xc3,0xd4,0x3b,0x48 = extll $1,0xde,$3
0x43,0x0f,0x22,0x48 = extqh $1,$2,$3
0x43,0xdf,0x3b,0x48 = extqh $1,0xde,$3
0xc3,0x06,0x22,0x48 = extql $1,$2,$3
0xc3,0xd6,0x3b,0x48 = extql $1,0xde,$3
0x43,0x0b,0x22,0x48 = extwh $1,$2,$3
0x43,0xdb,0x3b,0x48 = extwh $1,0xde,$3
0xc3,0x02,0x22,0x48 = extwl $1,$2,$3
0xc3,0xd2,0x3b,0x48 = extwl $1,0xde,$3
0xfc,0x3f,0x20,0xc4 = fbeq  $f1,0xfffffffffffffff4
0xfc,0x3f,0x20,0xd8 = fbge  $f1,0xfffffffffffffff4
0xfc,0x3f,0x20,0xdc = fbgt  $f1,0xfffffffffffffff4
0xfc,0x3f,0x20,0xcc = fble  $f1,0xfffffffffffffff4
0xfc,0x3f,0x20,0xc8 = fblt  $f1,0xfffffffffffffff4
0xfc,0x3f,0x20,0xd4 = fbne  $f1,0xfffffffffffffff4
0x43,0x05,0x22,0x5c = fcmoveq       ,$f10,$f11
0xa3,0x05,0x22,0x5c = fcmovge       ,$f10,$f11
0xe3,0x05,0x22,0x5c = fcmovgt       ,$f10,$f11
0xc3,0x05,0x22,0x5c = fcmovle       ,$f10,$f11
0x83,0x05,0x22,0x5c = fcmovlt       ,$f10,$f11
0x63,0x05,0x22,0x5c = fcmovne       ,$f10,$f11
0x00,0x80,0xe1,0x63 = fetch ($1)
0x00,0xa0,0xe1,0x63 = fetch_m       ($1)
0x01,0x0f,0x3f,0x70 = ftois $f1,$1
0x01,0x0e,0x3f,0x70 = ftoit $f1,$1
0x63,0x01,0x22,0x48 = insbl $1,$2,$3
0x63,0xd1,0x3b,0x48 = insbl $1,0xde,$3
0xe3,0x0c,0x22,0x48 = inslh $1,$2,$3
0xe3,0xdc,0x3b,0x48 = inslh $1,0xde,$3
0x63,0x05,0x22,0x48 = insll $1,$2,$3
0x63,0xd5,0x3b,0x48 = insll $1,0xde,$3
0xe3,0x0e,0x22,0x48 = insqh $1,$2,$3
0xe3,0xde,0x3b,0x48 = insqh $1,0xde,$3
0x63,0x07,0x22,0x48 = insql $1,$2,$3
0x63,0xd7,0x3b,0x48 = insql $1,0xde,$3
0xe3,0x0a,0x22,0x48 = inswh $1,$2,$3
0xe3,0xda,0x3b,0x48 = inswh $1,0xde,$3
0x63,0x03,0x22,0x48 = inswl $1,$2,$3
0x63,0xd3,0x3b,0x48 = inswl $1,0xde,$3
0x81,0x00,0x3f,0x50 = itofs $1,$f1
0x81,0x04,0x3f,0x50 = itoft $1,$f1
0x00,0x00,0xfa,0x6b = jmp   $31,$12,0
0x00,0x40,0x5b,0x6b = jsr    $26,($27),0
0xff,0xcf,0x22,0x68 = jsr_coroutine $1,($2),0xfff
0x10,0x00,0x22,0x20 = lda   $1,0x10($2)
0x10,0x00,0x22,0x24 = ldah  $1,0x10($2)
0x10,0x00,0x22,0x28 = ldbu  $1,0x10($2)
0x10,0x00,0x22,0xa0 = ldl   $1,0x10($2)
0x10,0x00,0x22,0xa8 = ldl_l $1,0x10($2)
0x10,0x00,0x22,0xa4 = ldq   $1,0x10($2)
0x10,0x00,0x22,0xac = ldq_l $1,0x10($2)
0x10,0x00,0x22,0x2c = ldq_u $1,0x10($2)
0x10,0x00,0x22,0x88 = lds   $f1,0x10($2)
0x10,0x00,0x22,0x8c = ldt   $f1,0x10($2)
0x10,0x00,0x22,0x30 = ldwu  $1,0x10($2)
0x00,0x40,0x00,0x60 = mb
0x43,0x00,0x22,0x48 = mskbl $1,$2,$3
0x43,0xd0,0x3b,0x48 = mskbl $1,0xde,$3
0x43,0x0c,0x22,0x48 = msklh $1,$2,$3
0x43,0xdc,0x3b,0x48 = msklh $1,0xde,$3
0x43,0x04,0x22,0x48 = mskll $1,$2,$3
0x43,0xd4,0x3b,0x48 = mskll $1,0xde,$3
0x43,0x0e,0x22,0x48 = mskqh $1,$2,$3
0x43,0xde,0x3b,0x48 = mskqh $1,0xde,$3
0x43,0x06,0x22,0x48 = mskql $1,$2,$3
0x43,0xd6,0x3b,0x48 = mskql $1,0xde,$3
0x43,0x0a,0x22,0x48 = mskwh $1,$2,$3
0x43,0xda,0x3b,0x48 = mskwh $1,0xde,$3
0x43,0x02,0x22,0x48 = mskwl $1,$2,$3
0x43,0xd2,0x3b,0x48 = mskwl $1,0xde,$3
0x03,0x00,0x22,0x4c = mull  $1,$2,$3
0x03,0xd0,0x3b,0x4c = mull  $1,0xde,$3
0x03,0x04,0x22,0x4c = mulq  $1,$2,$3
0x03,0xd4,0x3b,0x4c = mulq  $1,0xde,$3
0x43,0xb0,0x22,0x58 = muls/su       $f1,$f10,$f11
0x43,0xb4,0x22,0x58 = mult/su       $f1,$f10,$f11
0x03,0x05,0x22,0x44 = ornot $1,$2,$3
0x03,0xd5,0x3b,0x44 = ornot $1,0xde,$3
0x00,0xe0,0x20,0x60 = rc    $1
0x01,0x80,0xfa,0x6b = ret   $31,($26),1
0x00,0xc0,0x1f,0x60 = rpcc  $0
0x00,0xf0,0x20,0x60 = rs    $1
0x43,0x00,0x22,0x40 = s4addl        $1,$2,$3
0x43,0xd0,0x3b,0x40 = s4addl        $1,0xde,$3
0x63,0x01,0x22,0x40 = s4subl        $1,$2,$3
0x63,0xd1,0x3b,0x40 = s4subl        $1,0xde,$3
0x63,0x05,0x22,0x40 = s4subq        $1,$2,$3
0x63,0xd5,0x3b,0x40 = s4subq        $1,0xde,$3
0x43,0x02,0x22,0x40 = s8addl        $1,$2,$3
0x43,0xd2,0x3b,0x40 = s8addl        $1,0xde,$3
0x43,0x06,0x22,0x40 = s8addq        $1,$2,$3
0x43,0xd6,0x3b,0x40 = s8addq        $1,0xde,$3
0x63,0x03,0x22,0x40 = s8subl        $1,$2,$3
0x63,0xd3,0x3b,0x40 = s8subl        $1,0xde,$3
0x63,0x07,0x22,0x40 = s8subq        $1,$2,$3
0x63,0xd7,0x3b,0x40 = s8subq        $1,0xde,$3
0x02,0x00,0xe1,0x73 = sextb $1,$2
0x22,0x00,0xe1,0x73 = sextw $1,$2
0x23,0x07,0x22,0x48 = sll   $1,$2,$3
0x23,0xd7,0x3b,0x48 = sll   $1,0xde,$3
0x62,0xb1,0xe1,0x53 = sqrts/su      $f1,$f10
0x62,0xb5,0xe1,0x53 = sqrtt/su      $f1,$f10
0x83,0x07,0x22,0x48 = sra   $1,$2,$3
0x83,0xd7,0x3b,0x48 = sra   $1,0xde,$3
0x83,0x06,0x22,0x48 = srl   $1,$2,$3
0x83,0xd6,0x3b,0x48 = srl   $1,0xde,$3
0x10,0x00,0x22,0x38 = stb   $1, 0x10($2)
0x10,0x00,0x22,0xb0 = stl   $1,0x10($2)
0x10,0x00,0x22,0xb8 = stl_c $1,0x10($2)
0x10,0x00,0x22,0xb4 = stq   $1,0x10($2)
0x10,0x00,0x22,0xbc = stq_c $1,0x10($2)
0x10,0x00,0x22,0x3c = stq_u $1, 0x10($2)
0x10,0x00,0x22,0x98 = sts   $f1,0x10($2)
0x10,0x00,0x22,0x9c = stt   $f1,0x10($2)
0x10,0x00,0x22,0x34 = stw   $1,0x10($2)
0x23,0x01,0x22,0x40 = subl  $1,$2,$3
0x23,0xd1,0x3b,0x40 = subl  $1,0xde,$3
0x23,0x05,0x22,0x40 = subq  $1,$2,$3
0x23,0xd5,0x3b,0x40 = subq  $1,0xde,$3
0x23,0xb0,0x22,0x58 = subs/su       $f1,$f10,$f11
0x23,0xb4,0x22,0x58 = subt/su       $f1,$f10,$f11
0x00,0x00,0x00,0x60 = trapb
0x03,0x06,0x22,0x4c = umulh $1,$2,$3
0x03,0xd6,0x3b,0x4c = umulh $1,0xde,$3
0x00,0xf8,0xe1,0x63 = wh64  ($1)
0x00,0xfc,0xe1,0x63 = wh64en        ($1)
0x00,0x44,0x00,0x60 = wmb
0x03,0x08,0x22,0x44 = xor   $1,$2,$3
0x03,0xd8,0x3b,0x44 = xor   $1,0xde,$3
0x23,0xd6,0x3b,0x48 = zapnot        $1,0xde,$3
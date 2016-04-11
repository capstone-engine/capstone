0x1000:	tbb	[r1, r0]

0x1004:	movs	r4, #0xf0
	Update-flags: True

0x1006:	lsls	r4, r0, #0x1c
	Update-flags: True

0x1008:	subs	r4, #0x1f
	Update-flags: True

0x100a:	stm	r0!, {r1, r4, r5, r6, r7}
	Write-back: True

0x100c:	movs	r0, r0
	Update-flags: True

0x100e:	mov.w	r1, #0

0x1012:	ldr	r6, [r0, #0x44]
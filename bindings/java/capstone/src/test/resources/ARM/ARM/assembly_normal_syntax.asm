0x1000:	bl	#0xfbc

0x1004:	str	lr, [sp, #-4]!
	Write-back: True

0x1008:	andeq	r0, r0, r0
	Code condition: 1

0x100c:	str	r8, [r2, #-0x3e0]!
	Write-back: True

0x1010:	mcreq	p2, #0, r0, c3, c1, #7
	Code condition: 1

0x1014:	mov	r0, #0

0x1018:	strb	r3, [r1, r2]

0x101c:	cmp	r3, #0
	Update-flags: True

0x1020:	setend	be

0x1024:	ldm	r0, {r0, r2, lr} ^
	User-mode: True
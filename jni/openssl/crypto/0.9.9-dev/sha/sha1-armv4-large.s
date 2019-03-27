.text

.global	sha1_block_data_order
.type	sha1_block_data_order,%function

.align	2
sha1_block_data_order:
	stmdb	sp!,{r4-r12,lr}
	add	r2,r1,r2,lsl#6	@ r2 to point at the end of r1
	ldmia	r0,{r3,r4,r5,r6,r7}
.Lloop:
	ldr	r8,.LK_00_19
	mov	r14,sp
	sub	sp,sp,#15*4
	mov	r5,r5,ror#30
	mov	r6,r6,ror#30
	mov	r7,r7,ror#30		@ [6]
.L_00_15:
	ldrb	r10,[r1],#4
	ldrb	r11,[r1,#-3]
	ldrb	r12,[r1,#-2]
	add	r7,r8,r7,ror#2			@ E+=K_00_19
	orr	r10,r11,r10,lsl#8
	ldrb	r11,[r1,#-1]
	orr	r10,r12,r10,lsl#8
	add	r7,r7,r3,ror#27			@ E+=ROR(A,27)
	orr	r10,r11,r10,lsl#8
	add	r7,r7,r10			@ E+=X[i]
	eor	r11,r5,r6			@ F_xx_xx
	str	r10,[r14,#-4]!
	and	r11,r4,r11,ror#2
	eor	r11,r11,r6,ror#2		@ F_00_19(B,C,D)
	add	r7,r7,r11			@ E+=F_00_19(B,C,D)
	ldrb	r10,[r1],#4
	ldrb	r11,[r1,#-3]
	ldrb	r12,[r1,#-2]
	add	r6,r8,r6,ror#2			@ E+=K_00_19
	orr	r10,r11,r10,lsl#8
	ldrb	r11,[r1,#-1]
	orr	r10,r12,r10,lsl#8
	add	r6,r6,r7,ror#27			@ E+=ROR(A,27)
	orr	r10,r11,r10,lsl#8
	add	r6,r6,r10			@ E+=X[i]
	eor	r11,r4,r5			@ F_xx_xx
	str	r10,[r14,#-4]!
	and	r11,r3,r11,ror#2
	eor	r11,r11,r5,ror#2		@ F_00_19(B,C,D)
	add	r6,r6,r11			@ E+=F_00_19(B,C,D)
	ldrb	r10,[r1],#4
	ldrb	r11,[r1,#-3]
	ldrb	r12,[r1,#-2]
	add	r5,r8,r5,ror#2			@ E+=K_00_19
	orr	r10,r11,r10,lsl#8
	ldrb	r11,[r1,#-1]
	orr	r10,r12,r10,lsl#8
	add	r5,r5,r6,ror#27			@ E+=ROR(A,27)
	orr	r10,r11,r10,lsl#8
	add	r5,r5,r10			@ E+=X[i]
	eor	r11,r3,r4			@ F_xx_xx
	str	r10,[r14,#-4]!
	and	r11,r7,r11,ror#2
	eor	r11,r11,r4,ror#2		@ F_00_19(B,C,D)
	add	r5,r5,r11			@ E+=F_00_19(B,C,D)
	ldrb	r10,[r1],#4
	ldrb	r11,[r1,#-3]
	ldrb	r12,[r1,#-2]
	add	r4,r8,r4,ror#2			@ E+=K_00_19
	orr	r10,r11,r10,lsl#8
	ldrb	r11,[r1,#-1]
	orr	r10,r12,r10,lsl#8
	add	r4,r4,r5,ror#27			@ E+=ROR(A,27)
	orr	r10,r11,r10,lsl#8
	add	r4,r4,r10			@ E+=X[i]
	eor	r11,r7,r3			@ F_xx_xx
	str	r10,[r14,#-4]!
	and	r11,r6,r11,ror#2
	eor	r11,r11,r3,ror#2		@ F_00_19(B,C,D)
	add	r4,r4,r11			@ E+=F_00_19(B,C,D)
	ldrb	r10,[r1],#4
	ldrb	r11,[r1,#-3]
	ldrb	r12,[r1,#-2]
	add	r3,r8,r3,ror#2			@ E+=K_00_19
	orr	r10,r11,r10,lsl#8
	ldrb	r11,[r1,#-1]
	orr	r10,r12,r10,lsl#8
	add	r3,r3,r4,ror#27			@ E+=ROR(A,27)
	orr	r10,r11,r10,lsl#8
	add	r3,r3,r10			@ E+=X[i]
	eor	r11,r6,r7			@ F_xx_xx
	str	r10,[r14,#-4]!
	and	r11,r5,r11,ror#2
	eor	r11,r11,r7,ror#2		@ F_00_19(B,C,D)
	add	r3,r3,r11			@ E+=F_00_19(B,C,D)
	teq	r14,sp
	bne	.L_00_15		@ [((11+4)*5+2)*3]
	ldrb	r10,[r1],#4
	ldrb	r11,[r1,#-3]
	ldrb	r12,[r1,#-2]
	add	r7,r8,r7,ror#2			@ E+=K_00_19
	orr	r10,r11,r10,lsl#8
	ldrb	r11,[r1,#-1]
	orr	r10,r12,r10,lsl#8
	add	r7,r7,r3,ror#27			@ E+=ROR(A,27)
	orr	r10,r11,r10,lsl#8
	add	r7,r7,r10			@ E+=X[i]
	eor	r11,r5,r6			@ F_xx_xx
	str	r10,[r14,#-4]!
	and	r11,r4,r11,ror#2
	eor	r11,r11,r6,ror#2		@ F_00_19(B,C,D)
	add	r7,r7,r11			@ E+=F_00_19(B,C,D)
	ldr	r10,[r14,#15*4]
	ldr	r11,[r14,#13*4]
	ldr	r12,[r14,#7*4]
	add	r6,r8,r6,ror#2			@ E+=K_xx_xx
	eor	r10,r10,r11
	ldr	r11,[r14,#2*4]
	add	r6,r6,r7,ror#27			@ E+=ROR(A,27)
	eor	r10,r10,r12
	eor	r10,r10,r11
	eor	r11,r4,r5			@ F_xx_xx, but not in 40_59
	mov	r10,r10,ror#31
	add	r6,r6,r10			@ E+=X[i]
	str	r10,[r14,#-4]!
	and	r11,r3,r11,ror#2
	eor	r11,r11,r5,ror#2		@ F_00_19(B,C,D)
	add	r6,r6,r11			@ E+=F_00_19(B,C,D)
	ldr	r10,[r14,#15*4]
	ldr	r11,[r14,#13*4]
	ldr	r12,[r14,#7*4]
	add	r5,r8,r5,ror#2			@ E+=K_xx_xx
	eor	r10,r10,r11
	ldr	r11,[r14,#2*4]
	add	r5,r5,r6,ror#27			@ E+=ROR(A,27)
	eor	r10,r10,r12
	eor	r10,r10,r11
	eor	r11,r3,r4			@ F_xx_xx, but not in 40_59
	mov	r10,r10,ror#31
	add	r5,r5,r10			@ E+=X[i]
	str	r10,[r14,#-4]!
	and	r11,r7,r11,ror#2
	eor	r11,r11,r4,ror#2		@ F_00_19(B,C,D)
	add	r5,r5,r11			@ E+=F_00_19(B,C,D)
	ldr	r10,[r14,#15*4]
	ldr	r11,[r14,#13*4]
	ldr	r12,[r14,#7*4]
	add	r4,r8,r4,ror#2			@ E+=K_xx_xx
	eor	r10,r10,r11
	ldr	r11,[r14,#2*4]
	add	r4,r4,r5,ror#27			@ E+=ROR(A,27)
	eor	r10,r10,r12
	eor	r10,r10,r11
	eor	r11,r7,r3			@ F_xx_xx, but not in 40_59
	mov	r10,r10,ror#31
	add	r4,r4,r10			@ E+=X[i]
	str	r10,[r14,#-4]!
	and	r11,r6,r11,ror#2
	eor	r11,r11,r3,ror#2		@ F_00_19(B,C,D)
	add	r4,r4,r11			@ E+=F_00_19(B,C,D)
	ldr	r10,[r14,#15*4]
	ldr	r11,[r14,#13*4]
	ldr	r12,[r14,#7*4]
	add	r3,r8,r3,ror#2			@ E+=K_xx_xx
	eor	r10,r10,r11
	ldr	r11,[r14,#2*4]
	add	r3,r3,r4,ror#27			@ E+=ROR(A,27)
	eor	r10,r10,r12
	eor	r10,r10,r11
	eor	r11,r6,r7			@ F_xx_xx, but not in 40_59
	mov	r10,r10,ror#31
	add	r3,r3,r10			@ E+=X[i]
	str	r10,[r14,#-4]!
	and	r11,r5,r11,ror#2
	eor	r11,r11,r7,ror#2		@ F_00_19(B,C,D)
	add	r3,r3,r11			@ E+=F_00_19(B,C,D)

	ldr	r8,.LK_20_39		@ [+15+16*4]
	sub	sp,sp,#25*4
	cmn	sp,#0			@ [+3], clear carry to denote 20_39
.L_20_39_or_60_79:
	ldr	r10,[r14,#15*4]
	ldr	r11,[r14,#13*4]
	ldr	r12,[r14,#7*4]
	add	r7,r8,r7,ror#2			@ E+=K_xx_xx
	eor	r10,r10,r11
	ldr	r11,[r14,#2*4]
	add	r7,r7,r3,ror#27			@ E+=ROR(A,27)
	eor	r10,r10,r12
	eor	r10,r10,r11
	eor	r11,r5,r6			@ F_xx_xx, but not in 40_59
	mov	r10,r10,ror#31
	add	r7,r7,r10			@ E+=X[i]
	str	r10,[r14,#-4]!
	eor	r11,r4,r11,ror#2		@ F_20_39(B,C,D)
	add	r7,r7,r11			@ E+=F_20_39(B,C,D)
	ldr	r10,[r14,#15*4]
	ldr	r11,[r14,#13*4]
	ldr	r12,[r14,#7*4]
	add	r6,r8,r6,ror#2			@ E+=K_xx_xx
	eor	r10,r10,r11
	ldr	r11,[r14,#2*4]
	add	r6,r6,r7,ror#27			@ E+=ROR(A,27)
	eor	r10,r10,r12
	eor	r10,r10,r11
	eor	r11,r4,r5			@ F_xx_xx, but not in 40_59
	mov	r10,r10,ror#31
	add	r6,r6,r10			@ E+=X[i]
	str	r10,[r14,#-4]!
	eor	r11,r3,r11,ror#2		@ F_20_39(B,C,D)
	add	r6,r6,r11			@ E+=F_20_39(B,C,D)
	ldr	r10,[r14,#15*4]
	ldr	r11,[r14,#13*4]
	ldr	r12,[r14,#7*4]
	add	r5,r8,r5,ror#2			@ E+=K_xx_xx
	eor	r10,r10,r11
	ldr	r11,[r14,#2*4]
	add	r5,r5,r6,ror#27			@ E+=ROR(A,27)
	eor	r10,r10,r12
	eor	r10,r10,r11
	eor	r11,r3,r4			@ F_xx_xx, but not in 40_59
	mov	r10,r10,ror#31
	add	r5,r5,r10			@ E+=X[i]
	str	r10,[r14,#-4]!
	eor	r11,r7,r11,ror#2		@ F_20_39(B,C,D)
	add	r5,r5,r11			@ E+=F_20_39(B,C,D)
	ldr	r10,[r14,#15*4]
	ldr	r11,[r14,#13*4]
	ldr	r12,[r14,#7*4]
	add	r4,r8,r4,ror#2			@ E+=K_xx_xx
	eor	r10,r10,r11
	ldr	r11,[r14,#2*4]
	add	r4,r4,r5,ror#27			@ E+=ROR(A,27)
	eor	r10,r10,r12
	eor	r10,r10,r11
	eor	r11,r7,r3			@ F_xx_xx, but not in 40_59
	mov	r10,r10,ror#31
	add	r4,r4,r10			@ E+=X[i]
	str	r10,[r14,#-4]!
	eor	r11,r6,r11,ror#2		@ F_20_39(B,C,D)
	add	r4,r4,r11			@ E+=F_20_39(B,C,D)
	ldr	r10,[r14,#15*4]
	ldr	r11,[r14,#13*4]
	ldr	r12,[r14,#7*4]
	add	r3,r8,r3,ror#2			@ E+=K_xx_xx
	eor	r10,r10,r11
	ldr	r11,[r14,#2*4]
	add	r3,r3,r4,ror#27			@ E+=ROR(A,27)
	eor	r10,r10,r12
	eor	r10,r10,r11
	eor	r11,r6,r7			@ F_xx_xx, but not in 40_59
	mov	r10,r10,ror#31
	add	r3,r3,r10			@ E+=X[i]
	str	r10,[r14,#-4]!
	eor	r11,r5,r11,ror#2		@ F_20_39(B,C,D)
	add	r3,r3,r11			@ E+=F_20_39(B,C,D)
	teq	r14,sp			@ preserve carry
	bne	.L_20_39_or_60_79	@ [+((12+3)*5+2)*4]
	bcs	.L_done			@ [+((12+3)*5+2)*4], spare 300 bytes

	ldr	r8,.LK_40_59
	sub	sp,sp,#20*4		@ [+2]
.L_40_59:
	ldr	r10,[r14,#15*4]
	ldr	r11,[r14,#13*4]
	ldr	r12,[r14,#7*4]
	add	r7,r8,r7,ror#2			@ E+=K_xx_xx
	eor	r10,r10,r11
	ldr	r11,[r14,#2*4]
	add	r7,r7,r3,ror#27			@ E+=ROR(A,27)
	eor	r10,r10,r12
	eor	r10,r10,r11
	mov	r10,r10,ror#31
	add	r7,r7,r10			@ E+=X[i]
	str	r10,[r14,#-4]!
	and	r11,r4,r5,ror#2
	orr	r12,r4,r5,ror#2
	and	r12,r12,r6,ror#2
	orr	r11,r11,r12			@ F_40_59(B,C,D)
	add	r7,r7,r11			@ E+=F_40_59(B,C,D)
	ldr	r10,[r14,#15*4]
	ldr	r11,[r14,#13*4]
	ldr	r12,[r14,#7*4]
	add	r6,r8,r6,ror#2			@ E+=K_xx_xx
	eor	r10,r10,r11
	ldr	r11,[r14,#2*4]
	add	r6,r6,r7,ror#27			@ E+=ROR(A,27)
	eor	r10,r10,r12
	eor	r10,r10,r11
	mov	r10,r10,ror#31
	add	r6,r6,r10			@ E+=X[i]
	str	r10,[r14,#-4]!
	and	r11,r3,r4,ror#2
	orr	r12,r3,r4,ror#2
	and	r12,r12,r5,ror#2
	orr	r11,r11,r12			@ F_40_59(B,C,D)
	add	r6,r6,r11			@ E+=F_40_59(B,C,D)
	ldr	r10,[r14,#15*4]
	ldr	r11,[r14,#13*4]
	ldr	r12,[r14,#7*4]
	add	r5,r8,r5,ror#2			@ E+=K_xx_xx
	eor	r10,r10,r11
	ldr	r11,[r14,#2*4]
	add	r5,r5,r6,ror#27			@ E+=ROR(A,27)
	eor	r10,r10,r12
	eor	r10,r10,r11
	mov	r10,r10,ror#31
	add	r5,r5,r10			@ E+=X[i]
	str	r10,[r14,#-4]!
	and	r11,r7,r3,ror#2
	orr	r12,r7,r3,ror#2
	and	r12,r12,r4,ror#2
	orr	r11,r11,r12			@ F_40_59(B,C,D)
	add	r5,r5,r11			@ E+=F_40_59(B,C,D)
	ldr	r10,[r14,#15*4]
	ldr	r11,[r14,#13*4]
	ldr	r12,[r14,#7*4]
	add	r4,r8,r4,ror#2			@ E+=K_xx_xx
	eor	r10,r10,r11
	ldr	r11,[r14,#2*4]
	add	r4,r4,r5,ror#27			@ E+=ROR(A,27)
	eor	r10,r10,r12
	eor	r10,r10,r11
	mov	r10,r10,ror#31
	add	r4,r4,r10			@ E+=X[i]
	str	r10,[r14,#-4]!
	and	r11,r6,r7,ror#2
	orr	r12,r6,r7,ror#2
	and	r12,r12,r3,ror#2
	orr	r11,r11,r12			@ F_40_59(B,C,D)
	add	r4,r4,r11			@ E+=F_40_59(B,C,D)
	ldr	r10,[r14,#15*4]
	ldr	r11,[r14,#13*4]
	ldr	r12,[r14,#7*4]
	add	r3,r8,r3,ror#2			@ E+=K_xx_xx
	eor	r10,r10,r11
	ldr	r11,[r14,#2*4]
	add	r3,r3,r4,ror#27			@ E+=ROR(A,27)
	eor	r10,r10,r12
	eor	r10,r10,r11
	mov	r10,r10,ror#31
	add	r3,r3,r10			@ E+=X[i]
	str	r10,[r14,#-4]!
	and	r11,r5,r6,ror#2
	orr	r12,r5,r6,ror#2
	and	r12,r12,r7,ror#2
	orr	r11,r11,r12			@ F_40_59(B,C,D)
	add	r3,r3,r11			@ E+=F_40_59(B,C,D)
	teq	r14,sp
	bne	.L_40_59		@ [+((12+5)*5+2)*4]

	ldr	r8,.LK_60_79
	sub	sp,sp,#20*4
	cmp	sp,#0			@ set carry to denote 60_79
	b	.L_20_39_or_60_79	@ [+4], spare 300 bytes
.L_done:
	add	sp,sp,#80*4		@ "deallocate" stack frame
	ldmia	r0,{r8,r10,r11,r12,r14}
	add	r3,r8,r3
	add	r4,r10,r4
	add	r5,r11,r5,ror#2
	add	r6,r12,r6,ror#2
	add	r7,r14,r7,ror#2
	stmia	r0,{r3,r4,r5,r6,r7}
	teq	r1,r2
	bne	.Lloop			@ [+18], total 1307

	ldmia	sp!,{r4-r12,lr}
	tst	lr,#1
	moveq	pc,lr			@ be binary compatible with V4, yet
	.word	0xe12fff1e			@ interoperable with Thumb ISA:-)
.align	2
.LK_00_19:	.word	0x5a827999
.LK_20_39:	.word	0x6ed9eba1
.LK_40_59:	.word	0x8f1bbcdc
.LK_60_79:	.word	0xca62c1d6
.size	sha1_block_data_order,.-sha1_block_data_order
.asciz	"SHA1 block transform for ARMv4, CRYPTOGAMS by <appro@openssl.org>"

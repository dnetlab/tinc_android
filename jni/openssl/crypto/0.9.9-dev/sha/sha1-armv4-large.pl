#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@fy.chalmers.se> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# sha1_block procedure for ARMv4.
#
# January 2007.

# Size/performance trade-off
# ====================================================================
# impl		size in bytes	comp cycles[*]	measured performance
# ====================================================================
# thumb		304		3212		4420
# armv4-small	392/+29%	1958/+64%	2250/+96%
# armv4-compact	740/+89%	1552/+26%	1840/+22%
# armv4-large	1420/+92%	1307/+19%	1500/+23%
# full unroll	~5100/+260%	~1260/+4%	~1500/+0%
# ====================================================================
# thumb		= same as 'small' but in Thumb instructions[**] and
#		  with recurring code in two private functions;
# small		= detached Xload/update, loops are folded;
# compact	= detached Xload/update, 5x unroll;
# large		= interleaved Xload/update, 5x unroll;
# full unroll	= interleaved Xload/update, full unroll, estimated[!];
#
# [*]	Manually counted instructions in "grand" loop body. Measured
#	performance is affected by prologue and epilogue overhead,
#	i-cache availability, branch penalties, etc.
# [**]	While each Thumb instruction is twice smaller, they are not as
#	diverse as ARM ones: e.g., there are only two arithmetic
#	instructions with 3 arguments, no [fixed] rotate, addressing
#	modes are limited. As result it takes more instructions to do
#	the same job in Thumb, therefore the code is never twice as
#	small and always slower.

$output=shift;
open STDOUT,">$output";

$ctx="r0";
$inp="r1";
$len="r2";
$a="r3";
$b="r4";
$c="r5";
$d="r6";
$e="r7";
$K="r8";
$t0="r10";
$t1="r11";
$t2="r12";
$Xi="r14";
@V=($a,$b,$c,$d,$e);

# One can optimize this for aligned access on big-endian architecture,
# but code's endian neutrality makes it too pretty:-)
sub Xload {
my ($a,$b,$c,$d,$e)=@_;
$code.=<<___;
	ldrb	$t0,[$inp],#4
	ldrb	$t1,[$inp,#-3]
	ldrb	$t2,[$inp,#-2]
	add	$e,$K,$e,ror#2			@ E+=K_00_19
	orr	$t0,$t1,$t0,lsl#8
	ldrb	$t1,[$inp,#-1]
	orr	$t0,$t2,$t0,lsl#8
	add	$e,$e,$a,ror#27			@ E+=ROR(A,27)
	orr	$t0,$t1,$t0,lsl#8
	add	$e,$e,$t0			@ E+=X[i]
	eor	$t1,$c,$d			@ F_xx_xx
	str	$t0,[$Xi,#-4]!
___
}
sub Xupdate {
my ($a,$b,$c,$d,$e,$flag)=@_;
$code.=<<___;
	ldr	$t0,[$Xi,#15*4]
	ldr	$t1,[$Xi,#13*4]
	ldr	$t2,[$Xi,#7*4]
	add	$e,$K,$e,ror#2			@ E+=K_xx_xx
	eor	$t0,$t0,$t1
	ldr	$t1,[$Xi,#2*4]
	add	$e,$e,$a,ror#27			@ E+=ROR(A,27)
	eor	$t0,$t0,$t2
	eor	$t0,$t0,$t1
___
$code.=<<___ if (!defined($flag));
	eor	$t1,$c,$d			@ F_xx_xx, but not in 40_59
___
$code.=<<___;
	mov	$t0,$t0,ror#31
	add	$e,$e,$t0			@ E+=X[i]
	str	$t0,[$Xi,#-4]!
___
}

sub BODY_00_15 {
my ($a,$b,$c,$d,$e)=@_;
	&Xload(@_);
$code.=<<___;
	and	$t1,$b,$t1,ror#2
	eor	$t1,$t1,$d,ror#2		@ F_00_19(B,C,D)
	add	$e,$e,$t1			@ E+=F_00_19(B,C,D)
___
}

sub BODY_16_19 {
my ($a,$b,$c,$d,$e)=@_;
	&Xupdate(@_);
$code.=<<___;
	and	$t1,$b,$t1,ror#2
	eor	$t1,$t1,$d,ror#2		@ F_00_19(B,C,D)
	add	$e,$e,$t1			@ E+=F_00_19(B,C,D)
___
}

sub BODY_20_39 {
my ($a,$b,$c,$d,$e)=@_;
	&Xupdate(@_);
$code.=<<___;
	eor	$t1,$b,$t1,ror#2		@ F_20_39(B,C,D)
	add	$e,$e,$t1			@ E+=F_20_39(B,C,D)
___
}

sub BODY_40_59 {
my ($a,$b,$c,$d,$e)=@_;
	&Xupdate(@_,1);
$code.=<<___;
	and	$t1,$b,$c,ror#2
	orr	$t2,$b,$c,ror#2
	and	$t2,$t2,$d,ror#2
	orr	$t1,$t1,$t2			@ F_40_59(B,C,D)
	add	$e,$e,$t1			@ E+=F_40_59(B,C,D)
___
}

$code=<<___;
.text

.global	sha1_block_data_order
.type	sha1_block_data_order,%function

.align	2
sha1_block_data_order:
	stmdb	sp!,{r4-r12,lr}
	add	$len,$inp,$len,lsl#6	@ $len to point at the end of $inp
	ldmia	$ctx,{$a,$b,$c,$d,$e}
.Lloop:
	ldr	$K,.LK_00_19
	mov	$Xi,sp
	sub	sp,sp,#15*4
	mov	$c,$c,ror#30
	mov	$d,$d,ror#30
	mov	$e,$e,ror#30		@ [6]
.L_00_15:
___
for($i=0;$i<5;$i++) {
	&BODY_00_15(@V);	unshift(@V,pop(@V));
}
$code.=<<___;
	teq	$Xi,sp
	bne	.L_00_15		@ [((11+4)*5+2)*3]
___
	&BODY_00_15(@V);	unshift(@V,pop(@V));
	&BODY_16_19(@V);	unshift(@V,pop(@V));
	&BODY_16_19(@V);	unshift(@V,pop(@V));
	&BODY_16_19(@V);	unshift(@V,pop(@V));
	&BODY_16_19(@V);	unshift(@V,pop(@V));
$code.=<<___;

	ldr	$K,.LK_20_39		@ [+15+16*4]
	sub	sp,sp,#25*4
	cmn	sp,#0			@ [+3], clear carry to denote 20_39
.L_20_39_or_60_79:
___
for($i=0;$i<5;$i++) {
	&BODY_20_39(@V);	unshift(@V,pop(@V));
}
$code.=<<___;
	teq	$Xi,sp			@ preserve carry
	bne	.L_20_39_or_60_79	@ [+((12+3)*5+2)*4]
	bcs	.L_done			@ [+((12+3)*5+2)*4], spare 300 bytes

	ldr	$K,.LK_40_59
	sub	sp,sp,#20*4		@ [+2]
.L_40_59:
___
for($i=0;$i<5;$i++) {
	&BODY_40_59(@V);	unshift(@V,pop(@V));
}
$code.=<<___;
	teq	$Xi,sp
	bne	.L_40_59		@ [+((12+5)*5+2)*4]

	ldr	$K,.LK_60_79
	sub	sp,sp,#20*4
	cmp	sp,#0			@ set carry to denote 60_79
	b	.L_20_39_or_60_79	@ [+4], spare 300 bytes
.L_done:
	add	sp,sp,#80*4		@ "deallocate" stack frame
	ldmia	$ctx,{$K,$t0,$t1,$t2,$Xi}
	add	$a,$K,$a
	add	$b,$t0,$b
	add	$c,$t1,$c,ror#2
	add	$d,$t2,$d,ror#2
	add	$e,$Xi,$e,ror#2
	stmia	$ctx,{$a,$b,$c,$d,$e}
	teq	$inp,$len
	bne	.Lloop			@ [+18], total 1307

	ldmia	sp!,{r4-r12,lr}
	tst	lr,#1
	moveq	pc,lr			@ be binary compatible with V4, yet
	bx	lr			@ interoperable with Thumb ISA:-)
.align	2
.LK_00_19:	.word	0x5a827999
.LK_20_39:	.word	0x6ed9eba1
.LK_40_59:	.word	0x8f1bbcdc
.LK_60_79:	.word	0xca62c1d6
.size	sha1_block_data_order,.-sha1_block_data_order
.asciz	"SHA1 block transform for ARMv4, CRYPTOGAMS by <appro\@openssl.org>"
___

$code =~ s/\bbx\s+lr\b/.word\t0xe12fff1e/gm;	# make it possible to compile with -march=armv4
print $code;
close STDOUT; # enforce flush

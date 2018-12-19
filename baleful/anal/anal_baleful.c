/* radare2 - LGPL - Copyright 2011-2016 - SkUaTeR */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include <stdio.h>
#include <fcntl.h>

static int ptsHandle=0;

static int reg_read(RAnalEsil *esil, const char *regname, ut64 *num) {
	RRegItem *reg = r_reg_get (esil->anal->reg, regname, -1);
	if (reg) {
		if (num)
			*num = r_reg_get_value (esil->anal->reg, reg);
		return 1;
	}
	return 0;
}

static int reg_write(RAnalEsil *esil, const char *regname, ut64 num) {
	RRegItem *reg = r_reg_get (esil->anal->reg, regname, -1);
	if (reg) {
		if (num)
			r_reg_set_value (esil->anal->reg, reg,num);
		return 1;
	}
	return 0;
}
/*

   int myputcChar(int *a1) // Api 0
   {
   fputc(*a1, stderr);
   fflush(stderr);
   return *a1;
   }
   static void initPTS()
   {
   int fdm, fds, rc;
   char * name;
   char input[150];

   fdm = posix_openpt(O_RDWR);
   if (fdm < 0)
   {
   eprintf ("Error on posix_openpt()\n");
   }

   rc = grantpt(fdm);
   if (rc != 0)
   {
   eprintf("Error on grantpt()\n");
   }

   rc = unlockpt(fdm);
   if (rc != 0)
   {
   eprintf("Error on unlockpt()\n");
   }
   ptsname_r(fdm,input,150);//int fd, char *buf, size_t buflen);ptsname(fdm);
   ptsHandle=fdm;//open(input, O_RDWR);
   if (ptsHandle)
   eprintf("Opened %s for ESIL input/output\n",input );


   }

   void printCommand() {
   if (ptsHandle)
   {
   eprintf("printCommand: Enviando..\n");
   write(ptsHandle,"\01",1);
   }
   }
   void readCommand() {
   if (ptsHandle)
   write(ptsHandle,"\02",1);
   }

   void printOutput(char * s) {
   printCommand();
   if (ptsHandle)
   {
   write (ptsHandle, s, strlen (s)+1);

   }
   }

   static int esil_trap(RAnalEsil *esil) {
   ut64 valor;
   ut64 valor1;
   ut32 v;
   int f,i;
//FILE *f;
char *dst = r_anal_esil_pop (esil);
char buff[255];



//if (!ptsHandle) {
// eprintf("Iniciando pts\n");
// initPTS();
///

//f=open("/dev/pts/10", O_RDWR);
//if (!f)
//eprintf("eeror en pts\n");
r_anal_esil_get_parm (esil, dst, &valor);
reg_read(esil,"r_00",&valor1);
eprintf("esil->trap = %08x esil->trap_code = %08x pila = 0x%"PFMT64x " valor1 = 0x%"PFMT64x"\n",esil->trap,esil->trap_code,valor,valor1);
v=(ut32)valor1;
if (valor==0){
	sprintf(buff,"%c%c",(ut8)v,0);
	eprintf("emulando api:%s\n",buff);
	//printOutput(&buff);
	//printOutput(buff);
	//write (ptsHandle, buff, 2);

}

return 1;
}
*/
static int getp(const ut8 *buf, const ut8 *p0, const ut8 *p1, const ut8 *p2, const ut8 *p3, int type) {
	const ut8 * c = buf + 1;
	const ut8  *r0;
	const ut8  *r1;
	const ut8  *r2;
	const ut8  *r3;
	const ut32 *imm;
	const ut32 *imm1;
	int size=0;

	switch (type) {
	case 0: // 8 8 11 5 ESIL
		r0  = buf + 2;
		sprintf((char *)p0,"r_%02x",*r0);
		switch (*c) {
		case 1:
			r1  = buf + 3;
			imm = (ut32 *)(buf + 4);
			sprintf((char *)p1,"r_%02x",*r1);
			sprintf((char *)p2,"0x%04x",*imm);
			size=8;
			break;
		case 2:
			imm  = (ut32 *)(buf + 3);
			r1   = buf + 4;
			sprintf((char *)p1,"0x%04x",*imm);
			sprintf((char *)p2,"r_%02x",*r1);
			size=8;
			break;
		case 4:
			imm  = (ut32 *)(buf + 3);
			imm1 = (ut32 *)(buf + 7);
			sprintf((char *)p1,"0x%04x",*imm);
			sprintf((char *)p2,"0x%04x",*imm1);
			size=11;
			break;

		case 0:
		default:
			r1  = buf + 3;
			r2  = buf + 4;
			sprintf((char *)p1,"r_%02x",*r1);
			sprintf((char *)p2,"r_%02x",*r2);
			size=5;
			break;
		}
		break;
	case 1: // 9 9 12 6
		r0  = buf + 2;
		r3  = buf +3; // guarda aki el resto
		sprintf((char *)p0,"r_%02x",*r0);
		sprintf((char *)p3,"r_%02x",*r3);
		switch (*c) {
		case 1:
			r1  = buf + 4;
			imm =(ut32 *)(buf + 5);
			sprintf((char *)p1,"r_%02x",*r1);
			sprintf((char *)p2,"0x%04x",*imm);
			size=9;
			break;
		case 2:
			imm  = (ut32 *)(buf + 4);
			r1   = buf + 8;
			sprintf((char *)p1,"0x%04x",*imm);
			sprintf((char *)p2,"r_%02x",*r1);
			size=9;
			break;
		case 4:
			imm  = (ut32 *)(buf + 4);
			imm1 = (ut32 *)(buf + 8);
			sprintf((char *)p1,"0x%04x",*imm);
			sprintf((char *)p2,"0x%04x",*imm1);
			size=12;
			break;
		case 0:
		default:
			r1  = buf + 4;
			r2  = buf + 5;
			sprintf((char *)p1,"r_%02x",*r1);
			sprintf((char *)p2,"r_%02x",*r2);
			size=6;
			break;
		}
		break;
	case 2: // 7 7 10 4
		switch (*c) {
		case 1:
			r1  = buf + 2;
			imm = (ut32 *)(buf + 3);
			sprintf((char *)p1,"r_%02x",*r1);
			sprintf((char *)p2,"0x%04x",*imm);
			size=7;
			break;
		case 2:
			imm  = (ut32 *)(buf + 2);
			r1   = buf + 6;
			sprintf((char *)p1,"0x%04x",*imm);
			sprintf((char *)p2,"r_%02x",*r1);
			size=7;
			break;
		case 4:
			imm  = (ut32 *)(buf + 2);
			imm1 = (ut32 *)(buf + 6);
			sprintf((char *)p1,"0x%04x",*imm);
			sprintf((char *)p2,"0x%04x",*imm1);
			size=10;
			break;
		case 0:
		default:
			r1  = buf + 2;
			r2  = buf + 3;
			sprintf((char *)p1,"r_%02x",*r1);
			sprintf((char *)p2,"r_%02x",*r2);
			size=4;
		}
		break;
	case 3:// 7 4 ESIL
		switch(*c) {
		case 1:
			r1  = buf + 2;
			imm = (ut32 *)(buf + 3);
			sprintf((char *)p1,"r_%02x",*r1);
			sprintf((char *)p2,"0x%04x",*imm);
			size=7;
			break;
		case 0:
		default:
			r1  = buf + 2;
			r2  = buf + 3;
			sprintf((char *)p1,"r_%02x",*r1);
			sprintf((char *)p2,"r_%02x",*r2);
			size=4;
			break;
		}
		break;
	case 4: // 6 3
		switch(*c) {
		case 1:
			imm = (ut32 *)(buf + 2);
			sprintf((char *)p1,"0x%04x",*imm);
			size=6;
			break;
		default:
			r1  = buf + 2;
			sprintf ((char *)p1,"r_%02x",*r1);
			size = 3;
			break;
		}
		break;
	case 5: //5
		imm = (ut32 *)(buf + 1);
		sprintf ((char *)p1,"0x%04x",*imm);
		size = 5;
		break;
	case 6: //2
		r1  = buf + 1;
		sprintf ((char *)p1,"r_%02x",*r1);
		size = 2;
		break;
	}
	return size;
}

static int baleful_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	const ut8  *r   = 0;
	const ut8  *r0  = 0;
	const ut8  *r1  = 0;
	const ut8  *p   = 0;
	const ut32 *imm = 0;
	const ut32 *imm1 = 0;
	const ut8 p0[16];
	const ut8 p1[16];
	const ut8 p2[16];
	const ut8 p3[16];

	if (op == NULL)
		return 1;
	memset (op, 0, sizeof (RAnalOp));
	op->type = R_ANAL_OP_TYPE_NULL;
	op->delay = 0;
	op->jump = op->fail = -1;
	op->ptr = op->val = -1;
	op->addr = addr;
	op->refptr = 0;
	r_strbuf_init (&op->esil);
	switch (buf[0]) {
	case 2: // 8 8 11 5  ADD +
		op->type = R_ANAL_OP_TYPE_ADD;
		op->size = getp(buf,p0,p1,p2,p3,0);
		r_strbuf_setf (&op->esil, "%s,%s,+,%s,=",p2,p1,p0);
		break;
	case 3: // 8 8 11 5  SUB -
		op->type = R_ANAL_OP_TYPE_SUB;
		op->size = getp(buf,p0,p1,p2,p3,0);
		r_strbuf_setf (&op->esil, "%s,%s,-,%s,=",p2,p1,p0);
		break;
	case 4: // 8 8 11 5  MUL *
		op->type = R_ANAL_OP_TYPE_MUL;
		op->size = getp(buf,p0,p1,p2,p3,0);
		r_strbuf_setf (&op->esil, "%s,%s,*,%s,=",p2,p1,p0);
		break;
	case 6: // 8 8 11 5  XOR ^
		op->type = R_ANAL_OP_TYPE_XOR;
		op->size = getp(buf,p0,p1,p2,p3,0);
		r_strbuf_setf (&op->esil, "%s,%s,^,%s,=",p2,p1,p0);
		break;
	case 9: // 8 8 11 5  AND &
		op->type = R_ANAL_OP_TYPE_AND;
		op->size = getp(buf,p0,p1,p2,p3,0);
		r_strbuf_setf (&op->esil, "%s,%s,&,%s,=",p2,p1,p0);
		break;
	case 10: // 8 8 11 5 OR |
		op->type = R_ANAL_OP_TYPE_OR;
		op->size = getp(buf,p0,p1,p2,p3,0);
		r_strbuf_setf (&op->esil, "%s,%s,|,%s,=",p2,p1,p0);
		break;
	case 12: // 8 8 11 5 ROL <<<
		op->type = R_ANAL_OP_TYPE_ROL;
		op->size = getp(buf,p0,p1,p2,p3,0);
		r_strbuf_setf (&op->esil, "%s,%s,<<<,%s,=",p2,p1,p0);
		break;
	case 13: // 8 8 11 5 ROR >>>
		op->type = R_ANAL_OP_TYPE_ROR;
		op->size = getp(buf,p0,p1,p2,p3,0);
		r_strbuf_setf (&op->esil, "%s,%s,>>>,%s,=",p2,p1,p0);
		break;
	case 25: //          ++
		op->type = R_ANAL_OP_TYPE_ADD;
		op->size = getp(buf,p0,p1,p2,p3,6);
		r_strbuf_setf (&op->esil, "%s,++,=",p1);
		break;
	case 26: //          --
		op->type = R_ANAL_OP_TYPE_SUB;
		op->size = getp(buf,p0,p1,p2,p3,6);
		r_strbuf_setf (&op->esil, "%s,--,=",p1);
		break;
		////////////////////////////////////////// SPECIAL DIV/MOD ////////////////////////////////
	case 5: // 9 9 12 6  DIV
		op->type = R_ANAL_OP_TYPE_DIV;
		op->size = getp(buf,p0,p1,p2,p3,1);
		r_strbuf_setf (&op->esil, "%s,%s,/,%s,=,%s,%s,%%,%s,=",p2,p1,p0,p2,p1,p3);
		break;
		////////////////////////////////// MOVS ///////////////////////////////////////////////////
	case 24: //7 4       MOV
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = getp(buf,p0,p1,p2,p3,3);
		r_strbuf_setf (&op->esil, "%s,%s,=",p2,p1);
		break;
	case 27: //          MOV r,[r]
		r  = buf + 1;
		r1 = buf + 2;
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 3;
		r_strbuf_setf (&op->esil, "r_%02x,[4],r_%02x,=",*r1,*r);
		break;
	case 28://           MOV [r],r1
		r  = buf + 1;
		r1 = buf + 2;
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 3;
		r_strbuf_setf (&op->esil, "r_%02x,r_%02x,=[4]",*r1,*r);
		break;
		///////////////////////////////// JUMPS /////////////////////////////////////////////////
	case 14: //5         JMP
		imm  = (ut32 *)(buf + 1);
		op->type = R_ANAL_OP_TYPE_JMP;
		op->size = getp(buf,p0,p1,p2,p3,5);
		op->jump = r_num_get (NULL, (const char *)p1);
		r_strbuf_setf(&op->esil,"%s,pc,=",p1);
		break;
	case 16: //5         JZ
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->size = getp(buf,p0,p1,p2,p3,5);
		op->jump = r_num_get (NULL, (const char *)p1);
		op->fail = addr + op->size;
		r_strbuf_setf(&op->esil, "zf,?{,%s,pc,=,}",p1);
		break;
	case 21: //5         JNZ
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->size = getp(buf,p0,p1,p2,p3,5);
		op->jump = r_num_get (NULL, (const char *)p1);
		op->fail = addr + op->size;
		r_strbuf_setf(&op->esil, "zf,!,?{,%s,pc,=,}",p1);
		break;
	case 17: //5         JS
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->size = getp(buf,p0,p1,p2,p3,5);
		op->jump = r_num_get (NULL, (const char *)p1);
		op->fail = addr + op->size;
		r_strbuf_setf(&op->esil, "sf,?{,%s,pc,=,}",p1);
		break;
	case 20: //5         JNS
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->size = getp(buf,p0,p1,p2,p3,5);
		op->jump = r_num_get (NULL, (const char *)p1);
		op->fail = addr + op->size;
		r_strbuf_setf(&op->esil, "sf,!,?{,%s,pc,=,}",p1);
		break;
	case 19: //5         JG
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->size = getp(buf,p0,p1,p2,p3,5);
		op->jump = r_num_get (NULL, (const char *)p1);
		op->fail = addr + op->size;
		r_strbuf_setf(&op->esil, "gf,?{,%s,pc,=,}",p1);
		break;
	case 18: //5         JBE
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->size = getp (buf, p0, p1, p2, p3, 5);
		op->jump = r_num_get (NULL, (const char *)p1);
		op->fail = addr + op->size;
		r_strbuf_setf (&op->esil, "gf,!,?{,%s,pc,=,}",p1);
		break;
		////////////////////////////////   EFLAGS WRITER  ///////////////////////////////////////////////////////////
		// http://www.read.seas.harvard.edu/~kohler/class/aosref/i386/appc.htm
		//http://sourceforge.net/p/fake86/code/ci/master/tree/src/fake86/cpu.c
	case 22: // 7 7 10 4 AND
		op->type = R_ANAL_OP_TYPE_AND;
		op->size = getp(buf,p0,p1,p2,p3,2);
		r_strbuf_setf(&op->esil,"0,sf,=,%s,%s,<,sf,=,0,zf,=,%s,%s,&,0,==,$z,zf,=,0,gf,=",p2,p1,p2,p1);
		break;
	case 23: // 7 7 10 4 CMP
		op->type = R_ANAL_OP_TYPE_SUB;
		op->size = getp(buf,p0,p1,p2,p3,2);
		r_strbuf_setf(&op->esil,"0,sf,=,%s,%s,<,sf,=,0,zf,=,%s,%s,==,$z,zf,=,0,gf,=,%s,%s,>,gf,=",p2,p1,p2,p1,p2,p1);
		//"0,sf,=,%s,%s,<,sf,="      //SF
		//"0,zf,=,%s,%s,==,%%z,zf,=" //ZF
		//"0,gf,=,%s,%s,>,gf,="      //GF
		break;
		/////////////////////////////////////// STACK ////////////////////////////////////////////////////////////
	case 30: //6 3       PUSH
		p = buf + 1;
		op->type = R_ANAL_OP_TYPE_PUSH;
		op->size = getp(buf,p0,p1,p2,p3,4);
		r_strbuf_setf(&op->esil,"%s,stk,=[4],4,stk,+=",p1);
		break;
	case 31: //          POP
		op->type = R_ANAL_OP_TYPE_POP;
		op->size = getp(buf,p0,p1,p2,p3,6);
		r_strbuf_setf(&op->esil,"4,stk,-=,stk,[4],%s,=",p1);
		break;
	case 15: //5         CALL
		imm = (ut32 *)(buf + 1);
		op->type = R_ANAL_OP_TYPE_CALL;
		op->size = getp(buf,p0,p1,p2,p3,5);
		op->jump = r_num_get (NULL, (const char *)p1);
		op->fail = addr + op->size;
		r_strbuf_setf(&op->esil,"%04x,$$,+,stk,=[4],4,stk,+=,%s,pc,=",op->size,p1);
		break;
	case 1:  //          RET
		op->type = R_ANAL_OP_TYPE_RET;
		op->size = 1;
		r_strbuf_setf(&op->esil,"4,stk,-=,stk,[4],pc,=");
		break;
		///////////////////////////////////////////////////////////////////////////////////////////////////////////
	case 11:
		r_strbuf_setf (&op->esil, "regX = regY==0");
		op->size = 3;
		break;
	case 7:
		r_strbuf_setf (&op->esil, "regX = NEG regY");
		op->size = 3;
		break;
	case 8:
		r_strbuf_setf (&op->esil, "regX = NOT regY");
		op->size = 3;
		break;
		///////////////////////////////////////////////////////////////////////////////////////////////////////////
	case 32: //          SYSCALL
		p = buf + 1;
		op->type = R_ANAL_OP_TYPE_SWI;
		op->size = 2;
		r_strbuf_setf (&op->esil, "0x%02x,$",*p);
		break;
	case 29://           VMEND
		op->type = R_ANAL_OP_TYPE_TRAP;
		op->size = 1;
		r_strbuf_setf (&op->esil, "end virtual");
		break;
	case 0://            NOP
	default:
		op->type = R_ANAL_OP_TYPE_NOP;
		op->size = 1;
		r_strbuf_setf (&op->esil, "nop");
		break;
	}
	return op->size;
}

static void *  internalMemory = NULL;
static int indicememoria = 0;
static ut32 vtmp = 0;
static ut32 idxInputText = 0;
static char texto[] ="packers_and_vms_and_xors_oh_my\n";

static int esil_baleful_intr (RAnalEsil *esil, int intr) {
	ut64 valor1;
	if (!esil)
		return false;
	if (intr==0) {
		reg_read(esil,"r_00",&valor1);
		eprintf("%c\n",(ut32)valor1);
	} else if (intr==0x4) {
		eprintf("Leido %c\n",texto[idxInputText]);
		reg_write(esil,"r_00",(ut64)((char) texto[idxInputText++]));
	}
	else if (intr==0x11) {
		ut64 basedata=0;
		reg_read(esil,"r_00",&valor1);
		reg_read(esil,"r_data",&basedata);
		int  v1=indicememoria;
		indicememoria+= valor1;

		reg_write(esil,"r_00",(ut64) basedata+v1);
	}
	else
		eprintf ("INTERRUPT 0x%02x \n", intr);
	return true;
}

static bool esil_bale_interrupt_wrapper_cb (RAnalEsil *esil, ut32 interrupt, void *user) {	//user is always NULL, bc we has no init and fini
	return !!esil_baleful_intr(esil, interrupt);
}

RAnalEsilInterruptHandler bale_intr_handler00 = {
	.num = 0x00,				//interrupt number
	.cb = esil_bale_interrupt_wrapper_cb,	//the actual handler
};

RAnalEsilInterruptHandler bale_intr_handler04 = {
	.num = 0x04,				//interrupt number
	.cb = esil_bale_interrupt_wrapper_cb,	//the actual handler
};

RAnalEsilInterruptHandler bale_intr_handler11 = {
	.num = 0x11,				//interrupt number
	.cb = esil_bale_interrupt_wrapper_cb,	//the actual handler
};

RAnalEsilInterruptHandler *bale_intr_handlers[] = {
	&bale_intr_handler00,
	&bale_intr_handler04,
	&bale_intr_handler11,
	NULL,
};

static int set_reg_profile(RAnal *anal) {
	const char *p = \
		"=PC    pc\n"
		"=SP    stk\n"
		"gpr    pc      .32 0   0\n"
		"gpr    stk     .32 4   0\n"
		"gpr    zf      .32 8   0\n"
		"gpr    sf      .32 12  0\n"
		"gpr    gf      .32 16  0\n"
		"gpr    r_00    .32 20  0\n"
		"gpr    r_01    .32 24  0\n"
		"gpr    r_02    .32 28  0\n"
		"gpr    r_03    .32 32  0\n"
		"gpr    r_04    .32 36  0\n"
		"gpr    r_05    .32 40  0\n"
		"gpr    r_06    .32 44  0\n"
		"gpr    r_07    .32 48  0\n"
		"gpr    r_08    .32 52  0\n"
		"gpr    r_09    .32 56  0\n"
		"gpr    r_0a    .32 60  0\n"
		"gpr    r_0b    .32 64  0\n"
		"gpr    r_0c    .32 68  0\n"
		"gpr    r_0d    .32 72  0\n"
		"gpr    r_0e    .32 76  0\n"
		"gpr    r_0f    .32 80  0\n"
		"gpr    r_10    .32 84  0\n"
		"gpr    r_11    .32 88  0\n"
		"gpr    r_12    .32 92  0\n"
		"gpr    r_13    .32 96  0\n"
		"gpr    r_14    .32 100 0\n"
		"gpr    r_15    .32 104 0\n"
		"gpr    r_16    .32 108 0\n"
		"gpr    r_17    .32 112 0\n"
		"gpr    r_18    .32 116 0\n"
		"gpr    r_19    .32 120 0\n"
		"gpr    r_1a    .32 124 0\n"
		"gpr    r_1b    .32 128 0\n"
		"gpr    r_1c    .32 132 0\n"
		"gpr    r_1d    .32 136 0\n"
		"gpr    r_1e    .32 140 0\n"
		"gpr    r_1f    .32 144 0\n"
		"gpr    r_20    .32 148 0\n"
		"gpr    r_21    .32 152 0\n"
		"gpr    r_22    .32 156 0\n"
		"gpr    r_23    .32 160 0\n"
		"gpr    r_24    .32 168 0\n"
		"gpr    r_25    .32 172 0\n"
		"gpr    r_26    .32 176 0\n"
		"gpr    r_27    .32 180 0\n"
		"gpr    r_28    .32 184 0\n"
		"gpr    r_29    .32 188 0\n"
		"gpr    r_data  .32 192 0\n";
	return r_reg_set_profile_string (anal->reg, p);
}
static int esil_baleful_init (RAnalEsil *esil) {
	if (!esil) {
		return false;
	}
	return r_anal_esil_load_interrupts (esil, bale_intr_handlers, 0);
	/*
	   internalMemory=malloc(4096);
	   if (!internalMemory) {
	   eprintf("Error esil_baleful_init: Cant allocate internal memory.\n");

	   }
	   eprintf("memoria en :%08x\n\n\n\n",internalMemory);
	 *((ut32 *)internalMemory)=0xdeadbeef;
	 eprintf("leido :%08x\n",*((ut32 *)internalMemory));
	 */
}

static int esil_baleful_fini (RAnalEsil *esil) {
	//	if (internalMemory)
	//		free(internalMemory);
	return true;
}

static RAnalPlugin r_anal_plugin_baleful = {
	.name = "baleful",
	.desc = "baleful code analysis plugin",
	.license = "LGPL3",
	/*add to r_tuypes.h R_SYS_ARCH_BALEFUL = 0x10000000*/
	.arch = "baleful",
	.bits = 32,
	.esil_init = esil_baleful_init,
	.esil_fini = esil_baleful_fini,
	.esil = true,
	.op = &baleful_op,
	.set_reg_profile = set_reg_profile,
};

RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_baleful,
	.version = R2_VERSION
};

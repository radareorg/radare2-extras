// Baleful VM Decoder by SkUaTeR
//
//   compile: i586-mingw32msvc-gcc -mconsole decoder.c -odecoder.exe
//
// Need a vm.code at same directory


#include <stdio.h>
#include <windows.h>
// Defines for r2 compatibility
#define ut8 char
#define ut32 unsigned int
#define r_strbuf_setf sprintf

int ae_load_file_to_memory(const char *filename, char **result) { 
	int size = 0;
	FILE *f = fopen(filename, "rb");
	if (f == NULL) { 
		*result = NULL;
		return -1;
	} 
	fseek(f, 0, SEEK_END);
	size = ftell(f);
	fseek(f, 0, SEEK_SET);
	*result = (char *)malloc(size+1);
	if (size != fread(*result, sizeof(char), size, f)) { 
		free(*result);
		return -2; 
	} 
	fclose(f);
	(*result)[size] = 0;
	return size;
}

int anal_baleful_getregs(const ut8 *buf,ut8 * b,char * oper,int type) {
	const ut8 * c;
	const ut8  *r0;
	const ut8  *r1;
	const ut8  *r2;
	const ut8  *r3;
	const ut32 *imm;
	const ut32 *imm1;

	int size=0;
	c   = buf+1;
	switch(type) {
	case 0: // 8 8 11 5
		r0  = buf + 2;
		switch(*c) {
		case 1:
			r1  = buf + 3;
			imm = buf + 4;
			r_strbuf_setf(b,  "r_%02x = r_%02x %s 0x%04x",*r0,*r1,oper,*imm);
			size=8;
			break;
		case 2:
			imm  = buf + 3;
			r1   = buf + 4;
			r_strbuf_setf(b,  "r_%02x = 0x%04x %s r_%02x",*r0,*imm,oper,*r1);
			size=8;
			break;
		case 4:
			imm  = buf + 3;
			imm1 = buf + 7;
			r_strbuf_setf(b,  "r_%02x = 0x%04x %s 0x%04x",*r0,*imm,oper,*imm1);
			size=11;
			break;
		case 0:
			r1  = buf + 3;
			r2  = buf + 4;
			r_strbuf_setf(b,  "r_%02x = r_%02x %s r_%02x",*r0,*r1,oper,*r2);
			size=5;
			break;
		default:
			r1  = buf + 3;
			r2  = buf + 4;
			r_strbuf_setf(b,  "r_%02x = r_%02x %s r_%02x",*r0,*r1,oper,*r2);
			size=5;
			break;
		}
		break;
	case 1: // 9 9 12 6
		r0  = buf + 2;
		r3  = buf +3; // guarda aki el resto
		switch(*c) {
		case 1:
			r1  = buf + 4;
			imm = buf + 5;
			r_strbuf_setf(b,  "r_%02x = r_%02x %s 0x%04x",*r0,*r1,oper,*imm);
			size=9;
			break;
		case 2:
			r1   = buf + 5;
			r_strbuf_setf(b,  "r_%02x = 0x%04x %s r_%02x",*r0,*imm,oper,*r1);
			size=9;
			break;
		case 4:
			imm  = buf + 4;
			imm1 = buf + 8;
			r_strbuf_setf(b,  "r_%02x = 0x%04x %s 0x%04x",*r0,*imm,oper,*imm1);
			size=12;
			break;
		case 0:
			r1  = buf + 4;
			r2  = buf + 5;
			r_strbuf_setf(b,  "r_%02x = r_%02x %s r_%02x",*r0,*r1,oper,*r2);
			size=6;
			break;
		default:
			r1  = buf + 4;
			r2  = buf + 5;
			r_strbuf_setf(b,  "r_%02x = r_%02x %s r_%02x",*r0,*r1,oper,*r2);
			size=6;
			break;
		}
		break;
	case 2: // 7 7 10 4
		switch(*c) {
		case 1:
			r1  = buf + 2;
			imm = buf + 3;
			r_strbuf_setf(b,  "r_%02x %s 0x%04x",*r1,oper,*imm);
			size=7;
			break;
		case 2:
			imm  = buf + 2;
			r1   = buf + 6;
			r_strbuf_setf(b,  "0x%04x %s r_%02x",*imm,oper,*r1);
			size=7;
			break;
		case 4:
			imm  = buf + 2;
			imm1 = buf + 6;
			r_strbuf_setf(b,  "0x%04x %s 0x%04x",*imm,oper,*imm1);
			size=10;
			break;
		case 0:
			r1  = buf + 2;
			r2  = buf + 3;
			r_strbuf_setf(b,  "r_%02x %s r_%02x",*r1,oper,*r2);
			size=4;
			break;
		default:
			r1  = buf + 2;
			r2  = buf + 3;
			r_strbuf_setf(b,  "r_%02x %s r_%02x",*r1,oper,*r2);
			size=4;
			break;
		}
		break;
	case 3:// 7 4
		switch(*c) {
		case 1:
			r1  = buf + 2;
			imm = buf + 3;
			r_strbuf_setf(b,  "%s r_%02x,0x%04x",oper,*r1,*imm);
			size=7;
			break;
		case 0:
			r1  = buf + 2;
			r2 = buf + 3;
			r_strbuf_setf(b,  "%s r_%02x,r_%02x",oper,*r1,*r2);
			size=4;
			break;
		default:
			r1  = buf + 2;
			r2 = buf + 3;
			r_strbuf_setf(b,  "%s r_%02x,r_%02x",oper,*r1,*r2);
			size=4;
			break;
		}
		break;
	case 4: // 6 3
		switch(*c) {
		case 1:
			imm = buf + 2;
			r_strbuf_setf(b, "%s 0x%04x",oper,*imm);
			size=6;
			break;
		case 0:
			r0  = buf + 2;
			r_strbuf_setf(b, "%s r_%02x",oper,*r0);
			size=3;
			break;
		default:
			r0  = buf + 2;
			r_strbuf_setf(b, "%s r_%02x",oper,*r0);
			size=3;
			break;
		}
		break;
	case 5: //5
		imm  = buf + 1;
		r_strbuf_setf(b, "%s 0x%04x",oper,*imm);
		size=5;
		break;
	case 6://2
		r0  = buf + 1;
		r_strbuf_setf(b, "%s r_%02x",oper,*r0);
		size=2;
		break;
	break;
	}
	return size;
}
int main(void)
{
    int size;
    int reip;
    int vIP; 
	int tmp;
    char *vmMemoryBase=0;
    int buf;
	char salida[1024];
	const ut8  *r   = 0;
	const ut8  *r0  = 0;
	const ut8  *r1  = 0;
	const ut8  *p   = 0; 
	const ut32 *imm = 0;
	const ut32 *imm1 = 0;
	vIP = 0x1000u;
    tmp=vIP;
	size = ae_load_file_to_memory("vm.code", &vmMemoryBase);
    while(vIP<size) {
		buf=&vmMemoryBase[vIP];
		tmp=vIP;
		switch (vmMemoryBase[vIP]) {
		  case 2: // 8 8 11 5
			vIP+=anal_baleful_getregs(buf,&salida,"+",0);
			break;     
		  case 3: // 8 8 11 5
			vIP+= anal_baleful_getregs(buf,&salida,"-",0);
			break;     
		  case 4: // 8 8 11 5
			vIP+= anal_baleful_getregs(buf,&salida,"*",0);
			break;  
		  case 6: // 8 8 11 5
			vIP+= anal_baleful_getregs(buf,&salida,"^",0);
			break; 
		  case 9: // 8 8 11 5
			vIP+= anal_baleful_getregs(buf,&salida,"&",0);
			break; 
		  case 10: // 8 8 11 5
			vIP+= anal_baleful_getregs(buf,&salida,"|",0);
			break; 
		  case 12: // 8 8 11 5
			vIP+= anal_baleful_getregs(buf,&salida,"<<",0);
			break; 
		  case 13: // 8 8 11 5
			vIP+= anal_baleful_getregs(buf,&salida,">>",0);
			break;		
		  case 5: // 9 9 12 6
			vIP+= anal_baleful_getregs(buf,&salida,"/",1);
			break;
		  case 22: // 7 7 10 4
			vIP+= anal_baleful_getregs(buf,&salida,"and",2);
			break;
		  case 23: // 7 7 10 4
			vIP+= anal_baleful_getregs(buf,&salida,"cmp",2);
			break;	  
		  case 24: //7 4
			
			vIP+= anal_baleful_getregs(buf,&salida,"mov",3);
			break;
		  case 30: //6 3
			p = buf + 1;
			vIP+= anal_baleful_getregs(buf,&salida,"push",4);
			break;
		  case 15: //5
			imm = buf + 1;
			vIP+= anal_baleful_getregs(buf,&salida,"call",5);
			break;
		  case 14: //5
			vIP+= anal_baleful_getregs(buf,&salida,"jmp",5);
			break;
		  case 16: //5
			vIP+= anal_baleful_getregs(buf,&salida,"jz",5);
			break;
		  case 17: //5
			vIP+= anal_baleful_getregs(buf,&salida,"js",5);
			break;
		  case 18: //5
			vIP+= anal_baleful_getregs(buf,&salida,"jbe",5);
			break;
		  case 19: //5
			vIP+= anal_baleful_getregs(buf,&salida,"jg",5);
			break;
		  case 20: //5
			vIP+= anal_baleful_getregs(buf,&salida,"jns",5);
			break;
		  case 21: //5
			vIP+= anal_baleful_getregs(buf,&salida,"jnz",5);
			break;

		  case 27:
			r  = buf + 1;
			r1 = buf + 2;
			vIP+= 3;
			r_strbuf_setf (&salida, "mov r_%02x,[r_%02x]",*r,*r1);
			break;
		  case 28://0x1c
			r  = buf + 1;
			r1 = buf + 2;
			vIP+= 3;
			r_strbuf_setf (&salida, "mov [r_%02x],r_%02x",*r,*r1);
			break;
		  case 11:
			r_strbuf_setf (&salida, "regX = regY==0");
			vIP+= 3;
			break;	
		  case 7:
			r_strbuf_setf (&salida, "regX = NEG regY");
			vIP+= 3;
			break;
		  case 8:
			r_strbuf_setf (&salida, "regX = NOT regY");
			vIP+= 3;
			break;
		  case 25:
			vIP+= anal_baleful_getregs(buf,&salida,"++",6);
			break;
		  case 26:
			r = buf + 1;
			vIP+= anal_baleful_getregs(buf,&salida,"--",6);
			break;
		  case 31:
			vIP+= anal_baleful_getregs(buf,&salida,"pop",6);
			break;
		  case 32:
			p = buf + 1;
			vIP+= 2;
			if (*p==0)
				r_strbuf_setf (&salida, "apicall: putchar()");
			else
				r_strbuf_setf (&salida, "apicall: %02x",*p);
			break;
		  case 1:
			vIP+= 1;
			r_strbuf_setf (&salida, "ret");
			break;
		  case 0:
			vIP+= 1;
			r_strbuf_setf (&salida, "nop");
			break;
		  case 29:
			vIP+= 1;
			r_strbuf_setf (&salida, "end virtual");
			break;

		  default:
			vIP+= 1;
			r_strbuf_setf (&salida, "nop");
			break;
		}
		printf("%08x: %s   (size = %i)\n",tmp,salida,vIP-tmp);
		getchar();
	};
    
    return 0;
}

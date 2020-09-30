/* 

Radare2 Assembler Plugin for the Blackfin Architecture:
-------------------------------------------------------



   License:
   --------

   This code was written by Dr Samuel Chenoweth, 5/5/2020. Copyright is retained by the
   Commonwealth of Australia represented by the Department of Defence.

   This library is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, version 3.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA. 



   Release notes:
   --------------

   This file was written by Dr Samuel Chenoweth and integrated into libopcodes. Some mods were also made to the Blackfin disassembly source file (bfin-dis.c),
   and to the file that integrates the Blackfin assembler and disassembler into radare2 (asm_blackfin.c). 


   	Hints:
	------

	Execute the following command to set the disassembler to Blackfin architecture:
		e asm.arch=blackfin

	Execute the following command to see the Blackfin assembler help:
		rasm2 -a blackfin "help"
	Execute the following command to see info for a few instructions (from number 400 onward):
		rasm2 -a blackfin "help list 400"

	Example assembly command:
		rasm2 -a blackfin -o 0x2e "call 0x00001000"
	Instruction address provided in -o argument is only needed for instructions with pc-relative
       	addressing, such as certain types of call or jump.

	Sometimes, there are 32 bit and 16 bit versions of the same exact instruction;
	where this occurs 32 bits is the default, but the 16 bit version can be forced 
	by appending "(16)".

	The order of compound operations may differ from that in the Blackfin Programmer's Manual,
	for consistency with the Analog Devices Cross Core Embedded Studio assembler/disassembler
	and Radare's Blackfin disassembler.
	For example, use "R1 = ( A1 = R3.L * R6.H ) , R0 = ( A0 = R3.H * R6.L )",
	rather than "R0 = ( A0 = R3.H * R6.L ) , R1 = ( A1 = R3.L * R6.H )".


	Limitations:
	------------

	The assembler does not support line labels, function names, variables, or symbols of any kind. 
	
	This assembler has no macro capabilities or any other such advanced features.

	The assembly of parallel instruction combinations verifies instruction sizes and instruction types.
	However, there may be some subtle contraints that were overlooked, such as usage of the same 
	register as the destination for different instructions executed in parallel. 
	For example, "R2 = A0  || [ I1 ++ ] = R3  || R4 = [ I0 ++ ]",
	"A0 = R4  || [ I1 ++ ] = R3  || R4 = [ I0 ++ ]" 
	and "R4 = A0  || [ I1 ++ ] = R4  || R5 = [ I0 ++ ]" are valid parallel issues, 
	but "R4 = A0  || [ I1 ++ ] = R3  || R4 = [ I0 ++ ]" is invalid (due to R4 being used as the
	destination for two parallel instructions, creating a race condition for the final value in R4). 
	The Cross Core Embedded Studio assembler will throw an error if you try
	to issue an invalid parallel combination of this type, but this Radare2 assembler will generate 
	the machine code without any warnings or errors; do not rely on it alone for validation 
	of parallel instructions. 

	There is a footnote on p. 20-6 of the Blackfin Processor Programming Reference which says that 
	multi-issue cannot combine shift/rotate instructions with a store instruction using preg+offset
       	addressing. However, examples such as "R4 = ROT R4 BY 5  || [ P0 + 0x4 ] = R4  || R5 = [ I0 ++ ]"
	will be assembled by the Cross Core Embedded Studio assembler without warnings or errors. Since 
	Cross Core Embedded Studio seems to ignore this footnote, this Radare2 assembler also ignores 
	this footnote. 

	Some individual instructions are invalid or interpeted differently when the same register is used
       	twice; this is ignored by this assembler. 
	For example, p. C-18 of the Programming Reference says that an instruction such as 
	"R0 = [ P0 ++ P2 ]" is actually a non-post-modify version when the two pregs are the same, 
	i.e. "R0 = [ P0 ++ P0 ]" is functionally equivalent to "R0 = [P0]". Note that the Cross Core
	Embedded Studio assembler does not issue any errors or warnings about this, and neither does 
	this Radare2 assembler. 


	Issues and workarounds:
	-----------------------

	If assembling an instruction that uses one or more ":" characters,
	you typically need to put a space before or after at least one of them;
	otherwise, the rasm2 argument interpreter confuses this with "-F [in:out]".
	For example, to assemble an instruction such as "[--SP]=(R7:0,P5:0)",
	this should be entered as "[--SP]=(R7:0,P5: 0)" or "[--SP]=(R7 :0,P5:0)".

	At least the last "|" character used in an instruction (or parallel combination
	of instructions) must be represented as "\|";
	again, this is due to radare2's command processor being confused by characters
	that it does not expect in assembly code.
	An example of assembling a valid parallel instruction combination is:
		rasm2 -a blackfin "saa (r1:0, r3:2) || r0=[i0++] |\| r2=[i1++]"

 */

#define MAX_NORM_STR 2000

// This function returns a normalised version of an instruction assembly string,
// with whitespace removed, comment removed, consistent lower case, and no ;.
// This function also replaces any sequence of "\\|" with "|". 
// Upon return, the caller needs to copy this string to its own storage prior to calling this function again, as the returned pointer is to a static string.
static char *asm_normalise(const char *asm_str)
{
	static char norm_str[MAX_NORM_STR+1];
	int source, dest;
	char chr;

	source=0;
	dest=0;
	while (dest<MAX_NORM_STR && asm_str[source]!='\0' && asm_str[source]!=';' && asm_str[source]!='#')
	{
		while (asm_str[source]==' ' || asm_str[source]=='\t' || asm_str[source]=='\n' || asm_str[source]=='\r') source++;

		while (asm_str[source]=='\\' && asm_str[source+1]=='|') source++;

		chr=asm_str[source];

		if (chr>='A' && chr<='Z') chr=chr-'A'+'a';

		norm_str[dest]=chr;

		source++;
		dest++;
	}
	norm_str[dest]='\0';

	return norm_str;
}

// This function is passed a string containing an operand in the first len characters, which could be a decimal number
// or a lowercase hexadecimal number prefixed by 0x. This is assumed to be an absolute address. Having extracted this address,
// this function then calculates and returns a pc relative value (divided by 2) based on this address and the offset of the instruction itself.
int get_pcrelm2_from_absolute_address(char *operand_str, int len, uint32_t offset)
{
	uint32_t address;
	int32_t rel_address;

	if (operand_str[0]=='0'&& operand_str[1]=='x')
	{
		sscanf(operand_str+2, "%x", &address);
	}
	else
	{
		sscanf(operand_str, "%d", &address);
	}

	rel_address = ((int32_t)address)-((int32_t)offset);

	if (rel_address%2!=0) fprintf(stderr, "Warning: odd relative address being rounded off to even\n");

	return rel_address/2;
}

// This function is passed a string containing an operand in the first len characters, which could be a decimal number
// or a lowercase hexadecimal number prefixed by 0x. This is assumed to be an absolute address. Having extracted this address,
// this function then calculates and returns a pc relative value (divided by 2) based on this address and the offset of the instruction itself.
// This variant of the function also ensures that the result (i.e. after division by 2) is contained within 4 bits.
int get_pcrel5m2_from_absolute_address(char *operand_str, int len, uint32_t offset)
{
	int result=get_pcrelm2_from_absolute_address(operand_str, len, offset);

	if (result<-8 || result>7) fprintf(stderr, "Warning: target address out of range for pcrel5m2 and is being truncated\n");

	result = result & 0xf;

	return result;
}

// This function is passed a string containing an operand in the first len characters, which could be a decimal number
// or a lowercase hexadecimal number prefixed by 0x. This is assumed to be an absolute address. Having extracted this address,
// this function then calculates and returns a pc relative value (divided by 2) based on this address and the offset of the instruction itself.
// This variant of the function also ensures that the result (i.e. after division by 2) is contained within 10 bits.
int get_pcrel11m2_from_absolute_address(char *operand_str, int len, uint32_t offset)
{
	int result=get_pcrelm2_from_absolute_address(operand_str, len, offset);

	if (result<-512 || result>511) fprintf(stderr, "Warning: target address out of range for pcrel11m2 and is being truncated\n");

	result = result & 0x3ff;

	return result;
}

// This function is passed a string containing an operand in the first len characters, which could be a decimal number
// or a lowercase hexadecimal number prefixed by 0x. This is assumed to be an absolute address. Having extracted this address,
// this function then calculates and returns a pc relative value (divided by 2) based on this address and the offset of the instruction itself.
// This variant of the function also ensures that the result (i.e. after division by 2) is contained within 12 bits.
int get_pcrel13m2_from_absolute_address(char *operand_str, int len, uint32_t offset)
{
	int result=get_pcrelm2_from_absolute_address(operand_str, len, offset);

	if (result<-2048 || result>2047) fprintf(stderr, "Warning: target address out of range for pcrel13m2 and is being truncated\n");

	result = result & 0xfff;

	return result;
}

// This function is passed a string containing an operand in the first len characters, which could be a decimal number
// or a lowercase hexadecimal number prefixed by 0x. This is assumed to be an absolute address. Having extracted this address,
// this function then calculates and returns a pc relative value (divided by 2) based on this address and the offset of the instruction itself.
// This variant of the function also ensures that the result (i.e. after division by 2) is contained within 24 bits.
int get_pcrel25m2_from_absolute_address(char *operand_str, int len, uint32_t offset)
{
	int result=get_pcrelm2_from_absolute_address(operand_str, len, offset);

	if (result<-8388608 || result>8388607) fprintf(stderr, "Warning: target address out of range for pcrel25m2 and is being truncated\n");

	result = result & 0xffffff;

	return result;
}

// This function is passed a string containing an operand in the first len characters, which could be a decimal number
// or a lowercase hexadecimal number prefixed by 0x. The least significant 16 bits of this number are returned.
int get_uimm16(char *operand_str, int len, uint32_t offset)
{
	uint32_t value;

	if (operand_str[0]=='0'&& operand_str[1]=='x')
	{
		sscanf(operand_str+2, "%x", &value);
	}
	else
	{
		sscanf(operand_str, "%d", &value);
	}

	if (value<0 || value>0xffff) fprintf(stderr, "Warning: uimm16 value out of range\n");

	value = value & 0xffff;

	return value;
}

// This function is passed a string containing an operand in the first len characters, which could be a decimal number
// or a lowercase hexadecimal number prefixed by 0x. The least significant 16 bits of this number are returned, but scaled by 4.
int get_uimm18m4(char *operand_str, int len, uint32_t offset)
{
	uint32_t value;

	if (operand_str[0]=='0'&& operand_str[1]=='x')
	{
		sscanf(operand_str+2, "%x", &value);
	}
	else
	{
		sscanf(operand_str, "%d", &value);
	}

	if (value<0 || value>0x3ffff) fprintf(stderr, "Warning: uimm18m4 value out of range\n");

	value = value & 0x3ffff;

	if (value%4!=0) fprintf(stderr, "Warning: uimm18m4 value should be a multiple of 4\n");

	value=value/4;

	return value;
}


// This function is passed a string containing an operand in the first len characters, which could be a decimal number
// or a lowercase hexadecimal number prefixed by 0x. The least significant 4 bits of this number are returned, but scaled by 2.
int get_uimm5m2(char *operand_str, int len, uint32_t offset)
{
	uint32_t value;

	if (operand_str[0]=='0'&& operand_str[1]=='x')
	{
		sscanf(operand_str+2, "%x", &value);
	}
	else
	{
		sscanf(operand_str, "%d", &value);
	}

	if (value<0 || value>0x1f) fprintf(stderr, "Warning: uimm5m2 value out of range\n");

	value = value & 0x1f;

	if (value%2!=0) fprintf(stderr, "Warning: uimm5m2 value should be a multiple of 2\n");

	value=value/2;

	return value;
}

// This function is passed a string containing an operand in the first len characters, which could be a decimal number
// or a lowercase hexadecimal number prefixed by 0x. The least significant 5 bits of this number are returned.
int get_uimm5(char *operand_str, int len, uint32_t offset)
{
	uint32_t value;

	if (operand_str[0]=='0'&& operand_str[1]=='x')
	{
		sscanf(operand_str+2, "%x", &value);
	}
	else
	{
		sscanf(operand_str, "%d", &value);
	}

	if (value<0 || value>0x1f) fprintf(stderr, "Warning: uimm5 value out of range\n");

	value = value & 0x1f;

	return value;
}

// This function is passed a string containing an operand in the first len characters, which could be a decimal number
// or a lowercase hexadecimal number prefixed by 0x. The least significant 4 bits of this number are returned.
int get_uimm4(char *operand_str, int len, uint32_t offset)
{
	uint32_t value;

	if (operand_str[0]=='0'&& operand_str[1]=='x')
	{
		sscanf(operand_str+2, "%x", &value);
	}
	else
	{
		sscanf(operand_str, "%d", &value);
	}

	if (value<0 || value>0xf) fprintf(stderr, "Warning: uimm4 value out of range\n");

	value = value & 0xf;

	return value;
}

// This function is passed a string containing an operand in the first len characters, which could be a decimal number
// or a lowercase hexadecimal number prefixed by 0x. The least significant 4 bits of this number are returned.
int get_twos_comp_uimm4(char *operand_str, int len, uint32_t offset)
{
	uint32_t value;

	if (operand_str[0]=='0'&& operand_str[1]=='x')
	{
		sscanf(operand_str+2, "%x", &value);
	}
	else
	{
		sscanf(operand_str, "%d", &value);
	}

	if (value<1 || value>0x10) fprintf(stderr, "Warning: two_comp_uimm4 value out of range\n");

	value = value & 0x0f;

	value = 0x10-value;

	return value;
}

// This function is passed a string containing an operand in the first len characters, which could be a decimal number
// or a lowercase hexadecimal number prefixed by 0x. The least significant 5 bits of this number are returned.
int get_twos_comp_uimm5(char *operand_str, int len, uint32_t offset)
{
	uint32_t value;

	if (operand_str[0]=='0'&& operand_str[1]=='x')
	{
		sscanf(operand_str+2, "%x", &value);
	}
	else
	{
		sscanf(operand_str, "%d", &value);
	}

	if (value<1 || value>0x20) fprintf(stderr, "Warning: two_comp_uimm5 value out of range\n");

	value = value & 0x1f;

	value = 0x20-value;

	return value;
}

// This function is passed a string containing an operand in the first len characters, which could be a decimal number
// or a lowercase hexadecimal number prefixed by 0x. The least significant 4 bits of this number are returned, but scaled by 4.
int get_uimm6m4(char *operand_str, int len, uint32_t offset)
{
	uint32_t value;

	if (operand_str[0]=='0'&& operand_str[1]=='x')
	{
		sscanf(operand_str+2, "%x", &value);
	}
	else
	{
		sscanf(operand_str, "%d", &value);
	}

	if (value<0 || value>0x3f) fprintf(stderr, "Warning: uimm6m4 value out of range\n");

	value = value & 0x3f;

	if (value%4!=0) fprintf(stderr, "Warning: uimm6m4 value should be a multiple of 4\n");

	value=value/4;

	return value;
}

// This function is passed a string containing an operand in the first len characters, which could be a decimal number
// or a lowercase hexadecimal number prefixed by 0x. The least significant 5 bits of this number are returned, but scaled by 4.
int get_uimm7m4(char *operand_str, int len, uint32_t offset)
{
	uint32_t value;

	if (operand_str[0]=='0'&& operand_str[1]=='x')
	{
		sscanf(operand_str+2, "%x", &value);
	}
	else
	{
		sscanf(operand_str, "%d", &value);
	}

	if (value<4 || value>0x80) fprintf(stderr, "Warning: uimm7m4 value out of range\n");

	value = value & 0x7f;

	value = 0x80 - value;

	if (value%4!=0) fprintf(stderr, "Warning: uimm7m4 value should be a multiple of 4\n");

	value=value/4;

	return value;
}

// This function is passed a string containing an operand in the first len characters, which could be a decimal number
// or a lowercase hexadecimal number prefixed by 0x. The least significant 15 bits of this number are returned, but scaled by 4.
int get_uimm17m4(char *operand_str, int len, uint32_t offset)
{
	uint32_t value;

	if (operand_str[0]=='0'&& operand_str[1]=='x')
	{
		sscanf(operand_str+2, "%x", &value);
	}
	else
	{
		sscanf(operand_str, "%d", &value);
	}

	if (value<0 || value>0x1ffff) fprintf(stderr, "Warning: uimm17m4 value out of range\n");

	value = value & 0x1ffff;

	if (value%4!=0) fprintf(stderr, "Warning: uimm17m4 value should be a multiple of 4\n");

	value=value/4;

	return value;
}

// This function is passed a string containing an operand in the first len characters, which could be a decimal number
// or a lowercase hexadecimal number prefixed by 0x. The least significant 15 bits of this number are returned, but scaled by 4.
int get_imm17m4(char *operand_str, int len, uint32_t offset)
{
	int32_t value;
	int32_t sign;

	if (operand_str[0]=='-')
	{
		sign=-1;
		operand_str++;
	}
	else sign=1;

	if (operand_str[0]=='0'&& operand_str[1]=='x')
	{
		sscanf(operand_str+2, "%x", &value);
	}
	else
	{
		sscanf(operand_str, "%d", &value);
	}

	value*=sign;

	if (value%4!=0) fprintf(stderr, "Warning: imm17m4 value should be a multiple of 4\n");

	value=value/4;

	if (value<-0x8000 || value>0x7fff) fprintf(stderr, "Warning: imm17m4 value out of range.\n");

	// Adjust value so that it falls in the correct range for a 16 bit twos-complement representation.
	while (value<0x0) value+=0x10000;
	while (value>0xffff) value-=0x10000;

	return value;
}

// This function is passed a string containing an operand in the first len characters, which could be a decimal number
// or a lowercase hexadecimal number prefixed by 0x. The least significant 16 bits of this number are returned, but scaled by 2.
int get_uimm16m2(char *operand_str, int len, uint32_t offset)
{
	uint32_t value;

	if (operand_str[0]=='0'&& operand_str[1]=='x')
	{
		sscanf(operand_str+2, "%x", &value);
	}
	else
	{
		sscanf(operand_str, "%d", &value);
	}

	if (value<0 || value>0x1ffff) fprintf(stderr, "Warning: uimm16m2 value out of range\n");

	value = value & 0x1ffff;

	if (value%2!=0) fprintf(stderr, "Warning: uimm16m2 value should be a multiple of 2\n");

	value=value/2;

	return value;
}

// This function is passed a string containing an operand in the first len characters, which could be a decimal number
// or a lowercase hexadecimal number prefixed by 0x. The least significant 16 bits of this number are returned, but scaled by 2.
int get_imm16m2(char *operand_str, int len, uint32_t offset)
{
	int32_t value;
	int32_t sign;

	if (operand_str[0]=='-')
	{
		sign=-1;
		operand_str++;
	}
	else sign=1;

	if (operand_str[0]=='0'&& operand_str[1]=='x')
	{
		sscanf(operand_str+2, "%x", &value);
	}
	else
	{
		sscanf(operand_str, "%d", &value);
	}

	value*=sign;

	if (value%2!=0) fprintf(stderr, "Warning: imm16m2 value should be a multiple of 2\n");

	value=value/2;

	if (value<-0x8000 || value>0x7fff) fprintf(stderr, "Warning: imm16m2 value out of range\n");

	while (value<0) value+=0x10000;
	while (value>0xffff) value-=0x10000;

	return value;
}

// This function is passed a string containing an operand in the first len characters, which could be a decimal number
// or a lowercase hexadecimal number prefixed by 0x. The least significant 16 bits of this number are returned.
int get_imm16(char *operand_str, int len, uint32_t offset)
{
	int32_t value;
	int32_t sign;

	if (operand_str[0]=='-')
	{
		sign=-1;
		operand_str++;
	}
	else sign=1;

	if (operand_str[0]=='0'&& operand_str[1]=='x')
	{
		sscanf(operand_str+2, "%x", &value);
	}
	else
	{
		sscanf(operand_str, "%d", &value);
	}

	value*=sign;

	if (value<-0x8000 || value>0x7fff) fprintf(stderr, "Warning: imm16 value out of range\n");

	while (value<0) value+=0x10000;
	while (value>0xffff) value-=0x10000;

	return value;
}

// This function is passed a string containing an operand in the first len characters, which could be a decimal number
// or a lowercase hexadecimal number prefixed by 0x. The least significant 7 bits of this number are returned.
int get_imm7(char *operand_str, int len, uint32_t offset)
{
	int32_t value;
	int32_t sign;

	if (operand_str[0]=='-')
	{
		sign=-1;
		operand_str++;
	}
	else sign=1;

	if (operand_str[0]=='0'&& operand_str[1]=='x')
	{
		sscanf(operand_str+2, "%x", &value);
	}
	else
	{
		sscanf(operand_str, "%d", &value);
	}

	value*=sign;

	if (value<-0x40 || value>0x3f) fprintf(stderr, "Warning: imm7 value out of range\n");

	while (value<0) value+=0x80;
	while (value>0x7f) value-=0x80;

	return value;
}

// This function is passed a string containing an operand in the first len characters, which could be a decimal number
// or a lowercase hexadecimal number prefixed by 0x. The least significant 6 bits of this number are returned.
int get_imm6(char *operand_str, int len, uint32_t offset)
{
	int32_t value;
	int32_t sign;

	if (operand_str[0]=='-')
	{
		sign=-1;
		operand_str++;
	}
	else sign=1;

	if (operand_str[0]=='0'&& operand_str[1]=='x')
	{
		sscanf(operand_str+2, "%x", &value);
	}
	else
	{
		sscanf(operand_str, "%d", &value);
	}

	value*=sign;

	if (value<-0x20 || value>0x1f) fprintf(stderr, "Warning: imm6 value out of range\n");

	while (value<0) value+=0x40;
	while (value>0x3f) value-=0x40;

	return value;
}

// This function is passed a string containing an operand in the first len characters, which could be a decimal number
// or a lowercase hexadecimal number prefixed by 0x. The least significant 3 bits of this number are returned.
int get_imm3(char *operand_str, int len, uint32_t offset)
{
	int32_t value;
	int32_t sign;

	if (operand_str[0]=='-')
	{
		sign=-1;
		operand_str++;
	}
	else sign=1;

	if (operand_str[0]=='0'&& operand_str[1]=='x')
	{
		sscanf(operand_str+2, "%x", &value);
	}
	else
	{
		sscanf(operand_str, "%d", &value);
	}

	value*=sign;

	if (value<-0x04 || value>0x03) fprintf(stderr, "Warning: imm3 value out of range\n");

	while (value<0) value+=0x08;

	value = value & 0x07;

	return value;
}

// This function is passed a string containing an operand in the first len characters, which could be a decimal number
// or a lowercase hexadecimal number prefixed by 0x. The least significant 3 bits of this number are returned.
int get_uimm3(char *operand_str, int len, uint32_t offset)
{
	int32_t value;

	if (operand_str[0]=='0'&& operand_str[1]=='x')
	{
		sscanf(operand_str+2, "%x", &value);
	}
	else
	{
		sscanf(operand_str, "%d", &value);
	}

	if (value<0 || value>0x07) fprintf(stderr, "Warning: uimm3 value out of range\n");

	while (value<0) value+=0x08;

	value = value & 0x07;

	return value;
}

// This function is passed a string containing an operand in the first len characters, which could be a decimal number
// or a lowercase hexadecimal number prefixed by 0x. The least significant 5 bits of this number are returned.
int get_astatbitnum(char *operand_str, int len, uint32_t offset)
{
	int32_t value;

	if (operand_str[0]=='0'&& operand_str[1]=='x')
	{
		sscanf(operand_str+2, "%x", &value);
	}
	else
	{
		sscanf(operand_str, "%d", &value);
	}

	if (value<0 || value>0x1f) fprintf(stderr, "Warning: astat bit number out of range\n");

	while (value<0) value+=0x20;

	value = value & 0x1f;

	return value;
}

// This function is passed a string containing an operand in the first len characters, which is the name of an astat bit.
// A number between 0 and 31 is returned.
int get_astatbitname(char *operand_str, int len, uint32_t offset)
{	
	if (strncmp(operand_str, "az", 2)==0) return 0;
	else if (strncmp(operand_str, "an", 2)==0) return 1;
	else if (strncmp(operand_str, "ac0_copy", 8)==0) return 2;
	else if (strncmp(operand_str, "v_copy", 6)==0) return 3;
	// bit 4 unused
	else if (strncmp(operand_str, "cc", 2)==0) return 5;
	else if (strncmp(operand_str, "aq", 2)==0) return 6;
	// Bit 7 is unused
	else if (strncmp(operand_str, "rnd_mod", 7)==0) return 8;
	// Bits 9-11 unused
	else if (strncmp(operand_str, "ac0", 3)==0) return 12;
	else if (strncmp(operand_str, "ac1", 3)==0) return 13;
	// Bits 14-15 unused
	else if (strncmp(operand_str, "av0s", 4)==0) return 17;
	else if (strncmp(operand_str, "av0", 3)==0) return 16;
	else if (strncmp(operand_str, "av1s", 4)==0) return 19;
	else if (strncmp(operand_str, "av1", 3)==0) return 18;
	// Bits 20-23 unused
	else if (strncmp(operand_str, "vs", 2)==0) return 25;
	else if (strncmp(operand_str, "v", 1)==0) return 24;
	// Bits 26-31 unused
	else return 0;
}

// This function is passed a string containing an operand in the first len characters, which could be p0, p1, p2, p3, p4, p5, fp or sp.
// This function then calculates and returns corresponding the preg code.
int get_preg(char *operand_str, int len, uint32_t offset)
{
	if (strncmp(operand_str, "p0", 2)==0) return 0;
	else if (strncmp(operand_str, "p1", 2)==0) return 1;
	else if (strncmp(operand_str, "p2", 2)==0) return 2;
	else if (strncmp(operand_str, "p3", 2)==0) return 3;
	else if (strncmp(operand_str, "p4", 2)==0) return 4;
	else if (strncmp(operand_str, "p5", 2)==0) return 5;
	else if (strncmp(operand_str, "sp", 2)==0) return 6;
	else if (strncmp(operand_str, "fp", 2)==0) return 7;
	else return 0;
}

// This function is passed a string containing an operand in the first len characters, which could be 0, 1, 2, 3, 4, or 5.
// This function then calculates and returns the corresponding dreg code.
int get_preg_num(char *operand_str, int len, uint32_t offset)
{
	if (strncmp(operand_str, "0", 1)==0) return 0;
	else if (strncmp(operand_str, "1", 1)==0) return 1;
	else if (strncmp(operand_str, "2", 1)==0) return 2;
	else if (strncmp(operand_str, "3", 1)==0) return 3;
	else if (strncmp(operand_str, "4", 1)==0) return 4;
	else if (strncmp(operand_str, "5", 1)==0) return 5;
	else return 0;
}

// This function is passed a string containing an operand in the first len characters, which could be r0, r1, r2, r3, r4, r5, r6 or r7.
// This function then calculates and returns the corresponding dreg code.
int get_dreg(char *operand_str, int len, uint32_t offset)
{
	if (strncmp(operand_str, "r0", 2)==0) return 0;
	else if (strncmp(operand_str, "r1", 2)==0) return 1;
	else if (strncmp(operand_str, "r2", 2)==0) return 2;
	else if (strncmp(operand_str, "r3", 2)==0) return 3;
	else if (strncmp(operand_str, "r4", 2)==0) return 4;
	else if (strncmp(operand_str, "r5", 2)==0) return 5;
	else if (strncmp(operand_str, "r6", 2)==0) return 6;
	else if (strncmp(operand_str, "r7", 2)==0) return 7;
	else return 0;
}

// This function is passed a string containing an operand in the first len characters, which could be 0, 1, 2, 3, 4, 5, 6 or 7.
// This function then calculates and returns the corresponding dreg code.
int get_dreg_num(char *operand_str, int len, uint32_t offset)
{
	if (strncmp(operand_str, "0", 1)==0) return 0;
	else if (strncmp(operand_str, "1", 1)==0) return 1;
	else if (strncmp(operand_str, "2", 1)==0) return 2;
	else if (strncmp(operand_str, "3", 1)==0) return 3;
	else if (strncmp(operand_str, "4", 1)==0) return 4;
	else if (strncmp(operand_str, "5", 1)==0) return 5;
	else if (strncmp(operand_str, "6", 1)==0) return 6;
	else if (strncmp(operand_str, "7", 1)==0) return 7;
	else return 0;
}

// This function is passed a string containing an operand in the first len characters, which could be r0, r1, r2, r3, r4, r5, r6 or r7.
// This function then calculates and returns the corresponding even dreg code (by setting the least significant bit to zero).
int get_dreg_even(char *operand_str, int len, uint32_t offset)
{
	if (strncmp(operand_str, "r0", 2)==0) return 0;
	else if (strncmp(operand_str, "r1", 2)==0) return 0;
	else if (strncmp(operand_str, "r2", 2)==0) return 2;
	else if (strncmp(operand_str, "r3", 2)==0) return 2;
	else if (strncmp(operand_str, "r4", 2)==0) return 4;
	else if (strncmp(operand_str, "r5", 2)==0) return 4;
	else if (strncmp(operand_str, "r6", 2)==0) return 6;
	else if (strncmp(operand_str, "r7", 2)==0) return 6;
	else return 0;
}

// This function is passed a string containing an operand in the first len characters, which could be r1:0, r2:1, r3:2, r4:3, r5:4, r6:5, or r7:6.
// This function then calculates and returns the corresponding even dreg code of the lowest in the pair.
int get_dreg_pair(char *operand_str, int len, uint32_t offset)
{
	if (strncmp(operand_str, "r1:0", 4)==0) return 0;
	else if (strncmp(operand_str, "r2:1", 4)==0) return 1;
	else if (strncmp(operand_str, "r3:2", 4)==0) return 2;
	else if (strncmp(operand_str, "r4:3", 4)==0) return 3;
	else if (strncmp(operand_str, "r5:4", 4)==0) return 4;
	else if (strncmp(operand_str, "r6:5", 4)==0) return 5;
	else if (strncmp(operand_str, "r7:6", 4)==0) return 6;
	else return 0;
}

// This function is passed a string containing an operand in the first len characters, which could be i0, i1, i2, i3.
// This function then calculates and returns corresponding the ireg code.
int get_ireg(char *operand_str, int len, uint32_t offset)
{
	if (strncmp(operand_str, "i0", 2)==0) return 0;
	else if (strncmp(operand_str, "i1", 2)==0) return 1;
	else if (strncmp(operand_str, "i2", 2)==0) return 2;
	else if (strncmp(operand_str, "i3", 2)==0) return 3;
	else return 0;
}

// This function is passed a string containing an operand in the first len characters, which could be m0, m1, m2, m3.
// This function then calculates and returns corresponding the mreg code.
int get_mreg(char *operand_str, int len, uint32_t offset)
{
	if (strncmp(operand_str, "m0", 2)==0) return 0;
	else if (strncmp(operand_str, "m1", 2)==0) return 1;
	else if (strncmp(operand_str, "m2", 2)==0) return 2;
	else if (strncmp(operand_str, "m3", 2)==0) return 3;
	else return 0;
}

// This function is passed a string containing an operand in the first len characters, which is the name of a blackfin register in lowercase.
// This function returns the corresponding register group number.
int get_reg_group(char *operand_str, int len, uint32_t offset)
{
	if (strncmp(operand_str, "r0", 2)==0) return 0x00;
	else if (strncmp(operand_str, "r1", 2)==0) return 0x00;
	else if (strncmp(operand_str, "r2", 2)==0) return 0x00;
	else if (strncmp(operand_str, "r3", 2)==0) return 0x00;
	else if (strncmp(operand_str, "r4", 2)==0) return 0x00;
	else if (strncmp(operand_str, "r5", 2)==0) return 0x00;
	else if (strncmp(operand_str, "r6", 2)==0) return 0x00;
	else if (strncmp(operand_str, "r7", 2)==0) return 0x00;

	else if (strncmp(operand_str, "p0", 2)==0) return 0x01;
	else if (strncmp(operand_str, "p1", 2)==0) return 0x01;
	else if (strncmp(operand_str, "p2", 2)==0) return 0x01;
	else if (strncmp(operand_str, "p3", 2)==0) return 0x01;
	else if (strncmp(operand_str, "p4", 2)==0) return 0x01;
	else if (strncmp(operand_str, "p5", 2)==0) return 0x01;
	else if (strncmp(operand_str, "sp", 2)==0) return 0x01;
	else if (strncmp(operand_str, "fp", 2)==0) return 0x01;

	else if (strncmp(operand_str, "i0", 2)==0) return 0x02;
	else if (strncmp(operand_str, "i1", 2)==0) return 0x02;
	else if (strncmp(operand_str, "i2", 2)==0) return 0x02;
	else if (strncmp(operand_str, "i3", 2)==0) return 0x02;
	else if (strncmp(operand_str, "m0", 2)==0) return 0x02;
	else if (strncmp(operand_str, "m1", 2)==0) return 0x02;
	else if (strncmp(operand_str, "m2", 2)==0) return 0x02;
	else if (strncmp(operand_str, "m3", 2)==0) return 0x02;

	else if (strncmp(operand_str, "b0", 2)==0) return 0x03;
	else if (strncmp(operand_str, "b1", 2)==0) return 0x03;
	else if (strncmp(operand_str, "b2", 2)==0) return 0x03;
	else if (strncmp(operand_str, "b3", 2)==0) return 0x03;
	else if (strncmp(operand_str, "l0", 2)==0) return 0x03;
	else if (strncmp(operand_str, "l1", 2)==0) return 0x03;
	else if (strncmp(operand_str, "l2", 2)==0) return 0x03;
	else if (strncmp(operand_str, "l3", 2)==0) return 0x03;

	else if (strncmp(operand_str, "a0", 2)==0) return 0x04;
	else if (strncmp(operand_str, "a1", 2)==0) return 0x04;
	else if (strncmp(operand_str, "astat", 5)==0) return 0x04;
	else if (strncmp(operand_str, "rets", 4)==0) return 0x04;

	// Group 0x05 is reserved

	else if (strncmp(operand_str, "lc0", 3)==0) return 0x06;
	else if (strncmp(operand_str, "lt0", 3)==0) return 0x06;
	else if (strncmp(operand_str, "lb0", 3)==0) return 0x06;
	else if (strncmp(operand_str, "lc1", 3)==0) return 0x06;
	else if (strncmp(operand_str, "lt1", 3)==0) return 0x06;
	else if (strncmp(operand_str, "lb1", 3)==0) return 0x06;
	else if (strncmp(operand_str, "cycles2", 7)==0) return 0x06; // Must check for cycles2 first
	else if (strncmp(operand_str, "cycles", 6)==0) return 0x06;

	else if (strncmp(operand_str, "usp", 3)==0) return 0x07;
	else if (strncmp(operand_str, "seqstat", 7)==0) return 0x07;
	else if (strncmp(operand_str, "syscfg", 6)==0) return 0x07;
	else if (strncmp(operand_str, "reti", 4)==0) return 0x07;
	else if (strncmp(operand_str, "retx", 4)==0) return 0x07;
	else if (strncmp(operand_str, "retn", 4)==0) return 0x07;
	else if (strncmp(operand_str, "rete", 4)==0) return 0x07;
	else if (strncmp(operand_str, "emudat", 6)==0) return 0x07;

	else return -1;
}

// This function is passed a string containing an operand in the first len characters, which is the name of a blackfin register in lowercase.
// This function returns the corresponding register number (within its register group).
int get_reg_number(char *operand_str, int len, uint32_t offset)
{
	if (strncmp(operand_str, "r0", 2)==0) return 0x00;
	else if (strncmp(operand_str, "r1", 2)==0) return 0x01;
	else if (strncmp(operand_str, "r2", 2)==0) return 0x02;
	else if (strncmp(operand_str, "r3", 2)==0) return 0x03;
	else if (strncmp(operand_str, "r4", 2)==0) return 0x04;
	else if (strncmp(operand_str, "r5", 2)==0) return 0x05;
	else if (strncmp(operand_str, "r6", 2)==0) return 0x06;
	else if (strncmp(operand_str, "r7", 2)==0) return 0x07;

	else if (strncmp(operand_str, "p0", 2)==0) return 0x00;
	else if (strncmp(operand_str, "p1", 2)==0) return 0x01;
	else if (strncmp(operand_str, "p2", 2)==0) return 0x02;
	else if (strncmp(operand_str, "p3", 2)==0) return 0x03;
	else if (strncmp(operand_str, "p4", 2)==0) return 0x04;
	else if (strncmp(operand_str, "p5", 2)==0) return 0x05;
	else if (strncmp(operand_str, "sp", 2)==0) return 0x06;
	else if (strncmp(operand_str, "fp", 2)==0) return 0x07;

	else if (strncmp(operand_str, "i0", 2)==0) return 0x00;
	else if (strncmp(operand_str, "i1", 2)==0) return 0x01;
	else if (strncmp(operand_str, "i2", 2)==0) return 0x02;
	else if (strncmp(operand_str, "i3", 2)==0) return 0x03;
	else if (strncmp(operand_str, "m0", 2)==0) return 0x04;
	else if (strncmp(operand_str, "m1", 2)==0) return 0x05;
	else if (strncmp(operand_str, "m2", 2)==0) return 0x06;
	else if (strncmp(operand_str, "m3", 2)==0) return 0x07;

	else if (strncmp(operand_str, "b0", 2)==0) return 0x00;
	else if (strncmp(operand_str, "b1", 2)==0) return 0x01;
	else if (strncmp(operand_str, "b2", 2)==0) return 0x02;
	else if (strncmp(operand_str, "b3", 2)==0) return 0x03;
	else if (strncmp(operand_str, "l0", 2)==0) return 0x04;
	else if (strncmp(operand_str, "l1", 2)==0) return 0x05;
	else if (strncmp(operand_str, "l2", 2)==0) return 0x06;
	else if (strncmp(operand_str, "l3", 2)==0) return 0x07;

	else if (strncmp(operand_str, "a0.x", 4)==0) return 0x00;
	else if (strncmp(operand_str, "a0.w", 4)==0) return 0x01;
	else if (strncmp(operand_str, "a1.x", 4)==0) return 0x02;
	else if (strncmp(operand_str, "a1.w", 4)==0) return 0x03;
	// 2 reserved numbers here
	else if (strncmp(operand_str, "astat", 5)==0) return 0x06;
	else if (strncmp(operand_str, "rets", 4)==0) return 0x07;

	else if (strncmp(operand_str, "lc0", 3)==0) return 0x00;
	else if (strncmp(operand_str, "lt0", 3)==0) return 0x01;
	else if (strncmp(operand_str, "lb0", 3)==0) return 0x02;
	else if (strncmp(operand_str, "lc1", 3)==0) return 0x03;
	else if (strncmp(operand_str, "lt1", 3)==0) return 0x04;
	else if (strncmp(operand_str, "lb1", 3)==0) return 0x05;
	else if (strncmp(operand_str, "cycles2", 7)==0) return 0x07; // Must check for cycles2 first
	else if (strncmp(operand_str, "cycles", 6)==0) return 0x06;

	else if (strncmp(operand_str, "usp", 3)==0) return 0x00;
	else if (strncmp(operand_str, "seqstat", 7)==0) return 0x01;
	else if (strncmp(operand_str, "syscfg", 6)==0) return 0x02;
	else if (strncmp(operand_str, "reti", 4)==0) return 0x03;
	else if (strncmp(operand_str, "retx", 4)==0) return 0x04;
	else if (strncmp(operand_str, "retn", 4)==0) return 0x05;
	else if (strncmp(operand_str, "rete", 4)==0) return 0x06;
	else if (strncmp(operand_str, "emudat", 6)==0) return 0x07;

	else return -1;
}

// This function is passed a string containing an operand in the first len characters, which could be r0, r1, r2, r3, r4, r5, r6, r7,
// p0, p1, p2, p3, p4, p5, fp, sp, i0, i1, i2, i3, m0, m1, m2, m3, b0, b1, b2, b3, l0, l1, l2, l3.
// This function then calculates and returns corresponding the dreg code.
int get_reg(char *operand_str, int len, uint32_t offset)
{
	int group=get_reg_group(operand_str, len, offset);
	int number=get_reg_number(operand_str, len, offset);

	if (group<0 || number<0) return -1;
	else return group*0x08+number;
}

// This function is passed a string containing an operand in the first len characters, which is either ".l" or ".h".
// This function returns 0 for .l or 1 for .h.
int get_lowhigh(char *operand_str, int len, uint32_t offset)
{
	if (strncmp(operand_str, ".l", 2)==0) return 0;
	else if (strncmp(operand_str, ".h", 2)==0) return 1;
	else return -1;
}

// This function is passed a string containing an operand in the first len characters, which is either "=", "+=" or "-=".
// This function returns a corresponding integer code.
int get_op(char *operand_str, int len, uint32_t offset)
{
	if (strncmp(operand_str, "=", 1)==0) return 0;
	else if (strncmp(operand_str, "+=", 2)==0) return 1;
	else if (strncmp(operand_str, "-=", 2)==0) return 2;
	else return -1;
}

typedef enum
{
	INSTRUCTION_SIZE_16_BIT,
	INSTRUCTION_SIZE_32_BIT
} InstructionSize;

typedef struct
{
	int group_number;     // Which captured group in the regex is this operand?
	int (*string_to_int_converter)(char *operand_str, int len, uint32_t offset);  // Function for converting operand string (of specified length) to an integer. The offset of the instruction in memory also needs to be provided, for calculating PC-relative addresses. 
	int bit_location;     // How far does the operand int need to be bit shifted left, prior to the OR with the opcode?
} Operand;

#define MAX_OPERANDS 100

typedef struct
{
	int in_32bit_alu_mac;	// 1 if this instruction is one of the parallelisable 32 bit instructions, or 0 otherwise.
	int in_16bit_group1;	// 1 if this instruction is in Group 1 of the 16 bit parallelisable instructions, or 0 otherwise.
	int in_16bit_group2;	// 1 if this instruction is in Group 2 of the 16 bit parallelisable instructions, or 0 otherwise.
	int is_store;		// 1 if this instruction is in Group 1 or Group 2, and it is a store operation; 0 otherwise.
} ParallelConstraints;
// See pp. 20-3 to 20-8 of the Blackfin Processor Programming Reference. 

typedef struct
{
	// Basics:
	InstructionSize size;                       // Specifies if instruction is 16 bit or 32 bit

	// Instruction identification:
	const char asm_regex_str[MAX_NORM_STR+1];   // Regular expression for identifying instruction (and extracting groups for operands)

	// Opcode:
	uint32_t opcode_mask;                       // Bit pattern for generating opcode (bitwise OR against the operands to generate machine code)

	// Operands:
	int num_operands;
	Operand operands[MAX_OPERANDS];	

	// Parallelisability:
	ParallelConstraints parallel_constraints; 
} Instruction;

static Instruction instructions[]=
{
	// Jumps:

	{INSTRUCTION_SIZE_16_BIT, "^jump\\((p[0-5]|fp|sp)\\)$", 0x00000050, 1, {{1, &get_preg, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^jump\\(pc\\+(p[0-5]|fp|sp)\\)$", 0x00000080, 1, {{1, &get_preg, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^jump\\.s(0x[0-9,a-f]+|[0-9]+)$", 0x00002000, 1, {{1, &get_pcrel13m2_from_absolute_address, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^jump\\.l(0x[0-9,a-f]+|[0-9]+)$", 0xe2000000, 1, {{1, &get_pcrel25m2_from_absolute_address, 0}}, {0, 0, 0, 0} },

	// Conditional jumps:

	{INSTRUCTION_SIZE_16_BIT, "^ifccjump(0x[0-9,a-f]+|[0-9]+)$", 0x00001800, 1, {{1, &get_pcrel11m2_from_absolute_address, 0}}, {0, 0, 0, 0} },	
	{INSTRUCTION_SIZE_16_BIT, "^ifccjump(0x[0-9,a-f]+|[0-9]+)\\(bp\\)$", 0x00001c00, 1, {{1, &get_pcrel11m2_from_absolute_address, 0}}, {0, 0, 0, 0} },	
	{INSTRUCTION_SIZE_16_BIT, "^if!ccjump(0x[0-9,a-f]+|[0-9]+)$", 0x00001000, 1, {{1, &get_pcrel11m2_from_absolute_address, 0}}, {0, 0, 0, 0} },	
	{INSTRUCTION_SIZE_16_BIT, "^if!ccjump(0x[0-9,a-f]+|[0-9]+)\\(bp\\)$", 0x00001400, 1, {{1, &get_pcrel11m2_from_absolute_address, 0}}, {0, 0, 0, 0} },	

	// Calls:

	{INSTRUCTION_SIZE_16_BIT, "^call\\((p[0-5]|fp|sp)\\)$", 0x00000060, 1, {{1, &get_preg, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^call\\(pc\\+(p[0-5]|fp|sp)\\)$", 0x00000070, 1, {{1, &get_preg, 0}}, {0, 0, 0, 0} },	
	{INSTRUCTION_SIZE_32_BIT, "^call(0x[0-9,a-f]+|[0-9]+)$", 0xe3000000, 1, {{1, &get_pcrel25m2_from_absolute_address, 0}}, {0, 0, 0, 0} },

	// Returns:

	{INSTRUCTION_SIZE_16_BIT, "^rts$", 0x00000010, 0, {{}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^rti$", 0x00000011, 0, {{}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^rtx$", 0x00000012, 0, {{}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^rtn$", 0x00000013, 0, {{}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^rte$", 0x00000014, 0, {{}}, {0, 0, 0, 0} },

	// Loop setup:

	{INSTRUCTION_SIZE_32_BIT, "^lsetup\\((0x[0-9,a-f]+|[0-9]+),(0x[0-9,a-f]+|[0-9]+)\\)lc0$", 0xe0800000, 2, {{1, &get_pcrel5m2_from_absolute_address, 16}, {2, &get_pcrel11m2_from_absolute_address, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^lsetup\\((0x[0-9,a-f]+|[0-9]+),(0x[0-9,a-f]+|[0-9]+)\\)lc0=(p[0-5]|fp|sp)$", 0xe0a00000, 3, {{1, &get_pcrel5m2_from_absolute_address, 16}, {2, &get_pcrel11m2_from_absolute_address, 0}, {3, &get_preg, 12}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^lsetup\\((0x[0-9,a-f]+|[0-9]+),(0x[0-9,a-f]+|[0-9]+)\\)lc0=(p[0-5]|fp|sp)>>1$", 0xe0e00000, 3, {{1, &get_pcrel5m2_from_absolute_address, 16}, {2, &get_pcrel11m2_from_absolute_address, 0}, {3, &get_preg, 12}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^lsetup\\((0x[0-9,a-f]+|[0-9]+),(0x[0-9,a-f]+|[0-9]+)\\)lc1$", 0xe0900000, 2, {{1, &get_pcrel5m2_from_absolute_address, 16}, {2, &get_pcrel11m2_from_absolute_address, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^lsetup\\((0x[0-9,a-f]+|[0-9]+),(0x[0-9,a-f]+|[0-9]+)\\)lc1=(p[0-5]|fp|sp)$", 0xe0b00000, 3, {{1, &get_pcrel5m2_from_absolute_address, 16}, {2, &get_pcrel11m2_from_absolute_address, 0}, {3, &get_preg, 12}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^lsetup\\((0x[0-9,a-f]+|[0-9]+),(0x[0-9,a-f]+|[0-9]+)\\)lc1=(p[0-5]|fp|sp)>>1$", 0xe0f00000, 3, {{1, &get_pcrel5m2_from_absolute_address, 16}, {2, &get_pcrel11m2_from_absolute_address, 0}, {3, &get_preg, 12}}, {0, 0, 0, 0} },

	// Load:

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7]|p[0-5]|fp|sp|i[0-3]|m[0-3]|b[0-3]|l[0-3])\\.l=(0x[0-9,a-f]+|[0-9]+)$", 0xe1000000, 2, {{1, &get_reg, 16}, {2, &get_uimm16, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7]|p[0-5]|fp|sp|i[0-3]|m[0-3]|b[0-3]|l[0-3])\\.h=(0x[0-9,a-f]+|[0-9]+)$", 0xe1400000, 2, {{1, &get_reg, 16}, {2, &get_uimm16, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7]|p[0-5]|fp|sp|i[0-3]|m[0-3]|b[0-3]|l[0-3])=(0x[0-9,a-f]+|[0-9]+)\\(z\\)$", 0xe1800000, 2, {{1, &get_reg, 16}, {2, &get_uimm16, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a0=0$", 0xc408003f, 0, {}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1=0$", 0xc408403f, 0, {}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1=a0=0$", 0xc408803f, 0, {}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7]|p[0-5]|fp|sp|i[0-3]|m[0-3]|b[0-3]|l[0-3])=(-?0x[0-9,a-f]+|-?[0-9]+)\\(x\\)$", 0xe1200000, 2, {{1, &get_reg, 16}, {2, &get_imm16, 0}}, {0, 0, 0, 0} },
	// Note the modified assembly syntax for short versions of instructions for setting data registers and pointer registers with sign
	// extension, to distinguish them from the longer and more general instruction above. If you want the short form, use (X)(16) rather than (X).
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=(-?0x[0-9,a-f]+|-?[0-9]+)\\(x\\)\\(16\\)$", 0x00006000, 2, {{1, &get_dreg, 0}, {2, &get_imm7, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(p[0-5]|fp|sp)=(-?0x[0-9,a-f]+|-?[0-9]+)\\(x\\)\\(16\\)$", 0x00006800, 2, {{1, &get_preg, 0}, {2, &get_imm7, 3}}, {0, 0, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^(p[0-5]|fp|sp)=\\[(p[0-5]|fp|sp)\\]$", 0x00009140, 2, {{1, &get_preg, 0}, {2, &get_preg, 3}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(p[0-5]|fp|sp)=\\[(p[0-5]|fp|sp)\\+\\+\\]$", 0x00009040, 2, {{1, &get_preg, 0}, {2, &get_preg, 3}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(p[0-5]|fp|sp)=\\[(p[0-5]|fp|sp)\\-\\-\\]$", 0x000090c0, 2, {{1, &get_preg, 0}, {2, &get_preg, 3}}, {0, 1, 0, 0} },
	// Note the modified assembly syntax for short versions of otherwise equivalent instructions, by adding (16) at the end.
	{INSTRUCTION_SIZE_16_BIT, "^(p[0-5]|fp|sp)=\\[(p[0-5]|fp|sp)\\+(0x[0-9,a-f]+|[0-9]+)\\]\\(16\\)$", 0x0000ac00, 3, {{1, &get_preg, 0}, {2, &get_preg, 3}, {3, &get_uimm6m4, 6}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(p[0-5]|fp|sp)=\\[(p[0-5]|fp|sp)\\+(0x[0-9,a-f]+|[0-9]+)\\]$", 0xe5000000, 3, {{1, &get_preg, 16}, {2, &get_preg, 19}, {3, &get_uimm17m4, 0}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(p[0-5]|fp|sp)=\\[(p[0-5]|fp|sp)(\\-0x[0-9,a-f]+|\\-[0-9]+)\\]$", 0xe5008000, 3, {{1, &get_preg, 16}, {2, &get_preg, 19}, {3, &get_imm17m4, 0}}, {0, 1, 0, 0} },
	// Note the modified assembly syntax for short versions of otherwise equivalent instructions, by adding (16) at the end.
	{INSTRUCTION_SIZE_16_BIT, "^(p[0-5]|fp|sp)=\\[fp\\-(0x[0-9,a-f]+|[0-9]+)\\]\\(16\\)$", 0x0000b808, 2, {{1, &get_preg, 0}, {2, &get_uimm7m4, 4}}, {0, 1, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=\\[(p[0-5]|fp|sp)\\]$", 0x00009100, 2, {{1, &get_dreg, 0}, {2, &get_preg, 3}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=\\[(p[0-5]|fp|sp)\\+\\+\\]$", 0x00009000, 2, {{1, &get_dreg, 0}, {2, &get_preg, 3}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=\\[(p[0-5]|fp|sp)\\-\\-\\]$", 0x00009080, 2, {{1, &get_dreg, 0}, {2, &get_preg, 3}}, {0, 1, 0, 0} },
	// Note the modified assembly syntax for short versions of otherwise equivalent instructions, by adding (16) at the end.
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=\\[(p[0-5]|fp|sp)\\+(0x[0-9,a-f]+|[0-9]+)\\]\\(16\\)$", 0x0000a000, 3, {{1, &get_dreg, 0}, {2, &get_preg, 3}, {3, &get_uimm6m4, 6}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=\\[(p[0-5]|fp|sp)\\+(0x[0-9,a-f]+|[0-9]+)\\]$", 0xe4000000, 3, {{1, &get_dreg, 16}, {2, &get_preg, 19}, {3, &get_uimm17m4, 0}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=\\[(p[0-5]|fp|sp)(\\-0x[0-9,a-f]+|\\-[0-9]+)\\]$", 0xe4008000, 3, {{1, &get_dreg, 16}, {2, &get_preg, 19}, {3, &get_imm17m4, 0}}, {0, 1, 0, 0} },
	// Note that no warning or error is raised if the two pregs are the same, even though this is invalid.
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=\\[(p[0-5]|fp|sp)\\+\\+(p[0-5]|fp|sp)\\]$", 0x00008000, 3, {{1, &get_dreg, 6}, {2, &get_preg, 0}, {3, &get_preg, 3}}, {0, 1, 0, 0} },
	// Note the modified assembly syntax for short versions of otherwise equivalent instructions, by adding (16) at the end.
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=\\[fp\\-(0x[0-9,a-f]+|[0-9]+)\\]\\(16\\)$", 0x0000b800, 2, {{1, &get_dreg, 0}, {2, &get_uimm7m4, 4}}, {0, 1, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=\\[(i[0-3])\\]$", 0x00009d00, 2, {{1, &get_dreg, 0}, {2, &get_ireg, 3}}, {0, 1, 1, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=\\[(i[0-3])\\+\\+\\]$", 0x00009c00, 2, {{1, &get_dreg, 0}, {2, &get_ireg, 3}}, {0, 1, 1, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=\\[(i[0-3])\\-\\-\\]$", 0x00009c80, 2, {{1, &get_dreg, 0}, {2, &get_ireg, 3}}, {0, 1, 1, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=\\[(i[0-3])\\+\\+(m[0-3])\\]$", 0x00009d80, 3, {{1, &get_dreg, 0}, {2, &get_ireg, 3}, {3, &get_mreg, 5}}, {0, 1, 1, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=w\\[(p[0-5]|fp|sp)\\]\\(z\\)$", 0x00009500, 2, {{1, &get_dreg, 0}, {2, &get_preg, 3}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=w\\[(p[0-5]|fp|sp)\\+\\+\\]\\(z\\)$", 0x00009400, 2, {{1, &get_dreg, 0}, {2, &get_preg, 3}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=w\\[(p[0-5]|fp|sp)\\-\\-\\]\\(z\\)$", 0x00009480, 2, {{1, &get_dreg, 0}, {2, &get_preg, 3}}, {0, 1, 0, 0} },
	// Note the modified assembly syntax for short versions of otherwise equivalent instructions, by adding (16) at the end.
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=w\\[(p[0-5]|fp|sp)\\+(0x[0-9,a-f]+|[0-9]+)\\]\\(z\\)\\(16\\)$", 0x0000a400, 3, {{1, &get_dreg, 0}, {2, &get_preg, 3}, {3, &get_uimm5m2, 6}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=w\\[(p[0-5]|fp|sp)\\+(0x[0-9,a-f]+|[0-9]+)\\]\\(z\\)$", 0xe4400000, 3, {{1, &get_dreg, 16}, {2, &get_preg, 19}, {3, &get_uimm16m2, 0}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=w\\[(p[0-5]|fp|sp)(\\-0x[0-9,a-f]+|\\-[0-9]+)\\]\\(z\\)$", 0xe4400000, 3, {{1, &get_dreg, 16}, {2, &get_preg, 19}, {3, &get_imm16m2, 0}}, {0, 1, 0, 0} },
	// Note that no warning or error is raised if the two pregs are the same, even though this is invalid.
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=w\\[(p[0-5]|fp|sp)\\+\\+(p[0-5]|fp|sp)\\]\\(z\\)$", 0x00008600, 3, {{1, &get_dreg, 6}, {2, &get_preg, 0}, {3, &get_preg, 3}}, {0, 1, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=w\\[(p[0-5]|fp|sp)\\]\\(x\\)$", 0x00009540, 2, {{1, &get_dreg, 0}, {2, &get_preg, 3}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=w\\[(p[0-5]|fp|sp)\\+\\+\\]\\(x\\)$", 0x00009440, 2, {{1, &get_dreg, 0}, {2, &get_preg, 3}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=w\\[(p[0-5]|fp|sp)\\-\\-\\]\\(x\\)$", 0x000094c0, 2, {{1, &get_dreg, 0}, {2, &get_preg, 3}}, {0, 1, 0, 0} },
	// Note the modified assembly syntax for short versions of otherwise equivalent instructions, by adding (16) at the end.
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=w\\[(p[0-5]|fp|sp)\\+(0x[0-9,a-f]+|[0-9]+)\\]\\(x\\)\\(16\\)$", 0x0000a800, 3, {{1, &get_dreg, 0}, {2, &get_preg, 3}, {3, &get_uimm5m2, 6}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=w\\[(p[0-5]|fp|sp)\\+(0x[0-9,a-f]+|[0-9]+)\\]\\(x\\)$", 0xe5400000, 3, {{1, &get_dreg, 16}, {2, &get_preg, 19}, {3, &get_uimm16m2, 0}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=w\\[(p[0-5]|fp|sp)(\\-0x[0-9,a-f]+|\\-[0-9]+)\\]\\(x\\)$", 0xe5400000, 3, {{1, &get_dreg, 16}, {2, &get_preg, 19}, {3, &get_imm16m2, 0}}, {0, 1, 0, 0} },
	// Note that no warning or error is raised if the two pregs are the same, even though this is invalid.
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=w\\[(p[0-5]|fp|sp)\\+\\+(p[0-5]|fp|sp)\\]\\(x\\)$", 0x00008e00, 3, {{1, &get_dreg, 6}, {2, &get_preg, 0}, {3, &get_preg, 3}}, {0, 1, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])\\.h=w\\[(i[0-3])\\]$", 0x00009d40, 2, {{1, &get_dreg, 0}, {2, &get_ireg, 3}}, {0, 1, 1, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])\\.h=w\\[(i[0-3])\\+\\+\\]$", 0x00009c40, 2, {{1, &get_dreg, 0}, {2, &get_ireg, 3}}, {0, 1, 1, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])\\.h=w\\[(i[0-3])\\-\\-\\]$", 0x00009cc0, 2, {{1, &get_dreg, 0}, {2, &get_ireg, 3}}, {0, 1, 1, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])\\.h=w\\[(p[0-5]|fp|sp)\\]$", 0x00008400, 3, {{1, &get_dreg, 6}, {2, &get_preg, 0}, {2, &get_preg, 3}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])\\.h=w\\[(p[0-5]|fp|sp)\\+\\+(p[0-5]|fp|sp)\\]$", 0x00008400, 3, {{1, &get_dreg, 6}, {2, &get_preg, 0}, {3, &get_preg, 3}}, {0, 1, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])\\.l=w\\[(i[0-3])\\]$", 0x00009d20, 2, {{1, &get_dreg, 0}, {2, &get_ireg, 3}}, {0, 1, 1, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])\\.l=w\\[(i[0-3])\\+\\+\\]$", 0x00009c20, 2, {{1, &get_dreg, 0}, {2, &get_ireg, 3}}, {0, 1, 1, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])\\.l=w\\[(i[0-3])\\-\\-\\]$", 0x00009ca0, 2, {{1, &get_dreg, 0}, {2, &get_ireg, 3}}, {0, 1, 1, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])\\.l=w\\[(p[0-5]|fp|sp)\\]$", 0x00008200, 3, {{1, &get_dreg, 6}, {2, &get_preg, 0}, {2, &get_preg, 3}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])\\.l=w\\[(p[0-5]|fp|sp)\\+\\+(p[0-5]|fp|sp)\\]$", 0x00008200, 3, {{1, &get_dreg, 6}, {2, &get_preg, 0}, {3, &get_preg, 3}}, {0, 1, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=b\\[(p[0-5]|fp|sp)\\]\\(z\\)$", 0x00009900, 2, {{1, &get_dreg, 0}, {2, &get_preg, 3}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=b\\[(p[0-5]|fp|sp)\\+\\+\\]\\(z\\)$", 0x00009800, 2, {{1, &get_dreg, 0}, {2, &get_preg, 3}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=b\\[(p[0-5]|fp|sp)\\-\\-\\]\\(z\\)$", 0x00009880, 2, {{1, &get_dreg, 0}, {2, &get_preg, 3}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=b\\[(p[0-5]|fp|sp)\\+(0x[0-9,a-f]+|[0-9]+)\\]\\(z\\)$", 0xe4800000, 3, {{1, &get_dreg, 16}, {2, &get_preg, 19}, {3, &get_imm16, 0}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=b\\[(p[0-5]|fp|sp)(\\-0x[0-9,a-f]+|\\-[0-9]+)\\]\\(z\\)$", 0xe4800000, 3, {{1, &get_dreg, 16}, {2, &get_preg, 19}, {3, &get_imm16, 0}}, {0, 1, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=b\\[(p[0-5]|fp|sp)\\]\\(x\\)$", 0x00009940, 2, {{1, &get_dreg, 0}, {2, &get_preg, 3}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=b\\[(p[0-5]|fp|sp)\\+\\+\\]\\(x\\)$", 0x00009840, 2, {{1, &get_dreg, 0}, {2, &get_preg, 3}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=b\\[(p[0-5]|fp|sp)\\-\\-\\]\\(x\\)$", 0x000098c0, 2, {{1, &get_dreg, 0}, {2, &get_preg, 3}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=b\\[(p[0-5]|fp|sp)\\+(0x[0-9,a-f]+|[0-9]+)\\]\\(x\\)$", 0xe5800000, 3, {{1, &get_dreg, 16}, {2, &get_preg, 19}, {3, &get_imm16, 0}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=b\\[(p[0-5]|fp|sp)(\\-0x[0-9,a-f]+|\\-[0-9]+)\\]\\(x\\)$", 0xe5800000, 3, {{1, &get_dreg, 16}, {2, &get_preg, 19}, {3, &get_imm16, 0}}, {0, 1, 0, 0} },

	// Store:	

	// Note: need to allow opening [ to be missing, because the rasm2 command typically strips that character out
	// when pre-processing an instruction provided as a string.
	{INSTRUCTION_SIZE_16_BIT, "^\\[?(p[0-5]|fp|sp)\\]=(p[0-5]|fp|sp)$", 0x00009340, 2, {{1, &get_preg, 3}, {2, &get_preg, 0}}, {0, 1, 0, 1} },
	{INSTRUCTION_SIZE_16_BIT, "^\\[?(p[0-5]|fp|sp)\\+\\+\\]=(p[0-5]|fp|sp)$", 0x00009240, 2, {{1, &get_preg, 3}, {2, &get_preg, 0}}, {0, 1, 0, 1} },
	{INSTRUCTION_SIZE_16_BIT, "^\\[?(p[0-5]|fp|sp)\\-\\-\\]=(p[0-5]|fp|sp)$", 0x000092c0, 2, {{1, &get_preg, 3}, {2, &get_preg, 0}}, {0, 1, 0, 1} },
	{INSTRUCTION_SIZE_16_BIT, "^\\[?(p[0-5]|fp|sp)\\+(0x[0-9,a-f]+|[0-9]+)\\]=(p[0-5]|fp|sp)\\(16\\)$", 0x0000bc00, 3, {{1, &get_preg, 3}, {2, &get_uimm6m4, 6}, {3, &get_preg, 0}}, {0, 1, 0, 1} },
	{INSTRUCTION_SIZE_32_BIT, "^\\[?(p[0-5]|fp|sp)\\+(0x[0-9,a-f]+|[0-9]+)\\]=(p[0-5]|fp|sp)$", 0xe7000000, 3, {{1, &get_preg, 19}, {2, &get_uimm17m4, 0}, {3, &get_preg, 16}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^\\[?(p[0-5]|fp|sp)(\\-0x[0-9,a-f]+|\\-[0-9]+)\\]=(p[0-5]|fp|sp)$", 0xe7000000, 3, {{1, &get_preg, 19}, {2, &get_imm17m4, 0}, {3, &get_preg, 16}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^\\[?fp\\-(0x[0-9,a-f]+|[0-9]+)\\]=(p[0-5]|fp|sp)\\(16\\)$", 0x0000ba08, 2, {{1, &get_uimm7m4, 4}, {2, &get_preg, 0}}, {0, 1, 0, 1} },

	// Note: need to allow opening [ to be missing, because the rasm2 command typically strips that character out
	// when pre-processing an instruction provided as a string.
	{INSTRUCTION_SIZE_16_BIT, "^\\[?(p[0-5]|fp|sp)\\]=(r[0-7])$", 0x00009300, 2, {{1, &get_preg, 3}, {2, &get_dreg, 0}}, {0, 1, 0, 1} },
	{INSTRUCTION_SIZE_16_BIT, "^\\[?(p[0-5]|fp|sp)\\+\\+\\]=(r[0-7])$", 0x00009200, 2, {{1, &get_preg, 3}, {2, &get_dreg, 0}}, {0, 1, 0, 1} },
	{INSTRUCTION_SIZE_16_BIT, "^\\[?(p[0-5]|fp|sp)\\-\\-\\]=(r[0-7])$", 0x00009280, 2, {{1, &get_preg, 3}, {2, &get_dreg, 0}}, {0, 1, 0, 1} },
	{INSTRUCTION_SIZE_16_BIT, "^\\[?(p[0-5]|fp|sp)\\+(0x[0-9,a-f]+|[0-9]+)\\]=(r[0-7])\\(16\\)$", 0x0000b000, 3, {{1, &get_preg, 3}, {2, &get_uimm6m4, 6}, {3, &get_dreg, 0}}, {0, 1, 0, 1} },
	{INSTRUCTION_SIZE_32_BIT, "^\\[?(p[0-5]|fp|sp)\\+(0x[0-9,a-f]+|[0-9]+)\\]=(r[0-7])$", 0xe6000000, 3, {{1, &get_preg, 19}, {2, &get_uimm17m4, 0}, {3, &get_dreg, 16}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^\\[?(p[0-5]|fp|sp)(\\-0x[0-9,a-f]+|\\-[0-9]+)\\]=(r[0-7])$", 0xe6000000, 3, {{1, &get_preg, 19}, {2, &get_imm17m4, 0}, {3, &get_dreg, 16}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^\\[?(p[0-5]|fp|sp)\\+\\+(p[0-5]|fp|sp)\\]=(r[0-7])$", 0x00008800, 3, {{1, &get_preg, 0}, {2, &get_preg, 3}, {3, &get_dreg, 6}}, {0, 1, 0, 1} },
	{INSTRUCTION_SIZE_16_BIT, "^\\[?fp\\-(0x[0-9,a-f]+|[0-9]+)\\]=(r[0-7])\\(16\\)$", 0x0000ba00, 2, {{1, &get_uimm7m4, 4}, {2, &get_dreg, 0}}, {0, 1, 0, 1} },

	// Note: need to allow opening [ to be missing, because the rasm2 command typically strips that character out
	// when pre-processing an instruction provided as a string.
	{INSTRUCTION_SIZE_16_BIT, "^\\[?(i[0-3])\\]=(r[0-7])$", 0x00009f00, 2, {{1, &get_ireg, 3}, {2, &get_dreg, 0}}, {0, 1, 1, 1} },
	{INSTRUCTION_SIZE_16_BIT, "^\\[?(i[0-3])\\+\\+\\]=(r[0-7])$", 0x00009e00, 2, {{1, &get_ireg, 3}, {2, &get_dreg, 0}}, {0, 1, 1, 1} },
	{INSTRUCTION_SIZE_16_BIT, "^\\[?(i[0-3])\\-\\-\\]=(r[0-7])$", 0x00009e80, 2, {{1, &get_ireg, 3}, {2, &get_dreg, 0}}, {0, 1, 1, 1} },
	{INSTRUCTION_SIZE_16_BIT, "^\\[?(i[0-3])\\+\\+(m[0-3])\\]=(r[0-7])$", 0x00009f80, 3, {{1, &get_ireg, 3}, {2, &get_mreg, 5}, {3, &get_dreg, 0}}, {0, 1, 1, 1} },
	{INSTRUCTION_SIZE_16_BIT, "^w\\[(i[0-3])\\]=(r[0-7]).h$", 0x00009f40, 2, {{1, &get_ireg, 3}, {2, &get_dreg, 0}}, {0, 1, 1, 1} },
	{INSTRUCTION_SIZE_16_BIT, "^w\\[(i[0-3])\\+\\+\\]=(r[0-7]).h$", 0x00009e40, 2, {{1, &get_ireg, 3}, {2, &get_dreg, 0}}, {0, 1, 1, 1} },
	{INSTRUCTION_SIZE_16_BIT, "^w\\[(i[0-3])\\-\\-\\]=(r[0-7]).h$", 0x00009ec0, 2, {{1, &get_ireg, 3}, {2, &get_dreg, 0}}, {0, 1, 1, 1} },
	{INSTRUCTION_SIZE_16_BIT, "^w\\[(p[0-5]|fp|sp)\\]=(r[0-7]).h$", 0x00008c00, 3, {{1, &get_preg, 0}, {1, &get_preg, 3}, {2, &get_dreg, 6}}, {0, 1, 0, 1} },
	{INSTRUCTION_SIZE_16_BIT, "^w\\[(p[0-5]|fp|sp)\\+\\+(p[0-5]|fp|sp)\\]=(r[0-7]).h$", 0x00008c00, 3, {{1, &get_preg, 0}, {2, &get_preg, 3}, {3, &get_dreg, 6}}, {0, 1, 0, 1} },

	{INSTRUCTION_SIZE_16_BIT, "^w\\[(i[0-3])\\]=(r[0-7]).l$", 0x00009f20, 2, {{1, &get_ireg, 3}, {2, &get_dreg, 0}}, {0, 1, 1, 1} },
	{INSTRUCTION_SIZE_16_BIT, "^w\\[(i[0-3])\\+\\+\\]=(r[0-7]).l$", 0x00009e20, 2, {{1, &get_ireg, 3}, {2, &get_dreg, 0}}, {0, 1, 1, 1} },
	{INSTRUCTION_SIZE_16_BIT, "^w\\[(i[0-3])\\-\\-\\]=(r[0-7]).l$", 0x00009ea0, 2, {{1, &get_ireg, 3}, {2, &get_dreg, 0}}, {0, 1, 1, 1} },
	{INSTRUCTION_SIZE_16_BIT, "^w\\[(p[0-5]|fp|sp)\\]=(r[0-7]).l$", 0x00008a00, 3, {{1, &get_preg, 0}, {1, &get_preg, 3}, {2, &get_dreg, 6}}, {0, 1, 0, 1} },
	{INSTRUCTION_SIZE_16_BIT, "^w\\[(p[0-5]|fp|sp)\\+\\+(p[0-5]|fp|sp)\\]=(r[0-7]).l$", 0x00008a00, 3, {{1, &get_preg, 0}, {2, &get_preg, 3}, {3, &get_dreg, 6}}, {0, 1, 0, 1} },

	{INSTRUCTION_SIZE_16_BIT, "^w\\[(p[0-5]|fp|sp)\\]=(r[0-7])$", 0x00009700, 2, {{1, &get_preg, 3}, {2, &get_dreg, 0}}, {0, 1, 0, 1} },
	{INSTRUCTION_SIZE_16_BIT, "^w\\[(p[0-5]|fp|sp)\\+\\+\\]=(r[0-7])$", 0x00009600, 2, {{1, &get_preg, 3}, {2, &get_dreg, 0}}, {0, 1, 0, 1} },
	{INSTRUCTION_SIZE_16_BIT, "^w\\[(p[0-5]|fp|sp)\\-\\-\\]=(r[0-7])$", 0x00009680, 2, {{1, &get_preg, 3}, {2, &get_dreg, 0}}, {0, 1, 0, 1} },
	{INSTRUCTION_SIZE_16_BIT, "^w\\[(p[0-5]|fp|sp)\\+(0x[0-9,a-f]+|[0-9]+)\\]=(r[0-7])\\(16\\)$", 0x0000b400, 3, {{1, &get_preg, 3}, {2, &get_uimm5m2, 6}, {3, &get_dreg, 0}}, {0, 1, 0, 1} },
	{INSTRUCTION_SIZE_32_BIT, "^w\\[(p[0-5]|fp|sp)\\+(0x[0-9,a-f]+|[0-9]+)\\]=(r[0-7])$", 0xe6400000, 3, {{1, &get_preg, 19}, {2, &get_uimm16m2, 0}, {3, &get_dreg, 16}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^w\\[(p[0-5]|fp|sp)(\\-0x[0-9,a-f]+|\\-[0-9]+)\\]=(r[0-7])$", 0xe6400000, 3, {{1, &get_preg, 19}, {2, &get_imm16m2, 0}, {3, &get_dreg, 16}}, {0, 0, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^b\\[(p[0-5]|fp|sp)\\]=(r[0-7])$", 0x00009b00, 2, {{1, &get_preg, 3}, {2, &get_dreg, 0}}, {0, 1, 0, 1} },
	{INSTRUCTION_SIZE_16_BIT, "^b\\[(p[0-5]|fp|sp)\\+\\+\\]=(r[0-7])$", 0x00009a00, 2, {{1, &get_preg, 3}, {2, &get_dreg, 0}}, {0, 1, 0, 1} },
	{INSTRUCTION_SIZE_16_BIT, "^b\\[(p[0-5]|fp|sp)\\-\\-\\]=(r[0-7])$", 0x00009a80, 2, {{1, &get_preg, 3}, {2, &get_dreg, 0}}, {0, 1, 0, 1} },
	{INSTRUCTION_SIZE_32_BIT, "^b\\[(p[0-5]|fp|sp)\\+(0x[0-9,a-f]+|[0-9]+)\\]=(r[0-7])$", 0xe6800000, 3, {{1, &get_preg, 19}, {2, &get_imm16, 0}, {3, &get_dreg, 16}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^b\\[(p[0-5]|fp|sp)(\\-0x[0-9,a-f]+|\\-[0-9]+)\\]=(r[0-7])$", 0xe6800000, 3, {{1, &get_preg, 19}, {2, &get_imm16, 0}, {3, &get_dreg, 16}}, {0, 0, 0, 0} },

	// Move instructions:
	// genreg: (r[0-7]|p[0-5]|fp|sp|a[0-1]\\.x|a[0-1]\\.w)
	// dagreg: (i[0-3]|b[0-3]|m[0-3]|l[0-3])
	// sysreg: (astat|seqstat|syscfg|reti|retx|retn|rete|rets|lc[0-1]|lt[0-1]|lb[0-1]|cycles|cycles2|emudat)
	// genreg = genreg
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7]|p[0-5]|fp|sp|a[0-1]\\.x|a[0-1]\\.w)=(r[0-7]|p[0-5]|fp|sp|a[0-1]\\.x|a[0-1]\\.w)$", 0x00003000, 4, {{1, &get_reg_group, 9}, {1, &get_reg_number, 3}, {2, &get_reg_group, 6}, {2, &get_reg_number, 0}}, {0, 0, 0, 0} },
	// genreg = dareg
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7]|p[0-5]|fp|sp|a[0-1]\\.x|a[0-1]\\.w)=(i[0-3]|b[0-3]|m[0-3]|l[0-3])$", 0x00003000, 4, {{1, &get_reg_group, 9}, {1, &get_reg_number, 3}, {2, &get_reg_group, 6}, {2, &get_reg_number, 0}}, {0, 0, 0, 0} },
	// dareg = genreg
	{INSTRUCTION_SIZE_16_BIT, "^(i[0-3]|b[0-3]|m[0-3]|l[0-3])=(r[0-7]|p[0-5]|fp|sp|a[0-1]\\.x|a[0-1]\\.w)$", 0x00003000, 4, {{1, &get_reg_group, 9}, {1, &get_reg_number, 3}, {2, &get_reg_group, 6}, {2, &get_reg_number, 0}}, {0, 0, 0, 0} },
	// dareg = dareg
	{INSTRUCTION_SIZE_16_BIT, "^(i[0-3]|b[0-3]|m[0-3]|l[0-3])=(i[0-3]|b[0-3]|m[0-3]|l[0-3])$", 0x00003000, 4, {{1, &get_reg_group, 9}, {1, &get_reg_number, 3}, {2, &get_reg_group, 6}, {2, &get_reg_number, 0}}, {0, 0, 0, 0} },
	// genreg = usp
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7]|p[0-5]|fp|sp|a[0-1]\\.x|a[0-1]\\.w)=(usp)$", 0x00003000, 4, {{1, &get_reg_group, 9}, {1, &get_reg_number, 3}, {2, &get_reg_group, 6}, {2, &get_reg_number, 0}}, {0, 0, 0, 0} },
	// usp = genreg
	{INSTRUCTION_SIZE_16_BIT, "^(usp)=(r[0-7]|p[0-5]|fp|sp|a[0-1]\\.x|a[0-1]\\.w)$", 0x00003000, 4, {{1, &get_reg_group, 9}, {1, &get_reg_number, 3}, {2, &get_reg_group, 6}, {2, &get_reg_number, 0}}, {0, 0, 0, 0} },
	// dreg = sysreg
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=(astat|seqstat|syscfg|reti|retx|retn|rete|rets|lc[0-1]|lt[0-1]|lb[0-1]|cycles|cycles2|emudat)$", 0x00003000, 4, {{1, &get_reg_group, 9}, {1, &get_reg_number, 3}, {2, &get_reg_group, 6}, {2, &get_reg_number, 0}}, {0, 0, 0, 0} },
	// sysreg = dreg
	{INSTRUCTION_SIZE_16_BIT, "^(astat|seqstat|syscfg|reti|retx|retn|rete|rets|lc[0-1]|lt[0-1]|lb[0-1]|cycles|cycles2|emudat)=(r[0-7])$", 0x00003000, 4, {{1, &get_reg_group, 9}, {1, &get_reg_number, 3}, {2, &get_reg_group, 6}, {2, &get_reg_number, 0}}, {0, 0, 0, 0} },
	// sysreg = preg
	{INSTRUCTION_SIZE_16_BIT, "^(astat|seqstat|syscfg|reti|retx|retn|rete|rets|lc[0-1]|lt[0-1]|lb[0-1]|cycles|cycles2|emudat)=(p[0-5]|fp|sp)$", 0x00003000, 4, {{1, &get_reg_group, 9}, {1, &get_reg_number, 3}, {2, &get_reg_group, 6}, {2, &get_reg_number, 0}}, {0, 0, 0, 0} },
	// sysreg = usp
	{INSTRUCTION_SIZE_16_BIT, "^(astat|seqstat|syscfg|reti|retx|retn|rete|rets|lc[0-1]|lt[0-1]|lb[0-1]|cycles|cycles2|emudat)=(usp)$", 0x00003000, 4, {{1, &get_reg_group, 9}, {1, &get_reg_number, 3}, {2, &get_reg_group, 6}, {2, &get_reg_number, 0}}, {0, 0, 0, 0} },


	{INSTRUCTION_SIZE_32_BIT, "^a0=a1$", 0xc408c000, 0, {}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1=a0$", 0xc408e000, 0, {}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a0=(r[0-7])$", 0xc4092000, 1, {{1, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1=(r[0-7])$", 0xc409a000, 1, {{1, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r(0|2|4|6))=a0$", 0xc00b3800, 1, {{1, &get_dreg_even, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r(0|2|4|6))=a0\\(fu\\)$", 0xc08b3800, 1, {{1, &get_dreg_even, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r(0|2|4|6))=a0\\(iss2\\)$", 0xc12b3800, 1, {{1, &get_dreg_even, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r(1|3|5|7))=a1$", 0xc00f1800, 1, {{1, &get_dreg_even, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r(1|3|5|7))=a1\\(fu\\)$", 0xc08f1800, 1, {{1, &get_dreg_even, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r(1|3|5|7))=a1\\(iss2\\)$", 0xc12f1800, 1, {{1, &get_dreg_even, 6}}, {1, 0, 0, 0} },

	// Note: only the first destination dreg of the pairing is used; the other is determined implicitly, with no error or warning.
	{INSTRUCTION_SIZE_32_BIT, "^(r(0|2|4|6))=a0\\,(r(1|3|5|7))=a1$", 0xc00f3800, 1, {{1, &get_dreg_even, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r(1|3|5|7))=a1\\,(r(0|2|4|6))=a0$", 0xc00f3800, 1, {{1, &get_dreg_even, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r(0|2|4|6))=a0\\,(r(1|3|5|7))=a1\\(fu\\)$", 0xc08f3800, 1, {{1, &get_dreg_even, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r(1|3|5|7))=a1\\,(r(0|2|4|6))=a0\\(fu\\)$", 0xc08f3800, 1, {{1, &get_dreg_even, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r(0|2|4|6))=a0\\,(r(1|3|5|7))=a1\\(iss2\\)$", 0xc12f3800, 1, {{1, &get_dreg_even, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r(1|3|5|7))=a1\\,(r(0|2|4|6))=a0\\(iss2\\)$", 0xc12f3800, 1, {{1, &get_dreg_even, 6}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^ifcc(r[0-7])=(r[0-7])$", 0x00000700, 2, {{1, &get_dreg, 3}, {2, &get_dreg, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^ifcc(r[0-7])=(p[0-5]|fp|sp)$", 0x00000740, 2, {{1, &get_dreg, 3}, {2, &get_preg, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^ifcc(p[0-5]|fp|sp)=(r[0-7])$", 0x00000780, 2, {{1, &get_preg, 3}, {2, &get_dreg, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^ifcc(p[0-5]|fp|sp)=(p[0-5]|fp|sp)$", 0x000007c0, 2, {{1, &get_preg, 3}, {2, &get_preg, 0}}, {0, 0, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^if\\!cc(r[0-7])=(r[0-7])$", 0x00000600, 2, {{1, &get_dreg, 3}, {2, &get_dreg, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^if\\!cc(r[0-7])=(p[0-5]|fp|sp)$", 0x00000640, 2, {{1, &get_dreg, 3}, {2, &get_preg, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^if\\!cc(p[0-5]|fp|sp)=(r[0-7])$", 0x00000680, 2, {{1, &get_preg, 3}, {2, &get_dreg, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^if\\!cc(p[0-5]|fp|sp)=(p[0-5]|fp|sp)$", 0x000006c0, 2, {{1, &get_preg, 3}, {2, &get_preg, 0}}, {0, 0, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=(r[0-7])\\.l\\(z\\)$", 0x000042c0, 2, {{1, &get_dreg, 0}, {2, &get_dreg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=(r[0-7])\\.l\\(x\\)$", 0x00004280, 2, {{1, &get_dreg, 0}, {2, &get_dreg, 3}}, {0, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^a0\\.x=(r[0-7])\\.l$", 0xc4094000, 1, {{1, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1\\.x=(r[0-7])\\.l$", 0xc409c000, 1, {{1, &get_dreg, 3}}, {1, 0, 0, 0} }, 
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=a0\\.x$", 0xc40a0000, 1, {{1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=a1\\.x$", 0xc40a4000, 1, {{1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a0\\.l=(r[0-7])\\.l$", 0xc4090000, 1, {{1, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1\\.l=(r[0-7])\\.l$", 0xc4098000, 1, {{1, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a0\\.h=(r[0-7])\\.h$", 0xc4290000, 1, {{1, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1\\.h=(r[0-7])\\.h$", 0xc4298000, 1, {{1, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=a0$", 0xc0033800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=a0\\(fu\\)$", 0xc0833800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=a0\\(is\\)$", 0xc1033800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=a0\\(iu\\)$", 0xc1833800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=a0\\(t\\)$", 0xc0433800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=a0\\(s2rnd\\)$", 0xc0233800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=a0\\(iss2\\)$", 0xc1233800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=a0\\(ih\\)$", 0xc1633800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=a1$", 0xc0071800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=a1\\(is\\)$", 0xc1071800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=a1\\(fu\\)$", 0xc0871800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=a1\\(iu\\)$", 0xc1871800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=a1\\(t\\)$", 0xc0471800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=a1\\(s2rnd\\)$", 0xc0271800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=a1\\(iss2\\)$", 0xc1271800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=a1\\(ih\\)$", 0xc1671800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=a0\\,(r[0-7])\\.h=a1$", 0xc0073800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=a1\\,(r[0-7])\\.l=a0$", 0xc0073800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=a0\\,(r[0-7])\\.h=a1\\(fu\\)$", 0xc0873800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=a1\\,(r[0-7])\\.l=a0\\(fu\\)$", 0xc0873800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=a0\\,(r[0-7])\\.h=a1\\(is\\)$", 0xc1073800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=a1\\,(r[0-7])\\.l=a0\\(is\\)$", 0xc1073800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=a0\\,(r[0-7])\\.h=a1\\(iu\\)$", 0xc1873800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=a1\\,(r[0-7])\\.l=a0\\(iu\\)$", 0xc1873800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=a0\\,(r[0-7])\\.h=a1\\(t\\)$", 0xc0473800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=a1\\,(r[0-7])\\.l=a0\\(t\\)$", 0xc0473800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=a0\\,(r[0-7])\\.h=a1\\(s2rnd\\)$", 0xc0273800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=a1\\,(r[0-7])\\.l=a0\\(s2rnd\\)$", 0xc0273800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=a0\\,(r[0-7])\\.h=a1\\(iss2\\)$", 0xc1273800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=a1\\,(r[0-7])\\.l=a0\\(iss2\\)$", 0xc1273800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=a0\\,(r[0-7])\\.h=a1\\(ih\\)$", 0xc1673800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=a1\\,(r[0-7])\\.l=a0\\(ih\\)$", 0xc1673800, 1, {{1, &get_dreg, 6}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=(r[0-7])\\.b\\(z\\)$", 0x00004340, 2, {{1, &get_dreg, 0}, {2, &get_dreg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=(r[0-7])\\.b\\(x\\)$", 0x00004300, 2, {{1, &get_dreg, 0}, {2, &get_dreg, 3}}, {0, 0, 0, 0} },


	// Stack control:

	{INSTRUCTION_SIZE_16_BIT, "^\\[?\\-\\-sp\\]=(r[0-7]|p[0-5]|fp|sp|i[0-3]|m[0-3]|b[0-3]|l[0-3]|a[0-1]\\.x|a[0-1]\\.w|astat|rets|lc[0-1]|lt[0-1]|lb[0-1]|cycles2?|usp|seqstat|syscfg|reti|retx|retn|rete|emudat)$", 0x00000140, 1, {{1, &get_reg, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^\\[?\\-\\-sp\\]=\\(r7\\:([0-7])\\,p5:([0-5])\\)$", 0x000005c0, 2, {{1, &get_dreg_num, 3}, {2, &get_preg_num, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^\\[?\\-\\-sp\\]=\\(r7\\:([0-7])\\)$", 0x00000540, 1, {{1, &get_dreg_num, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^\\[?\\-\\-sp\\]=\\(p5:([0-5])\\)$", 0x000004c0, 1, {{1, &get_preg_num, 0}}, {0, 0, 0, 0} },

	// This will encode pop of any register except for preg and dreg, as per the programming reference manual (p. C-38). 
	// Instructions such as r7 = [sp++] or p5 = [sp++] are handled in the load instructions.
	{INSTRUCTION_SIZE_16_BIT, "^(i[0-3]|m[0-3]|b[0-3]|l[0-3]|a[0-1]\\.x|a[0-1]\\.w|astat|rets|lc[0-1]|lt[0-1]|lb[0-1]|cycles2?|usp|seqstat|syscfg|reti|retx|retn|rete|emudat)=\\[sp\\+\\+\\]$", 0x00000100, 1, {{1, &get_reg, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^\\(?r7\\:([0-7])\\,p5:([0-5])\\)=\\[sp\\+\\+\\]$", 0x00000580, 2, {{1, &get_dreg_num, 3}, {2, &get_preg_num, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^\\(?r7\\:([0-7])\\)=\\[sp\\+\\+\\]$", 0x00000500, 1, {{1, &get_dreg_num, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^\\(?p5:([0-5])\\)=\\[sp\\+\\+\\]$", 0x00000480, 1, {{1, &get_preg_num, 0}}, {0, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^link(0x[0-9,a-f]+|[0-9]+)$", 0xe8000000, 1, {{1, &get_uimm18m4, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^unlink$", 0xe8010000, 0, {}, {0, 0, 0, 0} },
	

	// Control code bit management:

	{INSTRUCTION_SIZE_16_BIT, "^cc=(r[0-7])==(r[0-7])$", 0x00000800, 2, {{1, &get_dreg, 0}, {2, &get_dreg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^cc=(r[0-7])==(\\-?0x[0-9,a-f]+|\\-?[0-9]+)$", 0x00000c00, 2, {{1, &get_dreg, 0}, {2, &get_imm3, 3}}, {0, 0, 0, 0} },
	
	{INSTRUCTION_SIZE_16_BIT, "^cc=(r[0-7])<(r[0-7])$", 0x00000880, 2, {{1, &get_dreg, 0}, {2, &get_dreg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^cc=(r[0-7])<(\\-?0x[0-9,a-f]+|\\-?[0-9]+)$", 0x00000c80, 2, {{1, &get_dreg, 0}, {2, &get_imm3, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^cc=(r[0-7])<=(r[0-7])$", 0x00000900, 2, {{1, &get_dreg, 0}, {2, &get_dreg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^cc=(r[0-7])<=(\\-?0x[0-9,a-f]+|\\-?[0-9]+)$", 0x00000d00, 2, {{1, &get_dreg, 0}, {2, &get_imm3, 3}}, {0, 0, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^cc=(r[0-7])<(r[0-7])\\(iu\\)$", 0x00000980, 2, {{1, &get_dreg, 0}, {2, &get_dreg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^cc=(r[0-7])<(0x[0-9,a-f]+|[0-9]+)\\(iu\\)$", 0x00000d80, 2, {{1, &get_dreg, 0}, {2, &get_uimm3, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^cc=(r[0-7])<=(r[0-7])\\(iu\\)$", 0x00000a00, 2, {{1, &get_dreg, 0}, {2, &get_dreg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^cc=(r[0-7])<=(0x[0-9,a-f]+|[0-9]+)\\(iu\\)$", 0x00000e00, 2, {{1, &get_dreg, 0}, {2, &get_uimm3, 3}}, {0, 0, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^cc=(p[0-5]|fp|sp)==(p[0-5]|fp|sp)$", 0x00000840, 2, {{1, &get_preg, 0}, {2, &get_preg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^cc=(p[0-5]|fp|sp)==(\\-?0x[0-9,a-f]+|\\-?[0-9]+)$", 0x00000c40, 2, {{1, &get_preg, 0}, {2, &get_imm3, 3}}, {0, 0, 0, 0} },
	
	{INSTRUCTION_SIZE_16_BIT, "^cc=(p[0-5]|fp|sp)<(p[0-5]|fp|sp)$", 0x000008c0, 2, {{1, &get_preg, 0}, {2, &get_preg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^cc=(p[0-5]|fp|sp)<(\\-?0x[0-9,a-f]+|\\-?[0-9]+)$", 0x00000cc0, 2, {{1, &get_preg, 0}, {2, &get_imm3, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^cc=(p[0-5]|fp|sp)<=(p[0-5]|fp|sp)$", 0x00000940, 2, {{1, &get_preg, 0}, {2, &get_preg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^cc=(p[0-5]|fp|sp)<=(\\-?0x[0-9,a-f]+|\\-?[0-9]+)$", 0x00000d40, 2, {{1, &get_preg, 0}, {2, &get_imm3, 3}}, {0, 0, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^cc=(p[0-5]|fp|sp)<(p[0-5]|fp|sp)\\(iu\\)$", 0x000009c0, 2, {{1, &get_preg, 0}, {2, &get_preg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^cc=(p[0-5]|fp|sp)<(0x[0-9,a-f]+|[0-9]+)\\(iu\\)$", 0x00000dc0, 2, {{1, &get_preg, 0}, {2, &get_uimm3, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^cc=(p[0-5]|fp|sp)<=(p[0-5]|fp|sp)\\(iu\\)$", 0x00000a40, 2, {{1, &get_preg, 0}, {2, &get_preg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^cc=(p[0-5]|fp|sp)<=(0x[0-9,a-f]+|[0-9]+)\\(iu\\)$", 0x00000e40, 2, {{1, &get_preg, 0}, {2, &get_uimm3, 3}}, {0, 0, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^cc=a0==a1$", 0x00000a80, 0, {}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^cc=a0<a1$", 0x00000b00, 0, {}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^cc=a0<=a1$", 0x00000b80, 0, {}, {0, 0, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=cc$", 0x00000200, 1, {{1, &get_dreg, 0}}, {0, 0, 0, 0} },
	// astat flag bits can be addressed as astat[0] etc, or by name. 
	{INSTRUCTION_SIZE_16_BIT, "^astat\\[(0x[0-9,a-f]+|[0-9]+)\\]=cc$", 0x00000380, 1, {{1, &get_astatbitnum, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(az|an|ac0_copy|v_copy|cc|aq|rnd_mod|ac0|ac1|av0|av0s|av1|av1s|v|vs)=cc$", 0x00000380, 1, {{1, &get_astatbitname, 0}}, {0, 0, 0, 0} },
	// Note: need to use \| instead of | when assembling from radare2 prompt
	{INSTRUCTION_SIZE_16_BIT, "^astat\\[(0x[0-9,a-f]+|[0-9]+)\\]\\\\?\\|=cc$", 0x000003a0, 1, {{1, &get_astatbitnum, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(az|an|ac0_copy|v_copy|cc|aq|rnd_mod|ac0|ac1|av0|av0s|av1|av1s|v|vs)\\\\?\\|=cc$", 0x000003a0, 1, {{1, &get_astatbitname, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^astat\\[(0x[0-9,a-f]+|[0-9]+)\\]\\&=cc$", 0x000003c0, 1, {{1, &get_astatbitnum, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(az|an|ac0_copy|v_copy|cc|aq|rnd_mod|ac0|ac1|av0|av0s|av1|av1s|v|vs)\\&=cc$", 0x000003c0, 1, {{1, &get_astatbitname, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^astat\\[(0x[0-9,a-f]+|[0-9]+)\\]\\^=cc$", 0x000003e0, 1, {{1, &get_astatbitnum, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(az|an|ac0_copy|v_copy|cc|aq|rnd_mod|ac0|ac1|av0|av0s|av1|av1s|v|vs)\\^=cc$", 0x000003e0, 1, {{1, &get_astatbitname, 0}}, {0, 0, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^cc=(r[0-7])$", 0x00000208, 1, {{1, &get_dreg, 0}}, {0, 0, 0, 0} },
	// astat flag bits can be addressed as astat[0] etc, or by name. 
	{INSTRUCTION_SIZE_16_BIT, "^cc=astat\\[(0x[0-9,a-f]+|[0-9]+)\\]$", 0x00000300, 1, {{1, &get_astatbitnum, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^cc=(az|an|ac0_copy|v_copy|cc|aq|rnd_mod|ac0|ac1|av0|av0s|av1|av1s|v|vs)$", 0x00000300, 1, {{1, &get_astatbitname, 0}}, {0, 0, 0, 0} },
	// Note: need to use \| instead of | when assembling from radare2 prompt
	{INSTRUCTION_SIZE_16_BIT, "^cc\\\\?\\|=astat\\[(0x[0-9,a-f]+|[0-9]+)\\]$", 0x00000320, 1, {{1, &get_astatbitnum, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^cc\\\\?\\|=(az|an|ac0_copy|v_copy|cc|aq|rnd_mod|ac0|ac1|av0|av0s|av1|av1s|v|vs)$", 0x00000320, 1, {{1, &get_astatbitname, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^cc\\&=astat\\[(0x[0-9,a-f]+|[0-9]+)\\]$", 0x00000340, 1, {{1, &get_astatbitnum, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^cc\\&=(az|an|ac0_copy|v_copy|cc|aq|rnd_mod|ac0|ac1|av0|av0s|av1|av1s|v|vs)$", 0x00000340, 1, {{1, &get_astatbitname, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^cc\\^=astat\\[(0x[0-9,a-f]+|[0-9]+)\\]$", 0x00000360, 1, {{1, &get_astatbitnum, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^cc\\^=(az|an|ac0_copy|v_copy|cc|aq|rnd_mod|ac0|ac1|av0|av0s|av1|av1s|v|vs)$", 0x00000360, 1, {{1, &get_astatbitname, 0}}, {0, 0, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^cc=\\!cc$", 0x00000218, 0, {}, {0, 0, 0, 0} },


	// Logical operations:
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=(r[0-7])\\&(r[0-7])$", 0x00005400, 3, {{1, &get_dreg, 6}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {0, 0, 0, 0} },
	// Note: need to escape ~ when assembling in radare2, e.g. r7=\~r6
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=\\~(r[0-7])$", 0x000043c0, 2, {{1, &get_dreg, 0}, {2, &get_dreg, 3}}, {0, 0, 0, 0} },
	// Note: need to escape | when assembling in radare2, e.g. r7 = r6 \| r4
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=(r[0-7])\\\\?\\|(r[0-7])$", 0x00005600, 3, {{1, &get_dreg, 6}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=(r[0-7])\\^(r[0-7])$", 0x00005800, 3, {{1, &get_dreg, 6}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {0, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=cc=bxorshift\\(a0,(r[0-7])\\)$", 0xc60b0000, 2, {{1, &get_dreg, 9}, {2, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=cc=bxor\\(a0,(r[0-7])\\)$", 0xc60b4000, 2, {{1, &get_dreg, 9}, {2, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=cc=bxor\\(a0,a1,cc\\)$", 0xc60c4000, 1, {{1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a0=bxorshift\\(a0,a1,cc\\)$", 0xc60c0000, 0, {}, {1, 0, 0, 0} },

	// Bit operations:
	{INSTRUCTION_SIZE_16_BIT, "^bitclr\\((r[0-7]),(0x[0-9,a-f]+|[0-9]+)\\)$", 0x00004c00, 2, {{1, &get_dreg, 0}, {2, &get_uimm5, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^bitset\\((r[0-7]),(0x[0-9,a-f]+|[0-9]+)\\)$", 0x00004a00, 2, {{1, &get_dreg, 0}, {2, &get_uimm5, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^bittgl\\((r[0-7]),(0x[0-9,a-f]+|[0-9]+)\\)$", 0x00004b00, 2, {{1, &get_dreg, 0}, {2, &get_uimm5, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^cc=bittst\\((r[0-7]),(0x[0-9,a-f]+|[0-9]+)\\)$", 0x00004900, 2, {{1, &get_dreg, 0}, {2, &get_uimm5, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^cc=\\!bittst\\((r[0-7]),(0x[0-9,a-f]+|[0-9]+)\\)$", 0x00004800, 2, {{1, &get_dreg, 0}, {2, &get_uimm5, 3}}, {0, 0, 0, 0} },
	
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=deposit\\((r[0-7]),(r[0-7])\\)$", 0xc60a8000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=deposit\\((r[0-7]),(r[0-7])\\)\\(x\\)$", 0xc60ac000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=extract\\((r[0-7]),(r[0-7])\\.l\\)\\(z\\)$", 0xc60a0000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=extract\\((r[0-7]),(r[0-7])\\.l\\)\\(x\\)$", 0xc60a4000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^bitmux\\((r[0-7]),(r[0-7]),a0\\)\\(asr\\)$", 0xc6080000, 2, {{1, &get_dreg, 3}, {2, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^bitmux\\((r[0-7]),(r[0-7]),a0\\)\\(asl\\)$", 0xc6084000, 2, {{1, &get_dreg, 3}, {2, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=ones(r[0-7])$", 0xc606c000, 2, {{1, &get_dreg, 9}, {2, &get_dreg, 0}}, {1, 0, 0, 0} },

	// Shift / rotate operations:
	{INSTRUCTION_SIZE_16_BIT, "^(p[0-5]|fp|sp)=\\((p[0-5]|fp|sp)\\+(p[0-5]|fp|sp)\\)<<1$", 0x00004580, 2, {{1, &get_preg, 0}, {3, &get_preg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(p[0-5]|fp|sp)=\\((p[0-5]|fp|sp)\\+(p[0-5]|fp|sp)\\)<<2$", 0x000045c0, 2, {{1, &get_preg, 0}, {3, &get_preg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=\\((r[0-7])\\+(r[0-7])\\)<<1$", 0x00004100, 2, {{1, &get_dreg, 0}, {3, &get_dreg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=\\((r[0-7])\\+(r[0-7])\\)<<2$", 0x00004140, 2, {{1, &get_dreg, 0}, {3, &get_dreg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(p[0-5]|fp|sp)=(p[0-5]|fp|sp)\\+\\((p[0-5]|fp|sp)<<1\\)$", 0x00005c00, 3, {{1, &get_preg, 6}, {2, &get_preg, 0}, {3, &get_preg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(p[0-5]|fp|sp)=(p[0-5]|fp|sp)\\+\\((p[0-5]|fp|sp)<<2\\)$", 0x00005e00, 3, {{1, &get_preg, 6}, {2, &get_preg, 0}, {3, &get_preg, 3}}, {0, 0, 0, 0} },
	
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])>>>=(0x[0-9,a-f]+|[0-9]+)$", 0x00004d00, 2, {{1, &get_dreg, 0}, {2, &get_uimm5, 3}}, {0, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\.l>>>(0x[0-9,a-f]+|[0-9]+)$", 0xc6800180, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_twos_comp_uimm4, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\.h>>>(0x[0-9,a-f]+|[0-9]+)$", 0xc6801180, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_twos_comp_uimm4, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\.l>>>(0x[0-9,a-f]+|[0-9]+)$", 0xc6802180, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_twos_comp_uimm4, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\.h>>>(0x[0-9,a-f]+|[0-9]+)$", 0xc6803180, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_twos_comp_uimm4, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\.l<<(0x[0-9,a-f]+|[0-9]+)\\(s\\)$", 0xc6804000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_uimm4, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\.h<<(0x[0-9,a-f]+|[0-9]+)\\(s\\)$", 0xc6805000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_uimm4, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\.l<<(0x[0-9,a-f]+|[0-9]+)\\(s\\)$", 0xc6806000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_uimm4, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\.h<<(0x[0-9,a-f]+|[0-9]+)\\(s\\)$", 0xc6807000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_uimm4, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])>>>(0x[0-9,a-f]+|[0-9]+)$", 0xc6820100, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_twos_comp_uimm5, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])<<(0x[0-9,a-f]+|[0-9]+)\\(s\\)$", 0xc6824000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_uimm5, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^a0=a0>>>(0x[0-9,a-f]+|[0-9]+)$", 0xc6830100, 1, {{1, &get_twos_comp_uimm5, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1=a1>>>(0x[0-9,a-f]+|[0-9]+)$", 0xc6831100, 1, {{1, &get_twos_comp_uimm5, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])>>>=(r[0-7])$", 0x00004000, 2, {{1, &get_dreg, 0}, {2, &get_dreg, 3}}, {0, 0, 0, 0} },

	// The order of the dreg operands is made consistent with both the disassembler and with the Analog Devices Cross Core Embedded Studio,
	// however this is inconsistent with the programmer's manual p. C-49. 
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=ashift(r[0-7])\\.lby(r[0-7])\\.l$", 0xc6000000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=ashift(r[0-7])\\.hby(r[0-7])\\.l$", 0xc6001000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=ashift(r[0-7])\\.lby(r[0-7])\\.l$", 0xc6002000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=ashift(r[0-7])\\.hby(r[0-7])\\.l$", 0xc6003000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=ashift(r[0-7])\\.lby(r[0-7])\\.l\\(s\\)$", 0xc6004000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=ashift(r[0-7])\\.hby(r[0-7])\\.l\\(s\\)$", 0xc6005000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=ashift(r[0-7])\\.lby(r[0-7])\\.l\\(s\\)$", 0xc6006000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=ashift(r[0-7])\\.hby(r[0-7])\\.l\\(s\\)$", 0xc6007000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=ashift(r[0-7])by(r[0-7])\\.l$", 0xc6020000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=ashift(r[0-7])by(r[0-7])\\.l\\(s\\)$", 0xc6024000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^a0=ashifta0by(r[0-7])\\.l$", 0xc6030000, 1, {{1, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1=ashifta1by(r[0-7])\\.l$", 0xc6031000, 1, {{1, &get_dreg, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^(p[0-5]|fp|sp)=(p[0-5]|fp|sp)>>1$", 0x00004500, 2, {{1, &get_preg, 0}, {2, &get_preg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(p[0-5]|fp|sp)=(p[0-5]|fp|sp)>>2$", 0x000044c0, 2, {{1, &get_preg, 0}, {2, &get_preg, 3}}, {0, 0, 0, 0} },

	// The arrangement of the preg operands is consistent with the disassembler and with the Analog Devices Cross Core Embedded Studio,
	// however this is inconsistent with the programmer's manual p. C-51.
	{INSTRUCTION_SIZE_16_BIT, "^(p[0-5]|fp|sp)=(p[0-5]|fp|sp)<<1$", 0x00005a00, 3, {{2, &get_preg, 0}, {2, &get_preg, 3}, {1, &get_preg, 6}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(p[0-5]|fp|sp)=(p[0-5]|fp|sp)<<2$", 0x00004440, 2, {{1, &get_preg, 0}, {2, &get_preg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])>>=(0x[0-9,a-f]+|[0-9]+)$", 0x00004e00, 2, {{1, &get_dreg, 0}, {2, &get_uimm5, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])<<=(0x[0-9,a-f]+|[0-9]+)$", 0x00004f00, 2, {{1, &get_dreg, 0}, {2, &get_uimm5, 3}}, {0, 0, 0, 0} },
	// Note: This and the disassembler will translate in the range 0x01 to 0x10, but Cross Core Embedded Studio uses 0x00 to 0x0f; probably not important.
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\.l>>(0x[0-9,a-f]+|[0-9]+)$", 0xc6808180, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_twos_comp_uimm4, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\.h>>(0x[0-9,a-f]+|[0-9]+)$", 0xc6809180, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_twos_comp_uimm4, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\.l>>(0x[0-9,a-f]+|[0-9]+)$", 0xc680a180, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_twos_comp_uimm4, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\.h>>(0x[0-9,a-f]+|[0-9]+)$", 0xc680b180, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_twos_comp_uimm4, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\.l<<(0x[0-9,a-f]+|[0-9]+)$", 0xc6808000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_uimm4, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\.h<<(0x[0-9,a-f]+|[0-9]+)$", 0xc6809000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_uimm4, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\.l<<(0x[0-9,a-f]+|[0-9]+)$", 0xc680a000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_uimm4, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\.h<<(0x[0-9,a-f]+|[0-9]+)$", 0xc680b000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_uimm4, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])>>(0x[0-9,a-f]+|[0-9]+)$", 0xc6828100, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_twos_comp_uimm5, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])<<(0x[0-9,a-f]+|[0-9]+)$", 0xc6828000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_uimm5, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^a0=a0>>(0x[0-9,a-f]+|[0-9]+)$", 0xc6834100, 1, {{1, &get_twos_comp_uimm5, 3}}, {1, 0, 0, 0} },
	// The opcode below agrees with the disassembler and the Cross Core Embedded Studio, but disagrees with the programmer's manual.
	{INSTRUCTION_SIZE_32_BIT, "^a0=a0<<(0x[0-9,a-f]+|[0-9]+)$", 0xc6830000, 1, {{1, &get_uimm5, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1=a1>>(0x[0-9,a-f]+|[0-9]+)$", 0xc6835100, 1, {{1, &get_twos_comp_uimm5, 3}}, {1, 0, 0, 0} },
	// The opcode below agrees with the disassembler and the Cross Core Embedded Studio, but disagrees with the programmer's manual.
	{INSTRUCTION_SIZE_32_BIT, "^a1=a1<<(0x[0-9,a-f]+|[0-9]+)$", 0xc6831000, 1, {{1, &get_uimm5, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])<<=(r[0-7])$", 0x00004080, 2, {{1, &get_dreg, 0}, {2, &get_dreg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])>>=(r[0-7])$", 0x00004040, 2, {{1, &get_dreg, 0}, {2, &get_dreg, 3}}, {0, 0, 0, 0} },

	// The opcode below agrees with the disassembler and the Cross Core Embedded Studio, but disagrees with the programmer's manual.
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=lshift(r[0-7])\\.lby(r[0-7])\\.l$", 0xc6008000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=lshift(r[0-7])\\.hby(r[0-7])\\.l$", 0xc6009000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=lshift(r[0-7])\\.lby(r[0-7])\\.l$", 0xc600a000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=lshift(r[0-7])\\.hby(r[0-7])\\.l$", 0xc600b000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=lshift(r[0-7])by(r[0-7])\\.l$", 0xc6028000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a0=lshifta0by(r[0-7])\\.l$", 0xc6034000, 1, { {1, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1=lshifta1by(r[0-7])\\.l$", 0xc6035000, 1, { {1, &get_dreg, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=rot(r[0-7])by(\\-?0x[0-9,a-f]+|\\-?[0-9]+)$", 0xc682c000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_imm6, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a0=rota0by(\\-?0x[0-9,a-f]+|\\-?[0-9]+)$", 0xc6838000, 1, {{1, &get_imm6, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1=rota1by(\\-?0x[0-9,a-f]+|\\-?[0-9]+)$", 0xc6839000, 1, {{1, &get_imm6, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=rot(r[0-7])by(r[0-7])\\.l$", 0xc602c000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a0=rota0by(r[0-7])\\.l$", 0xc6038000, 1, { {1, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1=rota1by(r[0-7])\\.l$", 0xc6039000, 1, { {1, &get_dreg, 3}}, {1, 0, 0, 0} },

	// Arithmetic operations:
	{INSTRUCTION_SIZE_32_BIT, "^a0=absa1$", 0xC410403F, 0, {}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1=absa0$", 0xC430003F, 0, {}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1=absa1$", 0xC430403F, 0, {}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1=absa1,a0=absa0$", 0xC410C03F, 0, {}, {1, 0, 0, 0} },
	
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=abs(r[0-7])$", 0xC4078000, 2, {{1, &get_dreg, 9}, {2, &get_dreg, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^(p[0-5]|fp|sp)=(p[0-5]|fp|sp)\\+(p[0-5]|fp|sp)$", 0x00005a00, 3, {{3, &get_preg, 3}, {2, &get_preg, 0}, {1, &get_preg, 6}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=(r[0-7])\\+(r[0-7])$", 0x00005000, 3, {{3, &get_dreg, 3}, {2, &get_dreg, 0}, {1, &get_dreg, 6}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+(r[0-7])\\(ns\\)$", 0xC4040000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+(r[0-7])\\(s\\)$", 0xC4042000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\.l\\+(r[0-7])\\.l\\(ns\\)$", 0xC4020000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\.l\\+(r[0-7])\\.h\\(ns\\)$", 0xC4024000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\.h\\+(r[0-7])\\.l\\(ns\\)$", 0xC4028000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\.h\\+(r[0-7])\\.h\\(ns\\)$", 0xC402c000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\.l\\+(r[0-7])\\.l\\(ns\\)$", 0xC4220000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\.l\\+(r[0-7])\\.h\\(ns\\)$", 0xC4224000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\.h\\+(r[0-7])\\.l\\(ns\\)$", 0xC4228000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\.h\\+(r[0-7])\\.h\\(ns\\)$", 0xC422c000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\.l\\+(r[0-7])\\.l\\(s\\)$", 0xC4022000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\.l\\+(r[0-7])\\.h\\(s\\)$", 0xC4026000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\.h\\+(r[0-7])\\.l\\(s\\)$", 0xC402a000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\.h\\+(r[0-7])\\.h\\(s\\)$", 0xC402e000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\.l\\+(r[0-7])\\.l\\(s\\)$", 0xC4222000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\.l\\+(r[0-7])\\.h\\(s\\)$", 0xC4226000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\.h\\+(r[0-7])\\.l\\(s\\)$", 0xC422a000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\.h\\+(r[0-7])\\.h\\(s\\)$", 0xC422e000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\+(r[0-7])\\(rnd20\\)$", 0xC4059000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\+(r[0-7])\\(rnd20\\)$", 0xC4259000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\-(r[0-7])\\(rnd20\\)$", 0xC405d000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\-(r[0-7])\\(rnd20\\)$", 0xC425d000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\+(r[0-7])\\(rnd12\\)$", 0xC4050000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\+(r[0-7])\\(rnd12\\)$", 0xC4250000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\-(r[0-7])\\(rnd12\\)$", 0xC4054000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\-(r[0-7])\\(rnd12\\)$", 0xC4254000, 3, {{3, &get_dreg, 0}, {2, &get_dreg, 3}, {1, &get_dreg, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])\\+=(\\-?0x[0-9,a-f]+|\\-?[0-9]+)$", 0x00006400, 2, {{1, &get_dreg, 0}, {2, get_imm7, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(p[0-5]|fp|sp)\\+=(\\-?0x[0-9,a-f]+|\\-?[0-9]+)$", 0x00006c00, 2, {{1, &get_preg, 0}, {2, get_imm7, 3}}, {0, 0, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^(i[0-3])\\+=(0x)?2$", 0x00009f60, 1, {{1, &get_ireg, 0}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(i[0-3])\\+=(0x)?4$", 0x00009f68, 1, {{1, &get_ireg, 0}}, {0, 1, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^divs\\((r[0-7]),(r[0-7])\\)$", 0x00004240, 2, {{1, &get_dreg, 0}, {2, &get_dreg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^divq\\((r[0-7]),(r[0-7])\\)$", 0x00004200, 2, {{1, &get_dreg, 0}, {2, &get_dreg, 3}}, {0, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=expadj\\((r[0-7]),(r[0-7])\\.l\\)$", 0xC6070000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=expadj\\((r[0-7])\\.l,(r[0-7])\\.l\\)$", 0xC6078000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=expadj\\((r[0-7])\\.h,(r[0-7])\\.l\\)$", 0xC607c000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=expadj\\((r[0-7]),(r[0-7])\\.l\\)\\(v\\)$", 0xC6074000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=max\\((r[0-7]),(r[0-7])\\)$", 0xC4070000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=min\\((r[0-7]),(r[0-7])\\)$", 0xC4074000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^a0\\-=a1$", 0xC40BC03F, 0, {}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a0\\-=a1\\(w32\\)$", 0xC40BE03F, 0, {}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^(p[0-5]|fp|sp)\\-=(p[0-5]|fp|sp)$", 0x00004400, 2, {{1, &get_preg, 0}, {2, get_preg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(i[0-3])\\-=(m[0-3])$", 0x00009E70, 2, {{1, &get_ireg, 0}, {2, get_mreg, 2}}, {0, 1, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^a0\\+=a1$", 0xC40B803F, 0, {}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a0\\+=a1\\(w32\\)$",0xC40BA03F, 0, {}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^(p[0-5]|fp|sp)\\+=(p[0-5]|fp|sp)\\(brev\\)$", 0x00004540, 2, {{1, &get_preg, 0}, {2, get_preg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(i[0-3])\\+=(m[0-3])$", 0x00009E60, 2, {{1, &get_ireg, 0}, {2, get_mreg, 2}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(i[0-3])\\+=(m[0-3])\\(brev\\)$", 0x00009EE0, 2, {{1, &get_ireg, 0}, {2, get_mreg, 2}}, {0, 1, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=\\(a0\\+=a1\\)$", 0xC40B003F, 1, {{1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0\\+=a1\\)$", 0xC40B403F, 1, {{1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a0\\+=a1\\)$", 0xC42B403F, 1, {{1, &get_dreg, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)$", 0xC2002000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(fu\\)$", 0xC2802000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(is\\)$", 0xC3002000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(iu\\)$", 0xC3802000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(t\\)$", 0xC2402000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(tfu\\)$", 0xC2C02000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(s2rnd\\)$", 0xC2202000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(iss2\\)$", 0xC3202000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(ih\\)$", 0xC3602000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },

	// The instructions below allow for even destination dreg only, in agreement with the Programmer's manual and Cross Core Embedded Studio, 
	// but in contrast to the disassembler. 
	{INSTRUCTION_SIZE_32_BIT, "^(r0|r2|r4|r6)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)$", 0xC2082000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r0|r2|r4|r6)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(fu\\)$", 0xC2882000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r0|r2|r4|r6)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(is\\)$", 0xC3082000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r0|r2|r4|r6)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(s2rnd\\)$", 0xC2282000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r0|r2|r4|r6)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(iss2\\)$", 0xC3282000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)$", 0xC2040000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(fu\\)$", 0xC2840000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(is\\)$", 0xC3040000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(iu\\)$", 0xC3840000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(t\\)$", 0xC2440000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(tfu\\)$", 0xC2C40000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(s2rnd\\)$", 0xC2240000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(iss2\\)$", 0xC3240000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(ih\\)$", 0xC3640000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m\\)$", 0xC2140000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m,fu\\)$", 0xC2940000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m,is\\)$", 0xC3140000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m,iu\\)$", 0xC3940000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m,t\\)$", 0xC2540000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m,tfu\\)$", 0xC2D40000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m,s2rnd\\)$", 0xC2340000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m,iss2\\)$", 0xC3340000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m,ih\\)$", 0xC3740000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },

	// The instructions below allow for odd destination dreg only, in agreement with the Programmer's manual and Cross Core Embedded Studio, 
	// but in contrast to the disassembler. 
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)$", 0xC20C0000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(fu\\)$", 0xC28C0000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(is\\)$", 0xC30C0000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(s2rnd\\)$", 0xC22C0000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(iss2\\)$", 0xC32C0000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m\\)$", 0xC21C0000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m,fu\\)$", 0xC29C0000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m,is\\)$", 0xC31C0000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	// The opcode for the following instruction is wrong in the Programmer's Manual; the opcode below is consistent with the disassembler and Cross Core Embedded Studio
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m,s2rnd\\)$", 0xC23c0000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m,iss2\\)$", 0xC33C0000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])\\*=(r[0-7])$", 0x000040C0, 2, {{1, &get_dreg, 0}, {2, &get_dreg, 3}}, {0, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^a0=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)$", 0xC0030000, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 10}, {3, &get_dreg, 0}, {4, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a0=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(fu\\)$", 0xC0830000, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 10}, {3, &get_dreg, 0}, {4, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a0=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(is\\)$", 0xC1030000, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 10}, {3, &get_dreg, 0}, {4, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a0=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(w32\\)$", 0xC0630000, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 10}, {3, &get_dreg, 0}, {4, &get_lowhigh, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^a0\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)$", 0xC0030800, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 10}, {3, &get_dreg, 0}, {4, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a0\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(fu\\)$", 0xC0830800, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 10}, {3, &get_dreg, 0}, {4, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a0\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(is\\)$", 0xC1030800, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 10}, {3, &get_dreg, 0}, {4, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a0\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(w32\\)$", 0xC0630800, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 10}, {3, &get_dreg, 0}, {4, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	
	{INSTRUCTION_SIZE_32_BIT, "^a0\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)$", 0xC0031000, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 10}, {3, &get_dreg, 0}, {4, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a0\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(fu\\)$", 0xC0831000, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 10}, {3, &get_dreg, 0}, {4, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a0\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(is\\)$", 0xC1031000, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 10}, {3, &get_dreg, 0}, {4, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a0\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(w32\\)$", 0xC0631000, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 10}, {3, &get_dreg, 0}, {4, &get_lowhigh, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)$", 0xC0001800, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 15}, {3, &get_dreg, 0}, {4, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(fu\\)$", 0xC0801800, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 15}, {3, &get_dreg, 0}, {4, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(is\\)$", 0xC1001800, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 15}, {3, &get_dreg, 0}, {4, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(w32\\)$", 0xC0601800, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 15}, {3, &get_dreg, 0}, {4, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m\\)$", 0xC0101800, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 15}, {3, &get_dreg, 0}, {4, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m,w32\\)$", 0xC0701800, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 15}, {3, &get_dreg, 0}, {4, &get_lowhigh, 14}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)$", 0xC0011800, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 15}, {3, &get_dreg, 0}, {4, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(fu\\)$", 0xC0811800, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 15}, {3, &get_dreg, 0}, {4, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(is\\)$", 0xC1011800, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 15}, {3, &get_dreg, 0}, {4, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(w32\\)$", 0xC0611800, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 15}, {3, &get_dreg, 0}, {4, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m\\)$", 0xC0111800, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 15}, {3, &get_dreg, 0}, {4, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m,w32\\)$", 0xC0711800, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 15}, {3, &get_dreg, 0}, {4, &get_lowhigh, 14}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)$", 0xC0021800, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 15}, {3, &get_dreg, 0}, {4, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(fu\\)$", 0xC0821800, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 15}, {3, &get_dreg, 0}, {4, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(is\\)$", 0xC1021800, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 15}, {3, &get_dreg, 0}, {4, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(w32\\)$", 0xC0621800, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 15}, {3, &get_dreg, 0}, {4, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	// For the following instruction the opcode from the Programmer's Manual was wrong.
	{INSTRUCTION_SIZE_32_BIT, "^a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m\\)$", 0xC0121800, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 15}, {3, &get_dreg, 0}, {4, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m,w32\\)$", 0xC0721800, 4, {{1, &get_dreg, 3}, {2, &get_lowhigh, 15}, {3, &get_dreg, 0}, {4, &get_lowhigh, 14}}, {1, 0, 0, 0} },


	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)$", 0xC0032000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(fu\\)$", 0xC0832000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(is\\)$", 0xC1032000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iu\\)$", 0xC1832000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(t\\)$", 0xC0432000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(tfu\\)$", 0xC0C32000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(s2rnd\\)$", 0xC0232000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iss2\\)$", 0xC1232000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(ih\\)$", 0xC1632000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)$", 0xC0032800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(fu\\)$", 0xC0832800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(is\\)$", 0xC1032800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iu\\)$", 0xC1832800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(t\\)$", 0xC0432800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(tfu\\)$", 0xC0C32800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(s2rnd\\)$", 0xC0232800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iss2\\)$", 0xC1232800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(ih\\)$", 0xC1632800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)$", 0xC0033000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(fu\\)$", 0xC0833000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(is\\)$", 0xC1033000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iu\\)$", 0xC1833000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(t\\)$", 0xC0433000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(tfu\\)$", 0xC0C33000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(s2rnd\\)$", 0xC0233000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iss2\\)$", 0xC1233000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=\\(a0\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(ih\\)$", 0xC1633000, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },


	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)$", 0xC0041800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(fu\\)$", 0xC0841800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(is\\)$", 0xC1041800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iu\\)$", 0xC1841800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(t\\)$", 0xC0441800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(tfu\\)$", 0xC0C41800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(s2rnd\\)$", 0xC0241800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iss2\\)$", 0xC1241800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(ih\\)$", 0xC1641800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m\\)$", 0xC0141800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,fu\\)$", 0xC0941800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,is\\)$", 0xC1141800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,iu\\)$", 0xC1941800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,t\\)$", 0xC0541800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,tfu\\)$", 0xC0D41800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,s2rnd\\)$", 0xC0341800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,iss2\\)$", 0xC1341800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,ih\\)$", 0xC1741800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)$", 0xC0051800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(fu\\)$", 0xC0851800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(is\\)$", 0xC1051800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iu\\)$", 0xC1851800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(t\\)$", 0xC0451800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(tfu\\)$", 0xC0C51800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(s2rnd\\)$", 0xC0251800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iss2\\)$", 0xC1251800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(ih\\)$", 0xC1651800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m\\)$", 0xC0151800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,fu\\)$", 0xC0951800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,is\\)$", 0xC1151800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,iu\\)$", 0xC1951800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,t\\)$", 0xC0551800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,tfu\\)$", 0xC0D51800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,s2rnd\\)$", 0xC0351800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,iss2\\)$", 0xC1351800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,ih\\)$", 0xC1751800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)$", 0xC0061800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(fu\\)$", 0xC0861800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(is\\)$", 0xC1061800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iu\\)$", 0xC1861800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(t\\)$", 0xC0461800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(tfu\\)$", 0xC0C61800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(s2rnd\\)$", 0xC0261800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iss2\\)$", 0xC1261800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(ih\\)$", 0xC1661800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m\\)$", 0xC0161800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,fu\\)$", 0xC0961800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,is\\)$", 0xC1161800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,iu\\)$", 0xC1961800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,t\\)$", 0xC0561800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,tfu\\)$", 0xC0D61800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,s2rnd\\)$", 0xC0361800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,iss2\\)$", 0xC1361800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,ih\\)$", 0xC1761800, 5, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },


	// For the instructions below, the opcodes in the Programmer's manual (p. C-87) are wrong. The opcodes below are consistent with the disassembler and the
	// Cross Core Embedded Studio. 
	{INSTRUCTION_SIZE_32_BIT, "^(r0|r2|r4|r6)=\\(a0=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)$", 0xC00B2000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r0|r2|r4|r6)=\\(a0=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(fu\\)$", 0xC08B2000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r0|r2|r4|r6)=\\(a0=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(is\\)$", 0xC10B2000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r0|r2|r4|r6)=\\(a0=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iu\\)$", 0xC18B2000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r0|r2|r4|r6)=\\(a0=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(s2rnd\\)$", 0xC02B2000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r0|r2|r4|r6)=\\(a0=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iss2\\)$", 0xC12B2000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r0|r2|r4|r6)=\\(a0\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)$", 0xC00B2800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r0|r2|r4|r6)=\\(a0\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(fu\\)$", 0xC08B2800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r0|r2|r4|r6)=\\(a0\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(is\\)$", 0xC10B2800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r0|r2|r4|r6)=\\(a0\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iu\\)$", 0xC18B2800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r0|r2|r4|r6)=\\(a0\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(s2rnd\\)$", 0xC02B2800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r0|r2|r4|r6)=\\(a0\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iss2\\)$", 0xC12B2800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r0|r2|r4|r6)=\\(a0\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)$", 0xC00B3000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r0|r2|r4|r6)=\\(a0\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(fu\\)$", 0xC08B3000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r0|r2|r4|r6)=\\(a0\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(is\\)$", 0xC10B3000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r0|r2|r4|r6)=\\(a0\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iu\\)$", 0xC18B3000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r0|r2|r4|r6)=\\(a0\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(s2rnd\\)$", 0xC02B3000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r0|r2|r4|r6)=\\(a0\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iss2\\)$", 0xC12B3000, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 10}, {4, &get_dreg, 0}, {5, &get_lowhigh, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)$", 0xC00c1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(fu\\)$", 0xC08c1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(is\\)$", 0xC10c1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iu\\)$", 0xC18C1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(s2rnd\\)$", 0xC02c1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iss2\\)$", 0xC12c1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m\\)$", 0xC01c1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,fu\\)$", 0xC09c1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,is\\)$", 0xC11c1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,iu\\)$", 0xC19C1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,s2rnd\\)$", 0xC03c1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,iss2\\)$", 0xC13c1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)$", 0xC00d1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(fu\\)$", 0xC08d1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(is\\)$", 0xC10d1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iu\\)$", 0xC18D1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(s2rnd\\)$", 0xC02d1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iss2\\)$", 0xC12d1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m\\)$", 0xC01d1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,fu\\)$", 0xC09d1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,is\\)$", 0xC11d1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,iu\\)$", 0xC19D1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,s2rnd\\)$", 0xC03d1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1\\+=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,iss2\\)$", 0xC13d1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)$", 0xC00e1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(fu\\)$", 0xC08e1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(is\\)$", 0xC10e1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iu\\)$", 0xC18E1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(s2rnd\\)$", 0xC02e1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iss2\\)$", 0xC12e1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m\\)$", 0xC01e1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,fu\\)$", 0xC09e1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,is\\)$", 0xC11e1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,iu\\)$", 0xC19E1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,s2rnd\\)$", 0xC03e1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1\\-=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m,iss2\\)$", 0xC13e1800, 5, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=\\-(r[0-7])$", 0x00004380, 2, {{1, &get_dreg, 0}, {2, &get_dreg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=\\-(r[0-7])\\(ns\\)$", 0xC407C000, 2, {{1, &get_dreg, 9}, {2, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=\\-(r[0-7])\\(s\\)$", 0xC407E000, 2, {{1, &get_dreg, 9}, {2, &get_dreg, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^a0=\\-a0$", 0xC40E003F, 0, {}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a0=\\-a1$", 0xC40E403F, 0, {}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1=\\-a0$", 0xC42E003F, 0, {}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1=\\-a1$", 0xC42E403F, 0, {}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1=\\-a1,a0=\\-a0$", 0xC40EC03F, 0, {}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\(rnd\\)$", 0xC40CC000, 2, {{1, &get_dreg, 9}, {2, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\(rnd\\)$", 0xC42CC000, 2, {{1, &get_dreg, 9}, {2, &get_dreg, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^a0=a0\\(s\\)$", 0xC408203F, 0, {}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1=a1\\(s\\)$", 0xC408603F, 0, {}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1=a1\\(s\\),a0=a0\\(s\\)$", 0xC408A03F, 0, {}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=signbits(r[0-7])$", 0xC6050000, 2, {{1, &get_dreg, 9}, {2, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=signbits(r[0-7])\\.l$", 0xC6054000, 2, {{1, &get_dreg, 9}, {2, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=signbits(r[0-7])\\.h$", 0xC6058000, 2, {{1, &get_dreg, 9}, {2, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=signbitsa0$", 0xC6060000, 1, {{1, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=signbitsa1$", 0xC6064000, 1, {{1, &get_dreg, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^(r[0-7])=(r[0-7])\\-(r[0-7])$", 0x00005200, 3, {{1, &get_dreg, 6}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\-(r[0-7])\\(ns\\)$", 0xC4044000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\-(r[0-7])\\(s\\)$", 0xC4046000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\.l\\-(r[0-7])\\.l\\(ns\\)$", 0xC4030000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\.l\\-(r[0-7])\\.h\\(ns\\)$", 0xC4034000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\.h\\-(r[0-7])\\.l\\(ns\\)$", 0xC4038000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\.h\\-(r[0-7])\\.h\\(ns\\)$", 0xC403C000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\.l\\-(r[0-7])\\.l\\(ns\\)$", 0xC4230000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\.l\\-(r[0-7])\\.h\\(ns\\)$", 0xC4234000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\.h\\-(r[0-7])\\.l\\(ns\\)$", 0xC4238000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\.h\\-(r[0-7])\\.h\\(ns\\)$", 0xC423C000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\.l\\-(r[0-7])\\.l\\(s\\)$", 0xC4032000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\.l\\-(r[0-7])\\.h\\(s\\)$", 0xC4036000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\.h\\-(r[0-7])\\.l\\(s\\)$", 0xC403A000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=(r[0-7])\\.h\\-(r[0-7])\\.h\\(s\\)$", 0xC403E000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\.l\\-(r[0-7])\\.l\\(s\\)$", 0xC4232000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\.l\\-(r[0-7])\\.h\\(s\\)$", 0xC4236000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\.h\\-(r[0-7])\\.l\\(s\\)$", 0xC423A000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\.h\\-(r[0-7])\\.h\\(s\\)$", 0xC423E000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_16_BIT, "^(i[0-3])\\-=(0x)?2$", 0x00009F64, 1, {{1, &get_ireg, 0}}, {0, 1, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^(i[0-3])\\-=(0x)?4$", 0x00009F6C, 1, {{1, &get_ireg, 0}}, {0, 1, 0, 0} },

	// External event management:

	{INSTRUCTION_SIZE_16_BIT, "^idle$", 0x00000020, 0, {{}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^csync$", 0x00000023, 0, {{}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^ssync$", 0x00000024, 0, {{}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^emuexcpt$", 0x00000025, 0, {{}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^cli(r[0-7])$", 0x00000030, 1, {{1, &get_dreg, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^sti(r[0-7])$", 0x00000040, 1, {{1, &get_dreg, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^raise(0x[0-9,a-f]+|[0-9]+)$", 0x00000090, 1, {{1, &get_uimm4, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^excpt(0x[0-9,a-f]+|[0-9]+)$", 0x000000a0, 1, {{1, &get_uimm4, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^testset\\((p[0-5])\\)$", 0x000000b0, 1, {{1, &get_preg, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^nop$", 0x00000000, 0, {{}}, {0, 1, 1, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^mnop$", 0xC0031800, 0, {{}}, {1, 0, 0, 0} },
	// The following instruction is only valid in a simulator. Note also that the opcode in the Programmer's Manual is wrong, in comparison to both the
	// Cross Core Embedded Studio and the disassembler.
	{INSTRUCTION_SIZE_16_BIT, "^abort$", 0x0000f8c3, 0, {{}}, {0, 0, 0, 0} },

	// Cache control:

	{INSTRUCTION_SIZE_16_BIT, "^prefetch\\[(p[0-5]|fp|sp)\\]$", 0x00000240, 1, {{1, &get_preg, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^prefetch\\[(p[0-5]|fp|sp)\\+\\+\\]$", 0x00000260, 1, {{1, &get_preg, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^flush\\[(p[0-5]|fp|sp)\\]$", 0x00000250, 1, {{1, &get_preg, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^flushinv\\[(p[0-5]|fp|sp)\\]$", 0x00000248, 1, {{1, &get_preg, 0}}, {0, 0, 0, 0} },
	{INSTRUCTION_SIZE_16_BIT, "^iflush\\[(p[0-5]|fp|sp)\\]$", 0x00000258, 1, {{1, &get_preg, 0}}, {0, 0, 0, 0} },

	// Video pixel:
	
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=align8\\((r[0-7]),(r[0-7])\\)$", 0xC60D0000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=align16\\((r[0-7]),(r[0-7])\\)$", 0xC60D4000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=align24\\((r[0-7]),(r[0-7])\\)$", 0xC60D8000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^disalgnexcpt$", 0xC412C000, 0, {{}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=byteop3p\\((r1\\:0|r3\\:2),(r1\\:0|r3\\:2)\\)\\(lo\\)$", 0xC4170000, 3, {{1, &get_dreg, 9}, {2, &get_dreg_pair, 3}, {3, &get_dreg_pair, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=byteop3p\\((r1\\:0|r3\\:2),(r1\\:0|r3\\:2)\\)\\(hi\\)$", 0xC4370000, 3, {{1, &get_dreg, 9}, {2, &get_dreg_pair, 3}, {3, &get_dreg_pair, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=byteop3p\\((r1\\:0|r3\\:2),(r1\\:0|r3\\:2)\\)\\(lo,r\\)$", 0xC4172000, 3, {{1, &get_dreg, 9}, {2, &get_dreg_pair, 3}, {3, &get_dreg_pair, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=byteop3p\\((r1\\:0|r3\\:2),(r1\\:0|r3\\:2)\\)\\(hi,r\\)$", 0xC4372000, 3, {{1, &get_dreg, 9}, {2, &get_dreg_pair, 3}, {3, &get_dreg_pair, 0}}, {1, 0, 0, 0} },
	
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=a1\\.l\\+a1\\.h,(r[0-7])=a0\\.l\\+a0\\.h$", 0xC40C403F, 2, {{1, &get_dreg, 6}, {2, &get_dreg, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^\\(?(r[0-7]),(r[0-7])\\)=byteop16p\\((r1\\:0|r3\\:2),(r1\\:0|r3\\:2)\\)$", 0xC4150000, 4, {{1, &get_dreg, 6}, {2, &get_dreg, 9}, {3, &get_dreg_pair, 3}, {4, &get_dreg_pair, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^\\(?(r[0-7]),(r[0-7])\\)=byteop16p\\((r1\\:0|r3\\:2),(r1\\:0|r3\\:2)\\)\\(r\\)$", 0xC4152000, 4, {{1, &get_dreg, 6}, {2, &get_dreg, 9}, {3, &get_dreg_pair, 3}, {4, &get_dreg_pair, 0}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=byteop1p\\((r1\\:0|r3\\:2),(r1\\:0|r3\\:2)\\)$", 0xC4140000, 3, {{1, &get_dreg, 9}, {2, &get_dreg_pair, 3}, {3, &get_dreg_pair, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=byteop1p\\((r1\\:0|r3\\:2),(r1\\:0|r3\\:2)\\)\\(t\\)$", 0xC4144000, 3, {{1, &get_dreg, 9}, {2, &get_dreg_pair, 3}, {3, &get_dreg_pair, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=byteop1p\\((r1\\:0|r3\\:2),(r1\\:0|r3\\:2)\\)\\(r\\)$", 0xC4142000, 3, {{1, &get_dreg, 9}, {2, &get_dreg_pair, 3}, {3, &get_dreg_pair, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=byteop1p\\((r1\\:0|r3\\:2),(r1\\:0|r3\\:2)\\)\\(t,r\\)$", 0xC4146000, 3, {{1, &get_dreg, 9}, {2, &get_dreg_pair, 3}, {3, &get_dreg_pair, 0}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=byteop2p\\((r1\\:0|r3\\:2),(r1\\:0|r3\\:2)\\)\\(rndl\\)$", 0xC4160000, 3, {{1, &get_dreg, 9}, {2, &get_dreg_pair, 3}, {3, &get_dreg_pair, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=byteop2p\\((r1\\:0|r3\\:2),(r1\\:0|r3\\:2)\\)\\(rndh\\)$", 0xC4360000, 3, {{1, &get_dreg, 9}, {2, &get_dreg_pair, 3}, {3, &get_dreg_pair, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=byteop2p\\((r1\\:0|r3\\:2),(r1\\:0|r3\\:2)\\)\\(tl\\)$", 0xC4164000, 3, {{1, &get_dreg, 9}, {2, &get_dreg_pair, 3}, {3, &get_dreg_pair, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=byteop2p\\((r1\\:0|r3\\:2),(r1\\:0|r3\\:2)\\)\\(th\\)$", 0xC4364000, 3, {{1, &get_dreg, 9}, {2, &get_dreg_pair, 3}, {3, &get_dreg_pair, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=byteop2p\\((r1\\:0|r3\\:2),(r1\\:0|r3\\:2)\\)\\(rndl,r\\)$", 0xC4162000, 3, {{1, &get_dreg, 9}, {2, &get_dreg_pair, 3}, {3, &get_dreg_pair, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=byteop2p\\((r1\\:0|r3\\:2),(r1\\:0|r3\\:2)\\)\\(rndh,r\\)$", 0xC4362000, 3, {{1, &get_dreg, 9}, {2, &get_dreg_pair, 3}, {3, &get_dreg_pair, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=byteop2p\\((r1\\:0|r3\\:2),(r1\\:0|r3\\:2)\\)\\(tl,r\\)$", 0xC4166000, 3, {{1, &get_dreg, 9}, {2, &get_dreg_pair, 3}, {3, &get_dreg_pair, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=byteop2p\\((r1\\:0|r3\\:2),(r1\\:0|r3\\:2)\\)\\(th,r\\)$", 0xC4366000, 3, {{1, &get_dreg, 9}, {2, &get_dreg_pair, 3}, {3, &get_dreg_pair, 0}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=bytepack\\((r[0-7]),(r[0-7])\\)$", 0xC4180000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^\\(?(r[0-7]),(r[0-7])\\)=byteop16m\\((r1\\:0|r3\\:2),(r1\\:0|r3\\:2)\\)$", 0xC4154000, 4, {{1, &get_dreg, 6}, {2, &get_dreg, 9}, {3, &get_dreg_pair, 3}, {4, &get_dreg_pair, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^\\(?(r[0-7]),(r[0-7])\\)=byteop16m\\((r1\\:0|r3\\:2),(r1\\:0|r3\\:2)\\)\\(r\\)$", 0xC4156000, 4, {{1, &get_dreg, 6}, {2, &get_dreg, 9}, {3, &get_dreg_pair, 3}, {4, &get_dreg_pair, 0}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^saa\\((r1\\:0|r3\\:2),(r1\\:0|r3\\:2)\\)$", 0xC4120000, 2, {{1, &get_dreg_pair, 3}, {2, &get_dreg_pair, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^saa\\((r1\\:0|r3\\:2),(r1\\:0|r3\\:2)\\)\\(r\\)$", 0xC4122000, 2, {{1, &get_dreg_pair, 3}, {2, &get_dreg_pair, 0}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^\\(?(r[0-7]),(r[0-7])\\)=byteunpack(r1\\:0|r3\\:2)$", 0xC4184000, 3, {{1, &get_dreg, 6}, {2, &get_dreg, 9}, {3, &get_dreg_pair, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^\\(?(r[0-7]),(r[0-7])\\)=byteunpack(r1\\:0|r3\\:2)\\(r\\)$", 0xC4186000, 3, {{1, &get_dreg, 6}, {2, &get_dreg, 9}, {3, &get_dreg_pair, 3}}, {1, 0, 0, 0} },

	// Vector operations:

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])\\.l=sign\\((r[0-7])\\.h\\)\\*(r[0-7])\\.h\\+sign\\((r[0-7])\\.l\\)\\*(r[0-7])\\.l$", 0xC40C0000, 3, {{1, &get_dreg, 9}, {3, &get_dreg, 3}, {4, &get_dreg, 0}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=vit_max\\((r[0-7]),(r[0-7])\\)\\(asr\\)$", 0xC609C000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=vit_max\\((r[0-7]),(r[0-7])\\)\\(asl\\)$", 0xC6098000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=vit_max\\((r[0-7])\\)\\(asr\\)$", 0xC6094000, 2, {{1, &get_dreg, 9}, {2, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.l=vit_max\\((r[0-7])\\)\\(asl\\)$", 0xC6090000, 2, {{1, &get_dreg, 9}, {2, &get_dreg, 0}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=abs(r[0-7])\\(v\\)$", 0xC4068000, 2, {{1, &get_dreg, 9}, {2, &get_dreg, 3}}, {1, 0, 0, 0} },

	// Note: | must be presented as \| when using rasm2 from radare2.
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\+(r[0-7])$", 0xC4000000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\+(r[0-7])\\(s\\)$", 0xC4002000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\+(r[0-7])\\(co\\)$", 0xC4001000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\+(r[0-7])\\(sco\\)$", 0xC4003000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\-\\\\?\\|\\+(r[0-7])$", 0xC4008000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\-\\\\?\\|\\+(r[0-7])\\(s\\)$", 0xC400a000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\-\\\\?\\|\\+(r[0-7])\\(co\\)$", 0xC4009000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\-\\\\?\\|\\+(r[0-7])\\(sco\\)$", 0xC400b000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\-(r[0-7])$", 0xC4004000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\-(r[0-7])\\(s\\)$", 0xC4006000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\-(r[0-7])\\(co\\)$", 0xC4005000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\-(r[0-7])\\(sco\\)$", 0xC4007000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\-\\\\?\\|\\-(r[0-7])$", 0xC400c000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\-\\\\?\\|\\-(r[0-7])\\(s\\)$", 0xC400e000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\-\\\\?\\|\\-(r[0-7])\\(co\\)$", 0xC400d000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\-\\\\?\\|\\-(r[0-7])\\(sco\\)$", 0xC400f000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\+(r[0-7]),(r[0-7])=(r[0-7])\\-\\\\?\\|\\-(r[0-7])$", 0xC4010000, 4, {{1, &get_dreg, 6}, {4, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\+(r[0-7]),(r[0-7])=(r[0-7])\\-\\\\?\\|\\-(r[0-7])\\(asr\\)$", 0xC4018000, 4, {{1, &get_dreg, 6}, {4, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\+(r[0-7]),(r[0-7])=(r[0-7])\\-\\\\?\\|\\-(r[0-7])\\(asl\\)$", 0xC401C000, 4, {{1, &get_dreg, 6}, {4, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\+(r[0-7]),(r[0-7])=(r[0-7])\\-\\\\?\\|\\-(r[0-7])\\(s\\)$", 0xC4012000, 4, {{1, &get_dreg, 6}, {4, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\+(r[0-7]),(r[0-7])=(r[0-7])\\-\\\\?\\|\\-(r[0-7])\\(s,asr\\)$", 0xC401A000, 4, {{1, &get_dreg, 6}, {4, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\+(r[0-7]),(r[0-7])=(r[0-7])\\-\\\\?\\|\\-(r[0-7])\\(s,asl\\)$", 0xC401E000, 4, {{1, &get_dreg, 6}, {4, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\+(r[0-7]),(r[0-7])=(r[0-7])\\-\\\\?\\|\\-(r[0-7])\\(co\\)$", 0xC4011000, 4, {{1, &get_dreg, 6}, {4, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\+(r[0-7]),(r[0-7])=(r[0-7])\\-\\\\?\\|\\-(r[0-7])\\(co,asr\\)$", 0xC4019000, 4, {{1, &get_dreg, 6}, {4, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\+(r[0-7]),(r[0-7])=(r[0-7])\\-\\\\?\\|\\-(r[0-7])\\(co,asl\\)$", 0xC401D000, 4, {{1, &get_dreg, 6}, {4, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\+(r[0-7]),(r[0-7])=(r[0-7])\\-\\\\?\\|\\-(r[0-7])\\(sco\\)$", 0xC4013000, 4, {{1, &get_dreg, 6}, {4, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\+(r[0-7]),(r[0-7])=(r[0-7])\\-\\\\?\\|\\-(r[0-7])\\(sco,asr\\)$", 0xC401B000, 4, {{1, &get_dreg, 6}, {4, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\+(r[0-7]),(r[0-7])=(r[0-7])\\-\\\\?\\|\\-(r[0-7])\\(sco,asl\\)$", 0xC401F000, 4, {{1, &get_dreg, 6}, {4, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\-(r[0-7]),(r[0-7])=(r[0-7])\\-\\\\?\\|\\+(r[0-7])$", 0xC4210000, 4, {{1, &get_dreg, 6}, {4, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\-(r[0-7]),(r[0-7])=(r[0-7])\\-\\\\?\\|\\+(r[0-7])\\(asr\\)$", 0xC4218000, 4, {{1, &get_dreg, 6}, {4, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\-(r[0-7]),(r[0-7])=(r[0-7])\\-\\\\?\\|\\+(r[0-7])\\(asl\\)$", 0xC421C000, 4, {{1, &get_dreg, 6}, {4, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\-(r[0-7]),(r[0-7])=(r[0-7])\\-\\\\?\\|\\+(r[0-7])\\(s\\)$", 0xC4212000, 4, {{1, &get_dreg, 6}, {4, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\-(r[0-7]),(r[0-7])=(r[0-7])\\-\\\\?\\|\\+(r[0-7])\\(s,asr\\)$", 0xC421A000, 4, {{1, &get_dreg, 6}, {4, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\-(r[0-7]),(r[0-7])=(r[0-7])\\-\\\\?\\|\\+(r[0-7])\\(s,asl\\)$", 0xC421E000, 4, {{1, &get_dreg, 6}, {4, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\-(r[0-7]),(r[0-7])=(r[0-7])\\-\\\\?\\|\\+(r[0-7])\\(co\\)$", 0xC4211000, 4, {{1, &get_dreg, 6}, {4, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\-(r[0-7]),(r[0-7])=(r[0-7])\\-\\\\?\\|\\+(r[0-7])\\(co,asr\\)$", 0xC4219000, 4, {{1, &get_dreg, 6}, {4, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\-(r[0-7]),(r[0-7])=(r[0-7])\\-\\\\?\\|\\+(r[0-7])\\(co,asl\\)$", 0xC421D000, 4, {{1, &get_dreg, 6}, {4, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\-(r[0-7]),(r[0-7])=(r[0-7])\\-\\\\?\\|\\+(r[0-7])\\(sco\\)$", 0xC4213000, 4, {{1, &get_dreg, 6}, {4, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\-(r[0-7]),(r[0-7])=(r[0-7])\\-\\\\?\\|\\+(r[0-7])\\(sco,asr\\)$", 0xC421B000, 4, {{1, &get_dreg, 6}, {4, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+\\\\?\\|\\-(r[0-7]),(r[0-7])=(r[0-7])\\-\\\\?\\|\\+(r[0-7])\\(sco,asl\\)$", 0xC421F000, 4, {{1, &get_dreg, 6}, {4, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+(r[0-7]),(r[0-7])=(r[0-7])\\-(r[0-7])(\\(ns\\))?$", 0xC4048000, 4, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_dreg, 0}, {4, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])\\+(r[0-7]),(r[0-7])=(r[0-7])\\-(r[0-7])\\(s\\)$", 0xC404A000, 4, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_dreg, 0}, {4, &get_dreg, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=a1\\+a0,(r[0-7])=a1\\-a0(\\(ns\\))?$", 0xC411003F, 2, {{1, &get_dreg, 6}, {2, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=a1\\+a0,(r[0-7])=a1\\-a0\\(s\\)$", 0xC411203F, 2, {{1, &get_dreg, 6}, {2, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=a0\\+a1,(r[0-7])=a0\\-a1(\\(ns\\))?$", 0xC411403F, 2, {{1, &get_dreg, 6}, {2, &get_dreg, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=a0\\+a1,(r[0-7])=a0\\-a1\\(s\\)$", 0xC411603F, 2, {{1, &get_dreg, 6}, {2, &get_dreg, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])>>>(0x[0-9,a-f]+|[0-9]+)\\(v\\)$", 0xC6810100, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_twos_comp_uimm5, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])<<(0x[0-9,a-f]+|[0-9]+)\\(v,s\\)$", 0xC6814000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_uimm5, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=ashift(r[0-7])by(r[0-7])\\.l\\(v\\)$", 0xC6010000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=ashift(r[0-7])by(r[0-7])\\.l\\(v,s\\)$", 0xC6014000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])>>(0x[0-9,a-f]+|[0-9]+)\\(v\\)$", 0xC6818180, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_twos_comp_uimm4, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=(r[0-7])<<(0x[0-9,a-f]+|[0-9]+)\\(v\\)$", 0xC6818000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_uimm4, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=lshift(r[0-7])by(r[0-7])\\.l\\(v\\)$", 0xC6018000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=max\\((r[0-7]),(r[0-7])\\)\\(v\\)$", 0xC4060000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=min\\((r[0-7]),(r[0-7])\\)\\(v\\)$", 0xC4064000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 3}, {3, &get_dreg, 0}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l),(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)$", 0xC2042000, 7, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l),(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(fu\\)$", 0xC2842000, 7, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l),(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(is\\)$", 0xC3042000, 7, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l),(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(iu\\)$", 0xC3842000, 7, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l),(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(t\\)$", 0xC2442000, 7, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l),(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(tfu\\)$", 0xC2C42000, 7, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l),(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(s2rnd\\)$", 0xC2242000, 7, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l),(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(iss2\\)$", 0xC3242000, 7, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l),(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(ih\\)$", 0xC3642000, 7, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m\\),(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)$", 0xC2142000, 7, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m\\),(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(fu\\)$", 0xC2942000, 7, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m\\),(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(is\\)$", 0xC3142000, 7, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m\\),(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(iu\\)$", 0xC3942000, 7, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m\\),(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(t\\)$", 0xC2542000, 7, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m\\),(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(tfu\\)$", 0xC2D42000, 7, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m\\),(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(s2rnd\\)$", 0xC2342000, 7, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m\\),(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(iss2\\)$", 0xC3342000, 7, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m\\),(r[0-7])\\.l=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(ih\\)$", 0xC3742000, 7, {{1, &get_dreg, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l),(r0|r2|r4|r6)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)$", 0xC20C2000, 7, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l),(r0|r2|r4|r6)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(fu\\)$", 0xC28C2000, 7, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l),(r0|r2|r4|r6)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(is\\)$", 0xC30C2000, 7, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l),(r0|r2|r4|r6)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(s2rnd\\)$", 0xC22C2000, 7, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l),(r0|r2|r4|r6)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(iss2\\)$", 0xC32C2000, 7, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m\\),(r0|r2|r4|r6)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)$", 0xC21C2000, 7, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m\\),(r0|r2|r4|r6)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(fu\\)$", 0xC29C2000, 7, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m\\),(r0|r2|r4|r6)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(is\\)$", 0xC31C2000, 7, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	// The Programmer's Manual has the wrong opcode for the following instruction:
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m\\),(r0|r2|r4|r6)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(s2rnd\\)$", 0xC23c2000, 7, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m\\),(r0|r2|r4|r6)=(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(iss2\\)$", 0xC33C2000, 7, {{1, &get_dreg_even, 6}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l),a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)$", 0xC0000000, 8, {{1, &get_op, 16}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {6, &get_op, 11}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l),a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(fu\\)$", 0xC0800000, 8, {{1, &get_op, 16}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {6, &get_op, 11}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l),a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(is\\)$", 0xC1000000, 8, {{1, &get_op, 16}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {6, &get_op, 11}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l),a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(w32\\)$", 0xC0600000, 8, {{1, &get_op, 16}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {6, &get_op, 11}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m\\),a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)$", 0xC0100000, 8, {{1, &get_op, 16}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {6, &get_op, 11}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m\\),a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(fu\\)$", 0xC0900000, 8, {{1, &get_op, 16}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {6, &get_op, 11}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m\\),a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(is\\)$", 0xC1100000, 8, {{1, &get_op, 16}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {6, &get_op, 11}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(m\\),a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(w32\\)$", 0xC0700000, 8, {{1, &get_op, 16}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {6, &get_op, 11}, {8, &get_lowhigh, 10}, {10, &get_lowhigh, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\),(r[0-7])\\.l=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)$", 0xC0042000, 9, {{1, &get_dreg, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\),(r[0-7])\\.l=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(fu\\)$", 0xC0842000, 9, {{1, &get_dreg, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\),(r[0-7])\\.l=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(is\\)$", 0xC1042000, 9, {{1, &get_dreg, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\),(r[0-7])\\.l=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iu\\)$", 0xC1842000, 9, {{1, &get_dreg, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\),(r[0-7])\\.l=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(t\\)$", 0xC0442000, 9, {{1, &get_dreg, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\),(r[0-7])\\.l=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(tfu\\)$", 0xC0C42000, 9, {{1, &get_dreg, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\),(r[0-7])\\.l=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(s2rnd\\)$", 0xC0242000, 9, {{1, &get_dreg, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\),(r[0-7])\\.l=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iss2\\)$", 0xC1242000, 9, {{1, &get_dreg, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\),(r[0-7])\\.l=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(ih\\)$", 0xC1642000, 9, {{1, &get_dreg, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m\\),(r[0-7])\\.l=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)$", 0xC0142000, 9, {{1, &get_dreg, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m\\),(r[0-7])\\.l=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(fu\\)$", 0xC0942000, 9, {{1, &get_dreg, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m\\),(r[0-7])\\.l=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(is\\)$", 0xC1142000, 9, {{1, &get_dreg, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m\\),(r[0-7])\\.l=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iu\\)$", 0xC1942000, 9, {{1, &get_dreg, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m\\),(r[0-7])\\.l=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(t\\)$", 0xC0542000, 9, {{1, &get_dreg, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m\\),(r[0-7])\\.l=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(tfu\\)$", 0xC0d42000, 9, {{1, &get_dreg, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m\\),(r[0-7])\\.l=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(s2rnd\\)$", 0xC0342000, 9, {{1, &get_dreg, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m\\),(r[0-7])\\.l=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iss2\\)$", 0xC1342000, 9, {{1, &get_dreg, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m\\),(r[0-7])\\.l=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(ih\\)$", 0xC1742000, 9, {{1, &get_dreg, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\),(r0|r2|r4|r6)=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)$", 0xC00C2000, 9, {{1, &get_dreg_even, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9} }, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\),(r0|r2|r4|r6)=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(fu\\)$", 0xC08C2000, 9, {{1, &get_dreg_even, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9} }, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\),(r0|r2|r4|r6)=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(is\\)$", 0xC10C2000, 9, {{1, &get_dreg_even, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9} }, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\),(r0|r2|r4|r6)=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(s2rnd\\)$", 0xC02C2000, 9, {{1, &get_dreg_even, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9} }, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\),(r0|r2|r4|r6)=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iss2\\)$", 0xC12C2000, 9, {{1, &get_dreg_even, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9} }, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m\\),(r0|r2|r4|r6)=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)$", 0xC01C2000, 9, {{1, &get_dreg_even, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9} }, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m\\),(r0|r2|r4|r6)=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(fu\\)$", 0xC09C2000, 9, {{1, &get_dreg_even, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9} }, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m\\),(r0|r2|r4|r6)=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(is\\)$", 0xC11C2000, 9, {{1, &get_dreg_even, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9} }, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m\\),(r0|r2|r4|r6)=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(s2rnd\\)$", 0xC03C2000, 9, {{1, &get_dreg_even, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9} }, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(m\\),(r0|r2|r4|r6)=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(iss2\\)$", 0xC13C2000, 9, {{1, &get_dreg_even, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {8, &get_op, 11}, {10, &get_lowhigh, 10}, {12, &get_lowhigh, 9} }, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\),a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)$", 0xC0040000, 9, {{1, &get_dreg, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {7, &get_op, 11}, {9, &get_lowhigh, 10}, {11, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\),a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(fu\\)$", 0xC0840000, 9, {{1, &get_dreg, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {7, &get_op, 11}, {9, &get_lowhigh, 10}, {11, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])\\.h=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\),a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(is\\)$", 0xC1040000, 9, {{1, &get_dreg, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {7, &get_op, 11}, {9, &get_lowhigh, 10}, {11, &get_lowhigh, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l),(r[0-7])\\.l=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)$", 0xC0002000, 9, {{1, &get_op, 16}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {6, &get_dreg, 6}, {7, &get_op, 11}, {9, &get_lowhigh, 10}, {11, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l),(r[0-7])\\.l=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(fu\\)$", 0xC0802000, 9, {{1, &get_op, 16}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {6, &get_dreg, 6}, {7, &get_op, 11}, {9, &get_lowhigh, 10}, {11, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l),(r[0-7])\\.l=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(is\\)$", 0xC1002000, 9, {{1, &get_op, 16}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {6, &get_dreg, 6}, {7, &get_op, 11}, {9, &get_lowhigh, 10}, {11, &get_lowhigh, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\),a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)$", 0xC00C0000, 9, {{1, &get_dreg_even, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {7, &get_op, 11}, {9, &get_lowhigh, 10}, {11, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\),a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(fu\\)$", 0xC08C0000, 9, {{1, &get_dreg_even, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {7, &get_op, 11}, {9, &get_lowhigh, 10}, {11, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r1|r3|r5|r7)=\\(a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\),a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\(is\\)$", 0xC10C0000, 9, {{1, &get_dreg_even, 6}, {2, &get_op, 16}, {3, &get_dreg, 3}, {4, &get_lowhigh, 15}, {5, &get_dreg, 0}, {6, &get_lowhigh, 14}, {7, &get_op, 11}, {9, &get_lowhigh, 10}, {11, &get_lowhigh, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l),(r0|r2|r4|r6)=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)$", 0xC0082000, 9, {{1, &get_op, 16}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {6, &get_dreg_even, 6}, {7, &get_op, 11}, {9, &get_lowhigh, 10}, {11, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l),(r0|r2|r4|r6)=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(fu\\)$", 0xC0882000, 9, {{1, &get_op, 16}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {6, &get_dreg_even, 6}, {7, &get_op, 11}, {9, &get_lowhigh, 10}, {11, &get_lowhigh, 9}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^a1(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l),(r0|r2|r4|r6)=\\(a0(=|\\+=|\\-=)(r[0-7])(\\.h|\\.l)\\*(r[0-7])(\\.h|\\.l)\\)\\(is\\)$", 0xC1082000, 9, {{1, &get_op, 16}, {2, &get_dreg, 3}, {3, &get_lowhigh, 15}, {4, &get_dreg, 0}, {5, &get_lowhigh, 14}, {6, &get_dreg_even, 6}, {7, &get_op, 11}, {9, &get_lowhigh, 10}, {11, &get_lowhigh, 9}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=\\-(r[0-7])\\(v\\)$", 0xC40FC000, 2, {{1, &get_dreg, 9}, {2, &get_dreg, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=pack\\((r[0-7])\\.l,(r[0-7])\\.l\\)$", 0xC6040000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=pack\\((r[0-7])\\.l,(r[0-7])\\.h\\)$", 0xC6044000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=pack\\((r[0-7])\\.h,(r[0-7])\\.l\\)$", 0xC6048000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^(r[0-7])=pack\\((r[0-7])\\.h,(r[0-7])\\.h\\)$", 0xC604C000, 3, {{1, &get_dreg, 9}, {2, &get_dreg, 0}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },

	{INSTRUCTION_SIZE_32_BIT, "^\\(?(r[0-7]),(r[0-7])\\)=search(r[0-7])\\(gt\\)$", 0xC40D0000, 3, {{1, &get_dreg, 6}, {2, &get_dreg, 9}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^\\(?(r[0-7]),(r[0-7])\\)=search(r[0-7])\\(ge\\)$", 0xC40D4000, 3, {{1, &get_dreg, 6}, {2, &get_dreg, 9}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^\\(?(r[0-7]),(r[0-7])\\)=search(r[0-7])\\(lt\\)$", 0xC40D8000, 3, {{1, &get_dreg, 6}, {2, &get_dreg, 9}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },
	{INSTRUCTION_SIZE_32_BIT, "^\\(?(r[0-7]),(r[0-7])\\)=search(r[0-7])\\(le\\)$", 0xC40DC000, 3, {{1, &get_dreg, 6}, {2, &get_dreg, 9}, {3, &get_dreg, 3}}, {1, 0, 0, 0} },

	// Invalid instruction:
	
	{INSTRUCTION_SIZE_16_BIT, "^invalid$", 0x0000ffff, 0, {{}} } // Invalid instruction	
};

static void display_assembler_workarounds(void)
{
	fprintf(stderr, 
	"Issues and workarounds:\n"
	"-----------------------\n\n"

	"If assembling an instruction that uses one or more \":\" characters,\n"
	"you typically need to put a space before or after at least one of them;\n"
	"otherwise, the rasm2 argument interpreter confuses this with \"-F [in:out]\".\n"
	"For example, to assemble an instruction such as \"[--SP]=(R7:0,P5:0)\",\n"
	"this should be entered as \"[--SP]=(R7:0,P5: 0)\" or \"[--SP]=(R7 :0,P5:0)\".\n\n"

	"At least the last \"|\" character used in an instruction (or parallel combination\n"
	"of instructions) must be represented as \"\\|\";\n"
	"again, this is due to radare2's command processor being confused by characters\n"
	"that it does not expect in assembly code.\n"
	"An example of assembling a valid parallel instruction combination is:\n"
	"	rasm2 -a blackfin \"saa (r1:0, r3:2) || r0=[i0++] |\\| r2=[i1++]\"\n\n"
	);

	return;
}

static void display_assembler_hints(void)
{
	fprintf(stderr, 
   	"Hints:\n"
	"------\n\n"

	"Execute the following command to set the disassembler to Blackfin architecture:\n"
	"	e asm.arch=blackfin\n\n"

	"Execute the following command to see the Blackfin assembler help:\n"
	"	rasm2 -a blackfin \"help\"\n"
	"Execute the following command to see info for a few instructions (from number 400 onward):\n"
	"	rasm2 -a blackfin \"help list 400\"\n\n"

	"Example assembly command:\n"
	"	rasm2 -a blackfin -o 0x2e \"call 0x00001000\"\n"
	"Instruction address provided in -o argument is only needed for instructions with pc-relative\n"
       	"addressing, such as certain types of call or jump.\n\n"

	"Sometimes, there are 32 bit and 16 bit versions of the same exact instruction;\n"
	"where this occurs 32 bits is the default, but the 16 bit version can be forced\n"
	"by appending \"(16)\".\n\n"

	"The order of compound operations may differ from that in the Blackfin Programmer's Manual,\n"
	"for consistency with the Analog Devices Cross Core Embedded Studio assembler/disassembler\n"
	"and Radare's Blackfin disassembler.\n"
	"For example, use \"R1 = ( A1 = R3.L * R6.H ) , R0 = ( A0 = R3.H * R6.L )\",\n"
	"rather than \"R0 = ( A0 = R3.H * R6.L ) , R1 = ( A1 = R3.L * R6.H )\".\n\n"
	);

	return;
}

static void display_assembler_limitations(void)
{
	fprintf(stderr, 
	"Limitations:\n"
	"------------\n\n"

	"The assembler does not support line labels, function names, variables, or symbols of any kind. \n\n"
	
	"This assembler has no macro capabilities or any other such advanced features.\n\n"

	"The assembly of parallel instruction combinations verifies instruction sizes and instruction types.\n"
	"However, there may be some subtle contraints that were overlooked, such as usage of the same \n"
	"register as the destination for different instructions executed in parallel. \n"
	"For example, \"R2 = A0  || [ I1 ++ ] = R3  || R4 = [ I0 ++ ]\",\n"
	"\"A0 = R4  || [ I1 ++ ] = R3  || R4 = [ I0 ++ ]\"\n" 
	"and \"R4 = A0  || [ I1 ++ ] = R4  || R5 = [ I0 ++ ]\" are valid parallel issues, \n"
	"but \"R4 = A0  || [ I1 ++ ] = R3  || R4 = [ I0 ++ ]\" is invalid (due to R4 being used as the\n"
	"destination for two parallel instructions, creating a race condition for the final value in R4).\n" 
	"The Cross Core Embedded Studio assembler will throw an error if you try\n"
	"to issue an invalid parallel combination of this type, but this Radare2 assembler will generate \n"
	"the machine code without any warnings or errors; do not rely on it alone for validation \n"
	"of parallel instructions. \n\n"

	"There is a footnote on p. 20-6 of the Blackfin Processor Programming Reference which says that \n"
	"multi-issue cannot combine shift/rotate instructions with a store instruction using preg+offset\n"
       	"addressing. However, examples such as \"R4 = ROT R4 BY 5  || [ P0 + 0x4 ] = R4  || R5 = [ I0 ++ ]\"\n"
	"will be assembled by the Cross Core Embedded Studio assembler without warnings or errors. Since \n"
	"Cross Core Embedded Studio seems to ignore this footnote, this Radare2 assembler also ignores \n"
	"this footnote. \n\n"

	"Some individual instructions are invalid or interpeted differently when the same register is used\n"
       	"twice; this is ignored by this assembler. \n"
	"For example, p. C-18 of the Programming Reference says that an instruction such as \n"
	"\"R0 = [ P0 ++ P2 ]\" is actually a non-post-modify version when the two pregs are the same, \n"
	"i.e. \"R0 = [ P0 ++ P0 ]\" is functionally equivalent to \"R0 = [P0]\". Note that the Cross Core\n"
	"Embedded Studio assembler does not issue any errors or warnings about this, and neither does \n"
	"this Radare2 assembler. \n\n"
	);

	return;
}

// This function lists some of the Blackfin instruction info, starting from the nominated position.
static void display_list(const char list_args[])
{
	int starting_instruction, last_instruction, instr_num, instrs_to_output=10;

	if (strlen(list_args)>0) 
	{
		if (sscanf(list_args, "%d", &starting_instruction)==1) ;
		else starting_instruction=0;
	}
	else starting_instruction=0;

	if (starting_instruction<0) starting_instruction=0;
	if (starting_instruction>=sizeof(instructions)/sizeof(Instruction)) starting_instruction=sizeof(instructions)/sizeof(Instruction)-1;

	last_instruction=starting_instruction+instrs_to_output-1;
	if (last_instruction>=sizeof(instructions)/sizeof(Instruction)) last_instruction=sizeof(instructions)/sizeof(Instruction)-1;

	fprintf(stderr, "\nInfo on instructions %d to %d:\n", starting_instruction, last_instruction);
	fprintf(stderr, "===============================\n\n");

	instr_num=starting_instruction;

	while (instr_num<=last_instruction)
	{
		if (instructions[instr_num].size==INSTRUCTION_SIZE_32_BIT)
		{
			fprintf(stderr, "Instruction %d:\n  Base Opcode=0x%08x\n", instr_num, instructions[instr_num].opcode_mask);
			fprintf(stderr, "  Regex=\"%s\"\n", instructions[instr_num].asm_regex_str);
			if (instructions[instr_num].parallel_constraints.in_32bit_alu_mac==1) fprintf(stderr, "  Parallel usage: Y || N || N\n");
			else fprintf(stderr, "  Parallel usage: Not at all!\n");
		}
		else if (instructions[instr_num].size==INSTRUCTION_SIZE_16_BIT)
		{
			fprintf(stderr, "Instruction %d:\n  Base Opcode=0x%04x\n", instr_num, instructions[instr_num].opcode_mask);
			fprintf(stderr, "  Regex=\"%s\"\n", instructions[instr_num].asm_regex_str);
			if (instructions[instr_num].parallel_constraints.in_16bit_group1==1 && instructions[instr_num].parallel_constraints.in_16bit_group2==0) fprintf(stderr, "  Parallel usage: N || Y || N\n");
			else if (instructions[instr_num].parallel_constraints.in_16bit_group1==0 && instructions[instr_num].parallel_constraints.in_16bit_group2==1) fprintf(stderr, "  Parallel usage: N || N || Y\n");
			else if (instructions[instr_num].parallel_constraints.in_16bit_group1==1 && instructions[instr_num].parallel_constraints.in_16bit_group2==1) fprintf(stderr, "  Parallel usage: N || Y || Y\n");
			else fprintf(stderr, "  Parallel usage: Not at all!\n");
		}

		instr_num++;
	}

	return;
}

// This function is executed if somebody attempts to assemble a "help" 'instruction.
static void display_assembler_help(const char help_args[])
{
	if (strncmp(help_args, "list", 4)==0)
	{
		display_list(help_args+4);
	}
	else
	{
		fprintf(stderr, "\nRadare2 Blackfin assembler help:\n");
		fprintf(stderr, "================================\n\n");

		display_assembler_hints();
		display_assembler_limitations();
		display_assembler_workarounds();
	}

	return;
}

// This function outputs the startup notice.
static void display_assembler_notice(void)
{
	fprintf(stderr, "Blackfin assembler/disassembler loaded. For instructions execute the following command:\n");
	fprintf(stderr, "\trasm2 -a blackfin \"help\"\n\n");
	
	return;
}

#define MAX_ASSEMBLY_LENGTH 2000

static unsigned long test_disas_offset=0;
static char test_disas_output[MAX_ASSEMBLY_LENGTH+1]="";
static RStrBuf *test_disas_buffer=NULL;
static unsigned char test_disas_bytes[8]; // Allow for parallel combination of instructions: 4 bytes + 2 bytes + 2 bytes

static int test_disas_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) 
{
        memcpy(myaddr, test_disas_bytes+memaddr-test_disas_offset, length);

	return 0;
}

static int test_disas_symbol_at_address(bfd_vma addr, struct disassemble_info *info) 
{
        return 0;
}

static void test_disas_memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) 
{
	return;
}


static void test_disas_print_address(bfd_vma address, struct disassemble_info *info) 
{
        if (test_disas_buffer==NULL) return;
        r_strbuf_appendf (test_disas_buffer, "0x%08"PFMT64x"", (ut64)address);
}


static int test_disas_fprintf(void *stream, const char *format, ...) 
{
        va_list ap;
	char output[MAX_ASSEMBLY_LENGTH+1];

	va_start(ap, format);
	vsnprintf(output, MAX_ASSEMBLY_LENGTH, format, ap);
	strncat(test_disas_output, output, MAX_ASSEMBLY_LENGTH);
	va_end(ap);
	return 0;

	if (test_disas_buffer==NULL) return 0;
        va_start(ap, format);
        r_strbuf_vappendf(test_disas_buffer, format, ap);
        va_end(ap);

	return 0;
}


// This function returns 1 if machine_code (of length mc_length) is the valid translation of the assembler string asm_str,
// according to the disassembler, or returns 0 otherwise.
static int __attribute__((unused)) verify_assembly(char asm_str[], ut8 *machine_code, int mc_length, unsigned int instruction_address)
{
	struct disassemble_info disinf;
	char *norm_str;

	norm_str=asm_normalise(asm_str);
	strcpy(asm_str, norm_str);

	if (mc_length<8) memcpy(test_disas_bytes, machine_code, mc_length);
	else memcpy(test_disas_bytes, machine_code, 8);
	test_disas_offset=instruction_address;

        memset(&disinf, 0, sizeof(struct disassemble_info));
        disinf.disassembler_options="64";
        disinf.buffer=test_disas_bytes;
        disinf.read_memory_func=&test_disas_read_memory;
        disinf.symbol_at_address_func=&test_disas_symbol_at_address;
        disinf.memory_error_func=&test_disas_memory_error_func;
        disinf.print_address_func=&test_disas_print_address;
        disinf.endian=1;
        disinf.fprintf_func=&test_disas_fprintf;
        disinf.stream=stderr;
	r_strbuf_set(test_disas_buffer, "");

	print_insn_bfin((bfd_vma)test_disas_offset, &disinf);

	norm_str=asm_normalise(test_disas_output);
	strcpy(test_disas_output, norm_str);

	if (strcmp(test_disas_output, asm_str)!=0)
	{
		fprintf(stderr, "Normalised string to assemble was:\n%s\nbut disassembly of machine code output yielded\n%s\n\n", asm_str, test_disas_output);
		test_disas_output[0]='\0';
		return 0;
	}

	test_disas_output[0]='\0';
	return 1;
}

#define ERRORBUF_SIZE 200

// This function takes a single instruction's normed assembly string (asm_str) and the offset at which the corresponding machine code will go,
// returning the length of the corresponding machine code (either 2 or 4 bytes), or 0 for error. The corresponding machine code is stored in machine_code,
// which must be a pointer to an array of ut8 of size 4 or more. 
static int bfin_assemble_single_instruction(char *asm_str, const uint32_t offset, ut8 *machine_code)
{
	int length=2, instruction_index, jj, group_index, operand_int;
	regmatch_t groups[MAX_OPERANDS];
	uint32_t opcode=0;
	int instruction_identified=0;
	regex_t cmpregex;
	int result;
	char errorbuf[ERRORBUF_SIZE];

	// Find the first matching instruction for asm_str
	for (instruction_index=0; instruction_index<sizeof(instructions)/sizeof(Instruction); instruction_index++)
	{
		if ((result=regcomp(&cmpregex, instructions[instruction_index].asm_regex_str, REG_EXTENDED))!=0)
		{
			regerror(result, &cmpregex, errorbuf, ERRORBUF_SIZE);
			fprintf(stderr, "Regex compilation of pattern \"%s\" failed, because \"%s\"\n", instructions[instruction_index].asm_regex_str, errorbuf);
			exit(-1);
		}

		// See: https://stackoverflow.com/questions/2577193/how-do-you-capture-a-group-with-regex
		if (regexec(&cmpregex, asm_str, MAX_OPERANDS, groups, 0) == 0)
		{
			instruction_identified=1;
			if (instructions[instruction_index].size==INSTRUCTION_SIZE_16_BIT) length=2;
			else length=4;
			opcode = instructions[instruction_index].opcode_mask;

			// Process each of the captured groups
			for (group_index=0; group_index<MAX_OPERANDS; group_index++)
			{
				// If this is an invalid captured group, then we have reached the end of the captured groups
				if (groups[group_index].rm_so==(size_t)(-1)) break;

				// Check if this captured group matches one of the operands we expect
				for (jj=0; jj<instructions[instruction_index].num_operands; jj++)
				{
					/// Is it a match?
					if (instructions[instruction_index].operands[jj].group_number==group_index)
					{
						operand_int=(*(instructions[instruction_index].operands[jj].string_to_int_converter))(asm_str+groups[group_index].rm_so, groups[group_index].rm_eo-groups[group_index].rm_so+1, offset);

						operand_int = operand_int<<instructions[instruction_index].operands[jj].bit_location;
						opcode = opcode | operand_int;
					}
				}
			}

			regfree(&cmpregex);
			break;
		}
		else
		{
			regfree(&cmpregex);
		}
	}

	if (instruction_identified!=1)
	{
		fprintf(stderr, "\nUnknown instruction: \"%s\"\n", asm_str);
		fprintf(stderr, "\nThere are %lu different instruction opcodes to choose from (yay!).\n\n", sizeof(instructions)/sizeof(Instruction));

		display_assembler_workarounds();

		return 0;
	}

	if (length==2)
	{
		machine_code[0]=opcode%256;
		opcode = opcode / 256;
		machine_code[1]=opcode%256;
		return length;
	}
	else if (length==4)
	{
		machine_code[2]=opcode%256;
		opcode = opcode / 256;
		machine_code[3]=opcode%256;
		opcode = opcode / 256;
		machine_code[0]=opcode%256;
		opcode = opcode / 256;
		machine_code[1]=opcode%256;
		return length;
	}
	else return 0;
}

// This function takes a single instruction's normed assembly string (asm_str),
// returning the index into the instructions[] table for the match, or -1 for error. 
static int bfin_identify_single_instruction(char *asm_str)
{
	int instruction_index;
	regmatch_t groups[MAX_OPERANDS];
	regex_t cmpregex;
	char errorbuf[ERRORBUF_SIZE];
	int result;

	// Find the first matching instruction for asm_str
	for (instruction_index=0; instruction_index<sizeof(instructions)/sizeof(Instruction); instruction_index++)
	{
		if ((result=regcomp(&cmpregex, instructions[instruction_index].asm_regex_str, REG_EXTENDED))!=0)
		{
			regerror(result, &cmpregex, errorbuf, ERRORBUF_SIZE);
			fprintf(stderr, "Regex compilation of pattern \"%s\" failed, because \"%s\"\n", instructions[instruction_index].asm_regex_str, errorbuf);
			exit(-1);
		}

		// See: https://stackoverflow.com/questions/2577193/how-do-you-capture-a-group-with-regex
		if (regexec(&cmpregex, asm_str, MAX_OPERANDS, groups, 0) == 0)
		{
			regfree(&cmpregex);
			return instruction_index;
		}
		else
		{
			regfree(&cmpregex);
		}
	}

	return -1;
}

#define MAX_PARALLEL_INSTRUCTIONS 3

// This function takes a single instruction or parallel instruction combination assembly string (asm_str) and the offset at which the corresponding machine code will go,
// returning the length of the corresponding machine code (either 2, 4 or 8 bytes), or 0 on error. The corresponding machine code is stored in machine_code,
// which must be a pointer to an array of ut8 of size 8. 
int bfin_assemble(const char *asm_str, const uint32_t offset, ut8 *machine_code)
{
	char *norm_str=asm_normalise(asm_str);
	static char instr_strs[MAX_PARALLEL_INSTRUCTIONS][MAX_NORM_STR+1];
	int instr_lens[MAX_PARALLEL_INSTRUCTIONS];
	ut8 instr_codes[MAX_PARALLEL_INSTRUCTIONS][4];
	int instr_group0_memberships[MAX_PARALLEL_INSTRUCTIONS];
	int instr_group1_memberships[MAX_PARALLEL_INSTRUCTIONS];
	int instr_group2_memberships[MAX_PARALLEL_INSTRUCTIONS];
	int instr_store_usage[MAX_PARALLEL_INSTRUCTIONS];
	int source_loc, dest_loc;
	int num_instrs=1, ii;
	uint32_t instr_offset;
	ut8 nop[]={0x00, 0x00};
	ut8 mnop[]={0x03, 0xc0, 0x00, 0x18};
	int instr_index;

	// Check for help request first
	if (strncmp(norm_str, "help", 4)==0)
	{
		display_assembler_help(norm_str+4);
		exit(0); // Prevent seeing the help 3 times over, and attempting to complete assembly of the "help" 'instruction'.
	}

	// Partition the normed string into between 1 and MAX_PARALLEL_INSTRUCTIONS substrings, separated by "||".
	source_loc=0;
	dest_loc=0;
	while (norm_str[source_loc]!='\0')
	{
		if (norm_str[source_loc]=='|' && norm_str[source_loc+1]=='|')
		{
			instr_strs[num_instrs-1][dest_loc]='\0';
			num_instrs++;
			if (num_instrs>MAX_PARALLEL_INSTRUCTIONS)
			{
				fprintf(stderr, "Max %d instructions in parallel are allowed!\n", MAX_PARALLEL_INSTRUCTIONS);
				return 0;
			}
			dest_loc=0;
			source_loc++;
		}
		else
		{
			instr_strs[num_instrs-1][dest_loc]=norm_str[source_loc];
			dest_loc++;
		}

		source_loc++;
	}
	instr_strs[num_instrs-1][dest_loc]='\0';

	// Compile the separate instructions to obtain the corresponding (unmodifed) machine codes
	instr_offset=offset;
	for (ii=0; ii<num_instrs; ii++)
	{
		instr_lens[ii]=bfin_assemble_single_instruction(instr_strs[ii], instr_offset, instr_codes[ii]);

		if (instr_lens[ii]==0) return 0;

		instr_index=bfin_identify_single_instruction(instr_strs[ii]);
		if (instr_index<0) return 0;
		instr_group0_memberships[ii]=instructions[instr_index].parallel_constraints.in_32bit_alu_mac;
		instr_group1_memberships[ii]=instructions[instr_index].parallel_constraints.in_16bit_group1;
		instr_group2_memberships[ii]=instructions[instr_index].parallel_constraints.in_16bit_group2;
		instr_store_usage[ii]=instructions[instr_index].parallel_constraints.is_store;

		instr_offset+=instr_lens[ii];
	}

	// Verify if the parallel combination is valid, and pad if necessary
	
	// Case with a single instruction (no parallel combination)
	if (num_instrs==1)
	{
		memcpy((void*)(machine_code), (void*)(instr_codes[0]), sizeof(ut8)*(instr_lens[0]));
		return instr_lens[0];
	}
	// Cases with two instructions (padding required if valid)
	else if (num_instrs==2)
	{
		// Case with a 32 bit instruction and a 16 bit instruction - add 16 bit nop at end
		if (instr_lens[0]==4 && instr_lens[1]==2 && instr_group0_memberships[0]==1 && instr_group1_memberships[1]==1)
		{
			// Add 8 to second byte of first instruction, to signal parallel combination
			instr_codes[0][1]+=8;

			memcpy((void*)(machine_code), (void*)(instr_codes[0]), sizeof(ut8)*(instr_lens[0]));
			memcpy((void*)(machine_code+instr_lens[0]), (void*)(instr_codes[1]), sizeof(ut8)*(instr_lens[1]));
			memcpy((void*)(machine_code+instr_lens[0]+instr_lens[1]), (void*)(nop), sizeof(nop));
			return instr_lens[0]+instr_lens[1]+sizeof(nop)/sizeof(ut8);
		}
		// Case with two 16 bit instructions - add a 32 bit mnop at the start
		else if (instr_lens[0]==2 && instr_lens[1]==2 && instr_group1_memberships[0]==1 && instr_group2_memberships[1]==1
				&& (instr_store_usage[0]!=1 || instr_store_usage[1]!=1) )
		{
			// Add 8 to second byte of first instruction, to signal parallel combination
			mnop[1]+=8;

			memcpy((void*)(machine_code), (void*)(mnop), sizeof(mnop));
			memcpy((void*)(machine_code+sizeof(mnop)/sizeof(ut8)), (void*)(instr_codes[0]), sizeof(ut8)*(instr_lens[0]));
			memcpy((void*)(machine_code+sizeof(mnop)/sizeof(ut8)+instr_lens[0]), (void*)(instr_codes[1]), sizeof(ut8)*(instr_lens[1]));
			return instr_lens[0]+instr_lens[1]+sizeof(mnop)/sizeof(ut8);
		}
		else
		{
			fprintf(stderr, "Invalid double parallel combination\n");
			return 0;
		}
	}
	// Case with three instructions, which might or might not be valid
	else if (num_instrs==3)
	{
		// To be valid, we need a 32 bit instruction followed by two 16 bit instructions.
		// Note: There are other restrictions that we are ignoring, so don't rely on the assembler for detecting invalid combinations of instructions.
		if (instr_lens[0]==4 && instr_lens[1]==2 && instr_lens[2]==2 && instr_group0_memberships[0]==1 && instr_group1_memberships[1]==1
		    && instr_group2_memberships[2]==1 && (instr_store_usage[1]!=1 || instr_store_usage[2]!=1) )
		{
			// Add 8 to second byte of first instruction, to signal parallel combination
			instr_codes[0][1]+=8;

			memcpy((void*)(machine_code), (void*)(instr_codes[0]), sizeof(ut8)*(instr_lens[0]));
			memcpy((void*)(machine_code+instr_lens[0]), (void*)(instr_codes[1]), sizeof(ut8)*(instr_lens[1]));
			memcpy((void*)(machine_code+instr_lens[0]+instr_lens[1]), (void*)(instr_codes[2]), sizeof(ut8)*(instr_lens[2]));
			return instr_lens[0]+instr_lens[1]+instr_lens[2];
		}
		else
		{
			fprintf(stderr, "Invalid triple parallel combination\n");
			return 0;
		}
	}
	else 
	{
		fprintf(stderr, "At most 3 instructions can be issued in parallel\n");
		return 0;
	}
}

/*
  Copyright 2003-2006 Ronald S. Burkey <info@sandroid.org>,
            2008 Onno Hommes
            2016 Inokentiy Babushkin

  This file is based on the implmentation found in yaAGC, but modified for new
  purposes.

  This file is part of yaAGC / radare2-extras.
  yaAGC is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  yaAGC is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  You should have received a copy of the GNU General Public License
  along with yaAGC; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

  Filename:  agc_disassembler.h
  Purpose:   Source file for AGC Disassembler.
  Contact:   Onno Hommes
  Reference: http://www.ibiblio.org/apollo
  Mods:      08/31/08 OH. Began.
*/

#include <stdio.h>
#include "asm_agc.h"

static int s_current_z, s_bank, s_value, s_erasable, s_fixed;

void disasm_instruction(bool extra_code, int value, char *buf, int len) {
    if (extra_code) {
        if (value == 040000)
            snprintf(buf, len, "com");
        else if (value == 020001)
            snprintf(buf, len, "ddoubl");
        else if (value == 060000)
            snprintf(buf, len, "double");
        else if (value == 052006)
            snprintf(buf, len, "dtcb");
        else if (value == 052005)
            snprintf(buf, len, "dtcf");
        else if (value == 6)
            snprintf(buf, len, "extend");
        else if (value == 4)
            snprintf(buf, len, "inhint");
        else if (s_fixed && value == s_current_z + 1 && value != 10000)
            snprintf(buf, len, "noop");
        else if (s_erasable && value == 030000)
            snprintf(buf, len, "noop");
        else if (value == 054000)
            snprintf(buf, len, "ovsk");
        else if (value == 3)
            snprintf(buf, len, "relint");
        else if (value == 050017)
            snprintf(buf, len, "resume");
        else if (value == 2)
            snprintf(buf, len, "return");
        else if (value == 054005)
            snprintf(buf, len, "tcaa");
        else if (value == 1)
            snprintf(buf, len, "xlq");
        else if (value == 0)
            snprintf(buf, len, "xxalq");
        else if (value == 022007)
            snprintf(buf, len, "zl");
        else switch (value & 0x7000) {
            case 0x0000:
                snprintf(buf, len, "tc\t%04o", value & 0xFFF);
                break;
            case 0x1000:
                if (0 == (value & 0x0C00))
                    snprintf(buf, len, "ccs\t%04o",value&0x3FF);
                else
                    snprintf(buf, len, "tcf\t%04o", value & 0xFFF);
                break;
            case 0x2000:
                switch (value & 0x0C00) {
                    case 0x000:
                        snprintf(buf, len, "das\t%04o", (value - 1) & 0x3FF);
                        break;
                    case 0x400:
                        snprintf(buf, len, "lxch\t%04o", value & 0x3FF);
                        break;
                    case 0x800:
                        snprintf(buf, len, "incr\t%04o", value & 0x3FF);
                        break;
                    case 0xC00:
                        snprintf(buf, len, "ads\t%04o", value & 0x3FF);
                        break;
                }
                break;
            case 0x3000:
                snprintf(buf, len, "ca\t%04o", value & 0xFFF);
                break;
            case 0x4000:
                snprintf(buf, len, "cs\t%04o", value & 0xFFF);
                break;
            case 0x5000:
                switch (value & 0x0C00) {
                    case 0x000:
                        snprintf(buf, len, "index\t%04o", value & 0x3FF);
                        break;
                    case 0x400:
                        snprintf(buf, len, "dxch\t%04o", (value - 1) & 0x3FF);
                        break;
                    case 0x800:
                        snprintf(buf, len, "ts\t%04o", value & 0x3FF);
                        break;
                    case 0xC00:
                        snprintf(buf, len, "xch\t%04o", value & 0x3FF);
                        break;
                }
                break;
            case 0x6000:
                snprintf(buf, len, "ad\t%04o", value & 0xFFF);
                break;
            case 0x7000:
                snprintf(buf, len, "mask\t%04o", value & 0xFFF);
                break;
        }
    } else {
        if (value == 040001)
            snprintf(buf, len, "Dcom");
        else if (value == 050017)
            snprintf(buf, len, "resume");
        else if (value == 070000)
            snprintf(buf, len, "square");
        else if (value == 022007)
            snprintf(buf, len, "zq");
        else switch (value & 0x7000) {
            case 0x0000:
                switch (value & 0x0E00) {
                    case 0x0000:
                        snprintf(buf, len, "read\t%03o", value & 0777);
                        break;
                    case 0x0200:
                        snprintf(buf, len, "write\t%03o", value & 0777);
                        break;
                    case 0x0400:
                        snprintf(buf, len, "rand\t%03o", value & 0777);
                        break;
                    case 0x0600:
                        snprintf(buf, len, "wand\t%03o", value & 0777);
                        break;
                    case 0x0800:
                        snprintf(buf, len, "ror\t%03o", value & 0777);
                        break;
                    case 0x0A00:
                        snprintf(buf, len, "wor\t%03o", value & 0777);
                        break;
                    case 0x0C00:
                        snprintf(buf, len, "rxor\t%03o", value & 0777);
                        break;
                    case 0x0E00:
                        snprintf(buf, len, "edrupt\t%03o", value & 0777);
                        break;
                }
                break;
            case 0x1000:
                if (0 == (value & 0x0C00))
                    snprintf(buf, len, "dv\t%04o", value & 0x3FF);
                else
                    snprintf(buf, len, "bzf\t%04o", value & 0xFFF);
                break;
            case 0x2000:
                switch (value & 0x0C00) {
                    case 0x000:
                        snprintf(buf, len, "msu\t%04o", value & 0x3FF);
                        break;
                    case 0x400:
                        snprintf(buf, len, "qxch\t%04o", value & 0x3FF);
                        break;
                    case 0x800:
                        snprintf(buf, len, "aug\t%04o", value & 0x3FF);
                        break;
                    case 0xC00:
                        snprintf(buf, len, "dim\t%04o", value & 0x3FF);
                        break;
                }
                break;
            case 0x3000:
                snprintf(buf, len, "dca\t%04o", (value - 1) & 0xFFF);
                break;
            case 0x4000:
                snprintf(buf, len, "dcs\t%04o", (value - 1) & 0xFFF);
                break;
            case 0x5000:
                snprintf(buf, len, "index\t%04o", value & 0xFFF);
                break;
            case 0x6000:
                if (!(value & 0x0C00))
                    snprintf(buf, len, "su\t%04o", value & 0x3FF);
                else
                    snprintf(buf, len, "bzmf\t%04o", value & 0xFFF);
                break;
            case 0x7000:
                snprintf(buf, len, "mp\t%04o", value & 0xFFF);
                break;
        }
    }
}

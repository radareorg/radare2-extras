# md32 `usip` mode: conditional branches + 16/32-bit `save` / `ret` / `restore`

Small patch (19 lines) against `md32/arch_md32.c` in radare2-extras (commit 5edf816,
"Add support for md32 architecture").

The `usip` CPU mode currently decodes `save`, `call`, `ret` and `restore`. This adds:

1. **Conditional branches** `b<cond>`: `hw1 & 0xF1FF == 0x400C`, tag in `{0xC,0xD,0xE}`,
   condition in `hw1[11:9]` (all 8 values occur), target `pc + (hw2 & 0xFFE)`,
   fallthrough `pc + 4`.
2. **16-bit `save`**: `hw & 0xFF0F == 0xDF05` (the 16-bit form of the 32-bit `0x5F05`).
3. **32-bit `ret`** `0x5EF9` and **32-bit `restore`** `hw & 0xFF0F == 0x7F05`.

## Evidence

Measured on the MediaTek MT6877 modem DSP ("uSIP" cores), on 5,392 functions /
787,948 instructions whose boundaries are known exactly from the build's `DbgInfo`
(a symbol-derived walk with the length rule `16 bits if byte & 0x80` lands on the
declared function end in **5392/5392** functions).

* Conditional branches: **981/985 (99.59 %)** land exactly on an instruction boundary
  inside the same function, and 76 % additionally on a source-line boundary.
* All 8 condition values are present (frequencies 274, 131, 71, 40, 30, 17, 17, 12),
  so the field is a full 3 bits. The mapping to eq/ne/lt/... is **not** determined;
  the patch numbers them.
* 16-bit `save`: 260 uses; 32-bit `ret`: 121; 32-bit `restore`: 93.
* `save` takes the same `w` field values in both widths, which is how the 16-bit form
  was identified (behavioural match, not similarity).

## Test

    ./test.sh

uses a 12-byte synthetic vector (no vendor code) and should print:

    0x00000000   5f051e90   save 0x1e90, 0x0
    0x00000004   000e78aa   call 0x000008ae
    0x00000008   460ce030   b3 0x00000038
    0x0000000c   def9       ret

## Known gap

ALU / load-store / immediate forms are still `.word` / `.hword` (~95 % of the corpus).
No contiguous opcode field could be found for them: a sweep over every bit window
(6-24 bits) x scales x bases x 32 rotations, using 1,301 function starts as the oracle,
produces no candidate above chance. The vendor toolchain for this core
(DSPTK 9.x "blaze", core Bril9, ISA `vdsp30`, binutils machine `md32sc-elf`) is not
public; the 2017 DSPTK 8.1 / MS15E30 toolchain decodes `ret` and `save` as unknown
opcodes, so it is a different generation.

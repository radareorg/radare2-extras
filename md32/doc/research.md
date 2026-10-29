# MD32 research and verification

Research date: 2026-10-29. The primary target is the MediaTek **MS15E30** MD32
implemented by the available vendor toolchain. The MT6877 uSIP samples are
handled as an explicitly separate, incompletely understood encoding.

## Sources and toolchain

- [cyrozap/ghidra-md32](https://github.com/cyrozap/ghidra-md32): public SLEIGH
  instruction and register descriptions, Apache-2.0. The provided copy under
  `third_party/ghidra-md32` was used to understand semantics and cross-check the
  decoder. It describes its implementation as incomplete and calls out packed
  instructions and variable-length delay slots as unresolved Ghidra issues.
- [cyrozap/mediatek-lte-baseband-re, MD32 tools](https://github.com/cyrozap/mediatek-lte-baseband-re/tree/master/DSP/MD32):
  byte-order notes, ELF machine 0x2454, and a Python wrapper around the vendor
  disassembler. Its binutils README identifies the Orange Pi Android 8.1 BSP
  as a public distribution of the MD32 toolchain.
- [Orange Pi MD32 toolchain mirror](https://github.com/Iscle/OrangePi_4G-IOT_Android_8.1_BSP/tree/master/ccu_tool/md32ccu):
  vendor compiler, assembler, linker, objcopy, objdump, libraries, and headers.
  This avoids downloading the original multipart 22 GB Android archive.
- [Ghidra delay-slot issue #3942](https://github.com/NationalSecurityAgency/ghidra/issues/3942):
  the MD32 processor-module author explains that the specification was recovered
  by probing a closed-source disassembler and testing instructions on hardware;
  no public ISA manual was available to them.
- `third_party/r2pkg`: the supplied MT6877 uSIP binaries, function inventory,
  source-line examples, and reverse-engineering notes. The scripts' private
  source blobs are not bundled, so our verification uses the two supplied
  extracted binaries and the supplied Markdown function inventory directly.

There **is a vendor MD32 binutils port**. I did not locate its published
MD32-specific C source or a newer uSIP ISA manual/toolchain. Upstream hits for
`MD32` in `include/opcode/h8300.h` refer to an H8 operand macro and do not provide
a MediaTek decoder.

Download the reference executable outside the source tree:

```sh
curl -fL \
  https://raw.githubusercontent.com/Iscle/OrangePi_4G-IOT_Android_8.1_BSP/master/ccu_tool/md32ccu/ToolChain/install_md32/md32-elf/bin/objdump \
  -o /tmp/md32-objdump
```

SHA256: `ad768602af6c62049ae5338ce390bb4799e6f8c4a78488f64d58b14b4dc4ab04`.
It is an unstripped x86-64 Linux ELF executable, 1,095,597 bytes. It is neither
built into nor required by the plugin.

The new decoder is portable C. `tools/extract_opcodes.py` reads the reference
ELF's named `ms15e30_isa` and operand tables to recover encoding facts. It checks
the executable's hash before producing the checked-in `md32_opcodes.h`:

```sh
python3 tools/extract_opcodes.py /tmp/md32-objdump -o /tmp/md32_opcodes.h
cmp md32_opcodes.h /tmp/md32_opcodes.h
```

The tables have 154 32-bit forms and 104 16-bit forms, distributed over four
16-bit execution groups. Masked reserved operand fields are retained, including
reserved control-register numbers. Immediate decoders include split fields,
scaled signed offsets, and compressed register numbers. Packed pairs reconstruct
the first instruction as `(halfword0 << 1) | (halfword1 >> 15)` and the second
as `halfword1 | 0x8000`, with execution groups selected by the shared prefix.
This is more general than assuming that a pair consists of two ordinary
standalone halfwords.

The additional downloaded reference headers are preserved under
`third_party/reference`:

| File | Source within the Orange Pi mirror | SHA256 |
| --- | --- | --- |
| `builtins_md32s15.h` | `ccu_tool/md32ccu/Md32/include/builtins_md32s15.h` | `2f7a767cca8974d5327a2b7a97d97e2edb90d6245016dfc2a9ced46b17d7d490` |
| `vendor-setjmp.h` | `ccu_tool/md32ccu/Md32/nml/s15r30_md32_v3.0/nlib/include/machine/setjmp.h` | `77e854c41fb65393aeedcfc14467e6bb04877975fe2d0aee67a282849f18450e` |

The builtin names confirm the DSP and control-operation names. The setjmp header
also mentions an `SP_NE_R14` build option, so r14-as-SP should be understood as
the ABI represented by the public Ghidra specification, not a proven universal
rule for all MD32 generations. The argument aliases follow that specification
(r3-r10; return values r1-r2).

## Firmware verification

An independent real program image was downloaded from
[linux-firmware's MT8173 firmware directory](https://gitlab.com/kernel-firmware/linux-firmware/-/tree/main/mediatek/mt8173):

```sh
curl -fL \
  https://gitlab.com/kernel-firmware/linux-firmware/-/raw/main/mediatek/mt8173/vpu_p.bin \
  -o /tmp/md32-vpu_p.bin
python3 tools/swap_words.py /tmp/md32-vpu_p.bin /tmp/md32-vpu_p.be.bin
```

Both files have 131,072 bytes. SHA256:

- Downloaded storage image: `fb226004888a01c04590fe23df6dcc3a1735d7b4cbbb072f4dc3f920f463951f`.
- Canonical instruction stream: `036b5267c19ec4574c05784f9441b85689710a313e490ed2ca3754d59ac11835`.

The oracle executes the original vendor `print_insn_md32` function and operand
helpers in Unicorn, with adapters for reading code and collecting formatted
output. It does not call our C decoder or generate its expectations from the
new opcode table. The vendor's printed displacements are converted to 32-bit
absolute addresses for comparison, and its unsigned spelling of negative
immediates is normalized. Invalid halfwords and partially invalid pairs remain
invalid; the vendor returns a two-byte resynchronization step for them.

The full run compared **141,924 cases** with **zero mismatches**: 65,536 first
halfword patterns, 25,800 randomized encodings covering every table row, 10,000
random packed-pair patterns, and 40,588 firmware decode positions. These are
comparisons against the reference decoder, not proof of hardware semantics.
Padding and non-code bytes in firmware are included in the linear comparison.

Native tests also cover exact short-buffer reads under ASan/UBSan, reserved
encodings, CPU selection, decoded-operation masks, relative-address behavior,
and actual radare2 loading, mixed-width analysis, delay-slot CFG fallthrough,
operand JSON, integer ESIL, signed/unsigned comparisons, signed byte loads, and
indirect calls through the link register.

For the supplied uSIP corpus, all 1,128 function ranges end exactly at a decode
boundary, totaling 100,275 instructions. The supported patterns yield 785
returns, 996 restores, 852 saves and 196 calls; 30,407 halfwords and 67,039 words
remain unresolved. This verifies structure, not the semantics of those unknown
instructions or the generality of the observed call rule.

## MD380 and related naming

The repository's `md380` plugin handles the TYT MD380 radio's firmware container
and selects ARM Thumb (`arch="arm"`, 16 bits). It is unrelated to the MD32 DSP
instruction decoder. The [MD380tools project](https://github.com/travisgoodspeed/md380tools)
likewise targets STM32 radio firmware.

The containing MediaTek DSP reverse-engineering project also describes
Coresonic cores, but its notes explicitly distinguish their 25-bit instruction
streams from the MD32 core's instruction stream. A source path containing
`coresonic` is not enough to identify an instruction encoding.

Newer products also reuse the MD32 name for RISC-V based cores. MediaTek's
[MT8395 datasheet](https://mediatek-marketing.files.svdcdn.com/production/documents/MTK_MT8395_Application-Processor-Datasheet_v1.8.pdf?dm=1724252510),
section 3.5.4, describes MD32-RV as RISC-V with proprietary DSP extensions.
Those are outside the MS15E30 decoder's scope.

## Remaining work

- Recover the newer uSIP ALU/load/store/register and full branch encodings from
  a matching compiler, disassembler, ISA manual, or hardware experiments. The
  supplied source-line and function-boundary correlations are useful evidence
  but do not establish a complete opcode specification.
- Establish delay/loop timing, carry/borrow behavior, DSP rounding/saturation,
  postincrement alias behavior, and parallel-slot data dependencies on hardware
  before extending ESIL to those operations.
- Model Harvard address-space mapping and hardware-loop back edges explicitly
  if full decompilation/emulation is required. The architecture decoder alone
  does not invent memory-map or cross-instruction state.

## Firmware follow-up

The initial validation figures above describe the earlier two-image bundle.
The newer three-image analysis, decoder corrections, strict ESIL runner and
current boot limitations are documented in the notes that
`tools/analyze_firmware.py` prints, whose generated inventory covers all 1,301
function records in the v2 bundle.

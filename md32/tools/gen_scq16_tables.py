#!/usr/bin/env python3
"""Generate scq16_opcodes.h (the SCQ16 instruction table) from isa/scq16_isa.json.

    python3 tools/gen_scq16_tables.py [isa/scq16_isa.json] [-o scq16_opcodes.h]
    python3 tools/gen_scq16_tables.py export SOURCE.py LEAVES.json [-o isa/scq16_isa.json]

The header carries everything the C decoder (scq16_decode.c) needs: one Scq16Alt per bit alternative of a form (mask/value over
the transformed unit, the delay-slot count, the flags, the operand descriptors, the text template and the ESIL template), an
index of the alternatives per unit length, the length-rule leaves (stand-alone units and packet heads: first byte and a prefix of
the second byte -> length, or a masked orphan) with their start index per first byte, the vector op9 classes and provisional
names, and the register names.  The output is deterministic: regenerating from the same JSON gives a byte-identical header.

Table layout (see README.md "SCQ16 mode" and doc/scq16.md):
  Scq16Alt { form, ref, form_name, mn, L, kind, conf, slots, nops, flags, mask, value, ops, fmt, esil }
  * mask/value are over w, the big-endian integer of the TRANSFORMED unit (A' in a packet head; byte 0 & 0x7f in a B slot or
    an orphan), bit 0 = LSB of the last byte; bit 7 of byte 0 is never part of a mask, so the same entry serves a stand-alone
    unit, a head and a B slot; within one length the first matching alternative wins (the list is ordered by specificity);
  * Scq16Operand { name, kind, fmt, npieces, is_signed, piece[2] {lo, w}, scale, bias, cval }: a register field (r5: r0-r31,
    r4: r0-r15, r4p: r1-r16, r3p: r1-r8, csr, acc), an immediate or a displacement collected from up to two bit pieces (the
    first piece is the most significant), value = (signed? sext: raw) * scale + bias, or a constant (cval) of the alternative;
  * fmt: the text template with {name} = the operand rendered by its fmt; esil: the ESIL template ({name} read, {=name} write,
    {#name} decimal value, {d} target, {ret} return address after the delay slots, {mask} of a bit-field width), NULL = no
    semantics, "" = no architectural effect;
  * flags: NAMED (an established operation name), PROV (provisional name, ends in ?), TABLELEN (form tied to the length
    table), CONTROL (control/system A': never a packet head), HYP (the ESIL is a hypothesis: the reading of a provisional
    name or of an open sign).
  Scq16Leaf { b0, depth, prefix, label }: (b0 & 0x7f, the top `depth` bits of b1) -> label > 0: length; label < 0: masked orphan
    of -label bytes; the deepest matching leaf wins.

`export` writes isa/scq16_isa.json from a form-description module (SOURCE: a Python description of the forms as Form/Alt objects
with their bit constraints, operands, text and ESIL templates, the vector classes and the register names) and the length-rule
leaves (LEAVES: a JSON with the lists "U" and "H" of [b0, depth, prefix, label, ...] rows; only those four fields are kept, the
head label ["o", n] meaning a masked orphan of n bytes).  The plugin semantics that the source does not carry yet are applied
on export (plugin_semantics(): the ESIL of the VU scalar ports as registers, the vector operations as the custom op `vop`,
the hypothetical readings of the provisional loads and of `fxts?` / `sel?` q0 c1, delayed transfers as `SETJT`/`SETD`, the
no-effect system forms, one text format fix).  The free-text notes of the source are not exported.
"""
import importlib.util
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

KINDS = ['alu', 'mv', 'mem', 'stack', 'branch', 'jump', 'call', 'ret', 'loop', 'sys', 'vec']
CONFS = ['high', 'medium', 'low', 'format-only']
OPKINDS = ['r5', 'r4', 'r4p', 'r3p', 'csr', 'acc', 'imm', 'disp', 'const']
FMTS = ['d', 'x', 'xb', 'n', 'inc', 'pm', 'h2', 'hx', 'b3', 'x04', 'x05', 'x06', 'disp', 'dispx', 'reg']
REGKINDS = ('r5', 'r4', 'r4p', 'r3p', 'csr', 'acc')
LENGTHS = (2, 3, 4, 5, 6, 8)
FL_NAMED, FL_PROV, FL_TABLELEN, FL_CONTROL, FL_HYP = 1, 2, 4, 8, 16

CONFIDENCE_LEVELS = {
    'high': 'encoding and operation established by independent checks',
    'medium': 'established by a single kind of check; a sign or width may still be open',
    'low': 'named hypothesis',
    'format-only': 'the shape (length, fields) is established but the operation is not: the mnemonic is a family placeholder',
}


def cstr(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


# ---------------------------------------------------------------------------------------------------------- export ----
# ESIL templates the form-description module does not carry: ref -> template, or {alternative index: template}; '' = no architectural effect.
PLUGIN_ESIL = {
    5: '', 6: '', 8: '',                                   # ieon / ieoff / loopend: no modelled state
    10: {0: ''},                                           # vwait?: a barrier, no modelled state
    71: '{wd},{mask},{pos},{rs},>>,&,~,{=rd},=',           # fxts?: signed bit-field extraction (hypothesis)
    82: '{imm},v{#x},=',                                   # vbcast.i v{x}, #imm (scalar shadow of the vector register)
    200: '{imm},v{#x},=',                                  # vbcast.i? (hypothesis)
    99: {1: '{rb},[2],{=r},=,{inc},{rb},+,{=rb},='},       # lhu? with post-increment (hypothesis)
    116: '{rb},[2],{=r},=,{inc},{rb},+,{=rb},=',           # lhu.post? (hypothesis)
    117: '{rb},[1],{=r},=,{inc},{rb},+,{=rb},=',           # lbu.post? (hypothesis)
    121: '{off},sp,+,[1],8,SWAP,~,{=rd},=',                # lb? -off(sp) (hypothesis: the sign)
    209: '{off},sp,+,[2],16,SWAP,~,{=rd},=',               # lh? -off(sp) (hypothesis: the sign)
    139: 'vu{#k},{=rd},=',                                 # vget rd, vu[k] (3 bytes)
    140: '{rs},v{#k},=',                                   # vbcast v{k}, rs
    141: '{rs},va{#k},=',                                  # vset.a A{k}, rs
    142: '{rs},vp{#k},=',                                  # vmem.set p{k}, rs
    143: 'vb1_{#k},{=rd},=',                               # vrd? rd, vb1[k] (hypothesis)
    214: 'vb3_{#k},{=rd},=',                               # vrd? rd, vb3[k] (hypothesis)
    215: 'vb5_{#k},{=rd},=',                               # vrd? rd, vb5[k] (hypothesis)
    216: 'udf{#k},{=rd},=',                                # udf.rd? (hypothesis)
    144: '{rs},vs{#k},=',                                  # vins? slot{k}, rs (3 bytes) (hypothesis)
    217: '{rs},vb5_{#k},=',                                # vwr? vb5[k], rs (hypothesis)
    218: '{rs},udf{#k},=',                                 # udf.wr? udf{k}, rs (hypothesis)
    187: '{F3},{F2},{F1},{B},{A},{op9},vop',               # vector operation: the custom op vop (a no-op in the plugin)
    188: '{F3},{F2},{F1},{B},{A},{op9},vop',               # bundle: the vec32 (the s1/s2 slots carry their own ESIL)
    189: '{rs},va{#ra},=',                                 # vset.a A{ra}, rs (2 bytes)
    190: '{rs},vp{#hi},=',                                 # vmem.set p{hi}, rs (2 bytes)
    191: '{rs},v{#vd},=',                                  # vbcast v{vd}, rs (2 bytes)
    192: 'vu{#k},{=rd},=',                                 # vget rd, vu[k] (2 bytes, k 0-15)
    193: 'vu{#k},{=rd},=',                                 # vget rd, vu[k] (2 bytes, k 16-31)
    196: '{rs},vs{#slot},=',                               # vins? slot{slot}, rs (2 bytes) (hypothesis)
}
# forms whose ESIL is a hypothesis (the reading of a provisional name or of an open sign): flag HYP
HYP_REFS = {71, 200, 99, 116, 117, 121, 209, 143, 214, 215, 216, 144, 217, 218, 196}
# sel? q0 c1 read as cmov.ge rd, rs, #(x - 7), ra: a new alternative with the same text as the catch-all it precedes
SEL_REF = 108
SEL_ESIL = '32,7,{x},-,~,32,{rs},~,>=,?{,{ra},{=rd},=,}'
# text format fixes: ref -> {operand: fmt}
TEXT_FMT = {66: {'x': 'xb'}}
_PC_WRITE = re.compile(r'([^,]+),pc,=')


def delayed(esil, n):
    """`X,pc,=` -> `X,SETJT,n,SETD`: the transfer is applied after n more instructions (the ESIL delay-slot mechanism)."""
    return _PC_WRITE.sub(lambda m: '%s,SETJT,%d,SETD' % (m.group(1), n), esil)


def plugin_semantics(T):
    """Apply the plugin semantics to the imported source (in memory); returns the set of hypothetical alternatives."""
    byref = {fm.ref: fm for fm in T.FORMS}
    hyp = set()
    # 1. the sel? q0 c1 alternative (skipped when the source already carries one with semantics)
    sel = byref[SEL_REF]
    catch = sel.alts[-1]
    assert catch.mn == 'sel?' and len(catch.cons) == 1
    alt = T.Alt('sel?', [T.OP(4, 0x42), T.BITS(22, 2, 0), T.BITS(20, 2, 1)], fmt='{rd}, {rs}, x{x}, {ra}  (q{q} c{c})',
                ops={'x': T.UI((10, 5), fmt='n')}, esil=SEL_ESIL)
    for k, op in alt.ops.items():
        op.name = k
    have = [a for a in sel.alts if a.mask_value() == alt.mask_value() and a.esil]
    if have:
        hyp.add(id(have[0]))
    else:
        sel.alts.insert(len(sel.alts) - 1, alt)
        hyp.add(id(alt))
    # 2. ESIL per form / alternative (an alternative with its own non-empty template keeps it)
    for ref, e in PLUGIN_ESIL.items():
        fm = byref[ref]
        if isinstance(e, dict):
            for i, s in e.items():
                fm.alts[i].esil = s
        else:
            fm.esil = e
            for a in fm.alts:
                if a.esil is not None:
                    a.esil = e if not a.esil else a.esil
    # 3. delayed transfers: the slot count of the alternative
    for fm in T.FORMS:
        if fm.kind not in ('jump', 'call', 'branch', 'ret'):
            continue
        for a in fm.alts:
            n = fm.slots_of(a)
            if not n:
                continue
            if a.esil is not None and ',pc,=' in a.esil:
                a.esil = delayed(a.esil, n)
            elif a.esil is None and fm.esil is not None and ',pc,=' in fm.esil:
                a.esil = delayed(fm.esil, n)
    # 4. text formats
    for ref, d in TEXT_FMT.items():
        for k, f in d.items():
            byref[ref].ops[k].fmt = f
    for fm in T.FORMS:
        if fm.ref in HYP_REFS:
            for a in fm.alts:
                hyp.add(id(a))
    return hyp


def load_source(path):
    spec = importlib.util.spec_from_file_location('scq16_isa_source', path)
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, os.path.dirname(os.path.abspath(path)))
    spec.loader.exec_module(mod)
    return mod


def export(source_path, leaves_path):
    T = load_source(source_path)
    hyp = plugin_semantics(T)
    pat = json.load(open(leaves_path))
    leaves = {}
    for key, name in (('U', 'unit'), ('H', 'head')):
        rows = []
        for row in pat[key]:
            b0, depth, prefix, label = row[0], row[1], row[2], row[3]
            if isinstance(label, list):
                assert label[0] == 'o'
                label = -int(label[1])
            rows.append([int(b0), int(depth), int(prefix), int(label)])
        leaves[name] = sorted(rows)
    classes = sorted(set(T.VCLASS.values()) | {'unclassified'})
    js = {
        'meta': {
            'isa': 'SCQ16 (MD32 family, byte-granular packet variant)',
            'endianness': 'big',
            'confidence_levels': CONFIDENCE_LEVELS,
            'unit': 'the minimum unit is the byte; a stand-alone unit has 2 to 6 bytes, a vector operation 4, a bundle 8; the first byte and, for some first bytes, a prefix of the second decide the length (length_leaves)',
            'packet': '{ A || B }: the head has bit 7 of its first byte set and is decoded as A\' = (unit << 1) | bit7(B); B is decoded with its first byte masked (& 0x7f); the two units execute in parallel; a transfer in B takes the packet start as the base of its displacement; a head whose A\' is a control/system form is a masked orphan (the unit decoded with b0 & 0x7f on its own)',
            'bit_numbering': 'w = big-endian integer of the transformed unit (A\' in a packet head; byte 0 & 0x7f in a B slot or an orphan), bit 0 = LSB of the last byte; bit 7 of byte 0 is never part of a mask',
            'form_order': 'within one length the first alternative whose (w & mask) == value matches wins; the list is ordered by specificity',
            'operand': 'pieces = [lo, width] bit pieces (the first is the most significant); value = (signed ? sext : raw) * scale + bias; register kinds r5 (r0-r31), r4 (r0-r15), r4p (r1-r16), r3p (r1-r8), csr, acc; a const operand is a value of the alternative',
            'esil': '{name} read, {=name} write, {#name} decimal value, {d} target, {ret} return address after the delay slots, {mask} of a bit-field width; null = no semantics, "" = no architectural effect; hypothetical = the reading of a provisional name or of an open sign',
            'length_leaves': '[b0 & 0x7f, depth, prefix of the top depth bits of b1, label]; label > 0: length in bytes, label < 0: masked orphan of -label bytes; the deepest matching leaf wins; unit = stand-alone units and B slots, head = packet heads (A\')',
            'delay_slots': 'slots = instructions (packets included) executed after a transfer or before the body of a loop',
        },
        'registers': {
            'gpr': list(T.REGS),
            'csr': [T.CSRN[i] for i in range(32)],
            'acc': [T.ACCN[i] for i in range(32)],
        },
        'kinds': KINDS,
        'forms': [],
        'length_leaves': leaves,
        'vector': {
            'classes': classes,
            'class_by_op9': {'0x%03x' % k: v for k, v in sorted(T.VCLASS.items())},
            'name_by_op9': {'0x%03x' % k: v for k, v in sorted(T.VNAME.items())},
        },
    }
    for fm in T.FORMS:
        fj = {'ref': fm.ref, 'name': fm.name, 'length': fm.L, 'kind': fm.kind, 'confidence': fm.conf, 'slots': fm.slots,
              'table_length': bool(fm.table_len), 'control': bool(T.is_control_form(fm))}
        if fm is T.VEC:
            fj['role'] = 'vector'
        elif fm is T.BUNDLE:
            fj['role'] = 'bundle'
        fj['alternatives'] = []
        for a in fm.alts:
            mask, value = a.mask_value()
            ops = []
            for k, op in fm.ops_of(a).items():
                if isinstance(op, tuple):
                    ops.append({'name': k, 'kind': 'const', 'fmt': op[2], 'value': a.consts[op[1]]})
                else:
                    ops.append({'name': k, 'kind': op.kind, 'fmt': 'reg' if op.kind in REGKINDS else op.fmt, 'pieces': [list(p) for p in op.pieces], 'signed': bool(op.signed),
                                'scale': op.scale, 'bias': op.bias})
            fj['alternatives'].append({
                'mnemonic': a.mn, 'match': '(w & %#x) == %#x' % (mask, value), 'mask': mask, 'value': value,
                'confidence': fm.conf_of(a), 'slots': fm.slots_of(a), 'named': bool(T.named_mn(fm, a.mn)),
                'provisional': a.mn.endswith('?'), 'hypothetical': id(a) in hyp, 'operands': ops,
                'text': fm.fmt_of(a), 'esil': fm.esil_of(a)})
        js['forms'].append(fj)
    return js


# -------------------------------------------------------------------------------------------------------- generate ----
def generate(js):
    forms = js['forms']
    leaves = js['length_leaves']
    vec = js['vector']
    L = []
    nalts = sum(len(f['alternatives']) for f in forms)
    L.append('/* scq16_opcodes.h - %s instruction forms.' % js['meta']['isa'])
    L.append(' * GENERATED by tools/gen_scq16_tables.py from isa/scq16_isa.json - do not edit by hand.')
    L.append(' * %d forms, %d bit alternatives; length-rule leaves: %d of stand-alone units, %d of packet heads; %d op9 codes with a vector class.' % (
        len(forms), nalts, len(leaves['unit']), len(leaves['head']), len(vec['class_by_op9'])))
    L.append(' * Convention: w = big-endian integer of the TRANSFORMED unit (A\' in a packet head; byte 0 & 0x7f in a B slot or an')
    L.append(' * orphan), bit 0 = LSB of the last byte; bit 7 of byte 0 is never part of a mask.  Alternative order = specificity:')
    L.append(' * see README.md "SCQ16 mode" and doc/scq16.md. */')
    L.append('#ifndef SCQ16_OPCODES_H')
    L.append('#define SCQ16_OPCODES_H')
    L.append('#include <stdint.h>')
    L.append('')
    L.append('enum scq16_kind { ' + ', '.join('SCQ16_K_%s' % k.upper() for k in KINDS) + ' };')
    L.append('enum scq16_conf { ' + ', '.join('SCQ16_C_%s' % c.upper().replace('-', '_') for c in CONFS) + ' };')
    L.append('enum scq16_opkind { ' + ', '.join('SCQ16_O_%s' % k.upper() for k in OPKINDS) + ' };')
    L.append('enum scq16_fmt { ' + ', '.join('SCQ16_F_%s' % f.upper() for f in FMTS) + ' };')
    L.append('#define SCQ16_FL_NAMED    1   /* an established operation name (not a family placeholder nor a vector class) */')
    L.append('#define SCQ16_FL_PROV     2   /* provisional name (ends in ?) */')
    L.append('#define SCQ16_FL_TABLELEN 4   /* form tied to the length table */')
    L.append('#define SCQ16_FL_CONTROL  8   /* control/system A\': never a packet head */')
    L.append('#define SCQ16_FL_HYP      16  /* the ESIL is a hypothesis: the reading of a provisional name or of an open sign */')
    L.append('')
    L.append('typedef struct { const char *name; uint8_t kind; uint8_t fmt; uint8_t npieces; uint8_t is_signed; struct { uint8_t lo, w; } piece[2]; int32_t scale, bias, cval; } Scq16Operand;')
    L.append('typedef struct { uint16_t form; uint16_t ref; const char *form_name; const char *mn; uint8_t L; uint8_t kind, conf, slots, nops, flags; uint64_t mask, value; const Scq16Operand *ops; const char *fmt; const char *esil; } Scq16Alt;')
    L.append('typedef struct { uint8_t b0, depth, prefix; int8_t label; } Scq16Leaf;   /* label > 0: length; < 0: masked orphan of -label bytes */')
    L.append('')
    opsets = []
    alt_rows = []
    by_len = {Lb: [] for Lb in LENGTHS}
    vec_alt = bundle_alt = None
    ai_global = 0
    for fi, fm in enumerate(forms):
        assert fm['kind'] in KINDS and fm['length'] in LENGTHS, (fm['name'], fm['kind'], fm['length'])
        for ai, a in enumerate(fm['alternatives']):
            rows = []
            for op in a['operands']:
                assert op['fmt'] in FMTS and op['kind'] in OPKINDS, (fm['name'], op)
                if op['kind'] == 'const':
                    rows.append('{ %s, SCQ16_O_CONST, SCQ16_F_%s, 0, 0, {{0,0},{0,0}}, 1, 0, %d }' % (cstr(op['name']), op['fmt'].upper(), op['value']))
                else:
                    pcs = [list(p) for p in op['pieces']] + [[0, 0]] * (2 - len(op['pieces']))
                    assert len(op['pieces']) <= 2
                    rows.append('{ %s, SCQ16_O_%s, SCQ16_F_%s, %d, %d, {{%d,%d},{%d,%d}}, %d, %d, 0 }' % (
                        cstr(op['name']), op['kind'].upper(), op['fmt'].upper(), len(op['pieces']), int(op['signed']), pcs[0][0], pcs[0][1], pcs[1][0], pcs[1][1], op['scale'], op['bias']))
            name = 'ops_%d_%d' % (fi, ai)
            if rows:
                opsets.append('static const Scq16Operand %s[] = {\n  %s\n};' % (name, ',\n  '.join(rows)))
            else:
                name = 'NULL'
            mask, value = a['mask'], a['value']
            assert fm.get('role') in ('vector', 'bundle') or not (mask >> (8 * fm['length'] - 1)) & 1, (fm['name'], 'mask over bit 7 of byte 0')
            flags = 0
            if a['named']:
                flags |= FL_NAMED
            if a['provisional']:
                flags |= FL_PROV
            if fm['table_length']:
                flags |= FL_TABLELEN
            if fm['control']:
                flags |= FL_CONTROL
            if a['hypothetical']:
                flags |= FL_HYP
            assert a['confidence'] in CONFS, (fm['name'], a['confidence'])
            esil = a['esil']
            alt_rows.append('  { %d, %d, %s, %s, %d, SCQ16_K_%s, SCQ16_C_%s, %d, %d, %d, 0x%xULL, 0x%xULL, %s, %s, %s }' % (
                fi, fm['ref'], cstr(fm['name']), cstr(a['mnemonic']), fm['length'], fm['kind'].upper(), a['confidence'].upper().replace('-', '_'),
                a['slots'], len(rows), flags, mask, value, name, cstr(a['text']), cstr(esil) if esil is not None else 'NULL'))
            by_len[fm['length']].append(ai_global)
            if fm.get('role') == 'vector' and vec_alt is None:
                vec_alt = ai_global
            if fm.get('role') == 'bundle' and bundle_alt is None:
                bundle_alt = ai_global
            ai_global += 1
    assert vec_alt is not None and bundle_alt is not None, 'the vector and bundle forms must carry their role'
    L += opsets
    L.append('')
    L.append('#define SCQ16_NFORMS %d' % len(forms))
    L.append('#define SCQ16_NALTS %d' % nalts)
    L.append('static const Scq16Alt scq16_alts[SCQ16_NALTS] = {')
    L.append(',\n'.join(alt_rows))
    L.append('};')
    for Lb in LENGTHS:
        idx = by_len[Lb]
        L.append('static const uint16_t scq16_alts_L%d[] = { %s };' % (Lb, ', '.join(str(i) for i in idx) if idx else '0'))
        L.append('#define SCQ16_NALTS_L%d %d' % (Lb, len(idx)))
    L.append('#define SCQ16_VEC_ALT %d' % vec_alt)
    L.append('#define SCQ16_BUNDLE_ALT %d' % bundle_alt)
    L.append('')
    U = sorted(tuple(r) for r in leaves['unit'])
    H = sorted(tuple(r) for r in leaves['head'])
    L.append('/* length-rule leaves: (b0 & 0x7f, the top `depth` bits of b1) -> L; the deepest matching leaf wins */')
    L.append('static const Scq16Leaf scq16_uleaves[] = {')
    L.append(',\n'.join('  { 0x%02x, %d, 0x%02x, %d }' % (b0, d, p, lab) for b0, d, p, lab in U))
    L.append('};')
    L.append('#define SCQ16_NULEAVES %d' % len(U))
    L.append('/* head leaves: (a0, prefix of a1) of the shifted unit A\' -> L(A\') or -Lm (masked orphan of Lm bytes) */')
    L.append('static const Scq16Leaf scq16_hleaves[] = {')
    L.append(',\n'.join('  { 0x%02x, %d, 0x%02x, %d }' % (b0, d, p, lab) for b0, d, p, lab in H))
    L.append('};')
    L.append('#define SCQ16_NHLEAVES %d' % len(H))
    for nm, lst in (('u', U), ('h', H)):
        starts = []
        j = 0
        for b0 in range(129):
            while j < len(lst) and lst[j][0] < b0:
                j += 1
            starts.append(j)
        L.append('static const uint16_t scq16_%sleaf_start[129] = { %s };' % (nm, ', '.join(str(s) for s in starts)))
    L.append('')
    classes = vec['classes']
    L.append('static const char *const scq16_vclass_names[] = { %s };' % ', '.join(cstr(c) for c in classes))
    vc = [classes.index(vec['class_by_op9'].get('0x%03x' % i, 'unclassified')) for i in range(512)]
    L.append('static const uint8_t scq16_vclass[512] = {\n  ' + ',\n  '.join(', '.join(str(x) for x in vc[i:i + 32]) for i in range(0, 512, 32)) + '\n};')
    vn = ['NULL'] * 512
    for k, v in vec['name_by_op9'].items():
        vn[int(k, 16)] = cstr(v)
    L.append('static const char *const scq16_vname[512] = {\n  ' + ',\n  '.join(', '.join(vn[i:i + 16]) for i in range(0, 512, 16)) + '\n};')
    L.append('')
    regs = js['registers']
    assert len(regs['gpr']) == 32 and len(regs['csr']) == 32 and len(regs['acc']) == 32
    L.append('static const char *const scq16_regs[32] = { %s };' % ', '.join(cstr(r) for r in regs['gpr']))
    L.append('static const char *const scq16_csrs[32] = { %s };' % ', '.join(cstr(r) for r in regs['csr']))
    L.append('static const char *const scq16_accs[32] = { %s };' % ', '.join(cstr(r) for r in regs['acc']))
    L.append('static const char *const scq16_kind_names[] = { %s };' % ', '.join(cstr(k) for k in KINDS))
    L.append('static const char *const scq16_conf_names[] = { %s };' % ', '.join(cstr(c) for c in CONFS))
    L.append('#endif')
    return '\n'.join(L) + '\n'


def main(argv):
    out = argv[argv.index('-o') + 1] if '-o' in argv else None
    args = [a for i, a in enumerate(argv) if a != '-o' and (i == 0 or argv[i - 1] != '-o')]
    if args and args[0] == 'export':
        if len(args) != 3:
            print(__doc__)
            return 2
        js = export(args[1], args[2])
        out = out or os.path.join(ROOT, 'isa', 'scq16_isa.json')
        with open(out, 'w', encoding='utf-8') as fh:
            json.dump(js, fh, indent=1, ensure_ascii=False)
            fh.write('\n')
        print('wrote %s: %d forms, %d alternatives, %d unit leaves, %d head leaves' % (
            out, len(js['forms']), sum(len(f['alternatives']) for f in js['forms']), len(js['length_leaves']['unit']), len(js['length_leaves']['head'])))
        return 0
    src = args[0] if args else os.path.join(ROOT, 'isa', 'scq16_isa.json')
    out = out or os.path.join(ROOT, 'scq16_opcodes.h')
    js = json.load(open(src, encoding='utf-8'))
    text = generate(js)
    with open(out, 'w', encoding='utf-8') as fh:
        fh.write(text)
    print('wrote %s: %d forms, %d alternatives' % (out, len(js['forms']), sum(len(f['alternatives']) for f in js['forms'])))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

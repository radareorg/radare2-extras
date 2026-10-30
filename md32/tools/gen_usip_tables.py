#!/usr/bin/env python3
"""Generate usip_opcodes.h (the uSIP instruction table) from isa/usip_isa.json.

    python3 tools/gen_usip_tables.py [isa/usip_isa.json] [-o usip_opcodes.h]

Compared with a plain mask/value table this header also carries
everything the C packet decoder (usip_decode.c) needs: every operand field referenced by the format string OR by a
constraint, the constraints as structured data (not strings), 16-bit flags and the indices of the context-only forms.

Table layout (see README.md "uSIP mode"):
  UsipOpcode { name, form, value, mask, width, nunits, flags, kind, conf, fmt, nargs, nfields, fields[], ncons, cons[] }
  * value/mask are over the big-endian concatenation of the units (bit width-1 = bit 15 of the head); 16-bit forms are
    matched with bit 15 masked out unless the mask says otherwise (the bit is the packet-close bit);
  * fields[]: operand fields; the first nargs are the ones used by fmt, in order of first use; each one = type + up to
    7 [hi,lo] bit ranges (MSB first, concatenated), USIP_BITS_ZERO(n) = n implicit zero bits; nbits/scale/base for the
    value transform;
  * fmt: operand template with {N} = fields[N] (rendered by type), {N:text} = text if the flag field N is set;
  * cons[]: constraints that are not mask/value (register/address windows, guards, packet rules).
"""
import json, os, sys, re, collections

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

TYPES = ['reg', 'imm', 'simm', 'rotimm', 'urot', 'disp', 'udisp', 'absaddr', 'acc', 'accw', 'csr', 'csr_ext', 'flag']
CONF = {'high': 'USIP_CONF_HIGH', 'medium-high': 'USIP_CONF_HIGH', 'medium': 'USIP_CONF_MEDIUM',
        'low-medium': 'USIP_CONF_MEDIUM', 'low': 'USIP_CONF_LOW', 'format-only': 'USIP_CONF_FORMAT'}
CONS_OPS = ['eq', 'ne', 'lt', 'in', 'notin', 'range', 'ranges', 'even', 'not_hi1010', 'eq_fields', 'packet_len',
            'slot0_excludes_head', 'any_eq', 'guard_setcc_tail', 'guard_tail_not_named16', 'guard_or2_tail']
MAXFIELDS = 8
MAXCONS = 3
MAXVALS = 6
# 16-bit ld/st forms whose x bit (head bit 8) selects a byte access: the decoder renames .w -> .b
XBYTE_FORMS = ('ld_E_3', 'ld_E_b', 'st_E_7', 'st_E_f')


def cstr(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def cons_entries(c, fidx):
    """one constraint dict -> (op, field, field2, [vals]); 'any' is only used as (F' == 0 || S == 0)"""
    if 'any' in c:
        alts = c['any']
        if len(alts) != 2 or any('eq' not in a or 'field' not in a for a in alts) or alts[0]['eq'] != alts[1]['eq']:
            raise SystemExit('unsupported any-constraint: %r' % c)
        return ('any_eq', fidx[alts[0]['field']], fidx[alts[1]['field']], [alts[0]['eq']])
    if 'guard' in c:
        gd = c['guard']
        if gd == 'setcc_tail':
            return ('guard_setcc_tail', 0xff, 0xff, c.get('small', [0, 2, 4, 0xFFE, 0xFFF]))
        if gd == 'tail_not_named16':
            return ('guard_tail_not_named16', 0xff, 0xff, [])
        if gd == 'or2_tail':
            return ('guard_or2_tail', fidx['u12'], 0xff, [])
        raise SystemExit('unknown guard %s' % gd)
    if 'eq_fields' in c:
        a, b = c['eq_fields']
        return ('eq_fields', fidx[a], fidx[b], [])
    if 'packet_len' in c:
        return ('packet_len', 0xff, 0xff, [c['packet_len']])
    if 'slot0_excludes_head' in c:
        m, v = c['slot0_excludes_head']
        return ('slot0_excludes_head', 0xff, 0xff, [m, v])
    f = fidx[c['field']]
    for op in ('eq', 'ne', 'lt'):
        if op in c:
            return (op, f, 0xff, [c[op]])
    if 'in' in c:
        return ('in', f, 0xff, list(c['in']))
    if 'notin' in c:
        return ('notin', f, 0xff, list(c['notin']))
    if 'range' in c:
        return ('range', f, 0xff, list(c['range']))
    if 'ranges' in c:
        return ('ranges', f, 0xff, [v for lo, hi in c['ranges'] for v in (lo, hi)])
    if 'even' in c:
        return ('even', f, 0xff, [])
    if 'not_hi1010' in c:
        return ('not_hi1010', f, 0xff, [])
    raise SystemExit('unknown constraint %r' % c)


def cons_fields(c):
    if 'any' in c:
        return [a['field'] for a in c['any']]
    if 'guard' in c:
        return ['u12'] if c['guard'] == 'or2_tail' else []
    if 'eq_fields' in c:
        return list(c['eq_fields'])
    return [c['field']] if 'field' in c else []


def exported_fields(form):
    """(template with {N}, [field dicts]): format fields first (order of first use), then constraint-only fields"""
    fmt = form['format']; fields = {f['name']: f for f in form['fields']}
    names = []; out = []; i = 0
    while i < len(fmt):
        if fmt[i] == '{':
            j = fmt.index('}', i); tok = fmt[i + 1:j]; i = j + 1
            nm, txt = (tok.split(':', 1) + [None])[:2]
            if nm not in fields:
                out.append('{' + tok + '}'); continue
            if nm not in names:
                names.append(nm)
            k = names.index(nm)
            out.append('{%d}' % k if txt is None else '{%d:%s}' % (k, txt))
        else:
            out.append(fmt[i]); i += 1
    nargs = len(names)
    for c in form.get('constraints', []):
        for nm in cons_fields(c):
            if nm not in fields:
                raise SystemExit('%s: constraint field %s missing' % (form['name'], nm))
            if nm not in names:
                names.append(nm)
    return ''.join(out), nargs, [fields[n] for n in names]


def emit(isa, out_path):
    forms = isa['forms']
    kinds = sorted({f['kind'] for f in forms})
    L = []
    A = L.append
    A('/* usip_opcodes.h - uSIP (MD32 family, VLIW packet variant) instruction forms.')
    A(' * GENERATED by tools/gen_usip_tables.py from isa/usip_isa.json - do not edit by hand.')
    A(' * Units are 16-bit big-endian halfwords; bit 15 of a unit closes the packet; an instruction is a head (bit 15 = 0) plus')
    A(' * 0, 1 or 2 tails that are NOT necessarily adjacent (heads first, tails round-robin): see README.md "uSIP mode". */')
    A('#ifndef USIP_OPCODES_H')
    A('#define USIP_OPCODES_H')
    A('')
    A('enum usip_arg_type {')
    for t in TYPES:
        A('\tUSIP_A_%s,' % t.upper())
    A('};')
    A('')
    A('enum usip_kind {')
    for k in kinds:
        A('\tUSIP_K_%s,' % k.upper().replace('.', '_'))
    A('};')
    A('')
    A('enum usip_conf { USIP_CONF_HIGH, USIP_CONF_MEDIUM, USIP_CONF_LOW, USIP_CONF_FORMAT };')
    A('')
    A('enum usip_cons_op {')
    for op in CONS_OPS:
        A('\tUSIP_C_%s,' % op.upper())
    A('};')
    A('')
    A('#define USIP_F_SLOT0     0x001  /* only valid as the first unit of a packet */')
    A('#define USIP_F_NOTSLOT0  0x002  /* never the first unit of a packet */')
    A('#define USIP_F_CTX       0x004  /* context rule: never matched directly (bz.s P4) */')
    A('#define USIP_F_DELAY     0x008  /* rest of the packet is a delay slot when the instruction does not close it */')
    A('#define USIP_F_ADJ1      0x010  /* tail must be the next unit */')
    A('#define USIP_F_ADJCTRL   0x020  /* tail at +1 (S=1) or +2 (S=0) */')
    A('#define USIP_F_NAMED     0x040  /* operation known (not format-only) */')
    A('#define USIP_F_NOTAIL    0x080  /* 16-bit op that never takes a tail (ret/save/restore) */')
    A('#define USIP_F_UNKNOWN16 0x100  /* 16-bit shape that does not count as a named 16-bit op (loose syllables, .hword) */')
    A('#define USIP_F_XBYTE     0x200  /* 16-bit ld/st: head bit 8 selects a byte access (.w -> .b) */')
    A('')
    A('#define USIP_BITS_ZERO(n)  { 0xff, (n) }   /* n implicit zero bits in the operand value */')
    A('#define USIP_MAXRANGES 7')
    A('#define USIP_MAXFIELDS %d' % MAXFIELDS)
    A('#define USIP_MAXCONS %d' % MAXCONS)
    A('#define USIP_MAXVALS %d' % MAXVALS)
    A('#define USIP_NOFIELD 0xff')
    A('')
    A('typedef struct { ut8 hi, lo; } UsipBits;')
    A('typedef struct {')
    A('\tconst char *name;   /* operand name in usip_isa.json */')
    A('\tut8 type;           /* enum usip_arg_type */')
    A('\tut8 nranges;')
    A('\tUsipBits r[USIP_MAXRANGES];  /* MSB first, concatenated */')
    A('\tut8 nbits;          /* rotimm/urot: rotation width; 0 = total bits */')
    A('\tut8 scale;          /* disp/udisp: multiplier (2 = halfword units) */')
    A('\tut32 base;          /* absaddr: OR-ed segment base */')
    A('} UsipField;')
    A('')
    A('typedef struct {')
    A('\tut8 op;             /* enum usip_cons_op */')
    A('\tut8 field, field2;  /* indices into UsipOpcode.fields (USIP_NOFIELD when unused) */')
    A('\tut8 nvals;')
    A('\tst32 vals[USIP_MAXVALS];  /* eq/ne/lt: [v]; in/notin: set; range: [lo, hi); ranges: pairs; slot0_excludes_head: [mask, value];')
    A('\t                           * packet_len: [n]; any_eq: [v] (field == v || field2 == v); guard_setcc_tail: the small set */')
    A('} UsipCons;')
    A('')
    A('typedef struct usip_opcode_t {')
    A('\tconst char *name;   /* mnemonic (format-only forms start with "." or end with "?") */')
    A('\tconst char *form;   /* stable form id (usip_isa.json) */')
    A('\tut64 value;         /* over the concatenated units, bit width-1 = head bit 15 */')
    A('\tut64 mask;')
    A('\tut8 width;          /* 16, 32, 48 */')
    A('\tut8 nunits;')
    A('\tut16 flags;         /* USIP_F_* */')
    A('\tut8 kind;           /* enum usip_kind */')
    A('\tut8 conf;           /* enum usip_conf */')
    A('\tconst char *fmt;    /* operand template: {N} = fields[N], {N:text} = text when flag fields[N] is 1 */')
    A('\tut8 nargs;          /* fields used by fmt */')
    A('\tut8 nfields;        /* nargs + fields referenced only by constraints */')
    A('\tUsipField fields[USIP_MAXFIELDS];')
    A('\tut8 ncons;')
    A('\tUsipCons cons[USIP_MAXCONS];')
    A('} UsipOpcode;')
    A('')
    A('#ifndef USIP_OPCODES_NO_TABLE  /* define it to get the types and enums only */')
    A('/* The table is ORDERED: the first entry of the right width whose (units & mask) == value, whose flags allow the slot')
    A(' * and whose constraints hold is the reading. */')
    A('static const UsipOpcode usip_opcodes[] = {')
    ctx_index = {}
    for idx, f in enumerate(forms):
        fl = []
        if f.get('slot0_only'): fl.append('USIP_F_SLOT0')
        if f.get('not_slot0'): fl.append('USIP_F_NOTSLOT0')
        if f.get('context_only'):
            fl.append('USIP_F_CTX'); ctx_index[f['name']] = idx
        if f.get('delay_slot'): fl.append('USIP_F_DELAY')
        if f.get('tail_adjacency') == 1: fl.append('USIP_F_ADJ1')
        if f.get('tail_adjacency') == 'ctrl': fl.append('USIP_F_ADJCTRL')
        if f.get('named'): fl.append('USIP_F_NAMED')
        if f['width'] == 16 and 'never takes a tail' in f.get('packet_rules', ''): fl.append('USIP_F_NOTAIL')
        if not f.get('known16', True): fl.append('USIP_F_UNKNOWN16')
        if f['name'] in XBYTE_FORMS: fl.append('USIP_F_XBYTE')
        flags = ' | '.join(fl) if fl else '0'
        tmpl, nargs, fields = exported_fields(f)
        if len(fields) > MAXFIELDS:
            raise SystemExit('%s: too many fields' % f['name'])
        fidx = {x['name']: i for i, x in enumerate(fields)}
        cons = [cons_entries(c, fidx) for c in f.get('constraints', [])]
        if len(cons) > MAXCONS:
            raise SystemExit('%s: too many constraints' % f['name'])
        n = f['width'] // 16
        A('\t/* %s: %s */' % (f['name'], f.get('semantics', '')[:110].replace('*/', '* /')))
        A('\t{ %s, %s, 0x%0*xULL, 0x%0*xULL, %d, %d,' % (cstr(f['mnemonic']), cstr(f['name']), 4 * n, int(f['match']['value'], 16),
                                                         4 * n, int(f['match']['mask'], 16), f['width'], n))
        A('\t  %s, USIP_K_%s, %s, %s, %d, %d, {' % (flags, f['kind'].upper().replace('.', '_'), CONF[f['confidence']], cstr(tmpl), nargs, len(fields)))
        for a in fields:
            rs = []
            for r in a['bits']:
                rs.append('USIP_BITS_ZERO(%d)' % r[1] if r[0] == 'z' else '{%d, %d}' % (r[0], r[1]))
            if len(rs) > 7:
                raise SystemExit('%s/%s: too many ranges' % (f['name'], a['name']))
            base = '0x%08x' % (a.get('seg', 0) << 26) if a['type'] == 'absaddr' else '0'
            A('\t\t{ %s, USIP_A_%s, %d, { %s }, %d, %d, %s },' % (cstr(a['name']), a['type'].upper(), len(rs), ', '.join(rs), a.get('nbits', 0), a.get('scale', 1), base))
        if cons:
            A('\t  }, %d, {' % len(cons))
            for op, fi, fi2, vals in cons:
                if len(vals) > MAXVALS:
                    raise SystemExit('%s: too many constraint values' % f['name'])
                A('\t\t{ USIP_C_%s, %s, %s, %d, { %s } },' % (op.upper(), fi if fi != 0xff else 'USIP_NOFIELD', fi2 if fi2 != 0xff else 'USIP_NOFIELD',
                                                           len(vals), ', '.join(str(v) for v in vals) if vals else '0'))
            A('\t  } },')
        else:
            A('\t  }, 0, { { 0, 0, 0, 0, { 0 } } } },')
    A('};')
    A('')
    A('/* context-only forms (matched by the packet decoder only) */')
    for nm, idx in sorted(ctx_index.items()):
        A('#define USIP_FORM_%s %d' % (nm.upper(), idx))
    A('')
    A('/* condition codes by (op nibble, tail bits 13:12) */')
    A('static const char *const usip_cond_imm8[3][4] = { /* op 9 */ {"ne", "eq", "le", "lt"}, /* op 8 */ {"ne.u8", "eq.u8", "leu", "ltu"}, /* op a */ {"geu", "gtu", "ge", "gt"} };')
    A('static const char *const usip_cond_reg[2][4] = { /* op d */ {"ne", "eq", "le", "lt"}, /* op c: t2 0/1 = zero forms */ {"nez", "eqz", "leu", "ltu"} };')
    A('')
    csr = isa['structure']['registers']['csr_classic']
    A('static const char *const usip_csr_classic[16] = { ' + ', '.join(cstr(x) for x in csr) + ' };')
    A('static const ut32 usip_seg[8] = { 0x00000000, 0x04000000, 0x08000000, 0x0c000000, 0x10000000, 0x14000000, 0x18000000, 0x1c000000 }; /* SEG[A] = A << 26; only A = 0, 6, 7 observed */')
    A('')
    A('/* save/restore register sets: index = w */')
    A('static const char *const usip_save_set[8] = { "r8,r9,r10,LR", "r12,r8!,r9!,r10!", "r11!,r12!,r13!,r14!,r13", NULL, "r8", "r12,r8!", "r11!,r12!", NULL };')
    A('')
    A('/* heads that must take a tail (structure.packet.must_pair): mask, value, allowed tail counts (bit n = n tails) */')
    A('typedef struct { ut16 mask, value; ut8 tails; } UsipMustPair;')
    A('static const UsipMustPair usip_must_pair[] = {')
    for d in isa['structure']['packet'].get('must_pair', []):
        bits = 0
        for t in d['tails']:
            bits |= 1 << t
        A('\t{ 0x%04x, 0x%04x, 0x%x }, /* %s */' % (int(d['mask'], 16), int(d['value'], 16), bits, d.get('why', '')))
    A('};')
    A('#endif /* USIP_OPCODES_NO_TABLE */')
    A('')
    A('#endif /* USIP_OPCODES_H */')
    with open(out_path, 'w') as fh:
        fh.write('\n'.join(L) + '\n')
    print('%s: %d entries; by confidence %s' % (out_path, len(forms), dict(collections.Counter(f['confidence'] for f in forms))))


def main():
    args = sys.argv[1:]
    out = os.path.join(ROOT, 'usip_opcodes.h')
    if '-o' in args:
        out = args[args.index('-o') + 1]
        del args[args.index('-o'):args.index('-o') + 2]
    src = args[0] if args else os.path.join(ROOT, 'isa', 'usip_isa.json')
    with open(src) as fh:
        emit(json.load(fh), out)


if __name__ == '__main__':
    main()

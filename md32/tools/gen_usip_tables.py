#!/usr/bin/env python3
"""Generate usip_opcodes.h (the uSIP instruction table) from isa/usip_isa.json.

    python3 tools/gen_usip_tables.py [isa/usip_isa.json] [-o usip_opcodes.h]

Compared with a plain mask/value table this header also carries everything the C packet decoder (usip_decode.c)
needs: every operand field referenced by the format string OR by a constraint, the constraints as structured data
(not strings), 16-bit flags, the indices of the context-only forms and the auxiliary tables of the ISA description
(must-pair heads, save/restore sets, sys-shape names, CSR names).  The output is deterministic: regenerating from the
same JSON gives a byte-identical header.

Table layout (see README.md "uSIP mode" and doc/usip.md):
  UsipOpcode { name, form, value, mask, width, nunits, flags, kind, conf, fmt, nargs, nfields, fields[], ncons, cons[] }
  * value/mask are over the big-endian concatenation of the units (bit width-1 = bit 15 of the head); 16-bit forms are
    matched with the mask as given (bit 15 is the packet-close bit: forms whose mask includes it match only closers);
  * fields[]: operand fields; the first nargs are the ones used by fmt, in order of first use; each one = type + up to
    7 [hi,lo] bit ranges (MSB first, concatenated), USIP_BITS_ZERO(n) = n implicit zero bits; nbits/scale/base for the
    value transform (base = segment base for absaddr, pc offset for disp, a constant added to the field for the other
    integer types);
  * fmt: operand template with {N} = fields[N] (rendered by type), {N:text} = text if the flag field N is set;
  * cons[]: constraints that are not mask/value (register/address windows, guards, packet rules); the target guards
    (guard_target_*) and the b.s guard are evaluated by the decoder after the match, with the packet/function context it
    has; the position/length constraints (packet_len, packet_len_ge, head_index, head_index_ge, ctx) of the 32/48-bit
    entries are deferred too: when they fail the decoder falls through to the next entry of the same cell.

Operand types offh (half-word offset), offw (word offset), loopn (loop count) and movhi (collected bits << 12) have
their own value formula in the decoder; the flags ADJDEF (tail at +2 or farther), PREFIX (packet-prefix entries matched
on the first units of the packet before the layout), RENAME (position rename scored as the underlying reading) and HHTT
(context entries admitted only inside the H H T T candidate) complete the packet rules of the table.
"""
import json, os, sys, collections

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

TYPES = ['reg', 'imm', 'simm', 'rotimm', 'urot', 'disp', 'udisp', 'absaddr', 'acc', 'accw', 'csr', 'csr_ext', 'flag', 'movhi',
         'offh', 'offw', 'loopn']
CONF = {'high': 'USIP_CONF_HIGH', 'medium-high': 'USIP_CONF_HIGH', 'medium': 'USIP_CONF_MEDIUM',
        'low-medium': 'USIP_CONF_MEDIUM', 'low': 'USIP_CONF_LOW', 'format-only': 'USIP_CONF_FORMAT'}
CONS_OPS = ['eq', 'ne', 'lt', 'ge', 'gt', 'in', 'notin', 'inmask', 'notinmask', 'range', 'ranges', 'even', 'odd', 'not_hi1010',
            'eq_fields', 'ne_fields', 'packet_len', 'packet_len_ge', 'head_index', 'head_index_ge', 'ctx',
            'slot0_excludes_head', 'any',
            'guard_setcc_tail', 'guard_tail_not_named16', 'guard_or2_tail',
            'guard_target_packet_start', 'guard_target_function_start', 'guard_target_fn_or_packet_start',
            'guard_head_not_validated_bs']
ANY_OPS = {'eq': 0, 'ne': 1, 'lt': 2, 'ge': 3, 'gt': 4, 'inmask': 5, 'notinmask': 6}
CTX_IDS = {'not_ext_of_op67': 0}
GUARDS = {'setcc_tail': 'guard_setcc_tail', 'tail_not_named16': 'guard_tail_not_named16', 'or2_tail': 'guard_or2_tail',
          'target_packet_start_same_function': 'guard_target_packet_start',
          'target_function_start': 'guard_target_function_start',
          'target_fn_or_packet_start_same_function': 'guard_target_fn_or_packet_start',
          'head_not_validated_bs': 'guard_head_not_validated_bs'}
MAXFIELDS = 12
MAXCONS = 8
MAXVALS = 9
MAXRANGES = 8
MAXANY = 3
SAVE_SET = ['r8,r9,r10,LR', 'r12,r8!,r9!,r10!', 'r11!,r12!,r13!,r14!', None, 'LR,r8', 'r12,r8!', 'r11!,r12!', None]


def cstr(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def simple_cons(c):
    """(op, value) of a one-field sub-constraint of `any`: a comparison, or a set as a 31-bit membership mask"""
    for op in ('eq', 'ne', 'lt', 'ge', 'gt'):
        if op in c:
            return op, c[op]
    for op in ('in', 'notin'):
        if op in c:
            if not all(isinstance(v, int) and 0 <= v < 31 for v in c[op]):
                raise SystemExit('set sub-constraint out of the mask range: %r' % c)
            m = 0
            for v in c[op]:
                m |= 1 << v
            return op + 'mask', m
    raise SystemExit('unsupported sub-constraint %r' % c)


def set_cons(op, f, vals):
    """in/notin: a value list when it fits, else a 64-bit membership mask (all values in 0..63)"""
    vals = list(vals)
    if len(vals) <= MAXVALS:
        return (op, f, 0xff, vals)
    if all(isinstance(v, int) and 0 <= v < 64 for v in vals):
        m = 0
        for v in vals:
            m |= 1 << v
        return (op + 'mask', f, 0xff, [m & 0xffffffff, m >> 32])
    raise SystemExit('set constraint too large: %r' % vals)


def cons_entries(c, fidx, width):
    """one constraint dict -> (op, field, field2, [vals])"""
    if 'any' in c:
        alts = c['any']
        if not 1 <= len(alts) <= MAXANY or any('field' not in a for a in alts):
            raise SystemExit('unsupported any-constraint: %r' % c)
        vals = []
        for a in alts:
            op, v = simple_cons(a)
            vals += [fidx[a['field']], ANY_OPS[op], v]
        return ('any', 0xff, 0xff, vals)
    if 'guard' in c:
        gd = c['guard']
        if gd not in GUARDS:
            raise SystemExit('unknown guard %s' % gd)
        if gd == 'setcc_tail':
            return (GUARDS[gd], 0xff, 0xff, c.get('small', [0, 2, 4, 0xFFE, 0xFFF]))
        if gd == 'or2_tail':
            return (GUARDS[gd], fidx['u12'], 0xff, [])
        return (GUARDS[gd], 0xff, 0xff, [])
    if 'eq_fields' in c:
        a, b = c['eq_fields']
        return ('eq_fields', fidx[a], fidx[b], [])
    if 'ne_fields' in c:
        a, b = c['ne_fields']
        return ('ne_fields', fidx[a], fidx[b], [])
    if 'packet_len' in c:
        if width == 16 and c['packet_len'] not in (1, 2):
            raise SystemExit('packet_len %r: the decoder caches 16-bit matches by packet length class 1 / 2 / 3+' % c['packet_len'])
        return ('packet_len', 0xff, 0xff, [c['packet_len']])
    if 'packet_len_ge' in c:
        if width == 16 and c['packet_len_ge'] != 2:
            raise SystemExit('packet_len_ge %r: the decoder caches 16-bit matches by packet length class 1 / 2 / 3+' % c['packet_len_ge'])
        return ('packet_len_ge', 0xff, 0xff, [c['packet_len_ge']])
    if 'head_index' in c:
        if width == 16 and c['head_index'] != 0:
            raise SystemExit('head_index %r: the decoder caches 16-bit matches by head index class 0 / 1 / 2+' % c['head_index'])
        return ('head_index', 0xff, 0xff, [c['head_index']])
    if 'head_index_ge' in c or 'head_pos_ge' in c:
        # (head_pos_ge: the spelling of the public copy of the table)
        v = c.get('head_index_ge', c.get('head_pos_ge'))
        if width == 16 and v != 2:
            raise SystemExit('head_index_ge %r: the decoder caches 16-bit matches by head index class 0 / 1 / 2+' % v)
        return ('head_index_ge', 0xff, 0xff, [v])
    if 'ctx' in c:
        if c['ctx'] not in CTX_IDS:
            raise SystemExit('unknown context condition %s' % c['ctx'])
        return ('ctx', 0xff, 0xff, [CTX_IDS[c['ctx']]])
    if 'slot0_excludes_head' in c:
        m, v = c['slot0_excludes_head']
        return ('slot0_excludes_head', 0xff, 0xff, [m, v])
    f = fidx[c['field']]
    for op in ('eq', 'ne', 'lt', 'ge', 'gt'):
        if op in c:
            return (op, f, 0xff, [c[op]])
    if 'in' in c:
        return set_cons('in', f, c['in'])
    if 'notin' in c:
        return set_cons('notin', f, c['notin'])
    if 'range' in c:
        return ('range', f, 0xff, list(c['range']))
    if 'ranges' in c:
        return ('ranges', f, 0xff, [v for lo, hi in c['ranges'] for v in (lo, hi)])
    if 'even' in c:
        return ('even', f, 0xff, [])
    if 'odd' in c:
        return ('odd', f, 0xff, [])
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
    if 'ne_fields' in c:
        return list(c['ne_fields'])
    return [c['field']] if 'field' in c else []


def exported_fields(form):
    """(template with {N}, nargs, [field dicts]): format fields first (order of first use), then constraint-only fields"""
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


def field_base(a):
    """UsipField.base: segment base (absaddr), pc offset (disp) or the constant added to the field value"""
    if a['type'] == 'absaddr':
        return '0x%08x' % (a.get('seg', 0) << 26)
    if a['type'] == 'disp':
        return str(a.get('pc_offset', 0))
    return str(a.get('offset', 0))


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
    A('/* sub-operations of USIP_C_ANY: vals = { field, op, value } triplets (up to %d), true when one of them holds;' % MAXANY)
    A(' * inmask/notinmask: value = membership mask of the field value (bit n = value n) */')
    A('enum usip_any_op { USIP_ANY_EQ, USIP_ANY_NE, USIP_ANY_LT, USIP_ANY_GE, USIP_ANY_GT, USIP_ANY_INMASK, USIP_ANY_NOTINMASK };')
    A('')
    A('/* named context conditions of USIP_C_CTX (vals[0]) */')
    A('enum usip_ctx_cond { USIP_CTX_NOT_EXT_OF_OP67 };')
    A('')
    A('#define USIP_F_SLOT0     0x001  /* only valid as the first unit of a packet */')
    A('#define USIP_F_NOTSLOT0  0x002  /* never the first unit of a packet */')
    A('#define USIP_F_CTX       0x004  /* context rule: never matched directly (bz.s P4, the R7 slot forms) */')
    A('#define USIP_F_DELAY     0x008  /* rest of the packet is a delay slot when the instruction does not close it */')
    A('#define USIP_F_ADJ1      0x010  /* tail must be the next unit */')
    A('#define USIP_F_ADJCTRL   0x020  /* tail at +1 (S=1) or +2 (S=0) */')
    A('#define USIP_F_NAMED     0x040  /* operation known (not format-only) */')
    A('#define USIP_F_NOTAIL    0x080  /* 16-bit op that never takes a tail (ret/save/restore) */')
    A("#define USIP_F_ADJ2      0x100  /* control tail with F' = 0 EXACTLY at +2 (the unit in between is the delay slot); any other distance = .word (loop# with F = 1 at +1: two 16-bit ops) */")
    A('#define USIP_F_UNKNOWN16 0x200  /* 16-bit shape that does not count as a named 16-bit op (loose syllables, .hword, stand-alone closers) */')
    A('#define USIP_F_ADJDEF    0x400  /* the tail must be at +2 or FARTHER; an adjacent tail undoes the pair into two 16-bit ops */')
    A('#define USIP_F_PREFIX    0x800  /* packet-prefix entry (48/64-bit b<cond>.l): matched on the first units of the packet BEFORE the layout, with its target guard; a failing guard = not taken (never .word); the rest of the packet is its delay slot */')
    A('#define USIP_F_RENAME    0x1000 /* position rename: the layout score counts the unit as its underlying reading (an unknown unit) */')
    A('#define USIP_F_HHTT      0x2000 /* context entry admitted only inside the H H T T candidate of a 4-unit packet */')
    A('')
    A('#define USIP_BITS_ZERO(n)  { 0xff, (n) }   /* n implicit zero bits in the operand value */')
    A('#define USIP_MAXRANGES %d' % MAXRANGES)
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
    A('\tut8 scale;          /* imm/simm/disp/udisp: multiplier (2 = halfword units, 4 = words); offh/offw/loopn/movhi have their own formula */')
    A('\tut32 base;          /* absaddr: OR-ed segment base; disp: pc offset of the target; reg/imm/udisp/...: constant ADDED to the field value */')
    A('} UsipField;')
    A('')
    A('typedef struct {')
    A('\tut8 op;             /* enum usip_cons_op */')
    A('\tut8 field, field2;  /* indices into UsipOpcode.fields (USIP_NOFIELD when unused) */')
    A('\tut8 nvals;')
    A('\tst32 vals[USIP_MAXVALS];  /* eq/ne/lt/ge/gt: [v]; in/notin: set; inmask/notinmask: [lo32, hi32] of a 64-bit membership mask;')
    A('\t                           * range: [lo, hi); ranges: pairs; slot0_excludes_head: [mask, value]; packet_len(_ge) / head_index(_ge): [n];')
    A('\t                           * ctx: [enum usip_ctx_cond]; any: [field, op, value] triplets (enum usip_any_op); guard_setcc_tail: the small set */')
    A('} UsipCons;')
    A('')
    A('typedef struct usip_opcode_t {')
    A('\tconst char *name;   /* mnemonic (format-only forms start with "." or end with "?") */')
    A('\tconst char *form;   /* stable form id (usip_isa.json) */')
    A('\tut64 value;         /* over the concatenated units, bit width-1 = head bit 15 */')
    A('\tut64 mask;')
    A('\tut8 width;          /* 16, 32, 48, 64 (the 64-bit packet-prefix entries) */')
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
    A(' * and whose constraints hold is the reading.  The target guards (USIP_C_GUARD_TARGET_*) are evaluated by the decoder')
    A(' * AFTER the match: for 32-bit entries a failing guard makes the pair .word (no fall-through), for 16-bit entries it')
    A(' * falls through to the next entry; for the USIP_F_PREFIX entries a failing guard means the entry is not taken.  The')
    A(' * position / length constraints (USIP_C_PACKET_LEN(_GE), USIP_C_HEAD_INDEX(_GE), USIP_C_CTX) need the packet context')
    A(' * (unknown = the constraint fails) and, on the 32/48-bit entries, a failure falls through to the next entry of the cell;')
    A(' * USIP_C_GUARD_HEAD_NOT_VALIDATED_BS undoes the pair into two 16-bit ops. */')
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
        if f.get('tail_adjacency') == 2: fl.append('USIP_F_ADJ2')
        if not f.get('known16', True): fl.append('USIP_F_UNKNOWN16')
        if f.get('tail_adjacency') == 'defer': fl.append('USIP_F_ADJDEF')
        if f.get('packet_prefix'): fl.append('USIP_F_PREFIX')
        if f.get('rename_only'): fl.append('USIP_F_RENAME')
        if f.get('group') == 'hhtt': fl.append('USIP_F_HHTT')
        flags = ' | '.join(fl) if fl else '0'
        tmpl, nargs, fields = exported_fields(f)
        if len(fields) > MAXFIELDS:
            raise SystemExit('%s: too many fields' % f['name'])
        fidx = {x['name']: i for i, x in enumerate(fields)}
        cons = [cons_entries(c, fidx, f['width']) for c in f.get('constraints', [])]
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
            if len(rs) > MAXRANGES:
                raise SystemExit('%s/%s: too many ranges' % (f['name'], a['name']))
            A('\t\t{ %s, USIP_A_%s, %d, { %s }, %d, %d, %s },' % (cstr(a['name']), a['type'].upper(), len(rs), ', '.join(rs), a.get('nbits', 0), a.get('scale', 1), field_base(a)))
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
    A('/* kind names, in enum usip_kind order */')
    A('static const char *const usip_kind_names[] = { ' + ', '.join(cstr(k) for k in kinds) + ' };')
    A('')
    A('/* context-only forms (matched by the packet decoder only) */')
    for nm, idx in sorted(ctx_index.items()):
        A('#define USIP_FORM_%s %d' % (nm.upper(), idx))
    A('')
    A('/* condition codes by (op nibble, tail bits 13:12) */')
    A('static const char *const usip_cond_imm8[3][4] = { /* op 9 */ {"ne", "eq", "le", "lt"}, /* op 8 */ {"ne.u8", "eq.u8", "leu", "ltu"}, /* op a */ {"geu", "gtu", "ge", "gt"} };')
    A('static const char *const usip_cond_reg[2][4] = { /* op d */ {"ne", "eq", "le", "lt"}, /* op c: t2 0/1 = zero forms */ {"nez", "eqz", "leu", "ltu"} };')
    A("/* 48/64-bit b<cond>.l (the USIP_F_PREFIX entries) by (op nibble of the head - 0xb, bits 13:12 of the second unit); NULL = condition open (bcc48?).")
    A(" * op b = register-register, op c = unsigned immediate, op d-f = signed immediate */")
    bcc = isa['structure'].get('conditions', {}).get('bcc48', {})
    rows = []
    for op in ('op b', 'op c', 'op d', 'op e', 'op f'):
        cells = bcc.get(op, {})
        rows.append('{ ' + ', '.join((cstr(cells[k].split(' ')[0].replace('.l', '')) if k in cells else 'NULL') for k in ('00', '01', '10', '11')) + ' }')
    A('static const char *const usip_cond_bcc48[5][4] = { ' + ', '.join(rows) + ' };')
    A('')
    regs = isa['structure']['registers']
    csr = regs['csr_classic']
    A('/* classic CSR names (the md32 csr field type; no uSIP form uses it) */')
    A('static const char *const usip_csr_classic[16] = { ' + ', '.join(cstr(x) for x in csr) + ' };')
    names = regs.get('csr_extended_names', {})
    A('/* extended CSR names (mfcsr/mtcsr number): index = CSR number 0x00-0x3f, NULL = unnamed */')
    A('static const char *const usip_csr_ext[64] = { ' + ', '.join(cstr(names['0x%02x' % i].split(' ')[0]) if '0x%02x' % i in names else 'NULL' for i in range(64)) + ' };')
    A('static const ut32 usip_seg[8] = { 0x00000000, 0x04000000, 0x08000000, 0x0c000000, 0x10000000, 0x14000000, 0x18000000, 0x1c000000 }; /* SEG[A] = A << 26; only A = 0, 6, 7 observed */')
    A('')
    A('/* save/restore register sets: index = w (w = 2 is four words, w = 4 two) */')
    A('static const char *const usip_save_set[8] = { ' + ', '.join(cstr(x) if x else 'NULL' for x in SAVE_SET) + ' };')
    A('')
    sysops = isa['structure'].get('sys_ops', {}).get('fld_4', {})
    A('/* names of the `sys` shape [0][1][00][rrr][x][B][1111] + d000 (tail field fld = 4) by B; NULL = plain sys #n.')
    A(' * fld 0: B = 15 ret / jr rB; fld 1: call rB; fld 2: ret? (B = 15); the F = S = 0 twins (tail 5000) use the same names */')
    A('static const char *const usip_sys_fld4[16] = { ' + ', '.join(cstr(sysops[str(i)].split(' ')[0]) if str(i) in sysops else 'NULL' for i in range(16)) + ' };')
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

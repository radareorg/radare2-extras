#!/usr/bin/env python3
"""Generate usip_opcodes.h (the uSIP instruction table) from isa/usip_isa.json.

    python3 tools/gen_usip_tables.py [isa/usip_isa.json] [-o usip_opcodes.h]

Compared with a plain mask/value table this header also carries everything the C packet decoder (usip_decode.c)
needs: every operand field referenced by the format string OR by a constraint, the constraints as structured data
(not strings), the entry flags, the indices of the context-only forms and the auxiliary tables of the ISA description
(must-pair heads, save/restore sets, sys-shape names, CSR names, the R-br0 cells, the 48-bit value and address
tables).  The output is deterministic: regenerating from the same JSON gives a byte-identical header.

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
    has; the position/length constraints (packet_len, packet_len_ge, head_index, head_index_ge, ctx, br0_cells) of the
    32/48-bit entries are deferred too: when they fail the decoder falls through to the next entry of the same cell.

Operand types offh (half-word offset), offw (14-bit word displacement), offb (byte displacement), loopn (loop count)
and movhi (collected bits << 12) have their own value formula in the decoder; the flags ADJDEF (tail at +2 or farther),
PREFIX (packet-prefix entries matched on the first units of the packet before the layout), RENAME (post-layout rename:
the entry is never used by the packet parser; once the layout is decided an instruction whose reading is one of the
entry's rename_from mnemonics, or "@kind", and whose units match the entry and its constraints is relabelled), HHTT
(context entries admitted only inside the H H T T candidate), B111 (context entries admitted in the 2-unit head + tail
packet and inside the H H T T candidate), F0CTX (context entries tried by the decoder when an op 0 head with its F' = 0
tail at +2 reads .word) and GUARDFT (a failing target guard falls through to the next entry of the cell instead of
making the pair .word; no entry left = two 16-bit ops) complete the packet rules of the table.  The constraints
tail_adjacent (the single tail is or is not the next unit), ieee_short (the value is the high word of a short IEEE-754
double), bf_valid (the bit-field cell is valid), br0_cells (the B class of the head and the distance of the tail are
one of the admitted cells; br0_cells_live lists the cells that only hold at the live-trace sites, which the plugin
never takes), the context conditions and the membership in the 48-bit value table (in_c48tab) are evaluated by the
decoder with the packet context; the auxiliary tables usip_never_tail / usip_never_head_with_tail (units that are never
a tail / heads that never take one), usip_c48_table (the 48-bit constants admitted by value), usip_br0_cells /
usip_br0_cells_weak (the R-br0 cells by (op, tt, B class, distance)) and usip_c48sym_table (the data addresses already
formed by the 48-bit family, for the R-c48sym tie-break) come from the JSON.

Table update (726 forms): the loopn operand type is the collected bits as is (loop #N = head bits 13:5, no +1: the
formula lives in the decoder); the flag FUSE (post-layout fusion: two adjacent one-unit instructions whose readings are
the two rename_from mnemonics, head and tail, and whose units match the entry become one two-unit instruction); the flag
SPLIT (an entry of the post-layout split procedure of the slot family, applied by the decoder's split pass and never by
the generic rename pass; the JSON key split_role: "either" = head or re-read tail of a split pair, "bare" = a bare unit
renamed before the pass) with a USIP_FORM_* index for every such entry; the constraint op instr_index (the position of
the INSTRUCTION inside the decoded packet, not the unit index); `any` with up to four alternatives, which may now be a
context condition or an instr_index test; six new context conditions (not_loop_reg_head, delay_slot_of_validated_branch,
target_beyond_packet, delay_slot_not_writing_rA, op4imm_head_multiunit, split_unit).

Table update (760 forms): the guards loop_b4_straddle16 (the loop #N entries: bit 4 of the head, field b4, must agree with
"the packet at the loop end crosses a 16-byte line"; exported with the field b4) and not_over_validated_call32 (the 64-bit
b<cond>.l entries whose extension unit is any 16-bit unit X: not taken over a validated 32-bit call / b read from U0 + X);
seven new context conditions (tail_at_plus2, head_unnamed_not_lsl0, rf0dall_guards, slotc_pair, call_within_2_packets,
op4imm_head, add2_free_closer); FUSE together with ADJ2 marks the fusion at distance 2 (add2_rot12); the loop #N? rule of
structure.packet.loop_imm_q (USIP_LOOPQ_N_EQ, usip_loopq_d12[]) and the packet execution model (USIP_PACKET_EXEC_PARALLEL)
are emitted as constants.
"""
import json, os, sys, collections

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

TYPES = ['reg', 'imm', 'simm', 'rotimm', 'urot', 'disp', 'udisp', 'absaddr', 'acc', 'accw', 'csr', 'csr_ext', 'flag', 'movhi',
         'offh', 'offw', 'loopn', 'offb']
CONF = {'high': 'USIP_CONF_HIGH', 'medium-high': 'USIP_CONF_HIGH', 'medium': 'USIP_CONF_MEDIUM',
        'low-medium': 'USIP_CONF_MEDIUM', 'low': 'USIP_CONF_LOW', 'format-only': 'USIP_CONF_FORMAT'}
CONS_OPS = ['eq', 'ne', 'lt', 'ge', 'gt', 'in', 'notin', 'inmask', 'notinmask', 'range', 'ranges', 'even', 'odd', 'not_hi1010',
            'eq_fields', 'ne_fields', 'packet_len', 'packet_len_ge', 'head_index', 'head_index_ge', 'ctx', 'instr_index',
            'slot0_excludes_head', 'any',
            'guard_setcc_tail', 'guard_tail_not_named16', 'guard_or2_tail',
            'guard_target_packet_start', 'guard_target_function_start', 'guard_target_fn_or_packet_start',
            'guard_head_not_validated_bs',
            'tail_adjacent', 'ieee_short', 'in_c48tab',
            'guard_target_pk_any_or_fn', 'guard_tail_named16', 'br0_cells', 'br0_cells_live', 'bf_valid', 'in_set', 'notin_set',
            'guard_loop_b4_straddle16', 'guard_not_over_validated_call32']
ANY_OPS = {'eq': 0, 'ne': 1, 'lt': 2, 'ge': 3, 'gt': 4, 'inmask': 5, 'notinmask': 6, 'tail_adjacent': 7,
           'packet_len': 8, 'guard': 9, 'range': 10, 'br0_cells': 11, 'br0_cells_live': 12, 'instr_index': 13, 'ctx': 14}
# guards that may appear inside an `any` (USIP_ANY_GUARD: value = enum usip_guard_id)
GUARD_IDS = {'tail_not_named16': 0, 'target_packet_start_same_function': 1}
CTX_IDS = {'not_ext_of_op67': 0, 'cop_rA_in_packet': 1, 'not_c48_lo_follows': 2,
           'b111_layout': 3, 'hhtt_second_head': 4, 'f0d_triple': 5, 'bfpair': 6, 'bf_dst_not_written': 7,
           'between_dsp_head_and_tail': 8, 'rest_named_no_q': 9,
           'not_loop_reg_head': 10, 'delay_slot_of_validated_branch': 11, 'target_beyond_packet': 12,
           'delay_slot_not_writing_rA': 13, 'op4imm_head_multiunit': 14, 'split_unit': 15,
           'tail_at_plus2': 16, 'head_unnamed_not_lsl0': 17, 'rf0dall_guards': 18, 'slotc_pair': 19, 'call_within_2_packets': 20,
           'op4imm_head': 21, 'add2_free_closer': 22}
CTX_FIELDS = {'cop_rA_in_packet': ['rA'], 'bf_dst_not_written': ['rB', 'x']}
GUARDS = {'setcc_tail': 'guard_setcc_tail', 'tail_not_named16': 'guard_tail_not_named16', 'or2_tail': 'guard_or2_tail',
          'target_packet_start_same_function': 'guard_target_packet_start',
          'target_function_start': 'guard_target_function_start',
          'target_fn_or_packet_start_same_function': 'guard_target_fn_or_packet_start',
          'head_not_validated_bs': 'guard_head_not_validated_bs',
          'target_packet_start_any_or_function_start': 'guard_target_pk_any_or_fn',
          'tail_named16': 'guard_tail_named16',
          'loop_b4_straddle16': 'guard_loop_b4_straddle16',
          'not_over_validated_call32': 'guard_not_over_validated_call32'}
# fields a guard reads beyond the tail (exported after the format fields)
GUARD_FIELDS = {'or2_tail': ['u12'], 'loop_b4_straddle16': ['b4']}
# R-br0 cells: B class of the head (B0 = B == 0, B15 = B == 15, B = any other) x tail distance (1 / 2) as a bit mask
BR0_CLASS = {'B0': 0, 'B15': 1, 'B': 2}
MAXFIELDS = 12
MAXCONS = 8
MAXVALS = 12
MAXRANGES = 8
MAXANY = 4
SAVE_SET = ['r8,r9,r10,LR', 'r12,r8!,r9!,r10!', 'r11!,r12!,r13!,r14!', None, 'LR,r8', 'r12,r8!', 'r11!,r12!', None]


def cstr(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def cident(s):
    """a form name as a C identifier fragment"""
    return ''.join(ch if ch.isalnum() or ch == '_' else '_' for ch in s)


def br0_mask(cells):
    m = 0
    for cls, dist in cells:
        if cls not in BR0_CLASS or dist not in (1, 2):
            raise SystemExit('unsupported br0 cell %r' % ((cls, dist),))
        m |= 1 << (2 * BR0_CLASS[cls] + dist - 1)
    return m


C48 = []   # the 48-bit value table (the `in` set of the c48tab entries), filled by emit()
SETS = []  # the large value sets (USIP_C_IN_SET / USIP_C_NOTIN_SET: vals[0] = index into usip_value_sets[]), filled by set_cons()


def simple_cons(c):
    """(op, value) of a sub-constraint of `any`: a comparison, a set as a 31-bit membership mask, tail_adjacent, a packet
    length, a guard, a half-open range (value = lo | hi << 16) or an R-br0 cell list (value = cell mask)"""
    if 'tail_adjacent' in c:
        return 'tail_adjacent', 1 if c['tail_adjacent'] else 0
    if 'packet_len' in c:
        return 'packet_len', c['packet_len']
    if 'guard' in c:
        if c['guard'] not in GUARD_IDS:
            raise SystemExit('unsupported guard inside any: %r' % c)
        return 'guard', GUARD_IDS[c['guard']]
    if 'range' in c:
        lo, hi = c['range']
        if not (0 <= lo < 0x10000 and 0 <= hi < 0x8000):
            raise SystemExit('range sub-constraint out of the packed value: %r' % c)
        return 'range', lo | (hi << 16)
    if 'br0_cells' in c:
        return 'br0_cells', br0_mask(c['br0_cells'])
    if 'br0_cells_live' in c:
        return 'br0_cells_live', br0_mask(c['br0_cells_live'])
    if 'instr_index' in c:
        return 'instr_index', c['instr_index']
    if 'ctx' in c:
        if c['ctx'] not in CTX_IDS:
            raise SystemExit('unknown context condition inside any: %s' % c['ctx'])
        return 'ctx', CTX_IDS[c['ctx']]
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


def any_field(a):
    """the field a sub-constraint of `any` reads (None when it has none)"""
    if 'field' in a:
        return a['field']
    if 'br0_cells' in a or 'br0_cells_live' in a:
        return 'rB'
    return None


def set_cons(op, f, vals):
    """in/notin: a value list when it fits, else a 64-bit membership mask (all values in 0..63); the 48-bit value table by reference"""
    vals = list(vals)
    if op == 'in' and C48 and sorted(vals) == sorted(C48):
        return ('in_c48tab', f, 0xff, [])
    if len(vals) <= MAXVALS:
        return (op, f, 0xff, vals)
    if all(isinstance(v, int) and 0 <= v < 64 for v in vals):
        m = 0
        for v in vals:
            m |= 1 << v
        return (op + 'mask', f, 0xff, [m & 0xffffffff, m >> 32])
    if not all(isinstance(v, int) for v in vals):
        raise SystemExit('set constraint too large: %r' % vals)
    key = tuple(sorted(set(vals)))
    if key not in SETS:
        SETS.append(key)
    return (op + '_set', f, 0xff, [SETS.index(key)])


def cons_entries(c, fidx, width, rename=False, ctxform=False):
    """one constraint dict -> (op, field, field2, [vals]); rename = the entry is a post-layout rename (its position
    constraints are evaluated with the exact head index, not through the 16-bit match cache); ctxform = a context-only
    entry (matched by the decoder's context rules, never through the cache)"""
    if 'any' in c:
        alts = c['any']
        if not 1 <= len(alts) <= MAXANY:
            raise SystemExit('unsupported any-constraint: %r' % c)
        vals = []
        for a in alts:
            op, v = simple_cons(a)
            if op == 'packet_len' and width == 16 and not rename and not ctxform and v not in (1, 2):
                raise SystemExit('packet_len %r inside any: the decoder caches 16-bit matches by packet length class 1 / 2 / 3+' % v)
            fl = any_field(a)
            vals += [fidx[fl] if fl is not None else 0xff, ANY_OPS[op], v]
        return ('any', 0xff, 0xff, vals)
    if 'tail_adjacent' in c:
        return ('tail_adjacent', 0xff, 0xff, [1 if c['tail_adjacent'] else 0])
    if 'ieee_short' in c:
        return ('ieee_short', fidx[c['field']], 0xff, [c['ieee_short']])
    if 'br0_cells' in c:
        return ('br0_cells', fidx['rB'], 0xff, [br0_mask(c['br0_cells'])])
    if 'br0_cells_live' in c:
        return ('br0_cells_live', fidx['rB'], 0xff, [br0_mask(c['br0_cells_live'])])
    if 'bf_valid' in c:
        return ('bf_valid', fidx['w'], fidx['pos'], [])
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
        if width == 16 and not rename and not ctxform and c['packet_len'] not in (1, 2):
            raise SystemExit('packet_len %r: the decoder caches 16-bit matches by packet length class 1 / 2 / 3+' % c['packet_len'])
        return ('packet_len', 0xff, 0xff, [c['packet_len']])
    if 'packet_len_ge' in c:
        if width == 16 and not rename and not ctxform and c['packet_len_ge'] != 2:
            raise SystemExit('packet_len_ge %r: the decoder caches 16-bit matches by packet length class 1 / 2 / 3+' % c['packet_len_ge'])
        return ('packet_len_ge', 0xff, 0xff, [c['packet_len_ge']])
    if 'head_index' in c:
        if width == 16 and not rename and not ctxform and c['head_index'] != 0:
            raise SystemExit('head_index %r: the decoder caches 16-bit matches by head index class 0 / 1 / 2+' % c['head_index'])
        return ('head_index', 0xff, 0xff, [c['head_index']])
    if 'instr_index' in c:
        return ('instr_index', 0xff, 0xff, [c['instr_index']])
    if 'head_index_ge' in c or 'head_pos_ge' in c:
        # (head_pos_ge: the spelling of the public copy of the table)
        v = c.get('head_index_ge', c.get('head_pos_ge'))
        if width == 16 and not rename and not ctxform and v != 2:
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
        return [any_field(a) for a in c['any'] if any_field(a) is not None] + [f for a in c['any'] if 'ctx' in a for f in CTX_FIELDS.get(a['ctx'], [])]
    if 'guard' in c:
        return list(GUARD_FIELDS.get(c['guard'], []))
    if 'eq_fields' in c:
        return list(c['eq_fields'])
    if 'ne_fields' in c:
        return list(c['ne_fields'])
    if 'br0_cells' in c or 'br0_cells_live' in c:
        return ['rB']
    if 'bf_valid' in c:
        return ['w', 'pos']
    if 'ctx' in c:
        return CTX_FIELDS.get(c['ctx'], [])
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


def br0_rows(cells):
    rows = []
    for op, tt, cls, dist in cells:
        if cls not in BR0_CLASS or dist not in (1, 2):
            raise SystemExit('unsupported br0 cell %r' % ((op, tt, cls, dist),))
        rows.append('{ 0x%x, %d, %d, %d }' % (op, tt, BR0_CLASS[cls], dist))
    return rows


def emit(isa, out_path):
    forms = isa['forms']
    kinds = sorted({f['kind'] for f in forms})
    del C48[:]
    del SETS[:]
    for f in forms:
        if f.get('group') == 'c48tab':
            for c in f.get('constraints', []):
                if c.get('field') == 'val' and 'in' in c:
                    C48.extend(c['in'])
            break
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
    A(' * inmask/notinmask: value = membership mask of the field value (bit n = value n); tail_adjacent: value = 0 / 1 (no field);')
    A(' * packet_len: value = the packet length (no field); guard: value = enum usip_guard_id (no field; a target guard inside an')
    A(' * any is evaluated by the context rule of the entry); range: value = lo | hi << 16 (lo <= field < hi);')
    A(' * br0_cells / br0_cells_live: value = cell mask (see USIP_C_BR0_CELLS), field = rB; instr_index: value = the position')
    A(' * of the instruction inside the decoded packet (no field); ctx: value = enum usip_ctx_cond (no field) */')
    A('enum usip_any_op { USIP_ANY_EQ, USIP_ANY_NE, USIP_ANY_LT, USIP_ANY_GE, USIP_ANY_GT, USIP_ANY_INMASK, USIP_ANY_NOTINMASK, USIP_ANY_TAIL_ADJACENT,')
    A('\tUSIP_ANY_PACKET_LEN, USIP_ANY_GUARD, USIP_ANY_RANGE, USIP_ANY_BR0_CELLS, USIP_ANY_BR0_CELLS_LIVE, USIP_ANY_INSTR_INDEX, USIP_ANY_CTX };')
    A('')
    A('/* guards that may appear inside USIP_C_ANY (USIP_ANY_GUARD) */')
    A('enum usip_guard_id { USIP_GD_TAIL_NOT_NAMED16, USIP_GD_TARGET_PACKET_START };')
    A('')
    A('/* named context conditions of USIP_C_CTX (vals[0]): not the extension word of an op 6/7 head; some `cop rA` with the same rA in the')
    A(' * packet; the tail is not 5ffd followed by bfff/ffff (the 48-bit constant 0x7fff7fff); the ld.bu / st.b pair of type 111 only in')
    A(' * the 2-unit head + tail packet or in the H H T T layout (never an O syllable after an op 7 head); the second head of H H T T')
    A(' * after a named ld/st; the [head][head-shaped unit][F\' = 0 tail at +2] triple; the bit-field pair layout; no other WAW-kind')
    A(' * instruction of the packet writes rB; unit 1 between a DSP head and its tail; the rest of the packet named without a ?;')
    A(' * the first-slot unit is not the head of a validated `loop rX` (a [S][0][11][d12] tail at +1 / +2 with its end a packet')
    A(' * start of the function after it); the unit is a .movi6? closer in the delay slot of a validated branch at unit 0; the')
    A(' * target of the 3-unit bz.s lies beyond the packet; its re-parsed delay slot does not write rA; the F = 0 head of a split')
    A(' * .op4imm pair in a packet of more than two units; the unit is the head or the re-read tail of a split pair; the single tail')
    A(' * is EXACTLY at +2 (else the entry falls through); the best reading leaves the first unit unnamed and it is not the bare')
    A(" * op 5 x = 0 unit; the align guardians of the F' = 0 half-word load with any base (the unit at +2 is not a trusted 16-bit op")
    A(' * nor control, the head is not 4400 after an op f x = 1 head, the middle unit does not write sp); the op c head with F = 0')
    A(' * and its single unnamed tail form a slot pair; some call in the packet or in the two following ones; the F = 0 head of a')
    A(' * split .op4imm pair; the bare .hword head and the bare unnamed closer at +2 fuse into add rB, rA, #rot12 (nowaw) */')
    A('enum usip_ctx_cond { USIP_CTX_NOT_EXT_OF_OP67, USIP_CTX_COP_RA_IN_PACKET, USIP_CTX_NOT_C48_LO_FOLLOWS, USIP_CTX_B111_LAYOUT,')
    A('\tUSIP_CTX_HHTT_SECOND_HEAD, USIP_CTX_F0D_TRIPLE, USIP_CTX_BFPAIR, USIP_CTX_BF_DST_NOT_WRITTEN, USIP_CTX_BETWEEN_DSP_HEAD_AND_TAIL,')
    A('\tUSIP_CTX_REST_NAMED_NO_Q, USIP_CTX_NOT_LOOP_REG_HEAD, USIP_CTX_DELAY_SLOT_OF_VALIDATED_BRANCH, USIP_CTX_TARGET_BEYOND_PACKET,')
    A('\tUSIP_CTX_DELAY_SLOT_NOT_WRITING_RA, USIP_CTX_OP4IMM_HEAD_MULTIUNIT, USIP_CTX_SPLIT_UNIT, USIP_CTX_TAIL_AT_PLUS2,')
    A('\tUSIP_CTX_HEAD_UNNAMED_NOT_LSL0, USIP_CTX_RF0DALL_GUARDS, USIP_CTX_SLOTC_PAIR, USIP_CTX_CALL_WITHIN_2_PACKETS, USIP_CTX_OP4IMM_HEAD,')
    A('\tUSIP_CTX_ADD2_FREE_CLOSER };')
    A('')
    A('#define USIP_F_SLOT0     0x001  /* only valid as the first unit of a packet */')
    A('#define USIP_F_NOTSLOT0  0x002  /* never the first unit of a packet */')
    A('#define USIP_F_CTX       0x004  /* context rule: never matched directly (bz.s P4/P5, the R7 slot forms, the hhtt / b111 / f0ctx groups) */')
    A('#define USIP_F_DELAY     0x008  /* rest of the packet is a delay slot when the instruction does not close it */')
    A('#define USIP_F_ADJ1      0x010  /* tail must be the next unit */')
    A('#define USIP_F_ADJCTRL   0x020  /* tail at +1 (S=1) or +2 (S=0) */')
    A('#define USIP_F_NAMED     0x040  /* operation known (not format-only) */')
    A('#define USIP_F_NOTAIL    0x080  /* 16-bit op that never takes a tail (ret/save/restore) */')
    A("#define USIP_F_ADJ2      0x100  /* control tail with F' = 0 EXACTLY at +2 (the unit in between is the delay slot); any other distance = .word (loop# with F = 1 at +1, and a ld/st entry: two 16-bit ops) */")
    A('#define USIP_F_UNKNOWN16 0x200  /* 16-bit shape that does not count as a named 16-bit op (loose syllables, .hword, stand-alone closers) */')
    A('#define USIP_F_ADJDEF    0x400  /* the tail must be at +2 or FARTHER; an adjacent tail undoes the pair into two 16-bit ops */')
    A('#define USIP_F_PREFIX    0x800  /* packet-prefix entry (48/64-bit b<cond>.l): matched on the first units of the packet BEFORE the layout, with its target guard; a failing guard = not taken (never .word); the rest of the packet is its delay slot */')
    A('#define USIP_F_RENAME    0x1000 /* post-layout rename: never used by the packet parser; once the layout is decided, an instruction whose reading is one of rename_from (mnemonic or @kind) and whose units match the entry and its constraints takes its name */')
    A('#define USIP_F_HHTT      0x2000 /* context entry admitted only inside the H H T T candidate of a 4-unit packet */')
    A('#define USIP_F_GUARDFT   0x4000 /* a failing target guard falls through to the next entry of the cell (no entry left: two 16-bit ops), never .word */')
    A('#define USIP_F_B111      0x8000 /* context entry (ld.bu / st.b with a named 16-bit tail) admitted in the 2-unit head + tail packet and inside the H H T T candidate */')
    A("#define USIP_F_F0CTX     0x10000 /* context entry tried by the decoder when an op 0 head with its F' = 0 tail at +2 reads .word (never by the pairing) */")
    A('#define USIP_F_FUSE      0x20000 /* post-layout FUSION: two ADJACENT one-unit instructions whose readings are the two rename_from mnemonics (head, tail) and whose units match the entry (+ its constraints) become ONE two-unit instruction of this entry; never used by the parser nor by the generic rename pass; with USIP_F_ADJ2 the fusion is at DISTANCE 2 (a bare head at i and a bare unnamed closer at i + 2) */')
    A('#define USIP_F_SPLIT     0x40000 /* entry of the post-layout split procedure of the slot family (the decoder applies it in its split pass, by USIP_FORM_* index; never the parser nor the generic rename pass); USIP_F_SPLITBARE marks the ones applied to bare units before the pass */')
    A('#define USIP_F_SPLITBARE 0x80000')
    A('')
    A('#define USIP_BITS_ZERO(n)  { 0xff, (n) }   /* n implicit zero bits in the operand value */')
    A('#define USIP_MAXRANGES %d' % MAXRANGES)
    A('#define USIP_MAXFIELDS %d' % MAXFIELDS)
    A('#define USIP_MAXCONS %d' % MAXCONS)
    A('#define USIP_MAXVALS %d' % MAXVALS)
    A('#define USIP_NOFIELD 0xff')
    A('')
    A('/* USIP_C_BR0_CELLS / USIP_C_BR0_CELLS_LIVE: vals[0] = mask of the admitted (B class, tail distance) cells of the F = 0 branch head:')
    A(' * bit 2 * class + distance - 1, class 0 = B == 0, 1 = B == 15, 2 = any other B, distance 1 / 2 (the tail at +1 or +2) */')
    A('#define USIP_BR0_BIT(cls, dist) (1 << (2 * (cls) + (dist) - 1))')
    A('')
    pkx = isa['structure']['packet']
    A('/* packet execution model (structure.packet.execution): the instructions of a packet execute in PARALLEL and every read sees')
    A(' * the state BEFORE the packet (an emulator reads all the operands of the packet before any write; two writes of the same')
    A(' * register in one packet are an impossible layout) */')
    A('#define USIP_PACKET_EXEC_PARALLEL %d' % (1 if 'execution' in pkx else 0))
    lq = pkx.get('loop_imm_q', {})
    A('/* the loop #N? rule (structure.packet.loop_imm_q): a loop #N reading with N == USIP_LOOPQ_N_EQ or whose tail displacement d12')
    A(' * is one of usip_loopq_d12[] prints loop #N? (mnemonic loop#?); the layout candidate loopcand does not admit it */')
    A('#define USIP_LOOPQ_N_EQ %d' % lq.get('N_eq', 0))
    A('#define USIP_LOOPQ_ENABLED %d' % (1 if lq else 0))
    A('static const ut16 usip_loopq_d12[%d] = { %s };' % (max(1, len(lq.get('last_d12_in', []))), ', '.join('0x%04x' % int(x, 16) for x in lq.get('last_d12_in', [])) or '0'))
    A('')
    A('typedef struct { ut8 hi, lo; } UsipBits;')
    A('typedef struct {')
    A('\tconst char *name;   /* operand name in usip_isa.json */')
    A('\tut8 type;           /* enum usip_arg_type */')
    A('\tut8 nranges;')
    A('\tUsipBits r[USIP_MAXRANGES];  /* MSB first, concatenated */')
    A('\tut8 nbits;          /* rotimm/urot: rotation width; 0 = total bits */')
    A('\tut8 scale;          /* imm/simm/disp/udisp: multiplier (2 = halfword units, 4 = words); offh/offw/offb/loopn/movhi have their own formula */')
    A('\tut32 base;          /* absaddr: OR-ed segment base; disp: pc offset of the target; reg/imm/udisp/...: constant ADDED to the field value */')
    A('} UsipField;')
    A('')
    A('typedef struct {')
    A('\tut8 op;             /* enum usip_cons_op */')
    A('\tut8 field, field2;  /* indices into UsipOpcode.fields (USIP_NOFIELD when unused) */')
    A('\tut8 nvals;')
    A('\tst32 vals[USIP_MAXVALS];  /* eq/ne/lt/ge/gt: [v]; in/notin: set; inmask/notinmask: [lo32, hi32] of a 64-bit membership mask;')
    A('\t                           * range: [lo, hi); ranges: pairs; slot0_excludes_head: [mask, value]; packet_len(_ge) / head_index(_ge) / instr_index: [n];')
    A('\t                           * ctx: [enum usip_ctx_cond]; any: [field, op, value] triplets (enum usip_any_op; field = USIP_NOFIELD when the')
    A('\t                           * sub-operation has none); guard_setcc_tail: the small set; tail_adjacent: [0 | 1]; ieee_short: [significant digits];')
    A('\t                           * in_c48tab: none; br0_cells(_live): [cell mask] with field = rB; bf_valid: none (field = w, field2 = pos);')
    A('\t                           * in_set / notin_set: [index into usip_value_sets] (the sets too large for vals) */')
    A('} UsipCons;')
    A('')
    A('typedef struct usip_opcode_t {')
    A('\tconst char *name;   /* mnemonic (format-only forms start with "." or end with "?") */')
    A('\tconst char *form;   /* stable form id (usip_isa.json) */')
    A('\tut64 value;         /* over the concatenated units, bit width-1 = head bit 15 */')
    A('\tut64 mask;')
    A('\tut8 width;          /* 16, 32, 48, 64 (the 64-bit packet-prefix entries) */')
    A('\tut8 nunits;')
    A('\tut32 flags;         /* USIP_F_* */')
    A('\tut8 kind;           /* enum usip_kind */')
    A('\tut8 conf;           /* enum usip_conf */')
    A('\tconst char *fmt;    /* operand template: {N} = fields[N], {N:text} = text when flag fields[N] is 1 */')
    A('\tut8 nargs;          /* fields used by fmt */')
    A('\tut8 nfields;        /* nargs + fields referenced only by constraints */')
    A('\tUsipField fields[USIP_MAXFIELDS];')
    A('\tut8 ncons;')
    A('\tUsipCons cons[USIP_MAXCONS];')
    A('\tconst char *const *rename_from;  /* USIP_F_RENAME: the readings the entry may replace (mnemonics, or "@kind") */')
    A('\tut8 nrename_from;')
    A('} UsipOpcode;')
    A('')
    A('#ifndef USIP_OPCODES_NO_TABLE  /* define it to get the types and enums only */')
    A('/* The table is ORDERED: the first entry of the right width whose (units & mask) == value, whose flags allow the slot')
    A(' * and whose constraints hold is the reading.  The target guards (USIP_C_GUARD_TARGET_*) are evaluated by the decoder')
    A(' * AFTER the match: for 32-bit entries a failing guard makes the pair .word (no fall-through) unless the entry carries')
    A(' * USIP_F_GUARDFT (then the next entry of the cell is tried; none left = two 16-bit ops), for 16-bit entries it falls')
    A(' * through to the next entry; for the USIP_F_PREFIX entries a failing guard means the entry is not taken.  The')
    A(' * position / length constraints (USIP_C_PACKET_LEN(_GE), USIP_C_HEAD_INDEX(_GE), USIP_C_CTX, USIP_C_BR0_CELLS) need the')
    A(' * packet context (unknown = the constraint fails, except the context conditions and the R-br0 cells, which hold when the')
    A(' * layout is unknown) and, on the 32/48-bit entries, a failure falls through to the next entry of the cell;')
    A(' * USIP_C_GUARD_HEAD_NOT_VALIDATED_BS undoes the pair into two 16-bit ops.  USIP_C_TAIL_ADJACENT, USIP_C_IEEE_SHORT, USIP_C_BF_VALID,')
    A(' * USIP_C_INSTR_INDEX, the context conditions and USIP_C_IN_C48TAB are evaluated by the decoder (see usip_decode.c). */')
    for f in forms:
        if f.get('rename_only'):
            A('static const char *const usip_rename_from_%s[] = { %s };' % (cident(f['name']), ', '.join(cstr(x) for x in f.get('rename_from', []))))
    T = []
    A = T.append
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
        if f.get('guard_failure') == 'fallthrough': fl.append('USIP_F_GUARDFT')
        if f.get('group') == 'b111': fl.append('USIP_F_B111')
        if f.get('group') == 'f0ctx': fl.append('USIP_F_F0CTX')
        if f.get('fuse_pair'):
            fl.append('USIP_F_FUSE'); ctx_index[f['name']] = idx
        if f.get('split_role'):
            fl.append('USIP_F_SPLIT'); ctx_index[f['name']] = idx
            if f['split_role'] == 'bare': fl.append('USIP_F_SPLITBARE')
            elif f['split_role'] != 'either': raise SystemExit('%s: unknown split_role %r' % (f['name'], f['split_role']))
        flags = ' | '.join(fl) if fl else '0'
        tmpl, nargs, fields = exported_fields(f)
        if len(fields) > MAXFIELDS:
            raise SystemExit('%s: too many fields' % f['name'])
        fidx = {x['name']: i for i, x in enumerate(fields)}
        cons = [cons_entries(c, fidx, f['width'], bool(f.get('rename_only')), bool(f.get('context_only'))) for c in f.get('constraints', [])]
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
        rn = ('usip_rename_from_%s, %d' % (cident(f['name']), len(f.get('rename_from', [])))) if f.get('rename_only') else 'NULL, 0'
        if cons:
            A('\t  }, %d, {' % len(cons))
            for op, fi, fi2, vals in cons:
                if len(vals) > MAXVALS:
                    raise SystemExit('%s: too many constraint values' % f['name'])
                A('\t\t{ USIP_C_%s, %s, %s, %d, { %s } },' % (op.upper(), fi if fi != 0xff else 'USIP_NOFIELD', fi2 if fi2 != 0xff else 'USIP_NOFIELD',
                                                           len(vals), ', '.join(str(v) for v in vals) if vals else '0'))
            A('\t  }, %s },' % rn)
        else:
            A('\t  }, 0, { { 0, 0, 0, 0, { 0 } } }, %s },' % rn)
    A('};')
    A = L.append
    A('/* the large value sets of USIP_C_IN_SET / USIP_C_NOTIN_SET (sorted), by index */')
    for i, vals in enumerate(SETS):
        A('static const st32 usip_set_%d[%d] = { %s };' % (i, len(vals), ', '.join(str(v) for v in vals)))
    A('typedef struct { const st32 *v; ut16 n; } UsipValueSet;')
    A('static const UsipValueSet usip_value_sets[%d] = { %s };' % (max(1, len(SETS)), ', '.join('{ usip_set_%d, %d }' % (i, len(v)) for i, v in enumerate(SETS)) or '{ NULL, 0 }'))
    L.extend(T)
    A('')
    A('/* kind names, in enum usip_kind order */')
    A('static const char *const usip_kind_names[] = { ' + ', '.join(cstr(k) for k in kinds) + ' };')
    A('')
    A('/* context-only forms (matched by the packet decoder only), the post-layout split entries and the fusion entries */')
    for nm, idx in sorted(ctx_index.items()):
        A('#define USIP_FORM_%s %d' % (cident(nm).upper(), idx))
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
    A('')
    pk = isa['structure']['packet']
    A('/* units that are never a tail, and heads that never take a tail (the grammar rejects the assignment) */')
    A('static const ut16 usip_never_tail[] = { ' + ', '.join('0x%04x' % int(x, 16) for x in pk.get('never_tail', [])) + ' };')
    A('static const ut16 usip_never_head_with_tail[] = { ' + ', '.join('0x%04x' % int(x, 16) for x in pk.get('never_head_with_tail', [])) + ' };')
    A('')
    A('/* the 48-bit constants admitted by value (USIP_C_IN_C48TAB: imm32 = head[13:9] << 27 | hi[12:0] << 14 | lo[13:0]); the head:hi partial')
    A(' * admission of the parser compares the upper 18 bits */')
    A('static const ut32 usip_c48_table[%d] = { ' % len(C48) + ', '.join('0x%08x' % v for v in C48) + ' };')
    A('')
    br0 = pk.get('br0_cells', {})
    A('/* R-br0: the (op nibble of the head, tail bits 13:12, B class, tail distance) cells of the F = 0 branch heads read as b<cond>.d')
    A(' * (the entries *_f0s0 and the F = S = 0 .d entries carry them as USIP_C_BR0_CELLS); class 0 = B == 0, 1 = B == 15, 2 = any other B.')
    A(' * The weak cells hold only at the origins of a live trace (USIP_C_BR0_CELLS_LIVE): the decoder never takes them. */')
    A('typedef struct { ut8 op, tt, bclass, dist; } UsipBr0Cell;')
    strict = br0_rows(br0.get('strict', [])); weak = br0_rows(br0.get('weak_live_only', []))
    A('static const UsipBr0Cell usip_br0_cells[%d] = { ' % len(strict) + ', '.join(strict) + ' };')
    A('static const UsipBr0Cell usip_br0_cells_weak[%d] = { ' % len(weak) + ', '.join(weak) + ' };')
    A('')
    sym = sorted(set(pk.get('c48sym_known_addresses', [])))
    A('/* R-c48sym: data addresses already formed by the 48-bit hi(1010) family (sorted); a reading that leaves a family head without tails')
    A(' * while a later free hi + lo of the packet encode one of them pays +0.5 (structure.packet.tie_breaks) */')
    A('static const ut32 usip_c48sym_table[%d] = {' % len(sym))
    for i in range(0, len(sym), 8):
        A('\t' + ', '.join('0x%08x' % v for v in sym[i:i + 8]) + ',')
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

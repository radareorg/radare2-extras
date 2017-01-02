extern crate libc;
extern crate disasm6502;

use libc::*;
use std::ffi::CString;

// order matters because of libr/util/lib.c
#[repr(i32)]
pub enum RLibType {
    RLibTypeIo = 0,
    RLibTypeDbg = 1,
    RLibTypeLang = 2,
    RLibTypeAsm = 3,
    RLibTypeAnal = 4,
    RLibTypeParse = 5,
    RLibTypeBin = 6,
    RLibTypeBinXtr = 7,
    RLibTypeBp = 8,
    RLibTypeSyscall = 9,
    RLibTypeFastcall = 10,
    RLibTypeCrypto = 11,
    RLibTypeCore = 12,
    RLibTypeEgg = 13,
    RLibTypeFs = 14,
    RLibTypeLast = 15,
}

//#[repr(C)]
// pub struct StaticCString(*const u8);
//unsafe impl Sync for StaticCString {}

// [std::default::Default;
pub struct RAsmPlugin {
    name: *const c_char,
    arch: *const c_char,
    cpus: *const c_char,
    desc: *const c_char,
    license: *const c_char, //c_char,
    user: usize,
    bits: c_int,
    endian: c_int,
    // bool (*init)(void *user);
    pub init: usize, //extern "C" fn(*mut c_void) -> bool,
    // bool (*fini)(void *user);
    pub fini: usize, //extern "C" fn(*mut c_void) -> bool,
    // int (*disassemble)(RAsm *a, RAsmOp *op, const ut8 *buf, int len);
    pub disassemble: extern "C" fn(*const c_void, *mut RAsmOp, *const uint8_t, c_int) -> c_int,
    // int (*assemble)(RAsm *a, RAsmOp *op, const char *buf);
    pub assemble: extern "C" fn(*const c_void, *const c_char) -> c_int,
    // RAsmModifyCallback modify;
    // typedef int (*RAsmModifyCallback)(RAsm *a, ut8 *buf, int field, ut64 val);
    pub modify: extern "C" fn(*mut c_void, *mut uint8_t, c_int, uint64_t) -> c_int,
    // int (*set_subarch)(RAsm *a, const char *buf);
    pub set_subarch: extern "C" fn(*const c_void, *const c_char) -> c_int,
    // char *(*mnemonics)(RAsm *a, int id, bool json);
    pub mnemonics: extern "C" fn(*const c_void, c_int, bool) -> *mut c_char,
    features: *const [u8]
}

const sz: usize = 256;
type RAsmOpString = [c_char; sz];

pub struct RAsmOp {
        size: c_int,
        payload: c_int,
        buf: RAsmOpString,
        buf_asm: RAsmOpString,
        buf_hex: RAsmOpString
}

pub struct RLibHandler {
    pub _type: c_int,
    pub desc: [c_char; 128], pub user: *const c_void,
    pub constructor: extern "C" fn(*const RLibPlugin, *mut c_void, *mut c_void),
    pub destructor: extern "C" fn(*const RLibPlugin, *mut c_void, *mut c_void),
}

pub struct RLibPlugin {
    pub _type: c_int,
    pub file: *const c_char,
    pub data: *const c_void,
    pub handler: *const RLibHandler, // struct r_lib_handler_t
    pub dl_handler: *const c_void
}

pub struct RLibStruct {
	pub _type: RLibType,
	pub data: *const c_void,
	pub version: *const [u8]
}

// static MY_NAME:StaticCString = StaticCString(b"6502.rs\0" as *const u8);
const R2_VERSION: &'static [u8] = b"1.2.0-git\0";
const MY_NAME : &'static [u8] = b"6502.rs\0";
const MY_ARCH : &'static [u8] = b"6502\0";
const MY_DESC : &'static [u8] = b"6502 disassembler in Rust\0";
const MY_LICENSE : &'static [u8] = b"MIT\0";

extern "C" fn _init (foo: *mut c_void) -> bool {
    true
}

extern "C" fn _mnemonics (foo: *const c_void, bar: c_int, cow: bool) -> *mut c_char {
    b"\0".as_ptr() as *mut c_char
}

extern "C" fn _disassemble (asm: *const c_void, asmop: *mut RAsmOp, buf: *const u8, len: c_int) -> c_int {
    let oplen : usize = std::cmp::min(len, 3) as usize;
    unsafe {
        let bytes = std::slice::from_raw_parts(buf as *const u8, oplen);
        if let Ok(instructions) = disasm6502::from_addr_array(bytes, 0) {
            if instructions.len() > 0 as usize {
                let ref ins = instructions[0];
                if ins.illegal {
                    (*asmop).payload = 0;
                    (*asmop).size = 1;
                    return -1;
                }
                let opstr = ins.as_str();
                let hexstr = ins.as_hex_str().replace(" ", "");
                let inslen = (hexstr.len() / 2) as c_int;
                println!("{}", inslen);
                (*asmop).size = inslen;
                (*asmop).payload = 0;
                (*asmop).buf_asm[0] = 0;
                let opstrlen = std::cmp::min(opstr.len(), sz);
                std::ptr::copy(
                    opstr.as_bytes() as *const [u8] as *const c_char,
                    &mut (*asmop).buf_asm as *mut [c_char] as *mut c_char,
                    opstrlen);
                std::ptr::copy(
                    hexstr.as_bytes() as *const [u8] as *const c_char,
                    &mut (*asmop).buf_hex as *mut [c_char] as *mut c_char,
                    opstrlen);
                std::ptr::copy(
                    &buf, // as *const [u8] as *const c_char,
                    &mut (*asmop).buf as *mut [c_char] as *mut *const u8,
                    opstrlen);
                return inslen;
            }
        }
    }
    -1 
}

extern "C" fn _assemble (asm: *const c_void, str: *const c_char) -> c_int {
    0
}

extern "C" fn _modify (asm: *mut c_void, buf: *mut uint8_t, len: c_int, at: uint64_t) -> c_int {
    0
}
extern "C" fn _set_subarch (asm: *const c_void, arch: *const c_char) -> c_int {
    0
}

const MYNAME : *const c_char = b"6502.rs\0" as *const [u8] as *const c_char;

const r_asm_plugin_6502rs: RAsmPlugin = RAsmPlugin {
    name : MYNAME,
    arch : MY_ARCH as *const [u8] as *const c_char,
    license : MY_LICENSE as *const [u8] as *const c_char,
    user : 0,
    cpus : b"\0" as *const [u8] as *const c_char,
    desc : MY_DESC as *const [u8] as *const c_char,
    bits : 16,
    endian: 0,
    disassemble: _disassemble,
    assemble: _assemble,
    init: 0,
    fini: 0,
    modify: _modify,
    set_subarch: _set_subarch,
    mnemonics: _mnemonics,
    features: b"\0"
};

#[no_mangle]
#[allow(non_upper_case_globals)]
pub static mut radare_plugin: RLibStruct = RLibStruct {
    _type : RLibType::RLibTypeAsm,
    data : ((&r_asm_plugin_6502rs) as *const RAsmPlugin) as *const c_void,
    version : b"1.2.0-git\0"
};


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}

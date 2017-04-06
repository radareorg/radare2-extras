extern crate libc;
extern crate disasm6502;

use libc::*;
use std::ffi::CString;

const MY_NAME : *const c_char = b"6502.rs\0" as *const [u8] as *const c_char;
const R2_VERSION: &'static [u8] = b"1.4.0-git\0";
const MY_ARCH : &'static [u8] = b"6502\0";
const MY_DESC : &'static [u8] = b"6502 disassembler in Rust\0";
const MY_LICENSE : &'static [u8] = b"MIT\0";
const MY_AUTHOR : &'static [u8] = b"radare";

// order matters because of libr/util/lib.c
#[repr(C,i32)]
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

#[repr(C)]
pub struct RAsmPlugin {
    name: *const c_char,
    arch: *const c_char,
    author: *const c_char,
    version: *const c_char,
    cpus: *const c_char,
    desc: *const c_char,
    license: *const c_char, //c_char,
    user: usize,
    bits: c_int,
    endian: c_int,
    pub init: Option<extern "C" fn(*mut c_void) -> bool>,
    pub fini: Option<extern "C" fn(*mut c_void) -> bool>,
    pub disassemble: Option<extern "C" fn(*const c_void, *mut RAsmOp, *const uint8_t, c_int) -> c_int>,
    pub assemble: Option<extern "C" fn(*const c_void, *const c_char) -> c_int>,
    pub modify: Option<extern "C" fn(*mut c_void, *mut uint8_t, c_int, uint64_t) -> c_int>,
    pub set_subarch: Option<extern "C" fn(*const c_void, *const c_char) -> c_int>,
    pub mnemonics: Option<extern "C" fn(*const c_void, c_int, bool) -> *mut c_char>,
    features: *const [u8]
}

const sz: usize = 256;
type RAsmOpString = [c_char; sz];

#[repr(C)]
pub struct RAsmOp {
        size: c_int,
        payload: c_int,
        buf: RAsmOpString,
        buf_asm: RAsmOpString,
        buf_hex: RAsmOpString
}

#[repr(C)]
pub struct RLibHandler {
    pub _type: c_int,
    pub desc: [c_char; 128], pub user: *const c_void,
    pub constructor: extern "C" fn(*const RLibPlugin, *mut c_void, *mut c_void),
    pub destructor: extern "C" fn(*const RLibPlugin, *mut c_void, *mut c_void),
}

#[repr(C)]
pub struct RLibPlugin {
    pub _type: c_int,
    pub file: *const c_char,
    pub data: *const c_void,
    pub handler: *const RLibHandler,
    pub dl_handler: *const c_void
}

#[repr(C)]
pub struct RLibStruct {
	pub _type: RLibType,
	pub data: *const c_void,
	pub version: *const [u8]
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

/*
extern "C" fn _init (foo: *mut c_void) -> bool {
    true
}

extern "C" fn _mnemonics (foo: *const c_void, bar: c_int, cow: bool) -> *mut c_char {
    b"\0".as_ptr() as *mut c_char
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
*/

const r_asm_plugin_6502rs: RAsmPlugin = RAsmPlugin {
    name : MY_NAME,
    arch : MY_ARCH as *const [u8] as *const c_char,
    author : MY_AUTHOR as *const [u8] as *const c_char,
    version : MY_NAME,
    license : MY_LICENSE as *const [u8] as *const c_char,
    user : 0,
    cpus : b"\0" as *const [u8] as *const c_char,
    desc : MY_DESC as *const [u8] as *const c_char,
    bits : 16,
    endian: 0,
    disassemble: Some(_disassemble),
    assemble: None, //Some(_assemble),
    init: None,
    fini: None,
    modify: None, //_modify,
    set_subarch: None, //_set_subarch,
    mnemonics: None, //_mnemonics,
    features: b"\0"
};

#[no_mangle]
#[allow(non_upper_case_globals)]
pub static mut radare_plugin: RLibStruct = RLibStruct {
    _type : RLibType::RLibTypeAsm,
    data : ((&r_asm_plugin_6502rs) as *const RAsmPlugin) as *const c_void,
    version : R2_VERSION
};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}

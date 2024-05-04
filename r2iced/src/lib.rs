#[allow(dead_code)]
mod r2api_ext;

use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};
use std::ffi::{c_char, c_int, c_void, CStr};
use std::ptr::{null, null_mut};

use crate::r2api_ext::*;
use r2api::*;

/// r2c_strdup creates a new libc malloc()ed C String from a Rust string.
unsafe fn r2c_strdup(s: &str) -> *mut c_char {
    let out_ptr = libc::malloc(s.len() + 1) as *mut c_char;
    assert!(!out_ptr.is_null(), "malloc failed");
    let out = std::slice::from_raw_parts_mut(out_ptr, s.len() + 1);
    out.copy_from_slice(std::mem::transmute::<&[u8], &[c_char]>(s.as_bytes()));
    out[s.len()] = 0;
    out_ptr
}

unsafe extern "C" fn decode(
    session_ptr: *mut RArchSession,
    op_ptr: *mut RAnalOp,
    mask: RArchDecodeMask,
) -> bool {
    let session = session_ptr.as_ref().unwrap();
    let config = session.config.as_ref().unwrap();
    let op = op_ptr.as_mut().unwrap();

    let data = std::slice::from_raw_parts(op.bytes, op.size as usize);

    let mut instruction = Instruction::default();
    let mut decoder = Decoder::with_ip(config.bits as u32, data, op.addr, DecoderOptions::NONE);
    if !decoder.can_decode() {
        return false;
    }
    if mask & R_ARCH_OP_MASK_DISASM == 0 {
        return false;
    }

    decoder.decode_out(&mut instruction);
    op.size = instruction.len() as c_int;

    let mut formatter = IntelFormatter::new();
    let mut output = String::new();
    formatter.format(&instruction, &mut output);
    op.mnemonic = r2c_strdup(&output);

    true
}

#[repr(transparent)]
pub struct UnsafeSync<T>(pub T);

unsafe impl<T> Sync for UnsafeSync<T> {}

macro_rules! static_cstr {
    ($str: tt) => {
        unsafe { CStr::from_bytes_with_nul_unchecked(concat!($str, "\x00").as_bytes()).as_ptr() }
    };
}

static ARCH_PLUGIN: UnsafeSync<RArchPlugin> = UnsafeSync(RArchPlugin {
    meta: RPluginMeta {
        name: static_cstr!("x86.iced") as *mut c_char,
        desc: static_cstr!("iced-x86 disassembler") as *mut c_char,
        author: static_cstr!("ripatel") as *mut c_char,
        version: null_mut(),
        license: static_cstr!("MIT") as *mut c_char,
        status: R_PLUGIN_STATUS_BROKEN,
    },
    arch: static_cstr!("x86") as *mut c_char,
    cpus: null_mut(),
    endian: R_SYS_ENDIAN_LITTLE,
    bits: 16 | 32 | 64,
    addr_bits: 0,
    init: None,
    fini: None,
    info: None,
    regs: None,
    encode: None,
    decode: Some(decode),
    patch: None,
    mnemonics: None,
    preludes: None,
    esilcb: None,
    // Unfortunately, we can't use ..RArchPlugin::default() here.
    // The Default trait is currently not const.
});

/// The primary entrypoint for the r2iced plugin.
/// radare2 discovers this symbol via [`libc::dlsym`].
#[no_mangle]
pub static radare_plugin: UnsafeSync<RLibStruct> = UnsafeSync(RLibStruct {
    type_: R_LIB_TYPE_ARCH,
    data: &ARCH_PLUGIN.0 as *const RArchPlugin as *mut c_void,
    version: static_cstr!("5.9.0"),
    free: None,
    pkgname: null(),
});

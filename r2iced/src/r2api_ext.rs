/* This module contains bindings that are missing in r2api */

use r2api::RPluginStatus;
use std::ffi::c_int;

pub const R_SYS_ENDIAN_LITTLE: u32 = 1;

pub const R_LIB_TYPE_ARCH: c_int = 17;

pub const R_PLUGIN_STATUS_BROKEN: RPluginStatus = 0;
pub const R_PLUGIN_STATUS_INCOMPLETE: RPluginStatus = 1;
pub const R_PLUGIN_STATUS_BASIC: RPluginStatus = 2;

pub const R_ARCH_OP_MASK_DISASM: u32 = 16;

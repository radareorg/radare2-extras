/* This module contains bindings that are missing in r2api */

use r2api::{RLogLevel, RPluginStatus};
use std::ffi::c_int;

pub const R_SYS_ENDIAN_LITTLE: u32 = 1;

pub const R_LIB_TYPE_ARCH: c_int = 17;

pub const R_PLUGIN_STATUS_BROKEN: RPluginStatus = 0;
pub const R_PLUGIN_STATUS_INCOMPLETE: RPluginStatus = 1;
pub const R_PLUGIN_STATUS_BASIC: RPluginStatus = 2;

pub const R_ARCH_OP_MASK_DISASM: u32 = 16;

pub const R_ARCH_SYNTAX_NONE: c_int = 0;
pub const R_ARCH_SYNTAX_INTEL: c_int = 1;
pub const R_ARCH_SYNTAX_ATT: c_int = 2;
pub const R_ARCH_SYNTAX_MASM: c_int = 3;

pub const R_LOG_LEVEL_FATAL: c_int = 0;
pub const R_LOG_LEVEL_ERROR: RLogLevel = 1;
pub const R_LOG_LEVEL_INFO: RLogLevel = 2;
pub const R_LOG_LEVEL_WARN: RLogLevel = 3;
pub const R_LOG_LEVEL_TODO: RLogLevel = 4;
pub const R_LOG_LEVEL_DEBUG: RLogLevel = 5;
pub const R_LOG_LEVEL_LAST: RLogLevel = 6;

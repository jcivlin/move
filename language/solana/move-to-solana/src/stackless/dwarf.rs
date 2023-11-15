// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

//! LLVM wrappers.
//!
//! The stackless code generator accesses llvm only through this mod.
//!
//! It:
//!
//! - Runs dtors
//! - Encapsulates unsafety, though making LLVM fully memsafe is hard.
//! - Hides weirdly mutable array pointers.
//! - Provides high-level instruction builders compatible with the stackless bytecode model.

use codespan::Location;
use llvm_sys::{
    core::*,
    debuginfo::{
        LLVMCreateDIBuilder, LLVMDIBuilderCreateBasicType, LLVMDIBuilderCreateCompileUnit,
        LLVMDIBuilderCreateFile, LLVMDIBuilderCreateMemberType, LLVMDIBuilderCreateModule,
        LLVMDIBuilderCreateNameSpace, LLVMDIBuilderCreatePointerType,
        LLVMDIBuilderCreateStructType, LLVMDIBuilderFinalize, LLVMDIFlagObjcClassComplete,
        LLVMDIFlagZero, LLVMDIFlags, LLVMDITypeGetName, LLVMDWARFEmissionKind,
        LLVMDWARFSourceLanguage::LLVMDWARFSourceLanguageRust, LLVMDWARFTypeEncoding,
        LLVMGetMetadataKind,
    },
    prelude::*,
};

use log::debug;
use move_model::model::StructEnv;
use std::{env, ffi::CStr, ptr};

use crate::stackless::Module;

#[derive(Clone, Debug)]
pub struct DIBuilderCore {
    module_di: LLVMModuleRef, // ref to the new module created here for DI purpose
    builder_ref: LLVMDIBuilderRef,
    // fields below reserved for future usage
    builder_file: LLVMMetadataRef,
    compiled_unit: LLVMMetadataRef,
    compiled_module: LLVMMetadataRef,
    module_ref: LLVMModuleRef, // ref to existed "Builder" Module used here as in 'new'
    module_source: String,
    // basic types
    pub type_u8: LLVMMetadataRef,
    pub type_u16: LLVMMetadataRef,
    pub type_u32: LLVMMetadataRef,
    pub type_u64: LLVMMetadataRef,
    pub type_u128: LLVMMetadataRef,
    pub type_u256: LLVMMetadataRef,
    pub type_bool: LLVMMetadataRef,
    pub type_address: LLVMMetadataRef,
}

#[derive(Clone, Debug)]
pub struct DIBuilder(Option<DIBuilderCore>);

macro_rules! to_cstring {
    ($x:expr) => {{
        let cstr = match std::ffi::CString::new($x) {
            Ok(cstr) => cstr,
            Err(_) => std::ffi::CString::new("unknown").expect("Failed to create CString"),
        };
        cstr
    }};
}

pub fn from_raw_slice_to_string(raw_ptr: *const i8, raw_len: ::libc::size_t) -> String {
    let byte_slice: &[i8] = unsafe { std::slice::from_raw_parts(raw_ptr, raw_len) };
    let byte_slice: &[u8] =
        unsafe { std::slice::from_raw_parts(byte_slice.as_ptr() as *const u8, byte_slice.len()) };
    String::from_utf8_lossy(byte_slice).to_string()
}

fn relative_to_absolute(relative_path: &str) -> std::io::Result<String> {
    let current_dir = env::current_dir()?;
    let absolute_path = current_dir
        .join(relative_path)
        .canonicalize()
        .expect("Cannot canonicanize path");

    Ok(absolute_path.to_string_lossy().to_string())
}

impl DIBuilder {
    pub fn new(module: &mut Module, source: &str, debug: bool) -> DIBuilder {
        if debug {
            let module_ref_name = module.get_module_id();
            let module_ref = module.as_mut();

            // create new module
            let module_name = module_ref_name + ".dbg_info";
            let cstr = to_cstring!(module_name.as_str());
            let (mut mod_nm_ptr, mut mod_nm_len) = (cstr.as_ptr(), cstr.as_bytes().len());
            let module_di =
                unsafe { LLVMModuleCreateWithName(mod_nm_ptr as *const ::libc::c_char) };

            // check dbg module name
            mod_nm_ptr = unsafe { LLVMGetModuleIdentifier(module_di, &mut mod_nm_len) };
            let module_di_name = &from_raw_slice_to_string(mod_nm_ptr, mod_nm_len);
            debug!(target: "dwarf", "Created dbg module {:#?}", module_di_name);

            let source = relative_to_absolute(source).expect("Must be the legal path");
            let cstr = to_cstring!(source.as_str());
            unsafe { LLVMSetSourceFileName(module_di, cstr.as_ptr(), cstr.as_bytes().len()) };

            // check the source name
            let mut src_len: ::libc::size_t = 0;
            let src_ptr = unsafe { LLVMGetSourceFileName(module_di, &mut src_len) };
            let module_src = &from_raw_slice_to_string(src_ptr, src_len);
            debug!(target: "dwarf", "Module {:#?} has source {:#?}", module_name, module_src);

            // create builder
            let builder_ref = unsafe { LLVMCreateDIBuilder(module_di) };

            // create file
            let path = std::path::Path::new(&source);
            let directory = path
                .parent()
                .expect("Failed to get directory")
                .to_str()
                .expect("Failed to convert to string");
            let cstr = to_cstring!(directory);
            let (dir_ptr, dir_len) = (cstr.as_ptr(), cstr.as_bytes().len());

            let file = path
                .file_name()
                .expect("Failed to get file name")
                .to_str()
                .expect("Failed to convert to string");
            let cstr = to_cstring!(file);
            let (filename_ptr, filename_len) = (cstr.as_ptr(), cstr.as_bytes().len());
            let (mod_nm_ptr, mod_nm_len, dir_ptr, dir_len) =
                (filename_ptr, filename_len, dir_ptr, dir_len);

            let builder_file = unsafe {
                LLVMDIBuilderCreateFile(builder_ref, mod_nm_ptr, mod_nm_len, dir_ptr, dir_len)
            };

            // create compile unit
            let producer = "move-mv-llvm-compiler".to_string();
            let cstr = to_cstring!(producer);
            let (producer_ptr, producer_len) = (cstr.as_ptr(), cstr.as_bytes().len());

            let flags = "".to_string();
            let cstr = to_cstring!(flags);
            let (flags_ptr, flags_len) = (cstr.as_ptr(), cstr.as_bytes().len());

            let slash = "/".to_string();
            let cstr = to_cstring!(slash);
            let (slash_ptr, slash_len) = (cstr.as_ptr(), cstr.as_bytes().len());

            let none = String::new();
            let cstr = to_cstring!(none);
            let (none_ptr, none_len) = (cstr.as_ptr(), cstr.as_bytes().len());

            let compiled_unit = unsafe {
                LLVMDIBuilderCreateCompileUnit(
                    builder_ref,
                    LLVMDWARFSourceLanguageRust,
                    builder_file,
                    producer_ptr,
                    producer_len,
                    0, /* is_optimized */
                    flags_ptr,
                    flags_len,
                    0,                /* runtime_version */
                    std::ptr::null(), /* *const i8 */
                    0,                /* usize */
                    LLVMDWARFEmissionKind::LLVMDWARFEmissionKindFull,
                    0,         /* u32 */
                    0,         /* i32 */
                    0,         /* i32 */
                    slash_ptr, /* *const i8 */
                    slash_len, /* usize */
                    none_ptr,  /* *const i8 */
                    none_len,  /* usize */
                )
            };

            // create di module
            let parent_scope = compiled_unit;
            let name = module_name;
            let cstr = to_cstring!(name);
            let (name_ptr, name_len) = (cstr.as_ptr(), cstr.as_bytes().len());

            let (config_macros_ptr, config_macros_len) = (none_ptr, none_len);
            let (include_path_ptr, include_path_len) = (none_ptr, none_len);
            let (api_notes_file_ptr, api_notes_file_len) = (none_ptr, none_len);
            let compiled_module = unsafe {
                LLVMDIBuilderCreateModule(
                    builder_ref,
                    parent_scope,
                    name_ptr,
                    name_len,
                    config_macros_ptr,
                    config_macros_len,
                    include_path_ptr,
                    include_path_len,
                    api_notes_file_ptr,
                    api_notes_file_len,
                )
            };

            fn create_type(
                builder_ref: LLVMDIBuilderRef,
                name: &str,
                size_in_bits: u64,
                encoding: LLVMDWARFTypeEncoding,
                flags: LLVMDIFlags,
            ) -> LLVMMetadataRef {
                let name_cstr = to_cstring!(name);
                let (name_ptr, name_len) = (name_cstr.as_ptr(), name_cstr.as_bytes().len());
                unsafe {
                    LLVMDIBuilderCreateBasicType(
                        builder_ref,
                        name_ptr,
                        name_len,
                        size_in_bits,
                        encoding,
                        flags,
                    )
                }
            }

            // store all control fields for future usage
            let builder_core = DIBuilderCore {
                module_di,
                builder_ref,
                builder_file,
                compiled_unit,
                compiled_module,
                module_ref,
                module_source: source.to_string(),
                type_u8: create_type(builder_ref, "u8", 8, 0, LLVMDIFlagZero),
                type_u16: create_type(builder_ref, "u16", 16, 0, LLVMDIFlagZero),
                type_u32: create_type(builder_ref, "u32", 32, 0, LLVMDIFlagZero),
                type_u64: create_type(builder_ref, "u64", 64, 0, LLVMDIFlagZero),
                type_u128: create_type(builder_ref, "u128", 132, 0, LLVMDIFlagZero),
                type_u256: create_type(builder_ref, "u256", 256, 0, LLVMDIFlagZero),
                type_bool: create_type(builder_ref, "bool", 8, 0, LLVMDIFlagZero),
                type_address: create_type(builder_ref, "address", 128, 0, LLVMDIFlagZero),
            };

            DIBuilder(Some(builder_core))
        } else {
            DIBuilder(None)
        }
    }

    pub fn module_di(&self) -> Option<LLVMModuleRef> {
        self.0.as_ref().map(|x| x.module_di)
    }

    pub fn builder_ref(&self) -> Option<LLVMDIBuilderRef> {
        self.0.as_ref().map(|x| x.builder_ref)
    }

    pub fn builder_file(&self) -> Option<LLVMMetadataRef> {
        self.0.as_ref().map(|x| x.builder_file)
    }

    pub fn compiled_unit(&self) -> Option<LLVMMetadataRef> {
        self.0.as_ref().map(|x| x.compiled_unit)
    }

    pub fn compiled_module(&self) -> Option<LLVMMetadataRef> {
        self.0.as_ref().map(|x| x.compiled_module)
    }

    pub fn module_ref(&self) -> Option<LLVMModuleRef> {
        self.0.as_ref().map(|x| x.module_ref)
    }

    pub fn module_source(&self) -> Option<String> {
        self.0.as_ref().map(|x| x.module_source.clone())
    }

    pub fn print_module_to_file(&self, file_path: String) {
        if let Some(x) = &self.0 {
            let mut err_string = ptr::null_mut();
            let cstr = to_cstring!(file_path);
            let (filename_ptr, _filename_ptr_len) = (cstr.as_ptr(), cstr.as_bytes().len());
            unsafe {
                let res = LLVMPrintModuleToFile(x.module_di, filename_ptr, &mut err_string);
                if res != 0 {
                    assert!(!err_string.is_null());
                    let msg = CStr::from_ptr(err_string).to_string_lossy();
                    print!("{msg}");
                    LLVMDisposeMessage(err_string);
                }
            };
        }
    }

    pub fn create_struct(
        &self,
        struct_env: &StructEnv,
        struct_llvm_name: &str,
        parent: Option<LLVMMetadataRef>,
    ) {
        if let Some(_di_builder_core) = &self.0 {
            let di_builder = self.builder_ref().unwrap();
            let di_builder_file = self.builder_file().unwrap();
            let mod_env = &struct_env.module_env;

            let name = struct_env.get_full_name_str();
            debug!(target: "struct", "dbg for struct {} with llvm name {}", &name, struct_llvm_name);
            // FIXME: not clear whether to use 'name' or 'struct_llvm_name' for DWARF
            let struct_name = struct_llvm_name;
            let name_cstr = to_cstring!(struct_name);
            let (struct_nm_ptr, struct_nm_len) = (name_cstr.as_ptr(), name_cstr.as_bytes().len());
            let unique_id = std::ffi::CString::new("unique_id").expect("CString conversion failed");

            let name_space = unsafe {
                LLVMDIBuilderCreateNameSpace(
                    di_builder,
                    di_builder_file,
                    struct_nm_ptr,
                    struct_nm_len,
                    0,
                )
            };
            let loc = struct_env.get_loc();
            let (filename, location) = struct_env
                .module_env
                .env
                .get_file_and_location(&loc)
                .unwrap_or(("unknown".to_string(), Location::new(0, 0)));
            debug!(target: "struct", "source: {}:{}", filename, location.line.0);

            let mut fields: Vec<LLVMMetadataRef> = struct_env.get_fields().map(|f|
                {
                let symbol = f.get_name();
                let fld_name = symbol.display(mod_env.symbol_pool()).to_string();
                let fld_name_cstr = to_cstring!(fld_name.clone());
                let (field_nm_ptr, field_nm_len) = (fld_name_cstr.as_ptr(), fld_name_cstr.as_bytes().len());
                let offset = f.get_offset() as u32;
                let ty = f.get_type();
                let fld_loc = if let Some(named_const) = mod_env.find_named_constant(symbol) {
                    assert!(named_const.get_name() == symbol);
                    named_const.get_loc()
                } else {
                    mod_env.env.unknown_loc()
                };
                let fld_loc_str = fld_loc.display(mod_env.env).to_string();
                debug!(target: "struct", "field {}: {:#?} {}", &fld_name, &fld_loc, fld_loc_str);

                let vars = ty.get_vars(); // FIXME: how vars can be used for DWARF?
                debug!(target: "struct", "vars {:#?}", vars);

                let fld = unsafe { LLVMDIBuilderCreateMemberType(
                    di_builder,
                    name_space,
                    field_nm_ptr,
                    field_nm_len,
                    di_builder_file, //File: LLVMMetadataRef,
                    location.line.0 + offset + 1,  // FIXME: cannot find Loc for fields in Move compiler
                    0, // FIXME: this might not be known until llvm BE!
                    0,
                    0,
                    0,
                    self.0.as_ref().unwrap().type_u32, // FIXME ty
                )};
                fld
            }).collect();
            debug!(target: "struct", "fields {:#?}", fields);

            let fields_mut: *mut LLVMMetadataRef = fields.as_mut_ptr();

            let struct_meta = unsafe {
                LLVMDIBuilderCreateStructType(
                    di_builder,
                    name_space,
                    struct_nm_ptr,   // Name: *const ::libc::c_char,
                    struct_nm_len,   // NameLen: ::libc::size_t,
                    di_builder_file, //File: LLVMMetadataRef,
                    location.line.0,
                    0, // FIXME: this might not be known until llvm BE!
                    0,
                    LLVMDIFlagObjcClassComplete, // FIXME! unclear how flags are used
                    parent.unwrap_or(ptr::null_mut()), // DerivedFrom: LLVMMetadataRef,
                    fields_mut,                  // Elements: *mut LLVMMetadataRef,
                    fields.len() as u32,         // NumElements: ::libc::c_uint,
                    0,               // RunTimeLang: ::libc::c_uint - FIXME: unclear how it is used
                    ptr::null_mut(), // VTableHolder: LLVMMetadataRef - FIXME: likely not used in MOVE
                    unique_id.as_ptr(), // UniqueId: *const ::libc::c_char - FIXME: not set for now, maybe useful
                    0,                  // UniqueIdLen: ::libc::size_t
                )
            };

            // Check the name in DWARF
            let mut struct_nm_len_new: usize = 0;
            let struct_nm_ptr_new =
                unsafe { LLVMDITypeGetName(struct_meta, &mut struct_nm_len_new) };
            let struct_name_new = from_raw_slice_to_string(struct_nm_ptr_new, struct_nm_len_new);
            assert!(
                struct_name == struct_name_new,
                "Must create DRARF struct with the same name"
            );

            // FIXME: is it used/usefull?
            let struct_kind = unsafe { LLVMGetMetadataKind(struct_meta) };
            debug!(target: "struct", "struct_kind {:#?}", struct_kind);

            let name_cstr_for_ptr = to_cstring!(format!("{}__ptr", struct_name));
            let (name_cstr_for_ptr_nm_ptr, name_cstr_for_ptr_nm_len) = (
                name_cstr_for_ptr.as_ptr(),
                name_cstr_for_ptr.as_bytes().len(),
            );

            // DWARF wants this set
            let struct_ptr = unsafe {
                LLVMDIBuilderCreatePointerType(
                    di_builder,
                    struct_meta,
                    192, // FIXME: maybe ignored?
                    192,
                    0,
                    name_cstr_for_ptr_nm_ptr,
                    name_cstr_for_ptr_nm_len,
                )
            };

            let module_di = &self.module_di().unwrap();
            let module_ctx = unsafe { LLVMGetModuleContext(*module_di) };
            let meta_as_value = unsafe { LLVMMetadataAsValue(module_ctx, struct_ptr) };
            unsafe { LLVMAddNamedMetadataOperand(*module_di, struct_nm_ptr, meta_as_value) };

            // FIXME: temporary LLVMDIBuilderFinalize set for debugging
            // unsafe { LLVMDIBuilderFinalize(di_builder) };
            let out = unsafe { LLVMPrintModuleToString(*module_di) };
            let c_string: *mut i8 = out;
            let c_str = unsafe {
                CStr::from_ptr(c_string)
                    .to_str()
                    .expect("Cannot convert to &str")
            };
            debug!(target: "struct", "DI content as &str: starting at next line and until line starting with !!!\n{}\n!!!\n", c_str);
        }
    }

    pub fn finalize(&self) {
        if let Some(x) = &self.0 {
            unsafe { LLVMDIBuilderFinalize(x.builder_ref) };
        }
    }
}

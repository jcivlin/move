// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

#![allow(unused)]

//#![forbid(unsafe_code)]

use anyhow::Context;
use clap::{Parser, Arg};
use llvm_sys::{core::LLVMContextCreate, prelude::LLVMModuleRef};
use move_binary_format::{
    binary_views::BinaryIndexedView,
    file_format::{CompiledModule, CompiledScript},
};
use move_bytecode_source_map::{mapping::SourceMapping, utils::source_map_from_file};
use move_command_line_common::files::{
    MOVE_COMPILED_EXTENSION, MOVE_EXTENSION, SOURCE_MAP_EXTENSION,
};
use move_ir_types::location::Spanned;
use move_mv_llvm_compiler::{cli::Args, disassembler::Disassembler};
use std::{fs, path::Path, f32::consts::E};

use move_compiler::shared::PackagePaths;
use codespan_reporting::{diagnostic::Severity, term::termcolor::Buffer};

use move_model::{run_bytecode_model_builder, run_model_builder};

// use clap::error::ContextValue::String;

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if args.llvm_ir && args.obj {
        anyhow::bail!("can't output both LLVM IR (-S) and object file (-O)");
    }

    if args.compile.is_some() && args.bytecode_file_path.is_some() {
        anyhow::bail!("can't do both: compile from source and deserialize from .mv");
    }

    match (&*args.gen_dot_cfg) {
        "write" | "view" | "" => {}
        _ => {
            eprintln!(
                "unexpected gen-dot-cfg option '{}', ignored.",
                &args.gen_dot_cfg
            );
        }
    };

    let move_extension = MOVE_EXTENSION;
    let mv_bytecode_extension = MOVE_COMPILED_EXTENSION;
    let source_map_extension = SOURCE_MAP_EXTENSION;

    let path =
        if let Some(source_path) = &args.bytecode_file_path {
            source_path
        } else if let Some(pack_path) = &args.move_package_path {
            pack_path
        } else {
            anyhow::bail!("Wrong params");
            "Error".to_string();        
        };


    // let move_path = Path::new(&args.move_package_path);
    // if !move_path.join("Move.toml").exists() {
    //     anyhow::bail!("No Move.toml in {}", move_path.to_str().unwrap());
    // }

    // let extension= move_path
    //     .extension()
    //     .context("Missing file extension for bytecode file")?;
    // if extension != move_extension {
    //     anyhow::bail!(
    //         "Bad source file extension {:?}; expected {}",
    //         extension,
    //         move_extension
    //     );
    // }


    let targets = vec![PackagePaths {
        name: None,
        paths: vec![path.to_string()],
        named_address_map: std::collections::BTreeMap::<String, _>::new(),
    }];


    let global_env = run_model_builder(targets, vec![])?;

    let errors_cnt = &global_env.error_count();
    dbg!(errors_cnt);
    // let errors = &global_env.error(loc, msg);

    if global_env.diag_count(Severity::Warning) > 0 {
        let mut writer = Buffer::no_color();
        global_env.report_diag(&mut writer, Severity::Warning);
        println!("{}", String::from_utf8_lossy(&writer.into_inner()).to_string());
    }

    /*
    {
        use move_mv_llvm_compiler::stackless::{Target, *};

        let tgt_platform = TargetPlatform::Solana;
        tgt_platform.initialize_llvm();
        let lltarget = Target::from_triple(tgt_platform.triple())?;
        let llmachine = lltarget.create_target_machine(
            tgt_platform.triple(),
            tgt_platform.llvm_cpu(),
            tgt_platform.llvm_features(),
        );
        let mod_id = global_env
            .get_modules()
            .last()
            .map(|m| m.get_id())
            .expect(".");
        let global_cx = GlobalContext::new(&global_env, tgt_platform, &llmachine);
        let mod_cx = global_cx.create_module_context(mod_id, &args);
        let mut llmod = mod_cx.translate();
        if !args.obj {
            llvm_write_to_file(llmod.as_mut(), args.llvm_ir, &args.output_file_path)?;
            drop(llmod);
        } else {
            write_object_file(llmod, &llmachine, &args.output_file_path)?;
        }

        // NB: context must outlive llvm module
        // fixme this should be handled with lifetimes
        drop(global_cx);
    };
    */
    {
        // use move_mv_llvm_compiler::stackless::*;
        // let global_cx = GlobalContext::new(&global_env, Target::Solana);
        use move_mv_llvm_compiler::stackless::{Target, *};

        let tgt_platform = TargetPlatform::Solana;
        tgt_platform.initialize_llvm();
        let lltarget = Target::from_triple(tgt_platform.triple())?;
        let llmachine = lltarget.create_target_machine(
            tgt_platform.triple(),
            tgt_platform.llvm_cpu(),
            tgt_platform.llvm_features(),
        );
        // let mod_id = global_env
        //     .get_modules()
        //     .last()
        //     .map(|m| m.get_id())
        //     .expect(".");
        let global_cx = GlobalContext::new(&global_env, tgt_platform, &llmachine);

        let num_modules = global_env.get_module_count();
        println!("Program {} generated {} {}", &path, num_modules,
            if num_modules > 1 {"modules".to_string()} else {"module".to_string()});

        for mod_id in global_env
            .get_modules()
            .map(|m| m.get_id()) {
                let mod_cx = global_cx.create_module_context(mod_id, &args);
                let mut llmod = mod_cx.translate();
                if !args.obj {
                    llvm_write_to_file(llmod.as_mut(), args.llvm_ir, &args.output_file_path)?;
                    drop(llmod);
                } else {
                    write_object_file(llmod, &llmachine, &args.output_file_path)?;
                }
        }
        // NB: context must outlive llvm module
        // fixme this should be handled with lifetimes
        drop(global_cx);
    };

    Ok(())
}

fn llvm_write_to_file(
    module: LLVMModuleRef,
    llvm_ir: bool,
    output_file_name: &String,
) -> anyhow::Result<()> {
    use llvm_sys::{
        bit_writer::LLVMWriteBitcodeToFD,
        core::{LLVMDisposeMessage, LLVMPrintModuleToFile, LLVMPrintModuleToString},
    };
    use move_mv_llvm_compiler::support::to_c_str;
    use std::{ffi::CStr, fs::File, os::unix::io::AsRawFd, ptr};

    unsafe {
        if llvm_ir {
            if output_file_name != "-" {
                let mut err_string = ptr::null_mut();
                let filename = to_c_str(output_file_name);
                let res = LLVMPrintModuleToFile(module, filename.as_ptr(), &mut err_string);

                if res != 0 {
                    assert!(!err_string.is_null());
                    let msg = CStr::from_ptr(err_string).to_string_lossy();
                    LLVMDisposeMessage(err_string);
                    anyhow::bail!("{}", msg);
                }
            } else {
                let buf = LLVMPrintModuleToString(module);
                assert!(!buf.is_null());
                let cstr = CStr::from_ptr(buf);
                print!("{}", cstr.to_string_lossy());
                LLVMDisposeMessage(buf);
            }
        } else {
            if output_file_name == "-" {
                anyhow::bail!("Not writing bitcode to stdout");
            }
            let bc_file = File::create(output_file_name)?;
            let res = LLVMWriteBitcodeToFD(module, bc_file.as_raw_fd(), false as i32, true as i32);

            if res != 0 {
                anyhow::bail!("Failed to write bitcode to file");
            }
        }
    }

    Ok(())
}

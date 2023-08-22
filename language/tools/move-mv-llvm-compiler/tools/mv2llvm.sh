#!/bin/bash

### Use this script to run all .mv files in a given directory thru `move-mv-llvm-compiler``.
###
### It is particularly convenient in combination with aptos compiler, for example the following line will
### call aptos move compiler (which supports move iterator, lambda and inline) and compile all files in the directory
### provided in `--package-dir` and will produce the bytecode (.mv files) in the directory provided in --output-dir:
### ./aptos move compile --package-dir  /home/sol/work/git/aptos/aptos-core/aptos-move/framework/move-stdlib --output-dir /tmp/aptos-stdlib
###
### Then run this script as
### mv2llvm.sh --dir /tmp/aptos-stdlib/build/MoveStdlib/bytecode_modules --mv2llvm [path to move-mv-llvm-compiler]
### Look for produced .ll files in the directory `/tmp/aptos-stdlib/build`.

usage() {
    echo "Usage: $0 --dir [directory with .mv files] --mv2llvm [path to move_mv_llvm_compiler] -arg1 ... --arg_n val_n [extra parameters of compilation]"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir)
            shift
            directory="$1"
            ;;
        --mv2llvm)
            shift
            move_mv_llvm_compiler="$1"
            ;;
        -*)
            arg_name="${1#-}"  # Remove leading dash
            shift
            arg_value="$1"
            args["$arg_name"]="$arg_value"
            ;;
        *)
            usage
            ;;
    esac
    shift
done

if [[ -z "$directory" ]] || [[ -z "$move_mv_llvm_compiler" ]]; then
    usage
fi

# Remove trailing slash from directory name if exists
directory="${directory%/}"

# Create the build directory
build_dir="$directory/build"
mkdir -p "$build_dir"

# Iterate over files in the directory
for file in "$directory"/*; do
    if [ -f "$file" ]; then
        file_name=$(basename "$file")
        file_ext="${file_name##*.}"

        # Skip non-mv files
        if [[ "$file_ext" != "mv" ]]; then
            continue
        fi

        # Build arguments for move_mv_llvm_compiler
        move_mv_llvm_compiler_args=("-b" "$file")
        for arg_name in "${!args[@]}"; do
            move_mv_llvm_compiler_args+=("--$arg_name" "${args[$arg_name]}")
        done

        # Build output file name with .ll extension
        output_file="$build_dir/${file_name%.mv}.ll"

        # Execute move_mv_llvm_compiler
        echo ""
        echo ""
        echo "Compiling: ${move_mv_llvm_compiler_args[*]} --> $output_file"
        RUST_BACKTRACE=1 "$move_mv_llvm_compiler" "${move_mv_llvm_compiler_args[@]}" -S -o "$output_file"
    fi
done

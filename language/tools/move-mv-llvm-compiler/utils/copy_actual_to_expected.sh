#!/bin/bash

# Copyright (c) The Diem Core Contributors
# Copyright (c) The Move Contributors
# SPDX-License-Identifier: Apache-2.0

# Check if the 'dir' parameter is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <dir>"
    exit 1
fi

# Check if the provided directory exists
if [ ! -d "$1" ]; then
    echo "Directory '$1' not found."
    exit 1
fi

# Find all files with extension '.actual' in subdirectories of the provided directory
find "$1" -type f -name '*.actual' | while read -r file; do
    # Determine the new filename by replacing the extension
    expected_file="${file%.actual}.expected"

    # Copy the file to the new filename
    cp "$file" "$expected_file"
    echo "Copied $file to $expected_file"
done

echo "Copy operation completed."

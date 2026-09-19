#!/bin/bash

target_dir="../../../../../include/capstone"

find "$target_dir" -name "*.h" -print0 | while IFS= read -r -d $'\0' header_file; do
  relative_path=$(echo "$header_file" | sed "s#^$PWD/##")

  ln -s "$relative_path" .

  echo "Created symlink: $(basename "$header_file") -> $relative_path"
done

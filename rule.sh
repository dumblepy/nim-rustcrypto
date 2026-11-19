#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || -z "$1" || "$1" == */* || "$1" == *$'\n'* || "$1" == *$'\r'* ]]; then
  printf '使い方: %s <ブランチ名（空文字・スラッシュ・改行は不可）>\n' "$0" >&2
  exit 1
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
rules_dir="$script_dir/.agent/rules/branch"
rule_file="$rules_dir/$1.mdc"

mkdir -p -- "$rules_dir"

# 既存のブランチルールを上書きしない。
set -o noclobber
printf '%s\n' '---' "description: $1 ブランチでの開発時に読み込む" 'alwaysApply: false' '---' > "$rule_file"

printf '作成しました: %s\n' "$rule_file"

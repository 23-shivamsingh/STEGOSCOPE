#!/usr/bin/env bash
set -euo pipefail
printf '\nSTEGOSCOPE: optional macOS CLI utilities\n'
printf 'Core workbench works WITHOUT these. This only installs extra analyzers.\n\n'
if ! command -v brew >/dev/null 2>&1; then
  printf 'Homebrew not found. Install it separately from https://brew.sh/ if desired.\n'
  exit 1
fi
read -r -p 'Install Binwalk, ExifTool, FFmpeg, zbar and Tesseract using Homebrew? [y/N] ' answer
if [[ "$answer" =~ ^[Yy]$ ]]; then
  brew install binwalk exiftool ffmpeg zbar tesseract
fi
if command -v gem >/dev/null 2>&1; then
  read -r -p 'Try installing zsteg via RubyGems (requires a writable Ruby gem environment)? [y/N] ' answer
  if [[ "$answer" =~ ^[Yy]$ ]]; then
    gem install zsteg
  fi
fi
printf '\nCheck availability: \n'
for cmd in binwalk exiftool ffprobe zbarimg tesseract zsteg steghide stegseek; do
  if command -v "$cmd" >/dev/null 2>&1; then printf '[OK]      %s\n' "$cmd"; else printf '[MISSING] %s\n' "$cmd"; fi
done
printf '\nSteghide: see https://ports.macports.org/port/steghide/ (MacPorts).\n'
printf 'Stegseek: see https://github.com/RickdeJager/stegseek (upstream).\n'

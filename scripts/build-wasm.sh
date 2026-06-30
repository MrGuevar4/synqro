#!/bin/bash
# Script to build WebAssembly version using wasm-pack
# Requires wasm-pack

cd wasm
wasm-pack build --target web
wasm-pack build --target nodejs

echo "Wasm packages generated in wasm/pkg/"

#!/bin/bash
# Basic script to cross-compile for Android
# Requires Android NDK and cargo-ndk

# Add targets
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android

# Build for all targets
cargo ndk -t armeabi-v7a -t arm64-v8a -t x86 -t x86_64 build --release

echo "Android binaries generated in target/ folder"

# PicoZstd

PicoZstd is a dependency-free C11 streaming Zstandard decoder for constrained and general-purpose systems. It is intended to serve directly as PicoParquet's ZSTD codec while remaining useful as a standalone decoder.

## v0.1 scope

- Decoder first; no encoder requirement
- Bounded caller-owned memory
- Zstandard frame and block parsing
- Raw, RLE, and compressed blocks
- Literals and sequence decoding with FSE/Huffman support
- Dictionary-free operation initially
- Streaming sink API
- No `malloc` in the hot decode path where practical
- Cortex-M through x86/AArch64 portability
- Optional SIMD with portable scalar code as the authority

## Status

The project is at specification stage. See [Issue #1](../../issues/1) for the v0.1 requirements.
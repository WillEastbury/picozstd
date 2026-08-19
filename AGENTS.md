# AGENTS.md

## Project constraints

- Keep the decoder dependency-free and conform to C11.
- Use bounded caller-owned memory; avoid hidden ownership and unbounded buffering.
- Keep frame and block parsing separate from the streaming sink interface.
- Implement raw, RLE, and compressed blocks, including literals, sequences, FSE, and Huffman decoding, within the v0.1 scope.
- v0.1 is dictionary-free and decoder-only unless a later specification expands it.
- Avoid `malloc` in hot decode paths where practical; surface capacity and malformed-input errors explicitly.
- Maintain portability from Cortex-M through x86/AArch64. Portable scalar code is authoritative, and SIMD is optional.
- Keep the API suitable for direct integration as PicoParquet's ZSTD codec callback.

Issue #1 is the source of truth for v0.1. Update documentation whenever supported frame features or API guarantees change.
# PicoZstd

PicoZstd is a small dependency-free C11 streaming decoder for standard
Zstandard frames. It is designed for constrained systems and for direct use
as PicoParquet's ZSTD codec callback.

## Status

The v0.1 decoder implementation and deterministic test suite are included.
The implementation uses portable scalar C, caller-owned storage, and no
dynamic allocation in the decode path.

Supported:

- Standard Zstandard frame headers, known or unknown content size, and checksums
- Dictionary-free frames (dictionary-bearing frames return an explicit error)
- Raw, RLE, and compressed blocks
- Raw/RLE literals and Huffman literals in one- and four-stream forms
- Predefined, RLE, compressed, and repeated FSE sequence tables
- Literal-length, match-length, offset, repeat-offset, and history-window matches
- Arbitrary input chunking through a sink callback

This is a decoder only. Legacy/magicless formats, skippable frames, and
external dictionaries are intentionally outside v0.1.

## Building and testing

The only build dependency is CMake plus a C11 compiler:

```sh
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## API

Include `picozstd.h`, allocate a `picozstd_decoder` and the buffers described
below, then initialize the decoder:

```c
static int write_sink(void *opaque, const uint8_t *data, size_t size);

picozstd_config config = {
    .window = window,
    .window_capacity = sizeof window,
    .literal_buffer = literals,
    .literal_capacity = sizeof literals,
    .block_buffer = compressed_block,
    .block_capacity = sizeof compressed_block,
    .sink = write_sink,
    .sink_opaque = application_state
};
picozstd_decoder decoder;
picozstd_decoder_init(&decoder, &config);
```

Feed any available input chunk with `picozstd_push()`. It reports the number
of accepted bytes through `consumed`; call `picozstd_decoder_finish()` after
the input source reaches end-of-file. A successful frame returns
`PICOZSTD_FRAME_DONE`. The decoder stops at the end of one frame, so trailing
input can be retained for a subsequent decoder.

All storage is supplied by the caller:

- `window` must hold the frame's advertised history window.
- `literal_buffer` must hold regenerated literals (up to 128 KiB).
- `block_buffer` must hold one compressed block (up to 128 KiB).
- The sink receives decoded output in bounded chunks. A null sink discards
  output while still validating the frame.

Status values distinguish malformed input, truncation, checksum failures,
unsupported dictionaries, insufficient workspace, sink failures, and window
capacity failures. See the enum and comments in `picozstd.h`.

## Integration notes

`picozstd.c` and `picozstd.h` are the complete library. They require only the
C11 standard library headers `<stddef.h>`, `<stdint.h>`, `<limits.h>`, and
`<string.h>`. The decoder object is caller-owned and may be reset with
`picozstd_decoder_reset()` for another frame using the same buffers.

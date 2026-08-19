#ifndef PICOZSTD_H
#define PICOZSTD_H

/*
 * PicoZstd - a small, dependency-free C11 Zstandard decoder.
 *
 * The decoder is deliberately stateful: all storage used by decoding is
 * supplied by the caller through picozstd_config and picozstd_decoder.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PICOZSTD_VERSION_MAJOR 0
#define PICOZSTD_VERSION_MINOR 1

#define PICOZSTD_MAX_BLOCK_SIZE (128u * 1024u)
#define PICOZSTD_MAX_FSE_TABLE_LOG 9
#define PICOZSTD_MAX_FSE_TABLE_SIZE (1u << PICOZSTD_MAX_FSE_TABLE_LOG)
#define PICOZSTD_MAX_HUFFMAN_TABLE_LOG 11
#define PICOZSTD_HUFFMAN_TABLE_SIZE (1u << PICOZSTD_MAX_HUFFMAN_TABLE_LOG)

typedef enum picozstd_status {
    PICOZSTD_OK = 0,
    PICOZSTD_NEED_INPUT = 1,
    PICOZSTD_FRAME_DONE = 2,

    PICOZSTD_ERR_ARGUMENT = -1,
    PICOZSTD_ERR_BAD_MAGIC = -2,
    PICOZSTD_ERR_RESERVED = -3,
    PICOZSTD_ERR_DICTIONARY_UNSUPPORTED = -4,
    PICOZSTD_ERR_WINDOW_TOO_LARGE = -5,
    PICOZSTD_ERR_WORKSPACE_TOO_SMALL = -6,
    PICOZSTD_ERR_MALFORMED = -7,
    PICOZSTD_ERR_UNSUPPORTED = -8,
    PICOZSTD_ERR_CHECKSUM = -9,
    PICOZSTD_ERR_SINK = -10,
    PICOZSTD_ERR_TRUNCATED = -11,
    PICOZSTD_ERR_OUTPUT_TOO_LARGE = -12
} picozstd_status;

typedef int (*picozstd_sink_fn)(void *opaque, const uint8_t *data, size_t size);

typedef struct picozstd_config {
    /*
     * The history window.  It must be at least as large as the Window_Size
     * advertised by a frame.  It may be NULL only for an empty frame.
     */
    uint8_t *window;
    size_t window_capacity;

    /*
     * Scratch storage for regenerated literals. Compressed blocks can
     * regenerate up to 128 KiB of literals. It is required for compressed
     * blocks, even when a particular block contains no literals.
     */
    uint8_t *literal_buffer;
    size_t literal_capacity;

    /*
     * Scratch storage for a compressed block.  Supplying this buffer makes
     * picozstd_push() usable with arbitrarily small input chunks.  Its
     * capacity must cover the largest compressed block that will be accepted.
     */
    uint8_t *block_buffer;
    size_t block_capacity;

    /*
     * Decoded output is delivered in bounded chunks. A NULL sink validates
     * and consumes the frame while discarding decoded bytes.
     */
    picozstd_sink_fn sink;
    void *sink_opaque;
} picozstd_config;

typedef struct picozstd_fse_entry {
    uint16_t baseline;
    uint8_t symbol;
    uint8_t number_of_bits;
} picozstd_fse_entry;

typedef struct picozstd_fse_table {
    uint8_t table_log;
    uint8_t max_symbol;
    uint16_t table_size;
    picozstd_fse_entry entry[PICOZSTD_MAX_FSE_TABLE_SIZE];
} picozstd_fse_table;

typedef struct picozstd_xxh64 {
    uint64_t total_length;
    uint64_t v1;
    uint64_t v2;
    uint64_t v3;
    uint64_t v4;
    uint8_t memory[32];
    size_t memory_size;
} picozstd_xxh64;

typedef struct picozstd_decoder {
    picozstd_config config;

    uint8_t header[18];
    uint8_t header_size;
    uint8_t header_needed;
    uint8_t block_header[3];
    uint8_t block_header_size;
    uint8_t checksum_bytes[4];
    uint8_t checksum_size;

    uint8_t stage;
    uint8_t block_type;
    uint8_t block_last;
    uint8_t rle_value;
    uint8_t checksum_enabled;
    uint8_t content_size_known;
    uint8_t huffman_valid;
    uint8_t sequence_tables_valid;

    uint64_t window_size;
    uint64_t content_size;
    uint64_t total_output;
    uint64_t block_output_start;
    uint64_t block_output_limit;
    uint64_t block_remaining;

    size_t block_buffer_size;
    size_t output_buffer_size;
    uint8_t output_buffer[256];

    uint64_t repeated_offsets[3];
    picozstd_xxh64 checksum;

    uint8_t huffman_table_log;
    uint8_t huffman_symbol[PICOZSTD_HUFFMAN_TABLE_SIZE];
    uint8_t huffman_bits[PICOZSTD_HUFFMAN_TABLE_SIZE];

    picozstd_fse_table literal_lengths;
    picozstd_fse_table offsets;
    picozstd_fse_table match_lengths;
    picozstd_fse_table fse_scratch;

    picozstd_status error;
} picozstd_decoder;

void picozstd_decoder_init(picozstd_decoder *decoder,
                           const picozstd_config *config);

void picozstd_decoder_reset(picozstd_decoder *decoder);

/*
 * Feed input to the decoder.  *consumed is always set to the number of input
 * bytes accepted by this call.  PICOZSTD_NEED_INPUT means that more bytes are
 * required; PICOZSTD_FRAME_DONE means that one complete frame was consumed and
 * any trailing bytes remain unconsumed.
 */
picozstd_status picozstd_push(picozstd_decoder *decoder,
                              const void *input,
                              size_t input_size,
                              size_t *consumed);

/*
 * Signal end of input.  This is useful when input is delivered in chunks and
 * distinguishes a truncated frame from a frame that merely needs more data.
 */
picozstd_status picozstd_decoder_finish(picozstd_decoder *decoder);

const char *picozstd_status_name(picozstd_status status);

#ifdef __cplusplus
}
#endif

#endif

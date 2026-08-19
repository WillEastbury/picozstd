#include "picozstd.h"

#include <stdio.h>
#include <string.h>

#define WINDOW_CAPACITY (4u * 1024u * 1024u)
#define SCRATCH_CAPACITY (128u * 1024u)
#define OUTPUT_CAPACITY (4u * 1024u * 1024u)

static uint8_t window_storage[WINDOW_CAPACITY];
static uint8_t literal_storage[SCRATCH_CAPACITY];
static uint8_t block_storage[SCRATCH_CAPACITY];
static uint8_t output_storage[OUTPUT_CAPACITY];
static size_t output_size;
static int sink_should_fail;

static int sink(void *opaque, const uint8_t *data, size_t size)
{
    (void)opaque;
    if (sink_should_fail || size > OUTPUT_CAPACITY - output_size) {
        return 1;
    }
    memcpy(output_storage + output_size, data, size);
    output_size += size;
    return 0;
}

static int check(int condition, const char *expression, int line)
{
    if (!condition) {
        fprintf(stderr, "check failed at line %d: %s\n", line, expression);
        return 0;
    }
    return 1;
}

#define CHECK(expression) \
    do { if (!check((expression), #expression, __LINE__)) return 0; } while (0)

static void repeat_bytes(uint8_t *output,
                         size_t count,
                         const uint8_t *pattern,
                         size_t pattern_size)
{
    size_t position;
    for (position = 0; position < count; ++position) {
        output[position] = pattern[position % pattern_size];
    }
}

static int decode_frame(const uint8_t *frame,
                        size_t frame_size,
                        size_t chunk_size,
                        size_t window_capacity,
                        size_t literal_capacity,
                        size_t block_capacity,
                        picozstd_status expected_status,
                        const uint8_t *expected_output,
                        size_t expected_size)
{
    picozstd_config config;
    picozstd_decoder decoder;
    size_t position = 0;
    picozstd_status status = PICOZSTD_NEED_INPUT;

    memset(&config, 0, sizeof(config));
    config.window = window_storage;
    config.window_capacity = window_capacity;
    config.literal_buffer = literal_storage;
    config.literal_capacity = literal_capacity;
    config.block_buffer = block_storage;
    config.block_capacity = block_capacity;
    config.sink = sink;
    output_size = 0;
    sink_should_fail = expected_status == PICOZSTD_ERR_SINK;
    picozstd_decoder_init(&decoder, &config);

    while (position < frame_size && status >= 0) {
        size_t available = frame_size - position;
        size_t offered = available < chunk_size ? available : chunk_size;
        size_t consumed = 0;
        status = picozstd_push(&decoder, frame + position, offered,
                                &consumed);
        CHECK(consumed <= offered);
        position += consumed;
        if (status == PICOZSTD_FRAME_DONE) {
            break;
        }
        if (status == PICOZSTD_NEED_INPUT) {
            CHECK(consumed != 0 || offered == 0);
        }
    }
    if (status == PICOZSTD_NEED_INPUT) {
        status = picozstd_decoder_finish(&decoder);
    }

    CHECK(status == expected_status);
    if (expected_status >= 0) {
        CHECK(position == frame_size);
        CHECK(output_size == expected_size);
        CHECK(memcmp(output_storage, expected_output, expected_size) == 0);
    }
    return 1;
}

static const uint8_t frame_raw_literals[] = {
    0x28, 0xB5, 0x2F, 0xFD, 0x64, 0x14, 0x04, 0xA5, 0x00, 0x00, 0x68, 0x68,
    0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x20,
    0x01, 0x00, 0x04, 0xC1, 0x3F, 0xBF, 0x6B, 0xDA, 0x95, 0x26
};

static const uint8_t frame_raw_block[] = {
    0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x03, 0x19, 0x00, 0x00, 0x72, 0x61, 0x77
};

static const uint8_t frame_rle_block[] = {
    0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x0A, 0x53, 0x00, 0x00, 0x5A
};

static const uint8_t frame_compressed_abcd[] = {
    0x28, 0xB5, 0x2F, 0xFD, 0x64, 0x40, 0x9B, 0x65, 0x00, 0x00, 0x20, 0x61,
    0x62, 0x63, 0x64, 0x01, 0x00, 0x39, 0x9C, 0x75, 0x47, 0x04, 0x37, 0x57,
    0x4A, 0xD4
};

static const uint8_t frame_fse_sequences[] = {
    0x28, 0xB5, 0x2F, 0xFD, 0x64, 0x08, 0x06, 0x55, 0x03, 0x00, 0x06, 0xE6,
    0x16, 0x04, 0xE0, 0x0F, 0x81, 0x51, 0x14, 0x00, 0x14, 0x00, 0x14, 0x00,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x05, 0x01, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x01, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x01,
    0x41, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x01,
    0x81, 0x2A, 0x94, 0x11, 0xE4, 0x6F, 0x06, 0x00, 0x01, 0x00, 0xA1, 0x0A,
    0xC1, 0x28, 0xBC, 0x9B
};

static const uint8_t frame_unknown_size[] = {
    0x28, 0xB5, 0x2F, 0xFD, 0x04, 0x08, 0xE5, 0x00, 0x00, 0xA0, 0x75, 0x6E,
    0x6B, 0x6E, 0x6F, 0x77, 0x6E, 0x2D, 0x73, 0x69, 0x7A, 0x65, 0x2D, 0x73,
    0x74, 0x72, 0x65, 0x61, 0x6D, 0x2D, 0x01, 0x00, 0x52, 0xBC, 0x7F, 0x32,
    0x01, 0x14, 0x52, 0x09, 0xCF
};

static int test_valid_frames(void)
{
    static uint8_t expected[OUTPUT_CAPACITY];
    static const uint8_t hello[] = "hello world! ";
    static const uint8_t abcd[] = "abcd";
    static const uint8_t aaaab[] = "aaaaab";
    static const uint8_t unknown[] = "unknown-size-stream-";
    static const uint8_t raw[] = "raw";
    static const uint8_t z[] = "Z";

    repeat_bytes(expected, 1300, hello, sizeof(hello) - 1u);
    CHECK(decode_frame(frame_raw_literals, sizeof(frame_raw_literals), 1,
                       WINDOW_CAPACITY, SCRATCH_CAPACITY, SCRATCH_CAPACITY,
                       PICOZSTD_FRAME_DONE, expected, 1300));

    CHECK(decode_frame(frame_raw_block, sizeof(frame_raw_block), 1,
                       WINDOW_CAPACITY, SCRATCH_CAPACITY, SCRATCH_CAPACITY,
                       PICOZSTD_FRAME_DONE, raw, 3));

    repeat_bytes(expected, 10, z, 1);
    CHECK(decode_frame(frame_rle_block, sizeof(frame_rle_block), 2,
                       WINDOW_CAPACITY, SCRATCH_CAPACITY, SCRATCH_CAPACITY,
                       PICOZSTD_FRAME_DONE, expected, 10));

    repeat_bytes(expected, 40000, abcd, sizeof(abcd) - 1u);
    CHECK(decode_frame(frame_compressed_abcd,
                       sizeof(frame_compressed_abcd), 7,
                       WINDOW_CAPACITY, SCRATCH_CAPACITY, SCRATCH_CAPACITY,
                       PICOZSTD_FRAME_DONE, expected, 40000));

    repeat_bytes(expected, 1800, aaaab, sizeof(aaaab) - 1u);
    CHECK(decode_frame(frame_fse_sequences, sizeof(frame_fse_sequences), 1,
                       WINDOW_CAPACITY, SCRATCH_CAPACITY, SCRATCH_CAPACITY,
                       PICOZSTD_FRAME_DONE, expected, 1800));

    repeat_bytes(expected, 1600, unknown, sizeof(unknown) - 1u);
    CHECK(decode_frame(frame_unknown_size, sizeof(frame_unknown_size), 3,
                       WINDOW_CAPACITY, SCRATCH_CAPACITY, SCRATCH_CAPACITY,
                       PICOZSTD_FRAME_DONE, expected, 1600));
    return 1;
}

static int test_errors(void)
{
    uint8_t bad_magic[sizeof(frame_raw_literals)];
    uint8_t reserved[sizeof(frame_raw_literals)];
    uint8_t bad_checksum[sizeof(frame_raw_literals)];
    uint8_t bad_size[sizeof(frame_raw_block)];
    static const uint8_t dictionary[] = {
        0x28, 0xB5, 0x2F, 0xFD, 0x65, 0x00, 0x14, 0x04
    };
    static const uint8_t reserved_block[] = {
        0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x00, 0x06, 0x00, 0x00
    };
    static const uint8_t skippable[] = {
        0x50, 0x2A, 0x4D, 0x18
    };

    memcpy(bad_magic, frame_raw_literals, sizeof(bad_magic));
    bad_magic[0] ^= 1u;
    CHECK(decode_frame(bad_magic, sizeof(bad_magic), sizeof(bad_magic),
                       WINDOW_CAPACITY, SCRATCH_CAPACITY, SCRATCH_CAPACITY,
                       PICOZSTD_ERR_BAD_MAGIC, NULL, 0));

    memcpy(reserved, frame_raw_literals, sizeof(reserved));
    reserved[4] |= 0x08u;
    CHECK(decode_frame(reserved, sizeof(reserved), sizeof(reserved),
                       WINDOW_CAPACITY, SCRATCH_CAPACITY, SCRATCH_CAPACITY,
                       PICOZSTD_ERR_RESERVED, NULL, 0));

    CHECK(decode_frame(dictionary, sizeof(dictionary), sizeof(dictionary),
                       WINDOW_CAPACITY, SCRATCH_CAPACITY, SCRATCH_CAPACITY,
                       PICOZSTD_ERR_DICTIONARY_UNSUPPORTED, NULL, 0));

    CHECK(decode_frame(reserved_block, sizeof(reserved_block),
                       sizeof(reserved_block), WINDOW_CAPACITY,
                       SCRATCH_CAPACITY, SCRATCH_CAPACITY,
                       PICOZSTD_ERR_MALFORMED, NULL, 0));

    memcpy(bad_size, frame_raw_block, sizeof(bad_size));
    bad_size[5] = 4u;
    CHECK(decode_frame(bad_size, sizeof(bad_size), sizeof(bad_size),
                       WINDOW_CAPACITY, SCRATCH_CAPACITY, SCRATCH_CAPACITY,
                       PICOZSTD_ERR_MALFORMED, NULL, 0));

    CHECK(decode_frame(skippable, sizeof(skippable), sizeof(skippable),
                       WINDOW_CAPACITY, SCRATCH_CAPACITY, SCRATCH_CAPACITY,
                       PICOZSTD_ERR_UNSUPPORTED, NULL, 0));

    memcpy(bad_checksum, frame_raw_literals, sizeof(bad_checksum));
    bad_checksum[sizeof(bad_checksum) - 1u] ^= 0x80u;
    CHECK(decode_frame(bad_checksum, sizeof(bad_checksum), 2,
                       WINDOW_CAPACITY, SCRATCH_CAPACITY, SCRATCH_CAPACITY,
                       PICOZSTD_ERR_CHECKSUM, NULL, 0));

    CHECK(decode_frame(frame_fse_sequences, sizeof(frame_fse_sequences), 8,
                       WINDOW_CAPACITY, SCRATCH_CAPACITY, 1,
                       PICOZSTD_ERR_WORKSPACE_TOO_SMALL, NULL, 0));
    CHECK(decode_frame(frame_raw_literals, sizeof(frame_raw_literals), 8,
                       1, SCRATCH_CAPACITY, SCRATCH_CAPACITY,
                       PICOZSTD_ERR_WINDOW_TOO_LARGE, NULL, 0));

    CHECK(decode_frame(frame_raw_literals, sizeof(frame_raw_literals) - 1u, 4,
                       WINDOW_CAPACITY, SCRATCH_CAPACITY, SCRATCH_CAPACITY,
                       PICOZSTD_ERR_TRUNCATED, NULL, 0));

    CHECK(decode_frame(frame_raw_literals, sizeof(frame_raw_literals), 4,
                       WINDOW_CAPACITY, SCRATCH_CAPACITY, SCRATCH_CAPACITY,
                       PICOZSTD_ERR_SINK, NULL, 0));
    sink_should_fail = 0;
    return 1;
}

int main(void)
{
    if (!test_valid_frames() || !test_errors()) {
        return 1;
    }
    puts("PicoZstd tests passed");
    return 0;
}

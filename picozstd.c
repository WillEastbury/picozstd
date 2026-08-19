#include "picozstd.h"

#include <limits.h>
#include <string.h>

#define PICOZSTD_MAGIC 0xFD2FB528u
#define PICOZSTD_MAX_CONTENT_SIZE UINT64_MAX
#define PICOZSTD_STAGE_HEADER 0u
#define PICOZSTD_STAGE_BLOCK_HEADER 1u
#define PICOZSTD_STAGE_RAW 2u
#define PICOZSTD_STAGE_RLE 3u
#define PICOZSTD_STAGE_COMPRESSED 4u
#define PICOZSTD_STAGE_CHECKSUM 5u
#define PICOZSTD_STAGE_DONE 6u
#define PICOZSTD_STAGE_ERROR 7u

static picozstd_status picozstd_emit_byte(picozstd_decoder *decoder,
                                          uint8_t value);
static picozstd_status picozstd_flush_output(picozstd_decoder *decoder);

static uint32_t picozstd_read_le32(const uint8_t *p)
{
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint16_t picozstd_read_le16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0]) | ((uint16_t)p[1] << 8));
}

static uint64_t picozstd_read_le64(const uint8_t *p)
{
    return ((uint64_t)p[0]) |
           ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

static uint32_t picozstd_read_le24(const uint8_t *p)
{
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16);
}

static int picozstd_is_skippable_magic(uint32_t magic)
{
    return (magic & UINT32_C(0xFFFFFFF0)) == UINT32_C(0x184D2A50);
}

static unsigned picozstd_floor_log2_u32(uint32_t value)
{
    unsigned result = 0;
    while (value > 1u) {
        value >>= 1;
        ++result;
    }
    return result;
}

static uint64_t picozstd_xxh64_round64(uint64_t accumulator, uint64_t input)
{
    accumulator += input * UINT64_C(14029467366897019727);
    accumulator = (accumulator << 31) | (accumulator >> 33);
    accumulator *= UINT64_C(11400714785074694791);
    return accumulator;
}

static uint64_t picozstd_xxh64_merge_round(uint64_t accumulator,
                                           uint64_t value)
{
    value = picozstd_xxh64_round64(0, value);
    accumulator ^= value;
    accumulator = accumulator * UINT64_C(11400714785074694791) +
                  UINT64_C(9650029242287828579);
    return accumulator;
}

static void picozstd_xxh64_init(picozstd_xxh64 *hash)
{
    hash->total_length = 0;
    hash->v1 = UINT64_C(11400714785074694791) +
               UINT64_C(14029467366897019727);
    hash->v2 = UINT64_C(14029467366897019727);
    hash->v3 = 0;
    hash->v4 = UINT64_C(0) - UINT64_C(11400714785074694791);
    hash->memory_size = 0;
}

static void picozstd_xxh64_process_block(picozstd_xxh64 *hash,
                                         const uint8_t *p)
{
    hash->v1 = picozstd_xxh64_round64(hash->v1, picozstd_read_le64(p));
    hash->v2 = picozstd_xxh64_round64(hash->v2, picozstd_read_le64(p + 8));
    hash->v3 = picozstd_xxh64_round64(hash->v3, picozstd_read_le64(p + 16));
    hash->v4 = picozstd_xxh64_round64(hash->v4, picozstd_read_le64(p + 24));
}

static void picozstd_xxh64_update(picozstd_xxh64 *hash,
                                  const uint8_t *data,
                                  size_t size)
{
    size_t offset = 0;

    if (size == 0) {
        return;
    }
    hash->total_length += (uint64_t)size;

    if (hash->memory_size != 0) {
        size_t needed = 32u - hash->memory_size;
        if (needed > size) {
            memcpy(hash->memory + hash->memory_size, data, size);
            hash->memory_size += size;
            return;
        }
        memcpy(hash->memory + hash->memory_size, data, needed);
        picozstd_xxh64_process_block(hash, hash->memory);
        hash->memory_size = 0;
        offset += needed;
    }

    while (offset + 32u <= size) {
        picozstd_xxh64_process_block(hash, data + offset);
        offset += 32u;
    }

    if (offset < size) {
        hash->memory_size = size - offset;
        memcpy(hash->memory, data + offset, hash->memory_size);
    }
}

static uint64_t picozstd_xxh64_digest(const picozstd_xxh64 *hash)
{
    uint64_t result;
    size_t offset = 0;

    if (hash->total_length >= 32u) {
        result = ((hash->v1 << 1) | (hash->v1 >> 63)) +
                 ((hash->v2 << 7) | (hash->v2 >> 57)) +
                 ((hash->v3 << 12) | (hash->v3 >> 52)) +
                 ((hash->v4 << 18) | (hash->v4 >> 46));
        result = picozstd_xxh64_merge_round(result, hash->v1);
        result = picozstd_xxh64_merge_round(result, hash->v2);
        result = picozstd_xxh64_merge_round(result, hash->v3);
        result = picozstd_xxh64_merge_round(result, hash->v4);
    } else {
        result = UINT64_C(2870177450012600261);
    }
    result += hash->total_length;

    while (offset + 8u <= hash->memory_size) {
        uint64_t lane = picozstd_xxh64_round64(0,
                                               picozstd_read_le64(hash->memory +
                                                                 offset));
        result ^= lane;
        result = ((result << 27) | (result >> 37)) *
                     UINT64_C(11400714785074694791) +
                 UINT64_C(9650029242287828579);
        offset += 8u;
    }
    if (offset + 4u <= hash->memory_size) {
        result ^= (uint64_t)picozstd_read_le32(hash->memory + offset) *
                  UINT64_C(11400714785074694791);
        result = (((result << 23) | (result >> 41)) *
                  UINT64_C(14029467366897019727)) +
                 UINT64_C(1609587929392839161);
        offset += 4u;
    }
    while (offset < hash->memory_size) {
        result ^= (uint64_t)hash->memory[offset] *
                  UINT64_C(2870177450012600261);
        result = ((result << 11) | (result >> 53)) *
                  UINT64_C(11400714785074694791);
        ++offset;
    }

    result ^= result >> 33;
    result *= UINT64_C(14029467366897019727);
    result ^= result >> 29;
    result *= UINT64_C(1609587929392839161);
    result ^= result >> 32;
    return result;
}

typedef struct picozstd_forward_bits {
    const uint8_t *data;
    size_t size;
    size_t bit_position;
} picozstd_forward_bits;

typedef struct picozstd_reverse_bits {
    const uint8_t *data;
    size_t size;
    size_t bit_position;
    int allow_overrun;
    int overrun;
} picozstd_reverse_bits;

static int picozstd_reverse_init(picozstd_reverse_bits *bits,
                                 const uint8_t *data,
                                 size_t size,
                                 int allow_overrun);
static uint32_t picozstd_reverse_peek(const picozstd_reverse_bits *bits,
                                      unsigned count);
static int picozstd_reverse_read(picozstd_reverse_bits *bits,
                                 unsigned count,
                                 uint32_t *value);
static int picozstd_fse_decode_unknown(const uint8_t *data,
                                       size_t size,
                                       const picozstd_fse_table *table,
                                       uint8_t *output,
                                       size_t output_capacity,
                                       size_t *output_size);
static int picozstd_parse_fse_table(picozstd_fse_table *table,
                                    const uint8_t *data,
                                    size_t size,
                                    unsigned max_symbol,
                                    size_t *bytes_used);
static void picozstd_fse_make_rle(picozstd_fse_table *table, uint8_t symbol);
static int picozstd_build_predefined(picozstd_fse_table *table,
                                     unsigned kind);

static int picozstd_huffman_read_tree(picozstd_decoder *decoder,
                                      const uint8_t *data,
                                      size_t size,
                                      size_t *bytes_used)
{
    uint8_t weights[256];
    unsigned rank[12];
    unsigned weight_count;
    unsigned table_log;
    uint32_t weight_total = 0;
    size_t header_size;
    unsigned n;

    if (size == 0) {
        return 0;
    }
    memset(weights, 0, sizeof(weights));
    if (data[0] >= 128u) {
        unsigned encoded_count = (unsigned)data[0] - 127u;
        size_t encoded_bytes = ((size_t)encoded_count + 1u) / 2u;
        if (encoded_count == 0 || encoded_count >= 256u ||
            encoded_bytes + 1u > size) {
            return 0;
        }
        weight_count = encoded_count + 1u;
        for (n = 0; n < encoded_count; ++n) {
            uint8_t packed = data[1u + n / 2u];
            weights[n] = (n & 1u) ? (packed & 0x0fu) : (packed >> 4);
        }
        header_size = 1u + encoded_bytes;
    } else {
        size_t compressed_size = data[0];
        picozstd_fse_table *table = &decoder->fse_scratch;
        size_t ncount_size;
        size_t produced;

        if (compressed_size == 0 || compressed_size + 1u > size ||
            !picozstd_parse_fse_table(table, data + 1u, compressed_size,
                                      255u, &ncount_size) ||
            ncount_size > compressed_size ||
            !picozstd_fse_decode_unknown(data + 1u + ncount_size,
                                         compressed_size - ncount_size,
                                         table, weights, 255u, &produced) ||
            produced == 0 || produced >= 256u) {
            return 0;
        }
        weight_count = (unsigned)produced + 1u;
        header_size = compressed_size + 1u;
    }

    memset(rank, 0, sizeof(rank));
    for (n = 0; n < weight_count - 1u; ++n) {
        uint8_t weight = weights[n];
        if (weight > PICOZSTD_MAX_HUFFMAN_TABLE_LOG) {
            return 0;
        }
        ++rank[weight];
        weight_total += (1u << weight) >> 1u;
    }
    if (weight_total == 0) {
        return 0;
    }

    table_log = picozstd_floor_log2_u32(weight_total) + 1u;
    if (table_log == 0 || table_log > PICOZSTD_MAX_HUFFMAN_TABLE_LOG) {
        return 0;
    }
    {
        uint32_t total = 1u << table_log;
        uint32_t rest = total - weight_total;
        unsigned last_weight;
        if (rest == 0 || (rest & (rest - 1u)) != 0) {
            return 0;
        }
        last_weight = picozstd_floor_log2_u32(rest) + 1u;
        if (last_weight > PICOZSTD_MAX_HUFFMAN_TABLE_LOG) {
            return 0;
        }
        weights[weight_count - 1u] = (uint8_t)last_weight;
        ++rank[last_weight];
    }
    if (rank[1] < 2u || (rank[1] & 1u) != 0) {
        return 0;
    }

    memset(decoder->huffman_symbol, 0, sizeof(decoder->huffman_symbol));
    memset(decoder->huffman_bits, 0, sizeof(decoder->huffman_bits));
    {
        unsigned table_position = 0;
        unsigned weight;
        for (weight = 1; weight <= table_log; ++weight) {
            unsigned length = 1u << (weight - 1u);
            uint8_t number_of_bits =
                (uint8_t)(table_log + 1u - weight);
            unsigned symbol;
            for (symbol = 0; symbol < weight_count; ++symbol) {
                unsigned repeat;
                if (weights[symbol] != weight) {
                    continue;
                }
                if (table_position + length >
                    (1u << table_log)) {
                    return 0;
                }
                for (repeat = 0; repeat < length; ++repeat) {
                    decoder->huffman_symbol[table_position] =
                        (uint8_t)symbol;
                    decoder->huffman_bits[table_position] =
                        number_of_bits;
                    ++table_position;
                }
            }
        }
        if (table_position != (1u << table_log)) {
            return 0;
        }
    }
    decoder->huffman_table_log = (uint8_t)table_log;
    decoder->huffman_valid = 1;
    *bytes_used = header_size;
    return 1;
}

static int picozstd_huffman_decode_stream(const picozstd_decoder *decoder,
                                          const uint8_t *data,
                                          size_t size,
                                          uint8_t *output,
                                          size_t output_size)
{
    picozstd_reverse_bits bits;
    size_t n;

    if (!picozstd_reverse_init(&bits, data, size, 0) ||
        decoder->huffman_table_log == 0) {
        return 0;
    }
    for (n = 0; n < output_size; ++n) {
        uint32_t index = picozstd_reverse_peek(&bits,
                                               decoder->huffman_table_log);
        uint8_t number_of_bits;
        uint32_t ignored;
        if (index >= (1u << decoder->huffman_table_log)) {
            return 0;
        }
        number_of_bits = decoder->huffman_bits[index];
        if (number_of_bits == 0 ||
            !picozstd_reverse_read(&bits, number_of_bits, &ignored)) {
            return 0;
        }
        output[n] = decoder->huffman_symbol[index];
    }
    return bits.bit_position == 0;
}

static int picozstd_decode_literals(picozstd_decoder *decoder,
                                    const uint8_t *data,
                                    size_t size,
                                    size_t *literal_size,
                                    size_t *section_size)
{
    uint8_t header;
    unsigned literal_type;
    unsigned size_format;
    size_t header_size;
    size_t regenerated_size;
    size_t compressed_size = 0;
    size_t encoded_compressed_size = 0;
    const uint8_t *payload;

    if (size == 0) {
        return 0;
    }
    header = data[0];
    literal_type = header & 3u;
    size_format = (header >> 2) & 3u;

    if (literal_type <= 1u) {
        if (size_format == 0u || size_format == 2u) {
            header_size = 1u;
            regenerated_size = header >> 3;
        } else if (size_format == 1u) {
            if (size < 2u) {
                return 0;
            }
            header_size = 2u;
            regenerated_size = (size_t)(picozstd_read_le16(data) >> 4);
        } else {
            if (size < 3u) {
                return 0;
            }
            header_size = 3u;
            regenerated_size = (size_t)(picozstd_read_le24(data) >> 4);
        }
        if (size_format == 1u) {
            regenerated_size =
                (size_t)(picozstd_read_le24(data) >> 4) & 0x0fffu;
        }
        if (regenerated_size > decoder->config.literal_capacity) {
            return 0;
        }
        if (header_size > size) {
            return 0;
        }
        payload = data + header_size;
        if (literal_type == 0u) {
            if (regenerated_size > size - header_size) {
                return 0;
            }
            memcpy(decoder->config.literal_buffer, payload, regenerated_size);
            *section_size = header_size + regenerated_size;
        } else {
            if (regenerated_size != 0u && size == header_size) {
                return 0;
            }
            if (regenerated_size != 0u) {
                memset(decoder->config.literal_buffer, payload[0],
                       regenerated_size);
                *section_size = header_size + 1u;
            } else {
                *section_size = header_size;
            }
        }
        *literal_size = regenerated_size;
        return 1;
    }

    if (literal_type == 3u) {
        if (!decoder->huffman_valid) {
            return 0;
        }
    }
    if (size_format == 0u || size_format == 1u) {
        header_size = 3u;
        if (size < header_size) {
            return 0;
        }
        {
            uint32_t value = picozstd_read_le24(data);
            regenerated_size = (value >> 4) & 0x3ffu;
            compressed_size = (value >> 14) & 0x3ffu;
        }
    } else if (size_format == 2u) {
        uint32_t value;
        header_size = 4u;
        if (size < header_size) {
            return 0;
        }
        value = picozstd_read_le32(data);
        regenerated_size = (value >> 4) & 0x3fffu;
        compressed_size = (value >> 18) & 0x3fffu;
    } else {
        header_size = 5u;
        if (size < header_size) {
            return 0;
        }
        regenerated_size = (size_t)((picozstd_read_le32(data) >> 4) &
                                     0x3ffffu);
        compressed_size = (size_t)((picozstd_read_le32(data) >> 22) |
                                    ((uint32_t)data[4] << 10));
    }
    if (compressed_size == 0u ||
        regenerated_size > decoder->config.literal_capacity ||
        (size_format != 0u && regenerated_size < 6u) ||
        compressed_size > size - header_size) {
        return 0;
    }
    encoded_compressed_size = compressed_size;

    payload = data + header_size;
    if (literal_type == 2u) {
        size_t tree_size;
        if (!picozstd_huffman_read_tree(decoder, payload, compressed_size,
                                        &tree_size) ||
            tree_size >= compressed_size) {
            return 0;
        }
        payload += tree_size;
        compressed_size -= tree_size;
    }

    if (size_format == 0u) {
        if (!picozstd_huffman_decode_stream(decoder, payload, compressed_size,
                                            decoder->config.literal_buffer,
                                            regenerated_size)) {
            return 0;
        }
    } else {
        size_t first_stream_size;
        size_t second_stream_size;
        size_t third_stream_size;
        size_t fourth_stream_size;
        if (compressed_size < 7u) {
            return 0;
        }
        first_stream_size = picozstd_read_le16(payload);
        second_stream_size = picozstd_read_le16(payload + 2u);
        third_stream_size = picozstd_read_le16(payload + 4u);
        if (first_stream_size == 0u || second_stream_size == 0u ||
            third_stream_size == 0u ||
            first_stream_size + second_stream_size +
                third_stream_size + 7u > compressed_size) {
            return 0;
        }
        fourth_stream_size = compressed_size - 6u -
                             first_stream_size - second_stream_size -
                             third_stream_size;
        if (fourth_stream_size == 0u) {
            return 0;
        }
        {
            size_t first_output_size = (regenerated_size + 3u) / 4u;
            size_t second_output_size = first_output_size;
            size_t third_output_size = first_output_size;
            size_t fourth_output_size = regenerated_size -
                                        first_output_size * 3u;
            const uint8_t *stream1 = payload + 6u;
            const uint8_t *stream2 = stream1 + first_stream_size;
            const uint8_t *stream3 = stream2 + second_stream_size;
            const uint8_t *stream4 = stream3 + third_stream_size;
            if (!picozstd_huffman_decode_stream(
                    decoder, stream1, first_stream_size,
                    decoder->config.literal_buffer, first_output_size) ||
                !picozstd_huffman_decode_stream(
                    decoder, stream2, second_stream_size,
                    decoder->config.literal_buffer + first_output_size,
                    second_output_size) ||
                !picozstd_huffman_decode_stream(
                    decoder, stream3, third_stream_size,
                    decoder->config.literal_buffer + first_output_size * 2u,
                    third_output_size) ||
                !picozstd_huffman_decode_stream(
                    decoder, stream4, fourth_stream_size,
                    decoder->config.literal_buffer + first_output_size * 3u,
                    fourth_output_size)) {
                return 0;
            }
        }
    }
    *literal_size = regenerated_size;
    *section_size = header_size + encoded_compressed_size;
    return *section_size <= size;
}

static picozstd_status picozstd_flush_output(picozstd_decoder *decoder)
{
    if (decoder->output_buffer_size == 0u) {
        return PICOZSTD_OK;
    }
    picozstd_xxh64_update(&decoder->checksum, decoder->output_buffer,
                          decoder->output_buffer_size);
    if (decoder->config.sink != NULL &&
        decoder->config.sink(decoder->config.sink_opaque,
                             decoder->output_buffer,
                             decoder->output_buffer_size) != 0) {
        decoder->error = PICOZSTD_ERR_SINK;
        decoder->stage = PICOZSTD_STAGE_ERROR;
        return decoder->error;
    }
    decoder->output_buffer_size = 0;
    return PICOZSTD_OK;
}

static picozstd_status picozstd_emit_byte(picozstd_decoder *decoder,
                                          uint8_t value)
{
    uint64_t block_output;

    if (decoder->config.window_capacity == 0u ||
        decoder->config.window == NULL ||
        decoder->total_output == UINT64_MAX) {
        decoder->error = PICOZSTD_ERR_WORKSPACE_TOO_SMALL;
        decoder->stage = PICOZSTD_STAGE_ERROR;
        return decoder->error;
    }
    block_output = decoder->total_output - decoder->block_output_start;
    if (block_output >= decoder->block_output_limit) {
        decoder->error = PICOZSTD_ERR_OUTPUT_TOO_LARGE;
        decoder->stage = PICOZSTD_STAGE_ERROR;
        return decoder->error;
    }
    if (decoder->content_size_known &&
        decoder->total_output >= decoder->content_size) {
        decoder->error = PICOZSTD_ERR_OUTPUT_TOO_LARGE;
        decoder->stage = PICOZSTD_STAGE_ERROR;
        return decoder->error;
    }
    decoder->config.window[(size_t)(decoder->total_output %
                                   (uint64_t)decoder->config.window_capacity)] =
        value;
    ++decoder->total_output;
    decoder->output_buffer[decoder->output_buffer_size++] = value;
    if (decoder->output_buffer_size == sizeof(decoder->output_buffer)) {
        return picozstd_flush_output(decoder);
    }
    return PICOZSTD_OK;
}

static picozstd_status picozstd_emit_repeat(picozstd_decoder *decoder,
                                            uint8_t value,
                                            uint64_t count)
{
    while (count != 0u) {
        picozstd_status status = picozstd_emit_byte(decoder, value);
        if (status < 0) {
            return status;
        }
        --count;
    }
    return PICOZSTD_OK;
}

static picozstd_status picozstd_emit_literals(picozstd_decoder *decoder,
                                              const uint8_t *data,
                                              size_t size)
{
    size_t n;
    for (n = 0; n < size; ++n) {
        picozstd_status status = picozstd_emit_byte(decoder, data[n]);
        if (status < 0) {
            return status;
        }
    }
    return PICOZSTD_OK;
}

static picozstd_status picozstd_emit_match(picozstd_decoder *decoder,
                                           uint64_t offset,
                                           uint64_t length)
{
    if (offset == 0u || offset > decoder->window_size ||
        offset > decoder->total_output) {
        decoder->error = PICOZSTD_ERR_MALFORMED;
        decoder->stage = PICOZSTD_STAGE_ERROR;
        return decoder->error;
    }
    while (length != 0u) {
        uint64_t source_position = decoder->total_output - offset;
        uint8_t value = decoder->config.window[
            (size_t)(source_position %
                     (uint64_t)decoder->config.window_capacity)];
        picozstd_status status = picozstd_emit_byte(decoder, value);
        if (status < 0) {
            return status;
        }
        --length;
    }
    return PICOZSTD_OK;
}

static int picozstd_read_mode_table(picozstd_decoder *decoder,
                                    picozstd_fse_table *destination,
                                    const picozstd_fse_table *previous,
                                    unsigned mode,
                                    unsigned kind,
                                    const uint8_t *data,
                                    size_t size,
                                    size_t *bytes_used)
{
    size_t used;
    unsigned max_symbol;

    *bytes_used = 0;
    switch (kind) {
    case 0:
        max_symbol = 35u;
        break;
    case 1:
        max_symbol = 31u;
        break;
    default:
        max_symbol = 52u;
        break;
    }
    switch (mode) {
    case 0:
        if (!picozstd_build_predefined(destination, kind)) {
            return 0;
        }
        return 1;
    case 1:
        if (size < 1u || data[0] > max_symbol) {
            return 0;
        }
        picozstd_fse_make_rle(destination, data[0]);
        *bytes_used = 1u;
        return 1;
    case 2:
        if (!picozstd_parse_fse_table(destination, data, size, max_symbol,
                                      &used)) {
            return 0;
        }
        *bytes_used = used;
        return 1;
    case 3:
        if (!decoder->sequence_tables_valid || previous == NULL) {
            return 0;
        }
        memcpy(destination, previous, sizeof(*destination));
        return 1;
    default:
        return 0;
    }
}

static const uint32_t picozstd_literal_length_base[36] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024,
    2048, 4096, 8192, 16384, 32768, 65536
};

static const uint8_t picozstd_literal_length_bits[36] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12,
    13, 14, 15, 16
};

static const uint32_t picozstd_match_length_base[53] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
    35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027,
    2051, 4099, 8195, 16387, 32771, 65539
};

static const uint8_t picozstd_match_length_bits[53] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1,
    2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};

static const uint32_t picozstd_offset_base[32] = {
    0, 1, 1, 5, 13, 29, 61, 125,
    253, 509, 1021, 2045, 4093, 8189, 16381, 32765,
    65533, 131069, 262141, 524285, 1048573, 2097149, 4194301,
    8388605, 16777213, 33554429, 67108861, 134217725, 268435453,
    536870909, 1073741821, 2147483645
};

static const uint8_t picozstd_offset_bits[32] = {
    0, 1, 2, 3, 4, 5, 6, 7,
    8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23,
    24, 25, 26, 27, 28, 29, 30, 31
};

static int picozstd_decode_compressed_block(picozstd_decoder *decoder,
                                            const uint8_t *data,
                                            size_t size)
{
    size_t literal_size;
    size_t literal_section_size;
    size_t sequence_offset;
    size_t sequence_size;
    const uint8_t *sequence_data;
    uint32_t number_of_sequences;
    size_t header_size;
    uint8_t mode;
    unsigned ll_mode;
    unsigned offset_mode;
    unsigned ml_mode;
    size_t literal_position = 0;
    picozstd_reverse_bits bits;
    uint32_t ll_state;
    uint32_t offset_state;
    uint32_t ml_state;
    size_t n;

    if (!picozstd_decode_literals(decoder, data, size, &literal_size,
                                 &literal_section_size) ||
        literal_section_size > size) {
        return 0;
    }
    sequence_offset = literal_section_size;
    sequence_size = size - sequence_offset;
    sequence_data = data + sequence_offset;
    if (sequence_size == 0u) {
        return 0;
    }

    if (sequence_data[0] < 128u) {
        number_of_sequences = sequence_data[0];
        header_size = 1u;
    } else if (sequence_data[0] < 255u) {
        if (sequence_size < 2u) {
            return 0;
        }
        number_of_sequences =
            ((uint32_t)(sequence_data[0] - 128u) << 8) |
            sequence_data[1];
        header_size = 2u;
    } else {
        if (sequence_size < 3u) {
            return 0;
        }
        number_of_sequences = 0x7f00u +
                            (uint32_t)picozstd_read_le16(sequence_data + 1u);
        header_size = 3u;
    }
    if (number_of_sequences == 0u) {
        if (header_size != sequence_size ||
            literal_size > decoder->block_output_limit ||
            picozstd_emit_literals(decoder, decoder->config.literal_buffer,
                                   literal_size) != PICOZSTD_OK) {
            return 0;
        }
        return 1;
    }
    if (header_size >= sequence_size) {
        return 0;
    }
    mode = sequence_data[header_size++];
    if ((mode & 3u) != 0u) {
        return 0;
    }
    ll_mode = (mode >> 6) & 3u;
    offset_mode = (mode >> 4) & 3u;
    ml_mode = (mode >> 2) & 3u;
    {
        const picozstd_fse_table old_ll = decoder->literal_lengths;
        const picozstd_fse_table old_offsets = decoder->offsets;
        const picozstd_fse_table old_ml = decoder->match_lengths;
        size_t used;
        if (!picozstd_read_mode_table(decoder, &decoder->literal_lengths,
                                      decoder->sequence_tables_valid ?
                                          &old_ll : NULL,
                                      ll_mode, 0,
                                      sequence_data + header_size,
                                      sequence_size - header_size, &used)) {
            return 0;
        }
        header_size += used;
        if (header_size > sequence_size ||
            !picozstd_read_mode_table(decoder, &decoder->offsets,
                                      decoder->sequence_tables_valid ?
                                          &old_offsets : NULL,
                                      offset_mode, 1,
                                      sequence_data + header_size,
                                      sequence_size - header_size, &used)) {
            return 0;
        }
        header_size += used;
        if (header_size > sequence_size ||
            !picozstd_read_mode_table(decoder, &decoder->match_lengths,
                                      decoder->sequence_tables_valid ?
                                          &old_ml : NULL,
                                      ml_mode, 2,
                                      sequence_data + header_size,
                                      sequence_size - header_size, &used)) {
            return 0;
        }
        header_size += used;
    }
    decoder->sequence_tables_valid = 1;
    if (header_size >= sequence_size ||
        !picozstd_reverse_init(&bits, sequence_data + header_size,
                               sequence_size - header_size, 0)) {
        return 0;
    }
    if (!picozstd_reverse_read(&bits, decoder->literal_lengths.table_log,
                               &ll_state) ||
        !picozstd_reverse_read(&bits, decoder->offsets.table_log,
                               &offset_state) ||
        !picozstd_reverse_read(&bits, decoder->match_lengths.table_log,
                               &ml_state)) {
        return 0;
    }

    for (n = 0; n < number_of_sequences; ++n) {
        const picozstd_fse_entry *ll_entry;
        const picozstd_fse_entry *offset_entry;
        const picozstd_fse_entry *ml_entry;
        uint32_t extra;
        uint32_t offset_extra = 0;
        uint32_t offset_code;
        uint32_t ll_code;
        uint32_t ml_code;
        uint64_t literal_length;
        uint64_t match_length;
        uint64_t offset_value;
        unsigned offset_bits;
        int literal_length_is_zero;
        picozstd_status status;

        if (ll_state >= decoder->literal_lengths.table_size ||
            offset_state >= decoder->offsets.table_size ||
            ml_state >= decoder->match_lengths.table_size) {
            return 0;
        }
        ll_entry = &decoder->literal_lengths.entry[ll_state];
        offset_entry = &decoder->offsets.entry[offset_state];
        ml_entry = &decoder->match_lengths.entry[ml_state];

        offset_code = offset_entry->symbol;
        if (offset_code >= 32u) {
            return 0;
        }
        offset_bits = picozstd_offset_bits[offset_code];
        if (offset_bits > 0u &&
            !picozstd_reverse_read(&bits, offset_bits, &offset_extra)) {
            return 0;
        }
        offset_value = picozstd_offset_base[offset_code] + offset_extra;
        ml_code = ml_entry->symbol;
        if (ml_code >= 53u ||
            !picozstd_reverse_read(&bits,
                                   picozstd_match_length_bits[ml_code],
                                   &extra)) {
            return 0;
        }
        match_length = picozstd_match_length_base[ml_code] + extra;
        ll_code = ll_entry->symbol;
        if (ll_code >= 36u ||
            !picozstd_reverse_read(&bits,
                                   picozstd_literal_length_bits[ll_code],
                                   &extra)) {
            return 0;
        }
        literal_length = picozstd_literal_length_base[ll_code] + extra;
        if (literal_length > literal_size - literal_position) {
            return 0;
        }
        literal_length_is_zero = literal_length == 0u;
        status = picozstd_emit_literals(
            decoder, decoder->config.literal_buffer + literal_position,
            (size_t)literal_length);
        if (status < 0) {
            return 0;
        }
        literal_position += (size_t)literal_length;

        if (offset_bits > 1u) {
            decoder->repeated_offsets[2] = decoder->repeated_offsets[1];
            decoder->repeated_offsets[1] = decoder->repeated_offsets[0];
            decoder->repeated_offsets[0] = offset_value;
        } else {
            if (offset_bits == 0u) {
                unsigned index = literal_length_is_zero ? 1u : 0u;
                offset_value = decoder->repeated_offsets[index];
                decoder->repeated_offsets[1] =
                    decoder->repeated_offsets[literal_length_is_zero ? 0u : 1u];
                decoder->repeated_offsets[0] = offset_value;
            } else {
                uint64_t repeat_code = picozstd_offset_base[offset_code] +
                                       (uint64_t)offset_extra +
                                       (literal_length_is_zero ? 1u : 0u);
                uint64_t selected_offset;
                if (repeat_code == 1u) {
                    selected_offset = decoder->repeated_offsets[1];
                    decoder->repeated_offsets[1] =
                        decoder->repeated_offsets[0];
                } else if (repeat_code == 2u) {
                    selected_offset = decoder->repeated_offsets[2];
                    decoder->repeated_offsets[2] =
                        decoder->repeated_offsets[1];
                    decoder->repeated_offsets[1] =
                        decoder->repeated_offsets[0];
                } else if (repeat_code == 3u) {
                    if (decoder->repeated_offsets[0] == 0u) {
                        return 0;
                    }
                    selected_offset = decoder->repeated_offsets[0] - 1u;
                    decoder->repeated_offsets[2] =
                        decoder->repeated_offsets[1];
                    decoder->repeated_offsets[1] =
                        decoder->repeated_offsets[0];
                } else {
                    return 0;
                }
                offset_value = selected_offset;
                decoder->repeated_offsets[0] = selected_offset;
            }
        }
        status = picozstd_emit_match(decoder, offset_value, match_length);
        if (status < 0) {
            return 0;
        }

        if (n + 1u < number_of_sequences) {
            uint32_t next_state;
            if (!picozstd_reverse_read(&bits, ll_entry->number_of_bits,
                                       &next_state)) {
                return 0;
            }
            ll_state = (uint32_t)ll_entry->baseline + next_state;
            if (!picozstd_reverse_read(&bits, ml_entry->number_of_bits,
                                       &next_state)) {
                return 0;
            }
            ml_state = (uint32_t)ml_entry->baseline + next_state;
            if (!picozstd_reverse_read(&bits, offset_entry->number_of_bits,
                                       &next_state)) {
                return 0;
            }
            offset_state = (uint32_t)offset_entry->baseline + next_state;
        }
    }
    if (bits.bit_position != 0u ||
        literal_position > literal_size) {
        return 0;
    }
    return picozstd_emit_literals(
               decoder, decoder->config.literal_buffer + literal_position,
               literal_size - literal_position) == PICOZSTD_OK;
}

static picozstd_status picozstd_set_error(picozstd_decoder *decoder,
                                          picozstd_status status)
{
    decoder->error = status;
    decoder->stage = PICOZSTD_STAGE_ERROR;
    return status;
}

static picozstd_status picozstd_parse_frame_header(picozstd_decoder *decoder)
{
    uint8_t descriptor;
    unsigned fcs_flag;
    unsigned dictionary_flag;
    unsigned dictionary_size;
    unsigned fcs_size;
    size_t position;
    uint64_t window_size;

    if (decoder->header_size < 5u ||
        picozstd_read_le32(decoder->header) != PICOZSTD_MAGIC) {
        if (decoder->header_size >= 4u &&
            picozstd_is_skippable_magic(picozstd_read_le32(decoder->header))) {
            return picozstd_set_error(decoder, PICOZSTD_ERR_UNSUPPORTED);
        }
        return picozstd_set_error(decoder, PICOZSTD_ERR_BAD_MAGIC);
    }
    descriptor = decoder->header[4];
    if ((descriptor & 0x08u) != 0u) {
        return picozstd_set_error(decoder, PICOZSTD_ERR_RESERVED);
    }
    fcs_flag = descriptor >> 6;
    dictionary_flag = descriptor & 3u;
    dictionary_size = dictionary_flag == 0u ? 0u :
                      dictionary_flag == 1u ? 1u :
                      dictionary_flag == 2u ? 2u : 4u;
    fcs_size = fcs_flag == 0u ?
               ((descriptor & 0x20u) != 0u ? 1u : 0u) :
               fcs_flag == 1u ? 2u :
               fcs_flag == 2u ? 4u : 8u;
    position = 5u;
    if ((descriptor & 0x20u) == 0u) {
        uint8_t window_descriptor;
        uint64_t window_base;
        unsigned exponent;
        unsigned mantissa;
        if (position >= decoder->header_size) {
            return picozstd_set_error(decoder, PICOZSTD_ERR_MALFORMED);
        }
        window_descriptor = decoder->header[position++];
        exponent = window_descriptor >> 3;
        mantissa = window_descriptor & 7u;
        if (exponent > 31u) {
            return picozstd_set_error(decoder, PICOZSTD_ERR_MALFORMED);
        }
        window_base = UINT64_C(1) << (10u + exponent);
        window_size = window_base + (window_base / 8u) * mantissa;
    } else {
        window_size = 0;
    }

    if (dictionary_size != 0u) {
        uint32_t dictionary_id = 0;
        unsigned n;
        if (position + dictionary_size > decoder->header_size) {
            return picozstd_set_error(decoder, PICOZSTD_ERR_MALFORMED);
        }
        for (n = 0; n < dictionary_size; ++n) {
            dictionary_id |= (uint32_t)decoder->header[position + n] <<
                            (8u * n);
        }
        (void)dictionary_id;
        return picozstd_set_error(decoder,
                                  PICOZSTD_ERR_DICTIONARY_UNSUPPORTED);
    }
    position += dictionary_size;
    if (position + fcs_size > decoder->header_size) {
        return picozstd_set_error(decoder, PICOZSTD_ERR_MALFORMED);
    }
    decoder->content_size_known = fcs_size != 0u;
    decoder->content_size = PICOZSTD_MAX_CONTENT_SIZE;
    if (fcs_size == 1u) {
        decoder->content_size = decoder->header[position];
    } else if (fcs_size == 2u) {
        decoder->content_size =
            (uint64_t)picozstd_read_le16(decoder->header + position) + 256u;
    } else if (fcs_size == 4u) {
        decoder->content_size = picozstd_read_le32(decoder->header + position);
    } else if (fcs_size == 8u) {
        decoder->content_size = picozstd_read_le64(decoder->header + position);
    }
    if ((descriptor & 0x20u) != 0u) {
        window_size = decoder->content_size;
    }
    decoder->window_size = window_size;
    if (window_size > (uint64_t)SIZE_MAX ||
        (window_size != 0u &&
         (decoder->config.window == NULL ||
          decoder->config.window_capacity < (size_t)window_size))) {
        return picozstd_set_error(decoder, PICOZSTD_ERR_WINDOW_TOO_LARGE);
    }
    decoder->checksum_enabled = (descriptor & 0x04u) != 0u;
    decoder->repeated_offsets[0] = 1u;
    decoder->repeated_offsets[1] = 4u;
    decoder->repeated_offsets[2] = 8u;
    decoder->stage = PICOZSTD_STAGE_BLOCK_HEADER;
    decoder->block_header_size = 0;
    return PICOZSTD_OK;
}

static picozstd_status picozstd_complete_frame(picozstd_decoder *decoder)
{
    picozstd_status status;
    if (decoder->content_size_known &&
        decoder->total_output != decoder->content_size) {
        return picozstd_set_error(decoder, PICOZSTD_ERR_MALFORMED);
    }
    status = picozstd_flush_output(decoder);
    if (status < 0) {
        return status;
    }
    decoder->stage = PICOZSTD_STAGE_DONE;
    return PICOZSTD_FRAME_DONE;
}

static picozstd_status picozstd_finish_block(picozstd_decoder *decoder)
{
    decoder->block_remaining = 0;
    decoder->block_buffer_size = 0;
    decoder->block_header_size = 0;
    if (decoder->block_last) {
        if (decoder->checksum_enabled) {
            decoder->checksum_size = 0;
            decoder->stage = PICOZSTD_STAGE_CHECKSUM;
            return PICOZSTD_OK;
        }
        return picozstd_complete_frame(decoder);
    }
    decoder->stage = PICOZSTD_STAGE_BLOCK_HEADER;
    return PICOZSTD_OK;
}

static picozstd_status picozstd_parse_block_header(picozstd_decoder *decoder)
{
    uint32_t header;
    uint32_t block_size;
    unsigned block_type;
    uint64_t block_maximum;

    if (decoder->block_header_size != 3u) {
        return picozstd_set_error(decoder, PICOZSTD_ERR_MALFORMED);
    }
    header = picozstd_read_le24(decoder->block_header);
    decoder->block_last = (uint8_t)(header & 1u);
    block_type = (header >> 1) & 3u;
    block_size = header >> 3;
    if (block_type == 3u) {
        return picozstd_set_error(decoder, PICOZSTD_ERR_MALFORMED);
    }
    block_maximum = decoder->window_size < PICOZSTD_MAX_BLOCK_SIZE ?
                    decoder->window_size : PICOZSTD_MAX_BLOCK_SIZE;
    if ((uint64_t)block_size > block_maximum) {
        return picozstd_set_error(decoder, PICOZSTD_ERR_MALFORMED);
    }
    decoder->block_type = (uint8_t)block_type;
    decoder->block_remaining = block_size;
    decoder->block_output_start = decoder->total_output;
    decoder->block_output_limit = block_maximum;
    decoder->block_buffer_size = 0;
    switch (block_type) {
    case 0:
        decoder->stage = PICOZSTD_STAGE_RAW;
        break;
    case 1:
        decoder->stage = PICOZSTD_STAGE_RLE;
        break;
    default:
        if ((size_t)block_size > decoder->config.block_capacity ||
            decoder->config.block_buffer == NULL ||
            decoder->config.literal_buffer == NULL ||
            decoder->config.literal_capacity == 0u) {
            return picozstd_set_error(decoder,
                                      PICOZSTD_ERR_WORKSPACE_TOO_SMALL);
        }
        decoder->stage = PICOZSTD_STAGE_COMPRESSED;
        break;
    }
    return PICOZSTD_OK;
}

void picozstd_decoder_init(picozstd_decoder *decoder,
                           const picozstd_config *config)
{
    if (decoder == NULL) {
        return;
    }
    memset(decoder, 0, sizeof(*decoder));
    if (config != NULL) {
        decoder->config = *config;
    }
    picozstd_xxh64_init(&decoder->checksum);
    decoder->content_size = PICOZSTD_MAX_CONTENT_SIZE;
    decoder->stage = PICOZSTD_STAGE_HEADER;
    decoder->error = PICOZSTD_OK;
}

void picozstd_decoder_reset(picozstd_decoder *decoder)
{
    picozstd_config config;
    if (decoder == NULL) {
        return;
    }
    config = decoder->config;
    picozstd_decoder_init(decoder, &config);
}

picozstd_status picozstd_push(picozstd_decoder *decoder,
                              const void *input,
                              size_t input_size,
                              size_t *consumed)
{
    const uint8_t *data = (const uint8_t *)input;
    size_t position = 0;

    if (consumed != NULL) {
        *consumed = 0;
    }
    if (decoder == NULL || consumed == NULL ||
        (input_size != 0u && input == NULL)) {
        return PICOZSTD_ERR_ARGUMENT;
    }
    if (decoder->stage == PICOZSTD_STAGE_ERROR) {
        return decoder->error;
    }
    if (decoder->stage == PICOZSTD_STAGE_DONE) {
        return PICOZSTD_FRAME_DONE;
    }

    for (;;) {
        if (decoder->stage == PICOZSTD_STAGE_HEADER) {
            if (decoder->header_size == 5u && decoder->header_needed == 0u) {
                uint8_t descriptor = decoder->header[4];
                unsigned fcs_flag = descriptor >> 6;
                unsigned dictionary_size =
                    (descriptor & 3u) == 0u ? 0u :
                    (descriptor & 3u) == 1u ? 1u :
                    (descriptor & 3u) == 2u ? 2u : 4u;
                unsigned fcs_size = fcs_flag == 0u ?
                    ((descriptor & 0x20u) != 0u ? 1u : 0u) :
                    fcs_flag == 1u ? 2u :
                    fcs_flag == 2u ? 4u : 8u;
                decoder->header_needed = (uint8_t)(5u +
                    ((descriptor & 0x20u) == 0u ? 1u : 0u) +
                    dictionary_size + fcs_size);
                if (decoder->header_needed > sizeof(decoder->header)) {
                    *consumed = position;
                    return picozstd_set_error(decoder,
                                              PICOZSTD_ERR_MALFORMED);
                }
            }
            if (decoder->header_needed == 0u) {
                size_t needed = 5u - decoder->header_size;
                size_t available = input_size - position;
                size_t take = needed < available ? needed : available;
                if (take == 0u) {
                    break;
                }
                memcpy(decoder->header + decoder->header_size,
                       data + position, take);
                decoder->header_size = (uint8_t)(decoder->header_size + take);
                position += take;
                if (decoder->header_size == 4u &&
                    picozstd_read_le32(decoder->header) != PICOZSTD_MAGIC) {
                    picozstd_status status =
                        picozstd_is_skippable_magic(
                            picozstd_read_le32(decoder->header)) ?
                        PICOZSTD_ERR_UNSUPPORTED : PICOZSTD_ERR_BAD_MAGIC;
                    *consumed = position;
                    return picozstd_set_error(decoder, status);
                }
                continue;
            }
            if (decoder->header_size < decoder->header_needed) {
                size_t needed = decoder->header_needed - decoder->header_size;
                size_t available = input_size - position;
                size_t take = needed < available ? needed : available;
                if (take == 0u) {
                    break;
                }
                memcpy(decoder->header + decoder->header_size,
                       data + position, take);
                decoder->header_size = (uint8_t)(decoder->header_size + take);
                position += take;
                continue;
            }
            {
                picozstd_status status =
                    picozstd_parse_frame_header(decoder);
                if (status < 0) {
                    *consumed = position;
                    return status;
                }
            }
            continue;
        }

        if (decoder->stage == PICOZSTD_STAGE_BLOCK_HEADER) {
            if (decoder->block_header_size < 3u) {
                size_t needed = 3u - decoder->block_header_size;
                size_t available = input_size - position;
                size_t take = needed < available ? needed : available;
                if (take == 0u) {
                    break;
                }
                memcpy(decoder->block_header + decoder->block_header_size,
                       data + position, take);
                decoder->block_header_size =
                    (uint8_t)(decoder->block_header_size + take);
                position += take;
                if (decoder->block_header_size < 3u) {
                    continue;
                }
            }
            {
                picozstd_status status = picozstd_parse_block_header(decoder);
                if (status < 0) {
                    *consumed = position;
                    return status;
                }
            }
            continue;
        }

        if (decoder->stage == PICOZSTD_STAGE_RAW) {
            size_t available = input_size - position;
            size_t take = decoder->block_remaining < available ?
                          (size_t)decoder->block_remaining : available;
            size_t n;
            for (n = 0; n < take; ++n) {
                picozstd_status status =
                    picozstd_emit_byte(decoder, data[position + n]);
                if (status < 0) {
                    *consumed = position + n;
                    return status;
                }
            }
            position += take;
            decoder->block_remaining -= take;
            if (decoder->block_remaining != 0u) {
                break;
            }
            {
                picozstd_status status = picozstd_finish_block(decoder);
                if (status == PICOZSTD_FRAME_DONE) {
                    *consumed = position;
                    return status;
                }
                if (status < 0) {
                    *consumed = position;
                    return status;
                }
            }
            continue;
        }

        if (decoder->stage == PICOZSTD_STAGE_RLE) {
            if (position == input_size) {
                break;
            }
            decoder->rle_value = data[position++];
            {
                picozstd_status status =
                    picozstd_emit_repeat(decoder, decoder->rle_value,
                                         decoder->block_remaining);
                if (status < 0) {
                    *consumed = position;
                    return status;
                }
            }
            decoder->block_remaining = 0;
            {
                picozstd_status status = picozstd_finish_block(decoder);
                if (status == PICOZSTD_FRAME_DONE) {
                    *consumed = position;
                    return status;
                }
                if (status < 0) {
                    *consumed = position;
                    return status;
                }
            }
            continue;
        }

        if (decoder->stage == PICOZSTD_STAGE_COMPRESSED) {
            size_t needed = (size_t)decoder->block_remaining -
                            decoder->block_buffer_size;
            size_t available = input_size - position;
            size_t take = needed < available ? needed : available;
            if (take != 0u) {
                memcpy(decoder->config.block_buffer +
                           decoder->block_buffer_size,
                       data + position, take);
                decoder->block_buffer_size += take;
                position += take;
            }
            if (decoder->block_buffer_size < (size_t)decoder->block_remaining) {
                break;
            }
            if (!picozstd_decode_compressed_block(
                    decoder, decoder->config.block_buffer,
                    decoder->block_buffer_size)) {
                if (decoder->stage == PICOZSTD_STAGE_ERROR) {
                    *consumed = position;
                    return decoder->error;
                }
                *consumed = position;
                return picozstd_set_error(decoder, PICOZSTD_ERR_MALFORMED);
            }
            {
                picozstd_status status = picozstd_finish_block(decoder);
                if (status == PICOZSTD_FRAME_DONE) {
                    *consumed = position;
                    return status;
                }
                if (status < 0) {
                    *consumed = position;
                    return status;
                }
            }
            continue;
        }

        if (decoder->stage == PICOZSTD_STAGE_CHECKSUM) {
            size_t needed = 4u - decoder->checksum_size;
            size_t available = input_size - position;
            size_t take = needed < available ? needed : available;
            if (take != 0u) {
                memcpy(decoder->checksum_bytes + decoder->checksum_size,
                       data + position, take);
                decoder->checksum_size =
                    (uint8_t)(decoder->checksum_size + take);
                position += take;
            }
            if (decoder->checksum_size < 4u) {
                break;
            }
            {
                picozstd_status status = picozstd_flush_output(decoder);
                if (status < 0) {
                    *consumed = position;
                    return status;
                }
            }
            if ((uint32_t)picozstd_xxh64_digest(&decoder->checksum) !=
                picozstd_read_le32(decoder->checksum_bytes)) {
                *consumed = position;
                return picozstd_set_error(decoder, PICOZSTD_ERR_CHECKSUM);
            }
            {
                picozstd_status status = picozstd_complete_frame(decoder);
                *consumed = position;
                return status;
            }
        }
        if (decoder->stage == PICOZSTD_STAGE_DONE) {
            *consumed = position;
            return PICOZSTD_FRAME_DONE;
        }
        if (decoder->stage == PICOZSTD_STAGE_ERROR) {
            *consumed = position;
            return decoder->error;
        }
    }

    *consumed = position;
    if (decoder->stage == PICOZSTD_STAGE_ERROR) {
        return decoder->error;
    }
    if (decoder->stage == PICOZSTD_STAGE_DONE) {
        return PICOZSTD_FRAME_DONE;
    }
    return PICOZSTD_NEED_INPUT;
}

picozstd_status picozstd_decoder_finish(picozstd_decoder *decoder)
{
    if (decoder == NULL) {
        return PICOZSTD_ERR_ARGUMENT;
    }
    if (decoder->stage == PICOZSTD_STAGE_DONE) {
        return PICOZSTD_FRAME_DONE;
    }
    if (decoder->stage == PICOZSTD_STAGE_ERROR) {
        return decoder->error;
    }
    return picozstd_set_error(decoder, PICOZSTD_ERR_TRUNCATED);
}

const char *picozstd_status_name(picozstd_status status)
{
    switch (status) {
    case PICOZSTD_OK:
        return "ok";
    case PICOZSTD_NEED_INPUT:
        return "need input";
    case PICOZSTD_FRAME_DONE:
        return "frame done";
    case PICOZSTD_ERR_ARGUMENT:
        return "invalid argument";
    case PICOZSTD_ERR_BAD_MAGIC:
        return "bad magic";
    case PICOZSTD_ERR_RESERVED:
        return "reserved frame flag";
    case PICOZSTD_ERR_DICTIONARY_UNSUPPORTED:
        return "dictionary unsupported";
    case PICOZSTD_ERR_WINDOW_TOO_LARGE:
        return "window too large";
    case PICOZSTD_ERR_WORKSPACE_TOO_SMALL:
        return "workspace too small";
    case PICOZSTD_ERR_MALFORMED:
        return "malformed frame";
    case PICOZSTD_ERR_UNSUPPORTED:
        return "unsupported feature";
    case PICOZSTD_ERR_CHECKSUM:
        return "checksum mismatch";
    case PICOZSTD_ERR_SINK:
        return "sink error";
    case PICOZSTD_ERR_TRUNCATED:
        return "truncated input";
    case PICOZSTD_ERR_OUTPUT_TOO_LARGE:
        return "output too large";
    default:
        return "unknown status";
    }
}
static int picozstd_forward_read(picozstd_forward_bits *bits,
                                 unsigned count,
                                 uint32_t *value)
{
    size_t total_bits;
    unsigned n;
    uint32_t result = 0;

    if (count > 32u || bits->size > SIZE_MAX / 8u) {
        return 0;
    }
    total_bits = bits->size * 8u;
    if (bits->bit_position > total_bits ||
        count > total_bits - bits->bit_position) {
        return 0;
    }
    for (n = 0; n < count; ++n) {
        size_t position = bits->bit_position + n;
        result |= (uint32_t)(((bits->data[position >> 3] >>
                               (position & 7u)) & 1u) << n);
    }
    bits->bit_position += count;
    *value = result;
    return 1;
}

static unsigned picozstd_highest_set_bit(uint8_t value)
{
    unsigned result = 0;
    while (value > 1u) {
        value >>= 1;
        ++result;
    }
    return result;
}

static int picozstd_reverse_init(picozstd_reverse_bits *bits,
                                 const uint8_t *data,
                                 size_t size,
                                 int allow_overrun)
{
    uint8_t last;

    if (size == 0) {
        return 0;
    }
    last = data[size - 1u];
    if (last == 0) {
        return 0;
    }
    bits->data = data;
    bits->size = size;
    bits->bit_position = (size - 1u) * 8u +
                         picozstd_highest_set_bit(last);
    bits->allow_overrun = allow_overrun;
    bits->overrun = 0;
    return 1;
}

static uint32_t picozstd_reverse_peek(const picozstd_reverse_bits *bits,
                                      unsigned count)
{
    size_t start;
    unsigned shift;
    unsigned n;
    uint32_t result = 0;

    if (count == 0 || count > 32u) {
        return 0;
    }
    if (bits->bit_position >= (size_t)count) {
        start = bits->bit_position - count;
        shift = 0;
    } else {
        start = 0;
        shift = count - (unsigned)bits->bit_position;
    }
    for (n = 0; n < count && start + n < bits->bit_position; ++n) {
        size_t position = start + n;
        result |= (uint32_t)(((bits->data[position >> 3] >>
                               (position & 7u)) & 1u) << (n + shift));
    }
    return result;
}

static int picozstd_reverse_read(picozstd_reverse_bits *bits,
                                 unsigned count,
                                 uint32_t *value)
{
    uint32_t result;
    size_t start;
    unsigned n;

    if (count > 32u) {
        return 0;
    }
    if (count > bits->bit_position) {
        if (!bits->allow_overrun) {
            return 0;
        }
        result = picozstd_reverse_peek(bits, count);
        bits->bit_position = 0;
        bits->overrun = 1;
        *value = result;
        return 1;
    }
    start = bits->bit_position - count;
    result = 0;
    for (n = 0; n < count; ++n) {
        size_t position = start + n;
        result |= (uint32_t)(((bits->data[position >> 3] >>
                               (position & 7u)) & 1u) << n);
    }
    bits->bit_position -= count;
    *value = result;
    return 1;
}

static int picozstd_fse_build_table(picozstd_fse_table *table,
                                    const int16_t *normalized,
                                    unsigned max_symbol,
                                    unsigned table_log)
{
    uint16_t symbol_next[256];
    uint16_t table_size;
    uint16_t high_threshold;
    uint16_t position;
    uint16_t step;
    unsigned symbol;
    unsigned state;
    unsigned nonzero = 0;
    int total = 0;

    if (table_log < 5u || table_log > PICOZSTD_MAX_FSE_TABLE_LOG ||
        max_symbol >= 256u) {
        return 0;
    }
    table_size = (uint16_t)(1u << table_log);
    memset(symbol_next, 0, sizeof(symbol_next));
    for (symbol = 0; symbol <= max_symbol; ++symbol) {
        int value = normalized[symbol];
        if (value < -1 || value > (int)table_size) {
            return 0;
        }
        if (value > 0) {
            total += value;
            ++nonzero;
        } else if (value == -1) {
            total += 1;
            ++nonzero;
        }
    }
    if (total != (int)table_size || nonzero < 2u) {
        return 0;
    }

    table->table_log = (uint8_t)table_log;
    table->max_symbol = (uint8_t)max_symbol;
    table->table_size = table_size;
    for (state = 0; state < table_size; ++state) {
        table->entry[state].symbol = 0xffu;
        table->entry[state].number_of_bits = 0;
        table->entry[state].baseline = 0;
    }

    high_threshold = (uint16_t)(table_size - 1u);
    for (symbol = 0; symbol <= max_symbol; ++symbol) {
        if (normalized[symbol] == -1) {
            table->entry[high_threshold].symbol = (uint8_t)symbol;
            symbol_next[symbol] = 1;
            if (high_threshold == 0) {
                return 0;
            }
            --high_threshold;
        } else {
            symbol_next[symbol] = (uint16_t)normalized[symbol];
        }
    }

    step = (uint16_t)(table_size / 2u + table_size / 8u + 3u);
    position = 0;
    for (symbol = 0; symbol <= max_symbol; ++symbol) {
        int count = normalized[symbol];
        int n;
        if (count <= 0) {
            continue;
        }
        for (n = 0; n < count; ++n) {
            unsigned guard = 0;
            while (position > high_threshold) {
                position = (uint16_t)((position + step) & (table_size - 1u));
                if (++guard > table_size) {
                    return 0;
                }
            }
            if (table->entry[position].symbol != 0xffu) {
                return 0;
            }
            table->entry[position].symbol = (uint8_t)symbol;
            position = (uint16_t)((position + step) & (table_size - 1u));
        }
    }
    if (position != 0) {
        return 0;
    }

    for (state = 0; state < table_size; ++state) {
        uint8_t current_symbol = table->entry[state].symbol;
        uint32_t next_state;
        unsigned high_bit;

        if (current_symbol == 0xffu || current_symbol > max_symbol) {
            return 0;
        }
        next_state = symbol_next[current_symbol]++;
        if (next_state == 0) {
            return 0;
        }
        high_bit = picozstd_floor_log2_u32(next_state);
        if (high_bit > table_log) {
            return 0;
        }
        table->entry[state].number_of_bits =
            (uint8_t)(table_log - high_bit);
        table->entry[state].baseline =
            (uint16_t)((next_state << table->entry[state].number_of_bits) -
                       table_size);
    }
    return 1;
}

static int picozstd_fse_read_ncount(const uint8_t *data,
                                    size_t size,
                                    int16_t *normalized,
                                    unsigned normalized_capacity,
                                    unsigned *max_symbol,
                                    unsigned *table_log,
                                    size_t *bytes_used)
{
    picozstd_forward_bits bits;
    uint32_t value;
    unsigned log;
    unsigned char_number = 0;
    unsigned previous_zero = 0;
    int remaining;
    int threshold;
    unsigned number_of_bits;

    if (size == 0 || normalized_capacity == 0) {
        return 0;
    }
    memset(normalized, 0, normalized_capacity * sizeof(normalized[0]));
    bits.data = data;
    bits.size = size;
    bits.bit_position = 0;
    if (!picozstd_forward_read(&bits, 4, &value)) {
        return 0;
    }
    log = value + 5u;
    if (log > PICOZSTD_MAX_FSE_TABLE_LOG) {
        return 0;
    }
    remaining = (1 << log) + 1;
    threshold = 1 << log;
    number_of_bits = log + 1u;

    while (remaining > 1) {
        if (previous_zero) {
            unsigned repeats = 0;
            do {
                if (!picozstd_forward_read(&bits, 2, &value)) {
                    return 0;
                }
                repeats += value;
            } while (value == 3u && repeats <= normalized_capacity);
            if (repeats > normalized_capacity - char_number) {
                return 0;
            }
            char_number += repeats;
            previous_zero = 0;
            if (char_number >= normalized_capacity) {
                return 0;
            }
        }

        {
            int maximum = (2 * threshold - 1) - remaining;
            int count;
            uint32_t low;

            if (!picozstd_forward_read(&bits, number_of_bits - 1u, &low)) {
                return 0;
            }
            if ((int)low < maximum) {
                count = (int)low;
            } else {
                uint32_t high;
                if (!picozstd_forward_read(&bits, 1, &high)) {
                    return 0;
                }
                high = low | (high << (number_of_bits - 1u));
                count = (int)high;
                if (count >= threshold) {
                    count -= maximum;
                }
            }
            --count;
            if (char_number >= normalized_capacity || count < -1) {
                return 0;
            }
            normalized[char_number++] = (int16_t)count;
            if (count >= 0) {
                remaining -= count;
            } else {
                --remaining;
            }
            previous_zero = (count == 0);
        }

        if (remaining < threshold) {
            if (remaining <= 1) {
                break;
            }
            number_of_bits = picozstd_floor_log2_u32((uint32_t)remaining) + 1u;
            threshold = 1 << (number_of_bits - 1u);
        }
    }
    if (remaining != 1 || char_number == 0) {
        return 0;
    }
    *max_symbol = char_number - 1u;
    *table_log = log;
    *bytes_used = (bits.bit_position + 7u) / 8u;
    return *bytes_used <= size;
}

static int picozstd_fse_decode_symbol(picozstd_reverse_bits *bits,
                                      const picozstd_fse_table *table,
                                      uint32_t *state,
                                      uint8_t *symbol)
{
    const picozstd_fse_entry *entry;
    uint32_t extra;
    uint32_t next;

    if (*state >= table->table_size) {
        return 0;
    }
    entry = &table->entry[*state];
    if (!picozstd_reverse_read(bits, entry->number_of_bits, &extra)) {
        return 0;
    }
    next = (uint32_t)entry->baseline + extra;
    if (next >= table->table_size) {
        return 0;
    }
    *state = next;
    *symbol = entry->symbol;
    return 1;
}

static int picozstd_fse_decode_unknown(const uint8_t *data,
                                       size_t size,
                                       const picozstd_fse_table *table,
                                       uint8_t *output,
                                       size_t output_capacity,
                                       size_t *output_size)
{
    picozstd_reverse_bits bits;
    uint32_t state1;
    uint32_t state2;
    uint32_t value;
    size_t written = 0;
    int use_first = 1;

    if (!picozstd_reverse_init(&bits, data, size, 1)) {
        return 0;
    }
    if (!picozstd_reverse_read(&bits, table->table_log, &value)) {
        return 0;
    }
    state1 = value;
    if (!picozstd_reverse_read(&bits, table->table_log, &value)) {
        return 0;
    }
    state2 = value;

    while (written < output_capacity) {
        uint8_t symbol;
        uint32_t *state = use_first ? &state1 : &state2;
        if (!picozstd_fse_decode_symbol(&bits, table, state, &symbol)) {
            return 0;
        }
        output[written++] = symbol;
        if (bits.overrun) {
            state = use_first ? &state2 : &state1;
            if (!picozstd_fse_decode_symbol(&bits, table, state, &symbol) ||
                written >= output_capacity) {
                return 0;
            }
            output[written++] = symbol;
            break;
        }
        use_first = !use_first;
    }
    if (written == output_capacity && bits.bit_position != 0u) {
        return 0;
    }
    *output_size = written;
    return written != 0;
}

static int picozstd_parse_fse_table(picozstd_fse_table *table,
                                    const uint8_t *data,
                                    size_t size,
                                    unsigned max_symbol,
                                    size_t *bytes_used)
{
    int16_t normalized[256];
    unsigned actual_max_symbol;
    unsigned table_log;
    size_t ncount_size;

    if (max_symbol >= 256u ||
        !picozstd_fse_read_ncount(data, size, normalized, max_symbol + 1u,
                                  &actual_max_symbol, &table_log,
                                  &ncount_size) ||
        actual_max_symbol > max_symbol ||
        !picozstd_fse_build_table(table, normalized, actual_max_symbol,
                                  table_log)) {
        return 0;
    }
    *bytes_used = ncount_size;
    return 1;
}

static void picozstd_fse_make_rle(picozstd_fse_table *table, uint8_t symbol)
{
    memset(table, 0, sizeof(*table));
    table->table_log = 0;
    table->max_symbol = symbol;
    table->table_size = 1;
    table->entry[0].symbol = symbol;
}

static const int16_t picozstd_ll_distribution[36] = {
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1
};

static const int16_t picozstd_ml_distribution[53] = {
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1,
    -1, -1, -1, -1, -1
};

static const int16_t picozstd_of_distribution[29] = {
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1
};

static int picozstd_build_predefined(picozstd_fse_table *table,
                                     unsigned kind)
{
    switch (kind) {
    case 0:
        return picozstd_fse_build_table(table, picozstd_ll_distribution, 35, 6);
    case 1:
        return picozstd_fse_build_table(table, picozstd_of_distribution, 28, 5);
    default:
        return picozstd_fse_build_table(table, picozstd_ml_distribution, 52, 6);
    }
}

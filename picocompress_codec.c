#include "picozstd.h"
#include "picocompress/codec.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#if defined(_MSC_VER)
#define PCX_ZSTD_ALIGNOF(type) __alignof(type)
#else
#define PCX_ZSTD_ALIGNOF(type) _Alignof(type)
#endif

#define PCX_ZSTD_HEADER_MAX 18u
#define PCX_ZSTD_DEFAULT_MAX_WINDOW (128u * 1024u * 1024u)

typedef struct pcx_zstd_state {
    picozstd_decoder decoder;
    uint8_t header[PCX_ZSTD_HEADER_MAX];
    size_t header_size;
    size_t header_needed;
    uint8_t *window;
    size_t window_capacity;
    uint8_t *literals;
    uint8_t *block;
    size_t max_window;
    pcx_write_fn write_fn;
    void *write_user;
    pcx_result terminal_result;
    uint8_t decoder_ready;
    uint8_t any_frame;
    uint8_t failed;
} pcx_zstd_state;

typedef struct pcx_zstd_frame_requirements {
    size_t header_size;
    uint64_t window_size;
} pcx_zstd_frame_requirements;

static uint32_t pcx_zstd_read_le32(const uint8_t *p)
{
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t pcx_zstd_read_le(const uint8_t *p, size_t bytes)
{
    uint64_t value = 0;
    size_t i;
    for (i = 0; i < bytes; ++i) {
        value |= ((uint64_t)p[i]) << (i * 8u);
    }
    return value;
}

static pcx_result pcx_zstd_map_status(picozstd_status status)
{
    switch (status) {
    case PICOZSTD_OK:
    case PICOZSTD_NEED_INPUT:
    case PICOZSTD_FRAME_DONE:
        return PCX_OK;
    case PICOZSTD_ERR_ARGUMENT:
        return PCX_ERR_INPUT;
    case PICOZSTD_ERR_DICTIONARY_UNSUPPORTED:
    case PICOZSTD_ERR_UNSUPPORTED:
    case PICOZSTD_ERR_WINDOW_TOO_LARGE:
        return PCX_ERR_UNSUPPORTED;
    case PICOZSTD_ERR_WORKSPACE_TOO_SMALL:
        return PCX_ERR_MEMORY;
    case PICOZSTD_ERR_SINK:
        return PCX_ERR_WRITE;
    case PICOZSTD_ERR_OUTPUT_TOO_LARGE:
        return PCX_ERR_OUTPUT_TOO_SMALL;
    case PICOZSTD_ERR_BAD_MAGIC:
    case PICOZSTD_ERR_RESERVED:
    case PICOZSTD_ERR_MALFORMED:
    case PICOZSTD_ERR_CHECKSUM:
    case PICOZSTD_ERR_TRUNCATED:
    default:
        return PCX_ERR_CORRUPT;
    }
}

static void pcx_zstd_release(pcx_zstd_state *state)
{
    if (!state) return;
    free(state->window);
    free(state->literals);
    free(state->block);
    state->window = NULL;
    state->literals = NULL;
    state->block = NULL;
    state->window_capacity = 0;
    state->decoder_ready = 0;
}

static pcx_result pcx_zstd_fail(pcx_zstd_state *state, pcx_result result)
{
    if (state) {
        state->failed = 1;
        state->terminal_result = result;
        pcx_zstd_release(state);
    }
    return result;
}

static int pcx_zstd_parse_size_option(const char *text, size_t *value)
{
    size_t result = 0;
    const unsigned char *p = (const unsigned char *)text;
    if (!text || !*text || !value) return 0;
    while (*p) {
        unsigned digit;
        if (*p < '0' || *p > '9') return 0;
        digit = (unsigned)(*p - '0');
        if (result > (SIZE_MAX - digit) / 10u) return 0;
        result = result * 10u + digit;
        ++p;
    }
    *value = result;
    return 1;
}

static pcx_result pcx_zstd_options(const pcx_options *options, size_t *max_window)
{
    size_t i;
    if (!max_window) return PCX_ERR_INPUT;
    *max_window = PCX_ZSTD_DEFAULT_MAX_WINDOW;
    if (!options) return PCX_OK;
    for (i = 0; i < options->count; ++i) {
        const pcx_option *option = &options->items[i];
        if (!option->key || !option->value) return PCX_ERR_INPUT;
        if (strcmp(option->key, "max-window") == 0) {
            if (!pcx_zstd_parse_size_option(option->value, max_window) || !*max_window)
                return PCX_ERR_INPUT;
        } else {
            return PCX_ERR_UNSUPPORTED;
        }
    }
    return PCX_OK;
}

static pcx_result pcx_zstd_header_size(const uint8_t *data, size_t size,
                                       size_t *header_size)
{
    uint8_t descriptor;
    unsigned fcs_flag;
    unsigned single_segment;
    unsigned dict_flag;
    size_t dict_size;
    size_t fcs_size;
    size_t total;

    if (!data || !header_size) return PCX_ERR_INPUT;
    if (size < 5u) return PCX_ERR_INPUT;
    if (pcx_zstd_read_le32(data) != UINT32_C(0xFD2FB528))
        return PCX_ERR_CORRUPT;
    descriptor = data[4];
    if (descriptor & 0x08u) return PCX_ERR_CORRUPT;
    fcs_flag = descriptor >> 6;
    single_segment = (descriptor >> 5) & 1u;
    dict_flag = descriptor & 3u;
    dict_size = dict_flag == 0u ? 0u : ((size_t)1u << (dict_flag - 1u));
    fcs_size = fcs_flag == 0u ? (single_segment ? 1u : 0u)
                              : ((size_t)1u << fcs_flag);
    total = 5u + (single_segment ? 0u : 1u) + dict_size + fcs_size;
    if (total > PCX_ZSTD_HEADER_MAX) return PCX_ERR_CORRUPT;
    *header_size = total;
    return PCX_OK;
}

static pcx_result pcx_zstd_parse_requirements(const uint8_t *data, size_t size,
                                              pcx_zstd_frame_requirements *requirements)
{
    uint8_t descriptor;
    unsigned fcs_flag;
    unsigned single_segment;
    unsigned dict_flag;
    size_t dict_size;
    size_t fcs_size;
    size_t cursor;
    uint64_t content_size = 0;
    uint64_t window_size;
    pcx_result result;

    if (!requirements) return PCX_ERR_INPUT;
    result = pcx_zstd_header_size(data, size, &requirements->header_size);
    if (result != PCX_OK) return result;
    if (size < requirements->header_size) return PCX_ERR_INPUT;

    descriptor = data[4];
    fcs_flag = descriptor >> 6;
    single_segment = (descriptor >> 5) & 1u;
    dict_flag = descriptor & 3u;
    dict_size = dict_flag == 0u ? 0u : ((size_t)1u << (dict_flag - 1u));
    fcs_size = fcs_flag == 0u ? (single_segment ? 1u : 0u)
                              : ((size_t)1u << fcs_flag);
    cursor = 5u;

    if (single_segment) {
        window_size = 0;
    } else {
        uint8_t descriptor_window = data[cursor++];
        unsigned exponent = descriptor_window >> 3;
        unsigned mantissa = descriptor_window & 7u;
        unsigned window_log = 10u + exponent;
        uint64_t base;
        if (window_log >= 63u) return PCX_ERR_UNSUPPORTED;
        base = UINT64_C(1) << window_log;
        window_size = base + (base >> 3) * mantissa;
    }

    if (dict_size) {
        uint64_t dictionary_id = pcx_zstd_read_le(data + cursor, dict_size);
        cursor += dict_size;
        if (dictionary_id != 0) return PCX_ERR_UNSUPPORTED;
    }

    if (fcs_size) {
        content_size = pcx_zstd_read_le(data + cursor, fcs_size);
        if (fcs_size == 2u) content_size += 256u;
    }
    if (single_segment) window_size = content_size;
    requirements->window_size = window_size;
    return PCX_OK;
}

static pcx_result pcx_zstd_ensure_workspace(pcx_zstd_state *state,
                                            uint64_t window_size)
{
    size_t wanted;
    uint8_t *replacement;
    if (!state) return PCX_ERR_INPUT;
    if (window_size > (uint64_t)state->max_window || window_size > SIZE_MAX)
        return PCX_ERR_UNSUPPORTED;
    wanted = (size_t)window_size;
    if (wanted > state->window_capacity) {
        replacement = (uint8_t *)realloc(state->window, wanted ? wanted : 1u);
        if (!replacement) return PCX_ERR_MEMORY;
        state->window = replacement;
        state->window_capacity = wanted;
    }
    if (!state->literals) {
        state->literals = (uint8_t *)malloc(PICOZSTD_MAX_BLOCK_SIZE);
        if (!state->literals) return PCX_ERR_MEMORY;
    }
    if (!state->block) {
        state->block = (uint8_t *)malloc(PICOZSTD_MAX_BLOCK_SIZE);
        if (!state->block) return PCX_ERR_MEMORY;
    }
    return PCX_OK;
}

static int pcx_zstd_write_bridge(void *opaque, const uint8_t *data, size_t size)
{
    pcx_zstd_state *state = (pcx_zstd_state *)opaque;
    if (!state || !state->write_fn) return 1;
    return state->write_fn(state->write_user, data, size);
}

static pcx_result pcx_zstd_start_frame(pcx_zstd_state *state)
{
    pcx_zstd_frame_requirements requirements;
    picozstd_config config;
    size_t consumed = 0;
    picozstd_status status;
    pcx_result result;

    result = pcx_zstd_parse_requirements(state->header, state->header_size,
                                         &requirements);
    if (result != PCX_OK) return result;
    result = pcx_zstd_ensure_workspace(state, requirements.window_size);
    if (result != PCX_OK) return result;

    memset(&config, 0, sizeof(config));
    config.window = requirements.window_size ? state->window : NULL;
    config.window_capacity = (size_t)requirements.window_size;
    config.literal_buffer = state->literals;
    config.literal_capacity = PICOZSTD_MAX_BLOCK_SIZE;
    config.block_buffer = state->block;
    config.block_capacity = PICOZSTD_MAX_BLOCK_SIZE;
    config.sink = pcx_zstd_write_bridge;
    config.sink_opaque = state;
    picozstd_decoder_init(&state->decoder, &config);
    state->decoder_ready = 1;

    status = picozstd_push(&state->decoder, state->header,
                           state->header_size, &consumed);
    if (status < 0) return pcx_zstd_map_status(status);
    if (consumed != state->header_size) return PCX_ERR_CORRUPT;
    if (status == PICOZSTD_FRAME_DONE) {
        state->any_frame = 1;
        state->decoder_ready = 0;
    }
    state->header_size = 0;
    state->header_needed = 0;
    return PCX_OK;
}

static pcx_result pcx_zstd_decoder_init(void *opaque, const pcx_options *options)
{
    pcx_zstd_state *state = (pcx_zstd_state *)opaque;
    pcx_result result;
    if (!state) return PCX_ERR_INPUT;
    memset(state, 0, sizeof(*state));
    result = pcx_zstd_options(options, &state->max_window);
    if (result != PCX_OK) return result;
    state->terminal_result = PCX_OK;
    return PCX_OK;
}

static pcx_result pcx_zstd_decoder_sink(void *opaque, const uint8_t *data,
                                        size_t len, pcx_write_fn write_fn,
                                        void *write_user)
{
    pcx_zstd_state *state = (pcx_zstd_state *)opaque;
    size_t position = 0;
    if (!state || (!data && len) || !write_fn) return PCX_ERR_INPUT;
    if (state->failed) return state->terminal_result;
    state->write_fn = write_fn;
    state->write_user = write_user;

    while (position < len) {
        if (!state->decoder_ready) {
            while (position < len && state->header_size < 5u) {
                state->header[state->header_size++] = data[position++];
            }
            if (state->header_size < 5u) return PCX_OK;
            if (!state->header_needed) {
                pcx_result result = pcx_zstd_header_size(
                    state->header, state->header_size, &state->header_needed);
                if (result != PCX_OK) return pcx_zstd_fail(state, result);
            }
            while (position < len && state->header_size < state->header_needed) {
                state->header[state->header_size++] = data[position++];
            }
            if (state->header_size < state->header_needed) return PCX_OK;
            {
                pcx_result result = pcx_zstd_start_frame(state);
                if (result != PCX_OK) return pcx_zstd_fail(state, result);
                if (!state->decoder_ready) continue;
            }
        }

        if (state->decoder_ready && position < len) {
            size_t consumed = 0;
            picozstd_status status = picozstd_push(
                &state->decoder, data + position, len - position, &consumed);
            position += consumed;
            if (status < 0)
                return pcx_zstd_fail(state, pcx_zstd_map_status(status));
            if (status == PICOZSTD_FRAME_DONE) {
                state->any_frame = 1;
                state->decoder_ready = 0;
                state->header_size = 0;
                state->header_needed = 0;
                continue;
            }
            if (status == PICOZSTD_NEED_INPUT && consumed == 0 && position < len)
                return pcx_zstd_fail(state, PCX_ERR_CORRUPT);
        }
    }
    return PCX_OK;
}

static pcx_result pcx_zstd_decoder_finish(void *opaque)
{
    pcx_zstd_state *state = (pcx_zstd_state *)opaque;
    pcx_result result = PCX_OK;
    if (!state) return PCX_ERR_INPUT;
    if (state->failed) result = state->terminal_result;
    else if (state->decoder_ready) {
        picozstd_status status = picozstd_decoder_finish(&state->decoder);
        if (status < 0) result = pcx_zstd_map_status(status);
        else if (status != PICOZSTD_FRAME_DONE) result = PCX_ERR_CORRUPT;
        else state->any_frame = 1;
    } else if (state->header_size != 0u) {
        result = PCX_ERR_CORRUPT;
    } else if (!state->any_frame) {
        result = PCX_ERR_INPUT;
    }
    pcx_zstd_release(state);
    return result;
}

typedef struct pcx_zstd_buffer_sink {
    uint8_t *output;
    size_t capacity;
    size_t size;
    int overflow;
} pcx_zstd_buffer_sink;

static int pcx_zstd_buffer_write(void *opaque, const uint8_t *data, size_t size)
{
    pcx_zstd_buffer_sink *sink = (pcx_zstd_buffer_sink *)opaque;
    if (!sink || size > sink->capacity - sink->size) {
        if (sink) sink->overflow = 1;
        return 1;
    }
    if (size) memcpy(sink->output + sink->size, data, size);
    sink->size += size;
    return 0;
}

static pcx_result pcx_zstd_decompress_buffer(const uint8_t *input,
                                             size_t input_len,
                                             uint8_t *output,
                                             size_t output_cap,
                                             size_t *output_len)
{
    pcx_zstd_state state;
    pcx_zstd_buffer_sink sink;
    pcx_result result;
    if ((!input && input_len) || (!output && output_cap) || !output_len)
        return PCX_ERR_INPUT;
    memset(&sink, 0, sizeof(sink));
    sink.output = output;
    sink.capacity = output_cap;
    result = pcx_zstd_decoder_init(&state, NULL);
    if (result == PCX_OK)
        result = pcx_zstd_decoder_sink(&state, input, input_len,
                                       pcx_zstd_buffer_write, &sink);
    if (result == PCX_OK)
        result = pcx_zstd_decoder_finish(&state);
    else
        pcx_zstd_release(&state);
    if (sink.overflow) result = PCX_ERR_OUTPUT_TOO_SMALL;
    if (result == PCX_OK) *output_len = sink.size;
    return result;
}

static const pcx_codec_v1 pcx_zstd_codec = {
    PCX_CODEC_ABI_V1,
    sizeof(pcx_codec_v1),
    "zstd",
    "PicoZstd dependency-free Zstandard decoder",
    "zstandard,picozstd",
    PCX_CODEC_CAP_DECOMPRESS | PCX_CODEC_CAP_STREAMING,
    0,
    0,
    sizeof(pcx_zstd_state),
    PCX_ZSTD_ALIGNOF(pcx_zstd_state),
    NULL,
    NULL,
    NULL,
    pcx_zstd_decoder_init,
    pcx_zstd_decoder_sink,
    pcx_zstd_decoder_finish,
    NULL,
    NULL,
    pcx_zstd_decompress_buffer
};

PCX_CODEC_EXPORT const pcx_codec_v1 *picocompress_zstd_codec(void)
{
    return &pcx_zstd_codec;
}

#ifndef PCX_CODEC_STATIC
PCX_CODEC_EXPORT const pcx_codec_v1 *picocompress_codec_query(void)
{
    return picocompress_zstd_codec();
}
#endif

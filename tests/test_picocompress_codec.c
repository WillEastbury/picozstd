#include "picocompress/codec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const pcx_codec_v1 *picocompress_zstd_codec(void);

static const uint8_t frame_compressed_abcd[] = {
    0x28, 0xB5, 0x2F, 0xFD, 0x64, 0x40, 0x9B, 0x65, 0x00, 0x00, 0x20, 0x61,
    0x62, 0x63, 0x64, 0x01, 0x00, 0x39, 0x9C, 0x75, 0x47, 0x04, 0x37, 0x57,
    0x4A, 0xD4
};

static uint8_t output[40000];
static size_t output_size;

static int sink(void *opaque, const uint8_t *data, size_t size)
{
    (void)opaque;
    if (size > sizeof(output) - output_size) return 1;
    memcpy(output + output_size, data, size);
    output_size += size;
    return 0;
}

static int expected_abcd(const uint8_t *data, size_t size)
{
    size_t i;
    for (i = 0; i < size; ++i)
        if (data[i] != (uint8_t)"abcd"[i & 3u]) return 0;
    return 1;
}

int main(void)
{
    const pcx_codec_v1 *codec = picocompress_zstd_codec();
    void *state;
    size_t decoded = 0;
    size_t i;
    pcx_result result;

    if (!codec || codec->abi_version != PCX_CODEC_ABI_V1 ||
        strcmp(codec->name, "zstd") != 0 ||
        !(codec->capabilities & PCX_CODEC_CAP_DECOMPRESS) ||
        !(codec->capabilities & PCX_CODEC_CAP_STREAMING) ||
        !codec->decompress_buffer) {
        fprintf(stderr, "invalid PicoCompress Zstd descriptor\n");
        return 1;
    }

    memset(output, 0, sizeof(output));
    result = codec->decompress_buffer(frame_compressed_abcd,
                                      sizeof(frame_compressed_abcd),
                                      output, sizeof(output), &decoded);
    if (result != PCX_OK || decoded != sizeof(output) ||
        !expected_abcd(output, sizeof(output))) {
        fprintf(stderr, "buffer decode failed result=%d decoded=%zu\n",
                (int)result, decoded);
        return 2;
    }

    state = calloc(1, codec->decoder_state_size);
    if (!state) return 3;
    result = codec->decoder_init(state, NULL);
    if (result != PCX_OK) {
        free(state);
        return 4;
    }
    output_size = 0;
    for (i = 0; i < sizeof(frame_compressed_abcd); ++i) {
        result = codec->decoder_sink(state, frame_compressed_abcd + i, 1,
                                     sink, NULL);
        if (result != PCX_OK) {
            fprintf(stderr, "stream decode failed byte=%zu result=%d\n",
                    i, (int)result);
            free(state);
            return 5;
        }
    }
    result = codec->decoder_finish(state);
    free(state);
    if (result != PCX_OK || output_size != sizeof(output) ||
        !expected_abcd(output, sizeof(output))) {
        fprintf(stderr, "stream finish failed result=%d decoded=%zu\n",
                (int)result, output_size);
        return 6;
    }

    puts("PicoZstd PicoCompress codec tests passed");
    return 0;
}

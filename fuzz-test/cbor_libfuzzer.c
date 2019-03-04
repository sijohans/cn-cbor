#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifdef DEBUG
#include <stdio.h>
#define assert(x)                                                           \
    do {                                                                    \
        if (!(x)) {                                                         \
            printf("Assertion error: %s at line %d.\r\n", #x, __LINE__);    \
            __builtin_trap();                                               \
        }                                                                   \
    } while(0)

#else
#include <assert.h>
#endif

#include "cn-cbor/cn-cbor.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    
    cn_cbor *cb = NULL;
    cn_cbor_errback err;
    err.err = CN_CBOR_NO_ERROR;

    cb = cn_cbor_decode(data, size, &err);
    ssize_t enc_sz;

    if (cb && (err.err == CN_CBOR_NO_ERROR)) {

        /* Why do we need at least one more byte here? */
        uint8_t *encoded = (uint8_t *) malloc(size + 1);

        /* A byte or string may not point outside our buffer. */
        if (cb->type == CN_CBOR_TEXT) {
            assert(((uint8_t *)&cb->v.str[cb->length]) <= ((uint8_t *)&data[size]));
        }

        if (cb->type == CN_CBOR_BYTES) {
            assert(((uint8_t *)&cb->v.bytes[cb->length]) <= ((uint8_t *)&data[size]));
        }

        if (encoded) {
            enc_sz = cn_cbor_encoder_write(encoded, 0, size + 1, cb);
            assert(enc_sz >= 0);
            assert(((size_t) enc_sz) == size);
            assert(memcmp(encoded, data, enc_sz) == 0);
            free(encoded);
        }
        cn_cbor_free(cb);
    }

    return 0;
}

#ifdef DEBUG

/* This "DEBUG" configuration would also work if using AFL. */

int main(void) {


    uint8_t tmp_buffer[1024];

    ssize_t size = read(0, tmp_buffer, sizeof(tmp_buffer));

    if (size <= 0) {
        return 0;
    }

    /*
     * We only allocate as much as we read, with this we will find
     * buffer overflow easier. Since we own tmp_buffer we would otherwise
     * not detect if a buffer overflow occurs if size < tmp_buffer and the
     * overflow occurs still inside tmp_buffer.
     */
    uint8_t *cpy = (uint8_t *) malloc(size);
    if (cpy == NULL) {
        return 0;
    }

    memcpy(cpy, tmp_buffer, size);

    int ret = LLVMFuzzerTestOneInput(cpy, (size_t) size);
    free(cpy);
    return ret;

}

#endif
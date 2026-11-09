#ifndef RUSTCRYPTO_HPKE_H
#define RUSTCRYPTO_HPKE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
int rustcrypto_hpke_generate_secret_key(uint8_t *out, size_t out_len);
int rustcrypto_hpke_public_key(const uint8_t *sk, size_t sk_len,
                              uint8_t *out, size_t out_len);
int rustcrypto_hpke_clear_secret_key(uint8_t *sk, size_t sk_len);
int rustcrypto_hpke_seal(const uint8_t *pk, size_t pk_len,
                        const uint8_t *info, size_t info_len,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *plaintext, size_t plaintext_len,
                        uint8_t *out, size_t out_len);
int rustcrypto_hpke_open(const uint8_t *sk, size_t sk_len,
                        const uint8_t *info, size_t info_len,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *sealed, size_t sealed_len,
                        uint8_t *out, size_t out_len);
#ifdef __cplusplus
}
#endif
#endif

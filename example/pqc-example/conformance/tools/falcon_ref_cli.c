/* Fixture-only helper: all deterministic seeds are public test data, not wallet keys. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "falcon.h"

#define LOGN 9
#define TRON_SK_LEN 1280
#define TRON_PK_LEN 896
#define TRON_SIG_MIN_LEN 617
#define TRON_SIG_MAX_LEN 667
#define TRON_SK_HEADER 0x59
#define TRON_PK_HEADER 0x09
#define TRON_SIG_HEADER 0x39
#define SIGN_RETRY_BUDGET 16

static void fail(const char *message) {
  fprintf(stderr, "error: %s\n", message);
  exit(2);
}

static void fail_errno(const char *operation, const char *path) {
  fprintf(stderr, "error: %s %s: %s\n", operation, path, strerror(errno));
  exit(2);
}

static uint8_t *read_file(const char *path, size_t *length) {
  FILE *file = fopen(path, "rb");
  long size = 0;
  uint8_t *bytes;
  if (file == NULL) {
    fail_errno("open", path);
  }
  if (fseek(file, 0, SEEK_END) != 0 || (size = ftell(file)) < 0
      || fseek(file, 0, SEEK_SET) != 0) {
    fclose(file);
    fail_errno("seek", path);
  }
  bytes = malloc((size_t)size == 0 ? 1 : (size_t)size);
  if (bytes == NULL) {
    fclose(file);
    fail("out of memory");
  }
  if ((size_t)size != 0 && fread(bytes, 1, (size_t)size, file) != (size_t)size) {
    fclose(file);
    free(bytes);
    fail_errno("read", path);
  }
  if (fclose(file) != 0) {
    free(bytes);
    fail_errno("close", path);
  }
  *length = (size_t)size;
  return bytes;
}

static void write_file(const char *path, const void *bytes, size_t length) {
  FILE *file = fopen(path, "wb");
  if (file == NULL) {
    fail_errno("open", path);
  }
  if (length != 0 && fwrite(bytes, 1, length, file) != length) {
    fclose(file);
    fail_errno("write", path);
  }
  if (fclose(file) != 0) {
    fail_errno("close", path);
  }
}

static int hex_digit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static uint8_t *parse_hex(const char *hex, size_t *length) {
  size_t hex_len = strlen(hex);
  uint8_t *bytes;
  if (hex_len == 0 || (hex_len & 1) != 0) {
    fail("seed must be non-empty, even-length hexadecimal");
  }
  *length = hex_len / 2;
  bytes = malloc(*length);
  if (bytes == NULL) {
    fail("out of memory");
  }
  for (size_t i = 0; i < *length; i++) {
    int high = hex_digit(hex[2 * i]);
    int low = hex_digit(hex[2 * i + 1]);
    if (high < 0 || low < 0) {
      free(bytes);
      fail("seed contains a non-hexadecimal character");
    }
    bytes[i] = (uint8_t)((high << 4) | low);
  }
  return bytes;
}

static void output_path(char *output, size_t output_size,
                        const char *directory, const char *filename) {
  int written = snprintf(output, output_size, "%s/%s", directory, filename);
  if (written < 0 || (size_t)written >= output_size) {
    fail("output path is too long");
  }
}

static int command_keygen(const char *seed_hex, const char *output_dir) {
  size_t seed_len;
  uint8_t *seed = parse_hex(seed_hex, &seed_len);
  uint8_t private_key[FALCON_PRIVKEY_SIZE(LOGN)];
  uint8_t public_key[FALCON_PUBKEY_SIZE(LOGN)];
  void *tmp = malloc(FALCON_TMPSIZE_KEYGEN(LOGN));
  shake256_context rng;
  char path[4096];
  int result;

  if (tmp == NULL) {
    free(seed);
    fail("out of memory");
  }
  shake256_init_prng_from_seed(&rng, seed, seed_len);
  result = falcon_keygen_make(&rng, LOGN,
      private_key, sizeof private_key,
      public_key, sizeof public_key,
      tmp, FALCON_TMPSIZE_KEYGEN(LOGN));
  free(seed);
  free(tmp);
  if (result != 0) {
    fprintf(stderr, "error: falcon_keygen_make returned %d\n", result);
    return 2;
  }
  if (sizeof private_key != TRON_SK_LEN + 1 || private_key[0] != TRON_SK_HEADER
      || sizeof public_key != TRON_PK_LEN + 1 || public_key[0] != TRON_PK_HEADER) {
    fail("unexpected Falcon-512 key encoding");
  }

  output_path(path, sizeof path, output_dir, "private-key.ref.bin");
  write_file(path, private_key, sizeof private_key);
  output_path(path, sizeof path, output_dir, "private-key.bin");
  write_file(path, private_key + 1, TRON_SK_LEN);
  output_path(path, sizeof path, output_dir, "public-key.ref.bin");
  write_file(path, public_key, sizeof public_key);
  output_path(path, sizeof path, output_dir, "public-key.bin");
  write_file(path, public_key + 1, TRON_PK_LEN);
  printf("valid=true privateKeyLength=%u publicKeyLength=%u "
         "tronPrivateKeyLength=%u tronPublicKeyLength=%u\n",
      (unsigned)sizeof private_key,
      (unsigned)sizeof public_key,
      (unsigned)TRON_SK_LEN,
      (unsigned)TRON_PK_LEN);
  return 0;
}

static int command_sign(const char *private_key_path, const char *message_path,
                        const char *seed_hex, const char *signature_path) {
  size_t input_sk_len, message_len, seed_len;
  uint8_t *input_sk = read_file(private_key_path, &input_sk_len);
  uint8_t *message = read_file(message_path, &message_len);
  uint8_t *seed = parse_hex(seed_hex, &seed_len);
  uint8_t private_key[FALCON_PRIVKEY_SIZE(LOGN)];
  uint8_t signature[FALCON_SIG_COMPRESSED_MAXSIZE(LOGN)];
  void *tmp = malloc(FALCON_TMPSIZE_SIGNDYN(LOGN));
  shake256_context rng;
  size_t signature_len = 0;
  int result = FALCON_ERR_INTERNAL;

  if (input_sk_len == TRON_SK_LEN) {
    private_key[0] = TRON_SK_HEADER;
    memcpy(private_key + 1, input_sk, TRON_SK_LEN);
  } else if (input_sk_len == sizeof private_key && input_sk[0] == TRON_SK_HEADER) {
    memcpy(private_key, input_sk, sizeof private_key);
  } else {
    free(input_sk);
    free(message);
    free(seed);
    free(tmp);
    fail("private key must be 1280-byte TRON or 1281-byte Falcon reference encoding");
  }
  free(input_sk);
  if (tmp == NULL) {
    free(message);
    free(seed);
    fail("out of memory");
  }
  shake256_init_prng_from_seed(&rng, seed, seed_len);
  free(seed);
  for (int attempt = 0; attempt < SIGN_RETRY_BUDGET; attempt++) {
    signature_len = sizeof signature;
    result = falcon_sign_dyn(&rng,
        signature, &signature_len, FALCON_SIG_COMPRESSED,
        private_key, sizeof private_key,
        message, message_len,
        tmp, FALCON_TMPSIZE_SIGNDYN(LOGN));
    if (result == 0
        && signature_len >= TRON_SIG_MIN_LEN
        && signature_len <= TRON_SIG_MAX_LEN
        && signature[0] == TRON_SIG_HEADER) {
      write_file(signature_path, signature, signature_len);
      printf("valid=true signatureLength=%u attempt=%d\n",
          (unsigned)signature_len, attempt + 1);
      free(message);
      free(tmp);
      return 0;
    }
  }
  fprintf(stderr,
      "error: no TIP-899-sized compressed signature after %d attempts "
      "(last result=%d, length=%u)\n",
      SIGN_RETRY_BUDGET, result, (unsigned)signature_len);
  free(message);
  free(tmp);
  return 2;
}

static int command_verify(const char *public_key_path, const char *message_path,
                          const char *signature_path) {
  size_t input_pk_len, message_len, signature_len;
  uint8_t *input_pk = read_file(public_key_path, &input_pk_len);
  uint8_t *message = read_file(message_path, &message_len);
  uint8_t *signature = read_file(signature_path, &signature_len);
  uint8_t public_key[FALCON_PUBKEY_SIZE(LOGN)];
  void *tmp = malloc(FALCON_TMPSIZE_VERIFY(LOGN));
  int result;

  if (input_pk_len == TRON_PK_LEN) {
    public_key[0] = TRON_PK_HEADER;
    memcpy(public_key + 1, input_pk, TRON_PK_LEN);
  } else if (input_pk_len == sizeof public_key && input_pk[0] == TRON_PK_HEADER) {
    memcpy(public_key, input_pk, sizeof public_key);
  } else {
    free(input_pk);
    free(message);
    free(signature);
    free(tmp);
    printf("valid=false reason=public-key-length-or-header\n");
    return 1;
  }
  free(input_pk);
  if (tmp == NULL) {
    free(message);
    free(signature);
    fail("out of memory");
  }
  if (signature_len < TRON_SIG_MIN_LEN
      || signature_len > TRON_SIG_MAX_LEN
      || signature[0] != TRON_SIG_HEADER) {
    result = FALCON_ERR_FORMAT;
  } else {
    result = falcon_verify(signature, signature_len, FALCON_SIG_COMPRESSED,
        public_key, sizeof public_key,
        message, message_len,
        tmp, FALCON_TMPSIZE_VERIFY(LOGN));
  }
  free(message);
  free(signature);
  free(tmp);
  printf("valid=%s result=%d\n", result == 0 ? "true" : "false", result);
  return result == 0 ? 0 : 1;
}

static void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  falcon-ref-cli keygen <seed-hex> <output-dir>\n");
  fprintf(stderr, "  falcon-ref-cli sign <private-key.bin> <message.bin> "
                  "<sign-seed-hex> <signature.bin>\n");
  fprintf(stderr, "  falcon-ref-cli verify <public-key.bin> <message.bin> <signature.bin>\n");
  exit(2);
}

int main(int argc, char **argv) {
  if (argc < 2) {
    usage();
  }
  if (strcmp(argv[1], "keygen") == 0) {
    if (argc != 4) usage();
    return command_keygen(argv[2], argv[3]);
  }
  if (strcmp(argv[1], "sign") == 0) {
    if (argc != 6) usage();
    return command_sign(argv[2], argv[3], argv[4], argv[5]);
  }
  if (strcmp(argv[1], "verify") == 0) {
    if (argc != 5) usage();
    return command_verify(argv[2], argv[3], argv[4]);
  }
  usage();
  return 2;
}

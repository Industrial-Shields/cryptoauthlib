/*
   Based on the first AES-GCM test from CryptoAuthLib
   To use this library on Arduino it is MANDATORY to increment the Wire library BUFFER_LENGTH to 64 bytes
 */

#include <cryptoauthlib.h>

#define AES_CONFIG_ENABLE_BIT_MASK   (uint8_t)0x01

#define TEST_FAILED() {Serial.print(F("TEST FAILED on line ")); Serial.println(__LINE__, DEC); while (true);}
#define TEST_ASSERT_EQUAL(a, b) if (a != b) { Serial.print(a, DEC); Serial.print(F(" != ")); Serial.println(b, DEC); TEST_FAILED(); }
#define TEST_ASSERT_EQUAL_MEMORY(a, b, len) if (memcmp(a, b, len) != 0) { TEST_FAILED(); }
#define TEST_ASSERT(a) if (a == 0) { Serial.print(a); Serial.println(F(" != 0")); TEST_FAILED(); }

ATCAIfaceCfg cfg = {
    .iface_type        = ATCA_I2C_IFACE,
    .devtype           = ATECC608A,
    .iface             = {
      .atcai2c         = {
        .slave_address = 0xC0,
        .bus           = 0,
        .baud          = 400000,
      },
    },
    .wake_delay        = 1500,
    .rx_retries        = 20
};

const uint8_t plaintext[] = { 0x9f, 0xee, 0xbb, 0xdf, 0x16, 0x0f, 0x96, 0x52, 0x53, 0xd9, 0x99, 0x58, 0xcc, 0xb1, 0x76, 0xdf, 0x9f, 0xee, 0xbb, 0xdf, 0x16, 0x0f, 0x96, 0x52, 0x53, 0xd9, 0x99, 0x58, 0xcc, 0xb1 };
const uint32_t text_size = sizeof(plaintext);

const uint8_t aad[] = { 0x47, 0x6b, 0x48, 0x80, 0xf5, 0x93, 0x33, 0x14, 0xdc, 0xc2, 0x3d, 0xf5, 0xdc, 0xb0, 0x09, 0x66, 0x47, 0x6b, 0x48, 0x80, 0xf5, 0x93, 0x33, 0x14, 0xdc, 0xc2, 0x3d, 0xf5, 0xdc, 0xb0 };
const uint32_t aad_size = sizeof(aad);

const uint8_t test_ciphertext[] = { 0xA6, 0x97, 0x10, 0x3A, 0x70, 0x29, 0x7A, 0xAA, 0xCD, 0x25, 0x9E, 0x1A, 0x85, 0x36, 0xA7, 0xDC, 0x3E, 0x61, 0x7D, 0xA2, 0xA8, 0x66, 0x3F, 0xD2, 0xFC, 0x5D, 0x6A, 0x6C, 0x36, 0xEA };
const uint8_t test_tag[] = { 0x72, 0xE3, 0x22, 0x8A, 0x06, 0xE5, 0x88, 0x14, 0x94, 0xC7, 0x08, 0xF3, 0xAC, 0x8B, 0xA9, 0xC5 };

ATCA_STATUS status;
uint16_t key_id = ATCA_TEMPKEY_KEYID;
uint8_t aes_key_block = 0;
uint8_t ciphertext[32];
uint8_t tag[AES_DATA_SIZE];
atca_aes_gcm_ctx_t ctx;
uint8_t key[] = { 0xb7, 0xcf, 0x6c, 0xf5, 0xe7, 0xf3, 0xca, 0x22, 0x3c, 0xa7, 0x3c, 0x81, 0x9d, 0xcd, 0x62, 0xfe };
uint8_t iv[] = { 0xa4, 0x13, 0x60, 0x09, 0xc0, 0xa7, 0xfd, 0xac, 0xfe, 0x53, 0xf5, 0x07 };

////////////////////////////////////////////////////////////////////////////////////////////////////
void setup() {
  Serial.begin(9600UL);
  Serial.println("ecc608-cryptoauthlib started");
  Serial.flush();

  status = atcab_init(&cfg);
  TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

  check_config_aes_enable();

  // Load AES keys into TempKey
  status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, key, 32);
  TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

  //Initialize gcm ctx with IV
  status = atcab_aes_gcm_init(&ctx, key_id, aes_key_block, iv, sizeof(iv));
  TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
  //Add aad to gcm
  status = atcab_aes_gcm_aad_update(&ctx, aad, 15);
  TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
  status = atcab_aes_gcm_aad_update(&ctx, &aad[15], 15);
  TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
  //Encrypt data
  status = atcab_aes_gcm_encrypt_update(&ctx, plaintext, 15, ciphertext);
  TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
  status = atcab_aes_gcm_encrypt_update(&ctx, &plaintext[15], 15, &ciphertext[15]);
  TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
  //Calculate authentication tag
  status = atcab_aes_gcm_encrypt_finish(&ctx, tag, sizeof(tag));
  TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
  TEST_ASSERT_EQUAL_MEMORY(ciphertext, test_ciphertext, text_size);
  TEST_ASSERT_EQUAL_MEMORY(tag, test_tag, sizeof(tag));

  Serial.println("TEST DONE");
  Serial.flush();
}

////////////////////////////////////////////////////////////////////////////////////////////////////
void loop() {
  // TODO
}

////////////////////////////////////////////////////////////////////////////////////////////////////
void check_config_aes_enable(void) {
  uint8_t aes_enable;

  // Byte 13 of the config zone contains the AES enable bit
  status = atcab_read_bytes_zone(ATCA_ZONE_CONFIG, 0, 13, &aes_enable, 1);
  TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
  TEST_ASSERT(aes_enable & AES_CONFIG_ENABLE_BIT_MASK);
}

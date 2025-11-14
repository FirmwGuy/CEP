#include "cps_fixture_defs.h"

const uint8_t k_cps_fixture_inline_cell_key[] = {0x11u, 0x01u};
const size_t  k_cps_fixture_inline_cell_key_len = sizeof k_cps_fixture_inline_cell_key;

const uint8_t k_cps_fixture_cas_plain_cell_key[] = {0x22u, 0x01u};
const size_t  k_cps_fixture_cas_plain_cell_key_len = sizeof k_cps_fixture_cas_plain_cell_key;
const uint8_t k_cps_fixture_cas_plain_chunk_key[] = {0x22u, 0x01u, 0x00u};
const size_t  k_cps_fixture_cas_plain_chunk_key_len = sizeof k_cps_fixture_cas_plain_chunk_key;

const uint8_t k_cps_fixture_cas_deflate_cell_key[] = {0x23u, 0x02u};
const size_t  k_cps_fixture_cas_deflate_cell_key_len = sizeof k_cps_fixture_cas_deflate_cell_key;
const uint8_t k_cps_fixture_cas_deflate_chunk_key[] = {0x23u, 0x02u, 0x00u};
const size_t  k_cps_fixture_cas_deflate_chunk_key_len = sizeof k_cps_fixture_cas_deflate_chunk_key;

const uint8_t k_cps_fixture_inline_payload[] = "inline-payload-fixture-01";
const size_t  k_cps_fixture_inline_payload_len = sizeof k_cps_fixture_inline_payload - 1u;

const uint8_t k_cps_fixture_cas_plain_payload[] = {
    0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
    0x18u, 0x19u, 0x1Au, 0x1Bu, 0x1Cu, 0x1Du, 0x1Eu, 0x1Fu,
    0x20u, 0x21u, 0x22u, 0x23u, 0x24u, 0x25u, 0x26u, 0x27u,
    0x28u, 0x29u, 0x2Au, 0x2Bu, 0x2Cu, 0x2Du, 0x2Eu, 0x2Fu,
    0x30u, 0x31u, 0x32u, 0x33u, 0x34u, 0x35u, 0x36u, 0x37u,
    0x38u, 0x39u, 0x3Au, 0x3Bu, 0x3Cu, 0x3Du, 0x3Eu, 0x3Fu,
    0x40u, 0x41u, 0x42u, 0x43u, 0x44u, 0x45u, 0x46u, 0x47u,
    0x48u, 0x49u, 0x4Au, 0x4Bu, 0x4Cu, 0x4Du, 0x4Eu, 0x4Fu,
};
const size_t  k_cps_fixture_cas_plain_payload_len = sizeof k_cps_fixture_cas_plain_payload;

const uint8_t k_cps_fixture_cas_deflate_payload[] = {
    /* 96 bytes of patterned text to exercise compression */
    'C','A','S','-','D','E','F','L','A','T','E','-','0','1','-','A',
    'C','A','S','-','D','E','F','L','A','T','E','-','0','1','-','B',
    'C','A','S','-','D','E','F','L','A','T','E','-','0','1','-','C',
    'C','A','S','-','D','E','F','L','A','T','E','-','0','1','-','D',
    'C','A','S','-','D','E','F','L','A','T','E','-','0','1','-','E',
    'C','A','S','-','D','E','F','L','A','T','E','-','0','1','-','F',
};
const size_t  k_cps_fixture_cas_deflate_payload_len = sizeof k_cps_fixture_cas_deflate_payload;

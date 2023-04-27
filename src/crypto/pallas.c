/*****************************************************************************
 *   Zcash Ledger App.
 *   (c) 2022 Hanh Huynh Huu.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>   // uint*_t
#include <string.h>   // memset, explicit_bzero
#include <stdbool.h>  // bool
#include <os.h>       // sprintf
#include <ox_bn.h>

#include <lcx_blake2.h>
#include "../types.h"
#include "fr.h"
#include "pallas.h"
#include "tx.h"

#include "globals.h"

const uint8_t THETA[] = {
    0x0f, 0x7b, 0xdb, 0x65, 0x81, 0x41, 0x79, 0xb4, 
    0x46, 0x47, 0xae, 0xf7, 0x82, 0xd5, 0xcd, 0xc8, 
    0x51, 0xf6, 0x4f, 0xc4, 0xdc, 0x88, 0x88, 0x57, 
    0xca, 0x33, 0x0b, 0xcc, 0x09, 0xac, 0x31, 0x8e,
};

const uint8_t Z[] = {
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x22, 0x46, 0x98, 0xfc, 0x09, 0x4c, 0xf9, 0x1b,
    0x99, 0x2d, 0x30, 0xec, 0xff, 0xff, 0xff, 0xf4,
};

const uint8_t iso_a[] = { 0x18, 0x35, 0x4a, 0x2e, 0xb0, 0xea, 0x8c, 0x9c, 0x49, 0xbe, 0x2d, 0x72, 0x58, 0x37, 0x07, 0x42, 0xb7, 0x41, 0x34, 0x58, 0x1a, 0x27, 0xa5, 0x9f, 0x92, 0xbb, 0x4b, 0x0b, 0x65, 0x7a, 0x01, 0x4b };
const uint8_t iso_b[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xf1 };

const uint8_t ROOT_OF_UNITY[] = { 0x2b, 0xce, 0x74, 0xde, 0xac, 0x30, 0xeb, 0xda, 0x36, 0x21, 0x20, 0x83, 0x05, 0x61, 0xf8, 0x1a, 0xea, 0x32, 0x2b, 0xf2, 0xb7, 0xbb, 0x75, 0x84, 0xbd, 0xad, 0x6f, 0xab, 0xd8, 0x7e, 0xa3, 0x2f };

const uint8_t ISOGENY_CONSTANTS[13][32] = {
    { 0x0e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x40, 0x81, 0x77, 0x54, 0x73, 0xd8, 0x37, 0x5b, 0x77, 0x5f, 0x60, 0x34, 0xaa, 0xaa, 0xaa, 0xab },
    { 0x35, 0x09, 0xaf, 0xd5, 0x18, 0x72, 0xd8, 0x8e, 0x26, 0x7c, 0x7f, 0xfa, 0x51, 0xcf, 0x41, 0x2a, 0x0f, 0x93, 0xb8, 0x2e, 0xe4, 0xb9, 0x94, 0x95, 0x8c, 0xf8, 0x63, 0xb0, 0x28, 0x14, 0xfb, 0x76 },
    { 0x17, 0x32, 0x9b, 0x9e, 0xc5, 0x25, 0x37, 0x53, 0x98, 0xc7, 0xd7, 0xac, 0x3d, 0x98, 0xfd, 0x13, 0x38, 0x0a, 0xf0, 0x66, 0xcf, 0xeb, 0x6d, 0x69, 0x0e, 0xb6, 0x4f, 0xae, 0xf3, 0x7e, 0xa4, 0xf7 },
    { 0x1c, 0x71, 0xc7, 0x1c, 0x71, 0xc7, 0x1c, 0x71, 0xc7, 0x1c, 0x71, 0xc7, 0x1c, 0x71, 0xc7, 0x1c, 0x81, 0x02, 0xee, 0xa8, 0xe7, 0xb0, 0x6e, 0xb6, 0xee, 0xbe, 0xc0, 0x69, 0x55, 0x55, 0x55, 0x80 },
    { 0x1d, 0x57, 0x2e, 0x7d, 0xdc, 0x09, 0x9c, 0xff, 0x5a, 0x60, 0x7f, 0xcc, 0xe0, 0x49, 0x4a, 0x79, 0x9c, 0x43, 0x4a, 0xc1, 0xc9, 0x6b, 0x69, 0x80, 0xc4, 0x7f, 0x2a, 0xb6, 0x68, 0xbc, 0xd7, 0x1f },
    { 0x32, 0x56, 0x69, 0xbe, 0xca, 0xec, 0xd5, 0xd1, 0x1d, 0x13, 0xbf, 0x2a, 0x7f, 0x22, 0xb1, 0x05, 0xb4, 0xab, 0xf9, 0xfb, 0x9a, 0x1f, 0xc8, 0x1c, 0x2a, 0xa3, 0xaf, 0x1e, 0xae, 0x5b, 0x66, 0x04 },
    { 0x1a, 0x12, 0xf6, 0x84, 0xbd, 0xa1, 0x2f, 0x68, 0x4b, 0xda, 0x12, 0xf6, 0x84, 0xbd, 0xa1, 0x2f, 0x76, 0x42, 0xb0, 0x1a, 0xd4, 0x61, 0xba, 0xd2, 0x5a, 0xd9, 0x85, 0xb5, 0xe3, 0x8e, 0x38, 0xe4 },
    { 0x1a, 0x84, 0xd7, 0xea, 0x8c, 0x39, 0x6c, 0x47, 0x13, 0x3e, 0x3f, 0xfd, 0x28, 0xe7, 0xa0, 0x95, 0x07, 0xc9, 0xdc, 0x17, 0x72, 0x5c, 0xca, 0x4a, 0xc6, 0x7c, 0x31, 0xd8, 0x14, 0x0a, 0x7d, 0xbb },
    { 0x3f, 0xb9, 0x8f, 0xf0, 0xd2, 0xdd, 0xca, 0xdd, 0x30, 0x32, 0x16, 0xcc, 0xe1, 0xdb, 0x9f, 0xf1, 0x17, 0x65, 0xe9, 0x24, 0xf7, 0x45, 0x93, 0x78, 0x02, 0xe2, 0xbe, 0x87, 0xd2, 0x25, 0xb2, 0x34 },
    { 0x02, 0x5e, 0xd0, 0x97, 0xb4, 0x25, 0xed, 0x09, 0x7b, 0x42, 0x5e, 0xd0, 0x97, 0xb4, 0x25, 0xed, 0x0a, 0xc0, 0x3e, 0x8e, 0x13, 0x4e, 0xb3, 0xe4, 0x93, 0xe5, 0x3a, 0xb3, 0x71, 0xc7, 0x1c, 0x4f },
    { 0x0c, 0x02, 0xc5, 0xbc, 0xca, 0x0e, 0x6b, 0x7f, 0x07, 0x90, 0xbf, 0xb3, 0x50, 0x6d, 0xef, 0xb6, 0x59, 0x41, 0xa3, 0xa4, 0xa9, 0x7a, 0xa1, 0xb3, 0x5a, 0x28, 0x27, 0x9b, 0x1d, 0x1b, 0x42, 0xae },
    { 0x17, 0x03, 0x3d, 0x3c, 0x60, 0xc6, 0x81, 0x73, 0x57, 0x3b, 0x3d, 0x7f, 0x7d, 0x68, 0x13, 0x10, 0xd9, 0x76, 0xbb, 0xfa, 0xbb, 0xc5, 0x66, 0x1d, 0x4d, 0x90, 0xab, 0x82, 0x0b, 0x12, 0x32, 0x0a },
    { 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x46, 0x98, 0xfc, 0x09, 0x4c, 0xf9, 0x1b, 0x99, 0x2d, 0x30, 0xec, 0xff, 0xff, 0xfd, 0xe5 },
};

const jac_p_t SPEND_AUTH_GEN = {
    .x = { 0x37, 0x55, 0x23, 0xB3, 0x28, 0xF1, 0xD6, 0x06, 0x3B, 0x8D, 0x18, 0x7C, 0x3E, 0x5F, 0x44, 0x5F, 0x0C, 0x7F, 0x0C, 0xE3, 0x7B, 0x70, 0xA1, 0x0C, 0x8D, 0x1A, 0x72, 0x84, 0xB8, 0x75, 0xC9, 0x63 },
    .y = { 0x1A, 0xD0, 0x35, 0x7F, 0xDF, 0x1A, 0x66, 0xDB, 0x7B, 0x10, 0xBC, 0xFC, 0xFE, 0xD6, 0x24, 0xFB, 0xDF, 0xC9, 0x14, 0xFE, 0xC0, 0x05, 0xBD, 0xD8, 0x4C, 0xE3, 0x3E, 0x81, 0x7B, 0x0C, 0x3B, 0xC9 },
    .z = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
};

uint8_t buffer[64];
uint8_t b0[64];

static void save_probe(cx_bn_t x, uint8_t i) {
    cx_bn_export(x, memprobe + i*32, 32);
}

void hash_to_field(fp_t *h0, fp_t *h1, uint8_t *dst, size_t dst_len, uint8_t *msg, size_t len) {
    // PRINTF("msg %.*H\n", len, msg);
    cx_blake2b_t hash_ctx;
    cx_hash_t *ph = (cx_hash_t *)&hash_ctx;
    uint8_t a, x;

    memset(buffer, 0, 64);
    cx_blake2b_init_no_throw(&hash_ctx, 512);
    cx_hash(ph, 0, buffer, 64, NULL, 0); // [0; 128]
    cx_hash(ph, 0, buffer, 64, NULL, 0);
    cx_hash(ph, 0, msg, len, NULL, 0);
    buffer[1] = 128;
    cx_hash(ph, 0, buffer, 3, NULL, 0); // [0, 128, 0]
    cx_hash(ph, 0, dst, dst_len, NULL, 0);
    a = 28 + dst_len;
    cx_hash(ph, 0, (uint8_t *)"-pallas_XMD:BLAKE2b_SSWU_RO_", 28, NULL, 0);
    cx_hash(ph, 0, &a, 1, NULL, 0);
    cx_hash(ph, CX_LAST, NULL, 0, buffer, 64);
    // PRINTF("b_0 %.*H\n", 64, buffer);
    memmove(b0, buffer, 64);

    cx_blake2b_init_no_throw(&hash_ctx, 512);
    cx_hash(ph, 0, b0, 64, NULL, 0);
    x = 1;
    cx_hash(ph, 0, &x, 1, NULL, 0);
    cx_hash(ph, 0, dst, dst_len, NULL, 0);
    cx_hash(ph, 0, (uint8_t *)"-pallas_XMD:BLAKE2b_SSWU_RO_", 28, NULL, 0);
    cx_hash(ph, 0, &a, 1, NULL, 0);
    cx_hash(ph, CX_LAST, NULL, 0, buffer, 64);
    // PRINTF("b_1 %.*H\n", 64, buffer);

    for (int i = 0; i < 64; i++) 
        b0[i] ^= buffer[i];

    cx_blake2b_init_no_throw(&hash_ctx, 512);
    cx_hash(ph, 0, b0, 64, NULL, 0);
    memmove(b0, buffer, 64); // b0 = b1
    x = 2;
    cx_hash(ph, 0, &x, 1, NULL, 0);
    cx_hash(ph, 0, dst, dst_len, NULL, 0);
    cx_hash(ph, 0, (uint8_t *)"-pallas_XMD:BLAKE2b_SSWU_RO_", 28, NULL, 0);
    cx_hash(ph, 0, &a, 1, NULL, 0);
    cx_hash(ph, CX_LAST, NULL, 0, buffer, 64);
    // PRINTF("b_2 %.*H\n", 64, buffer); // buffer = b2

    fp_from_wide_be(b0);
    fp_from_wide_be(buffer);

    memmove(h0, b0, 32);
    memmove(h1, buffer, 32);
}

#define BN_DEF(a) cx_bn_t a; cx_bn_alloc(&a, 32);
#define BN_DEF_ZERO BN_DEF(zero); cx_bn_set_u32(zero, 0);

#ifdef NO_MONTGOMERY
#define CX_BN_MUL(r, a, b) cx_bn_mod_mul(r, a, b, M)
#else
#define CX_BN_MUL(r, a, b) cx_mont_mul(r, a, b, ctx)
#endif

void map_to_curve_simple_swu(jac_p_t *p, fp_t *u) {
    cx_bn_lock(32, 0);
    BN_DEF(temp);
    BN_DEF(temp2);
    BN_DEF_ZERO;
    BN_DEF(one); cx_bn_set_u32(one, 1);
    BN_DEF(M); cx_bn_init(M, fp_m, 32);
    BN_DEF(u0); cx_bn_init(u0, (uint8_t *)u, 32);
    BN_DEF(z); cx_bn_init(z, Z, 32);

    BN_DEF(u2);
    CX_BN_MUL(u2, u0, u0);
    // print_bn("u*u", u2);
    BN_DEF(z_u2);
    CX_BN_MUL(z_u2, z, u2);
    // print_bn("z_u2", z_u2);
    BN_DEF(z_u22);
    CX_BN_MUL(z_u22, z_u2, z_u2);
    BN_DEF(ta);
    cx_bn_mod_add_fixed(ta, z_u22, z_u2, M);
    // print_bn("ta", ta);
    BN_DEF(num_x1);
    cx_bn_mod_add_fixed(num_x1, ta, one, M);
    BN_DEF(b); cx_bn_init(b, iso_b, 32);
    CX_BN_MUL(temp, b, num_x1);
    cx_bn_copy(num_x1, temp);
    // print_bn("num_x1", num_x1);

    BN_DEF(div);
    int cmp;
    cx_bn_cmp_u32(ta, 0, &cmp);
    if (cmp == 0)
        cx_bn_copy(div, z);
    else {
        cx_bn_copy(div, ta);
        cx_bn_mod_sub(div, zero, div, M);
    }
    BN_DEF(a); cx_bn_init(a, iso_a, 32);
    CX_BN_MUL(temp, a, div);
    cx_bn_copy(div, temp);
    // print_bn("div", div);
    BN_DEF(num2_x1);
    CX_BN_MUL(num2_x1, num_x1, num_x1);
    // print_bn("num2_x1", num2_x1);

    BN_DEF(div2);
    BN_DEF(div3);
    CX_BN_MUL(div2, div, div);
    CX_BN_MUL(div3, div2, div);
    // print_bn("div2", div2);
    // print_bn("div3", div3);

    BN_DEF(num_gx1);
    CX_BN_MUL(temp, a, div2);
    cx_bn_mod_add_fixed(temp, num2_x1, temp, M);
    CX_BN_MUL(num_gx1, temp, num_x1);
    CX_BN_MUL(temp, b, div3);
    cx_bn_mod_add_fixed(num_gx1, num_gx1, temp, M);
    // print_bn("num_gx1", num_gx1);

    BN_DEF(num_x2);
    CX_BN_MUL(num_x2, z_u2, num_x1);
    // print_bn("num_x2", num_x2);

    cx_bn_copy(temp, div3);
    cx_bn_mod_invert_nprime(temp2, temp, M);
    CX_BN_MUL(temp, num_gx1, temp2);
    bool gx1_square = true;
    cx_err_t err = cx_bn_mod_sqrt(temp, temp, M, 0);
    if (err != CX_OK) {
        gx1_square = false;
        BN_DEF(root); cx_bn_init(root, ROOT_OF_UNITY, 32);
        CX_BN_MUL(temp2, root, temp);
        cx_bn_mod_sqrt(temp, temp2, M, 1);
    }
    BN_DEF(y1);
    cx_bn_copy(y1, temp);
    // print_bn("y1", y1);

    BN_DEF(y2);
    BN_DEF(theta); cx_bn_init(theta, THETA, 32);
    CX_BN_MUL(temp, theta, z_u2);
    CX_BN_MUL(temp2, temp, u0);
    CX_BN_MUL(y2, temp2, y1);
    // print_bn("y2", y2);

    BN_DEF(num_x);
    BN_DEF(y);
    if (gx1_square) {
        cx_bn_copy(num_x, num_x1);
        cx_bn_copy(y, y1);
    }
    else {
        cx_bn_copy(num_x, num_x2);
        cx_bn_copy(y, y2);
    }
    // print_bn("num_x", num_x);
    // print_bn("y", y);

    bool u_odd, y_odd;
    cx_bn_is_odd(u0, &u_odd);
    cx_bn_is_odd(y, &y_odd);
    if (u_odd != y_odd)
        cx_bn_mod_sub(y, zero, y, M);

    CX_BN_MUL(temp, num_x, div);
    cx_bn_export(temp, (uint8_t *)&p->x, 32);
    CX_BN_MUL(temp, y, div3);
    cx_bn_export(temp, (uint8_t *)&p->y, 32);
    cx_bn_export(div, (uint8_t *)&p->z, 32);
    cx_bn_unlock();
}

void iso_map(jac_p_t *res, const jac_p_t *p) {
    cx_bn_lock(32, 0);
    BN_DEF_ZERO;
    BN_DEF(temp);
    BN_DEF(temp2);
    BN_DEF(M); cx_bn_init(M, fp_m, 32);
    jac_p_bn_t pp;
    pallas_jac_init(&pp, p);

    BN_DEF(z2);
    CX_BN_MUL(z2, pp.z, pp.z);
    BN_DEF(z3);
    CX_BN_MUL(z3, z2, pp.z);
    BN_DEF(z4);
    CX_BN_MUL(z4, z2, z2);
    BN_DEF(z6);
    CX_BN_MUL(z6, z3, z3);

    BN_DEF(iso);
    BN_DEF(num_x);
    cx_bn_init(iso, ISOGENY_CONSTANTS[0], 32);
    CX_BN_MUL(temp, iso, pp.x);
    cx_bn_init(iso, ISOGENY_CONSTANTS[1], 32);
    CX_BN_MUL(num_x, iso, z2);
    cx_bn_mod_add_fixed(num_x, temp, num_x, M);
    CX_BN_MUL(temp, num_x, pp.x);
    cx_bn_copy(num_x, temp);
    cx_bn_init(iso, ISOGENY_CONSTANTS[2], 32);
    CX_BN_MUL(temp, iso, z4);
    cx_bn_mod_add_fixed(num_x, temp, num_x, M);
    CX_BN_MUL(temp, num_x, pp.x);
    cx_bn_copy(num_x, temp);
    cx_bn_init(iso, ISOGENY_CONSTANTS[3], 32);
    CX_BN_MUL(temp, iso, z6);
    cx_bn_mod_add_fixed(num_x, temp, num_x, M);
    // print_bn("num_x", num_x);

    BN_DEF(div_x);
    CX_BN_MUL(temp, z2, pp.x);
    cx_bn_init(iso, ISOGENY_CONSTANTS[4], 32);
    CX_BN_MUL(div_x, iso, z4);
    cx_bn_mod_add_fixed(div_x, temp, div_x, M);
    CX_BN_MUL(temp, div_x, pp.x);
    cx_bn_copy(div_x, temp);
    cx_bn_init(iso, ISOGENY_CONSTANTS[5], 32);
    CX_BN_MUL(temp, iso, z6);
    cx_bn_mod_add_fixed(div_x, temp, div_x, M);
    // print_bn("div_x", div_x);

    BN_DEF(num_y);
    cx_bn_init(iso, ISOGENY_CONSTANTS[6], 32);
    CX_BN_MUL(temp, iso, pp.x);
    cx_bn_init(iso, ISOGENY_CONSTANTS[7], 32);
    CX_BN_MUL(num_y, iso, z2);
    cx_bn_mod_add_fixed(num_y, temp, num_y, M);
    CX_BN_MUL(temp, num_y, pp.x);
    cx_bn_copy(num_y, temp);
    cx_bn_init(iso, ISOGENY_CONSTANTS[8], 32);
    CX_BN_MUL(temp, iso, z4);
    cx_bn_mod_add_fixed(num_y, temp, num_y, M);
    CX_BN_MUL(temp, num_y, pp.x);
    cx_bn_copy(num_y, temp);
    cx_bn_init(iso, ISOGENY_CONSTANTS[9], 32);
    CX_BN_MUL(temp, iso, z6);
    cx_bn_mod_add_fixed(num_y, temp, num_y, M);
    CX_BN_MUL(temp, num_y, pp.y);
    cx_bn_copy(num_y, temp);
    // print_bn("num_y", num_y);

    BN_DEF(div_y);
    cx_bn_init(iso, ISOGENY_CONSTANTS[10], 32);
    CX_BN_MUL(div_y, iso, z2);
    cx_bn_mod_add_fixed(div_y, div_y, pp.x, M);
    CX_BN_MUL(temp, div_y, pp.x);
    cx_bn_copy(div_y, temp);
    cx_bn_init(iso, ISOGENY_CONSTANTS[11], 32);
    CX_BN_MUL(temp, iso, z4);
    cx_bn_mod_add_fixed(div_y, div_y, temp, M);
    CX_BN_MUL(temp, div_y, pp.x);
    cx_bn_copy(div_y, temp);
    cx_bn_init(iso, ISOGENY_CONSTANTS[12], 32);
    CX_BN_MUL(temp, iso, z6);
    cx_bn_mod_add_fixed(div_y, div_y, temp, M);
    CX_BN_MUL(temp, div_y, z3);
    cx_bn_copy(div_y, temp);
    // print_bn("div_y", div_y);

    BN_DEF(zo);
    CX_BN_MUL(zo, div_x, div_y);
    BN_DEF(xo);
    CX_BN_MUL(xo, num_x, div_y);
    CX_BN_MUL(temp, xo, zo);
    cx_bn_copy(xo, temp);
    BN_DEF(yo);
    CX_BN_MUL(temp, num_y, div_x);
    CX_BN_MUL(temp2, temp, zo);
    CX_BN_MUL(yo, temp2, zo);

    cx_bn_export(xo, res->x, 32);
    cx_bn_export(yo, res->y, 32);
    cx_bn_export(zo, res->z, 32);

    cx_bn_unlock();
}

void hash_to_curve(jac_p_t *res, uint8_t *domain, size_t domain_len, uint8_t *msg, size_t msg_len) {
    fp_t h[2];
    hash_to_field(&h[0], &h[1], domain, domain_len, msg, msg_len);
    jac_p_t p[2];
    for (int i = 0; i < 2; i++) {
        map_to_curve_simple_swu(&p[i], &h[i]);
    }

    cx_bn_lock(32, 0);
    BN_DEF_ZERO;
    cx_bn_t M; cx_bn_alloc_init(&M, 32, fp_m, 32);
    jac_p_bn_t pp[2];
    for (int i = 0; i < 2; i++) {
        pallas_jac_init(pp + i, p + i);
    }
    pallas_add_jac(pp, pp, pp + 1, M);
    pallas_jac_export(p, pp);
    cx_bn_unlock();

    iso_map(p, p);

    memmove(res, p, sizeof(jac_p_t));
}

int pallas_from_bytes(jac_p_t *res, uint8_t *a) {
    uint8_t tmp[32];
    memmove(tmp, a, 32);
    bool sign = tmp[31] >> 7;
    tmp[31] &= 0x7F;

    swap_endian(tmp, 32);
    fp_t *x = (fp_t *)tmp;
    if (!fp_ok(x)) return CX_INVALID_PARAMETER;
    if (ff_is_zero(tmp) && !sign) {
        memset(res, 0, sizeof(jac_p_t));
        return CX_OK;
    }
    cx_bn_lock(32, 0);
    BN_DEF_ZERO;
    BN_DEF(M); cx_bn_init(M, fp_m, 32);
    BN_DEF(x0); cx_bn_init(x0, tmp, 32);
    BN_DEF(x3);
    CX_BN_MUL(x3, x0, x0);
    CX_BN_MUL(x3, x3, x0);
    BN_DEF(b); cx_bn_set_u32(b, 5);
    cx_bn_mod_add_fixed(x3, x3, b, M);
    BN_DEF(y);
    cx_err_t err = cx_bn_mod_sqrt(y, x3, M, sign);
    if (err < 0) return CX_INVALID_PARAMETER;
    cx_bn_export(y, res->y, 32);
    cx_bn_unlock();
    memmove(res->x, x, 32);
    memmove(res->z, fq_1, 32);
    return 0;
}

void pallas_to_bytes(uint8_t *res, const jac_p_t *p) {
    cx_bn_lock(32, 0);
    BN_DEF(M); cx_bn_init(M, fp_m, 32);
    BN_DEF(zinv); cx_bn_init(zinv, p->z, 32);
    int cmp;
    cx_bn_cmp_u32(zinv, 0, &cmp);
    if (cmp == 0) memset(res, 0, 32);
    else {
        cx_bn_mod_invert_nprime(zinv, zinv, M);
        BN_DEF(zinv2);
        CX_BN_MUL(zinv2, zinv, zinv);
        BN_DEF(zinv3);
        CX_BN_MUL(zinv3, zinv2, zinv);
        BN_DEF(x);
        BN_DEF(x0); cx_bn_init(x0, p->x, 32);
        CX_BN_MUL(x, x0, zinv2);
        BN_DEF(y);
        BN_DEF(y0); cx_bn_init(y0, p->y, 32);
        CX_BN_MUL(y, y0, zinv3);
        bool odd;
        cx_bn_is_odd(y, &odd);
        uint8_t sign = !!odd << 7;
        cx_bn_export(x, res, 32);
        swap_endian(res, 32);
        res[31] |= sign;
    }
    cx_bn_unlock();
}

bool pallas_is_identity(const jac_p_bn_t *a) {
    int cmp;
    cx_bn_cmp_u32(a->z, 0, &cmp); 
    return cmp == 0;
}

void pallas_copy_jac_bn(jac_p_bn_t *res, const jac_p_bn_t *a) {
    cx_bn_copy(res->x, a->x);
    cx_bn_copy(res->y, a->y);
    cx_bn_copy(res->z, a->z);
}

void pallas_copy_jac(jac_p_t *res, const jac_p_t *a) {
    memmove(res->x, a->x, 32);
    memmove(res->y, a->y, 32);
    memmove(res->z, a->z, 32);
}

void pallas_add_jac(jac_p_bn_t *res, const jac_p_bn_t *a, const jac_p_bn_t *b, cx_bn_t M) {
    if (pallas_is_identity(a)) pallas_copy_jac_bn(res, b);
    else if (pallas_is_identity(b)) pallas_copy_jac_bn(res, a);
    else {
        BN_DEF_ZERO;
        // print_bn("a.x", a->x);
        // print_bn("a.y", a->y);
        // print_bn("a.z", a->z);

        // print_bn("b.x", b->x);
        // print_bn("b.y", b->y);
        // print_bn("b.z", b->z);

        BN_DEF(temp);
        BN_DEF(z1z1);
        CX_BN_MUL(z1z1, a->z, a->z);
        BN_DEF(z2z2);
        CX_BN_MUL(z2z2, b->z, b->z);
        BN_DEF(u1);
        CX_BN_MUL(u1, a->x, z2z2);
        BN_DEF(u2);
        CX_BN_MUL(u2, b->x, z1z1);
        BN_DEF(s1);
        CX_BN_MUL(s1, a->y, z2z2);
        CX_BN_MUL(temp, s1, b->z);
        cx_bn_copy(s1, temp);
        BN_DEF(s2);
        CX_BN_MUL(s2, b->y, z1z1);
        CX_BN_MUL(temp, s2, a->z);
        cx_bn_copy(s2, temp);

        // print_bn("u1", u1);
        // print_bn("u2", u2);
        // print_bn("s1", s1);
        // print_bn("s2", s2);

        BN_DEF(h);
        cx_bn_mod_sub(h, u2, u1, M);
        BN_DEF(i);
        cx_bn_mod_add_fixed(i, h, h, M);
        CX_BN_MUL(temp, i, i);
        cx_bn_copy(i, temp);
        BN_DEF(j);
        CX_BN_MUL(j, h, i);
        BN_DEF(r);
        cx_bn_mod_sub(r, s2, s1, M);
        cx_bn_mod_add_fixed(r, r, r, M);

        BN_DEF(v);
        CX_BN_MUL(v, u1, i);
        // print_bn("h", h);
        // print_bn("i", i);
        // print_bn("j", j);
        // print_bn("r", r);
        // print_bn("v", v);

        BN_DEF(x3);
        CX_BN_MUL(x3, r, r);
        cx_bn_mod_sub(x3, x3, j, M);
        cx_bn_mod_sub(x3, x3, v, M);
        cx_bn_mod_sub(x3, x3, v, M);

        CX_BN_MUL(temp, s1, j);
        cx_bn_copy(s1, temp);
        cx_bn_mod_add_fixed(s1, s1, s1, M);

        BN_DEF(y3);
        cx_bn_mod_sub(y3, v, x3, M);
        CX_BN_MUL(temp, y3, r);
        cx_bn_copy(y3, temp);
        cx_bn_mod_sub(y3, y3, s1, M);

        BN_DEF(z3);
        cx_bn_mod_add_fixed(z3, a->z, b->z, M);
        CX_BN_MUL(temp, z3, z3);
        cx_bn_copy(z3, temp);
        cx_bn_mod_sub(z3, z3, z1z1, M);
        cx_bn_mod_sub(z3, z3, z2z2, M);
        CX_BN_MUL(temp, z3, h);
        cx_bn_copy(z3, temp);

        // print_bn("x3", x3);
        // print_bn("y3", y3);
        // print_bn("z3", z3);

        cx_bn_copy(res->x, x3);
        cx_bn_copy(res->y, y3);
        cx_bn_copy(res->z, z3);

        cx_bn_destroy(&zero);
        cx_bn_destroy(&temp);
        cx_bn_destroy(&z1z1);
        cx_bn_destroy(&z2z2);
        cx_bn_destroy(&u1);
        cx_bn_destroy(&u2);
        cx_bn_destroy(&s1);
        cx_bn_destroy(&s2);

        cx_bn_destroy(&h);
        cx_bn_destroy(&i);
        cx_bn_destroy(&j);
        cx_bn_destroy(&r);
        cx_bn_destroy(&v);

        cx_bn_destroy(&x3);
        cx_bn_destroy(&y3);
        cx_bn_destroy(&z3);
    }
    // print_bn("res.x", res->x);
    // print_bn("res.y", res->y);
    // print_bn("res.z", res->z);
}

void pallas_double_jac(jac_p_bn_t *v, cx_bn_t M) {
    // TODO: Montgommery 
    BN_DEF_ZERO;
    BN_DEF(temp);
    BN_DEF(a);
    CX_BN_MUL(a, v->x, v->x);
    BN_DEF(b);
    CX_BN_MUL(b, v->y, v->y);
    BN_DEF(c);
    CX_BN_MUL(c, b, b);
    BN_DEF(d);
    cx_bn_mod_add_fixed(d, v->x, b, M);
    CX_BN_MUL(temp, d, d);
    cx_bn_copy(d, temp);
    cx_bn_mod_sub(d, d, a, M);
    cx_bn_mod_sub(d, d, c, M);
    cx_bn_mod_add_fixed(d, d, d, M);
    BN_DEF(e);
    cx_bn_mod_add_fixed(e, a, a, M);
    cx_bn_mod_add_fixed(e, e, a, M);
    BN_DEF(f);
    CX_BN_MUL(f, e, e);

    // save_probe(a, 0);
    // save_probe(b, 1);
    // save_probe(c, 2);
    // save_probe(d, 3);
    // save_probe(e, 4);
    // save_probe(f, 5);

    BN_DEF(z3);
    CX_BN_MUL(z3, v->z, v->y);
    cx_bn_mod_add_fixed(z3, z3, z3, M);
    BN_DEF(x3);
    cx_bn_mod_sub(x3, f, d, M);
    cx_bn_mod_sub(x3, x3, d, M);
    cx_bn_mod_add_fixed(c, c, c, M);
    cx_bn_mod_add_fixed(c, c, c, M);
    cx_bn_mod_add_fixed(c, c, c, M);
    BN_DEF(y3);
    cx_bn_mod_sub(y3, d, x3, M);
    CX_BN_MUL(temp, e, y3);
    cx_bn_copy(y3, temp);
    cx_bn_mod_sub(y3, y3, c, M);

    cx_bn_copy(v->x, x3);
    cx_bn_copy(v->y, y3);
    cx_bn_copy(v->z, z3);

    cx_bn_destroy(&zero);
    cx_bn_destroy(&temp);
    cx_bn_destroy(&a);
    cx_bn_destroy(&b);
    cx_bn_destroy(&c);
    cx_bn_destroy(&d);
    cx_bn_destroy(&e);
    cx_bn_destroy(&f);
    cx_bn_destroy(&x3);
    cx_bn_destroy(&y3);
    cx_bn_destroy(&z3);
}

void pallas_base_mult(jac_p_t *res, const jac_p_t *base, fv_t *x) {
    cx_bn_lock(32, 0);
    cx_bn_t M; cx_bn_alloc_init(&M, 32, fp_m, 32);

    jac_p_bn_t acc;
    cx_bn_alloc_init(&acc.x, 32, fq_0, 32);
    cx_bn_alloc_init(&acc.y, 32, fq_0, 32);
    cx_bn_alloc_init(&acc.z, 32, fq_0, 32);

    jac_p_bn_t b;
    pallas_jac_init(&b, base);

    int j0 = 1; // skip highest bit
    for (int i = 0; i < 32; i++) {
        uint8_t c = (*x)[i];
        for (int j = j0; j < 8; j++) {
            // print_bn("acc x", acc.x);
            pallas_double_jac(&acc, M);
            if (((c >> (7-j)) & 1) != 0) {
                pallas_add_jac(&acc, &acc, &b, M);
                // print_bn("acc x", acc.x);
                // print_bn("acc y", acc.y);
                // print_bn("acc z", acc.z);
            }
        }
        j0 = 0;
    }
    pallas_jac_export(res, &acc);

    cx_bn_unlock();
}

void pallas_jac_alloc(jac_p_bn_t *dest) {
    cx_bn_alloc(&dest->x, 32);
    cx_bn_alloc(&dest->y, 32);
    cx_bn_alloc(&dest->z, 32);
}

void pallas_jac_init(jac_p_bn_t *dest, const jac_p_t *src) {
    cx_bn_alloc_init(&dest->x, 32, src->x, 32);
    cx_bn_alloc_init(&dest->y, 32, src->y, 32);
    cx_bn_alloc_init(&dest->z, 32, src->z, 32);
}

void pallas_jac_export(jac_p_t *dest, jac_p_bn_t *src) {
    cx_bn_export(src->x, dest->x, 32);
    cx_bn_export(src->y, dest->y, 32);
    cx_bn_export(src->z, dest->z, 32);
    cx_bn_destroy(&src->x);
    cx_bn_destroy(&src->y);
    cx_bn_destroy(&src->z);
}

void pallas_add_assign(jac_p_t *v, const jac_p_t *a) {
    cx_bn_lock(32, 0);
    BN_DEF(M); cx_bn_init(M, fp_m, 32);
    jac_p_bn_t v0, a0;
    pallas_jac_init(&v0, v);
    pallas_jac_init(&a0, a);
    pallas_add_jac(&v0, &v0, &a0, M);
    pallas_jac_export(v, &v0);
    cx_bn_unlock();
}

static int h_star(uint8_t *hash, uint8_t *data, size_t len) {
    cx_blake2b_t hasher;
    cx_blake2b_init2_no_throw(&hasher, 512,
                              NULL, 0, (uint8_t *) "Zcash_RedPallasH", 16);
    cx_hash((cx_hash_t *)&hasher, CX_LAST, data, len, hash, 64);
    fv_from_wide(hash);

    return 0;
}

int pallas_sign(uint8_t *signature, fv_t *sk, uint8_t *message) {
    uint8_t buffer[144];
    memset(buffer, 0, sizeof(buffer));

    cx_get_random_bytes(buffer, 80);
    prf_chacha(&chacha_sig_rng, buffer, 80);
    memmove(buffer + 80, message, 64);
    PRINTF("random %.*H\n", 80, buffer);

    uint8_t r_buffer[64]; // we need 64 bytes but only the first 32 will be used as a return value
    h_star(r_buffer, buffer, 144);
    PRINTF("nonce %.*H\n", 32, r_buffer);

    fv_t r;
    memmove(&r, r_buffer, 32);
    jac_p_t p;
    pallas_base_mult(&p, &SPEND_AUTH_GEN, &r);
    pallas_to_bytes(buffer, &p); // R = r.G
    PRINTF("R %.*H\n", 32, buffer);

    memmove(signature, buffer, 32); // R
    memmove(buffer + 32, message, 64);
    h_star(r_buffer, buffer, 96);
    fv_t *S = (fv_t *)(signature + 32);
    memmove(S, r_buffer, 32);

    fv_mult(S, S, sk);
    fv_add(S, S, &r); // S = r + H*(Rbar || M) . sk
    swap_endian(signature + 32, 32);

    PRINTF("signature %.*H\n", 64, signature);

    return 0;
}

u_int8_t memprobe[7*32];

#pragma once

typedef struct {
    fp_t x, y, z;
} jac_p_t;

void hash_to_field(fp_t *h0, fp_t *h1, uint8_t *dst, size_t dst_len, uint8_t *msg, size_t len);
void map_to_curve_simple_swu(jac_p_t *p, fp_t *u);

void pallas_add_jac(jac_p_t *v, const jac_p_t *a, const jac_p_t *b);
void iso_map(jac_p_t *res, const jac_p_t *p);

void hash_to_curve(jac_p_t *res, uint8_t *domain, size_t domain_len, uint8_t *msg, size_t msg_len);

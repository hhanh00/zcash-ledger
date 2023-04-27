#pragma once

typedef struct {
    fp_t x, y, z;
} jac_p_t;

typedef struct {
    cx_bn_t x, y, z;
} jac_p_bn_t;

extern const jac_p_t SPEND_AUTH_GEN;

void hash_to_field(fp_t *h0, fp_t *h1, uint8_t *dst, size_t dst_len, uint8_t *msg, size_t len);
void map_to_curve_simple_swu(jac_p_t *p, fp_t *u);
void iso_map(jac_p_t *res, const jac_p_t *p);

void hash_to_curve(jac_p_t *res, uint8_t *domain, size_t domain_len, uint8_t *msg, size_t msg_len);

int pallas_from_bytes(jac_p_t *res, uint8_t *a);
void pallas_to_bytes(uint8_t *res, const jac_p_t *p);

void pallas_copy_jac_bn(jac_p_bn_t *res, const jac_p_bn_t *a);
bool pallas_is_identity(const jac_p_bn_t *a);

void pallas_jac_alloc(jac_p_bn_t *dest);
void pallas_jac_init(jac_p_bn_t *dest, const jac_p_t *src);
void pallas_jac_export(jac_p_t *dest, jac_p_bn_t *src);

void pallas_add_jac(jac_p_bn_t *v, const jac_p_bn_t *a, const jac_p_bn_t *b, cx_bn_t M, bool montgomery);
void pallas_double_jac(jac_p_bn_t *v, cx_bn_t M);
void pallas_base_mult(jac_p_t *res, const jac_p_t *base, fv_t *x);

void pallas_copy_jac(jac_p_t *res, const jac_p_t *a);
void pallas_add_assign(jac_p_t *v, const jac_p_t *a);

int pallas_sign(uint8_t *signature, fv_t *sk, uint8_t *message);

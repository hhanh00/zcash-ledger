#ifdef MONTGOMERY_EMU
static cx_bn_t R, RInv, mont_temp;
static void init_mont(uint8_t *fx_m) {
    cx_bn_alloc_init(&M, 32, fx_m, 32);
    cx_bn_alloc(&mont_temp, 32);
    cx_bn_alloc_init(&R, 32, mont_h, 32);
    cx_bn_alloc(&RInv, 32);
    cx_bn_mod_invert_nprime(RInv, R, M);
}
#define FROM_MONT(a) from_mont(a)
#define TO_MONT(a) to_mont(a)
#define CX_MUL(r, a, b) mont_mul(r, a, b)

static void from_mont(cx_bn_t a) {
    cx_bn_mod_mul(mont_temp, a, RInv, M);
    cx_bn_copy(a, mont_temp);
}
static void to_mont(cx_bn_t a) {
    cx_bn_mod_mul(mont_temp, a, R, M);
    cx_bn_copy(a, mont_temp);
}
static void mont_mul(cx_bn_t r, cx_bn_t a, cx_bn_t b) {
    cx_bn_mod_mul(r, a, b, M);
    from_mont(r);
}

#else
static cx_bn_t H;
static cx_bn_mont_ctx_t MONT_CTX;
static void init_mont(uint8_t *fx_m) {
    cx_bn_alloc_init(&M, 32, fx_m, 32);
    cx_bn_alloc_init(&H, 32, mont_h, 32);
    cx_mont_alloc(&MONT_CTX, 32);
    cx_mont_init2(&MONT_CTX, M, H);
}
#define FROM_MONT(a) cx_mont_from_montgomery(a, a, &MONT_CTX)
#define TO_MONT(a) cx_mont_to_montgomery(a, a, &MONT_CTX)
#define CX_MUL(r, a, b) cx_mont_mul(r, a, b, &MONT_CTX)
#endif

#define CX_BN_MOD_MUL(r, a, b) cx_bn_mod_mul(r, a, b, M)
#define CX_BN_MUL_OPT_MONT(r, a, b) (montgomery ? CX_MUL(r, a, b) : CX_BN_MOD_MUL(r, a, b))

#define BN_IMPORT(dest, src, field) cx_bn_alloc_init(&dest.field, 32, src->field, 32); TO_MONT(dest.field);
#define BN_EXPORT(src, dest, field) FROM_MONT(src.field); cx_bn_export(src.field, dest->field, 32);

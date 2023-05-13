/**
 * Montgomery multiplication helpers
 * 
 * The emulator Speculos does not support Montgomery Multiplication (MM)
 * at this time.
 * 
 * We emulate it by using regular multiplication.
 * 
 * In Montgomery Form, a value x is replaced by x.h
 * and the M. multiplication becomes MM(x*y) = MM(x*h * y*h) = xy * h
 * i.e. it reduces the result by /R. R is chosen so that the reduction
 * is quick.
 * 
 * Converting TO MF: x => x.h
 * Converting FROM MF: x => x/h
*/
#include <ox_bn.h>

static cx_bn_t zero;

#ifdef MONTGOMERY_EMU
static cx_bn_t R, RInv, mont_temp;
static void init_mont(const uint8_t *fx_m) {
    cx_bn_alloc(&zero, 32); cx_bn_set_u32(zero, 0);
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
#elif defined(NO_MONTGOMERY)
static void init_mont(const uint8_t *fx_m) {
    cx_bn_alloc(&zero, 32); cx_bn_set_u32(zero, 0);
    cx_bn_alloc_init(&M, 32, fx_m, 32);
}
#define FROM_MONT(a) 
#define TO_MONT(a) 
#define CX_MUL(r, a, b) cx_bn_mod_mul(r, a, b, M)
#else
static cx_bn_t H;
static cx_bn_mont_ctx_t MONT_CTX;
static void init_mont(const uint8_t *fx_m) {
    cx_bn_alloc(&zero, 32); cx_bn_set_u32(zero, 0);
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


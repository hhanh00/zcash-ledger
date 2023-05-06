#pragma once

/// @brief Point in jacobian coordinates
typedef struct {
    fp_t x, y, z;
} jac_p_t;

/// @brief Point in jacobian coordinates stored in 
/// the big number unit
typedef struct {
    cx_bn_t x, y, z;
} jac_p_bn_t;

/// @brief Spend authentication generator
extern const jac_p_t SPEND_AUTH_GEN;

/// @brief Hash a message to a point on Pallas
/// @param res Result: Point in Jacobian coordinates
/// @param domain Domain separator, i.e. personalisation
/// @param domain_len size in bytes
/// @param msg Message to hash
/// @param msg_len size in bytes
void hash_to_curve(jac_p_t *res, uint8_t *domain, size_t domain_len, uint8_t *msg, size_t msg_len);

/// @brief Convert a 32-byte value to a point
/// @param res Point
/// @param a value
/// @return cx_err_t FAILS if the value does not correspond to a point on the curve
int pallas_from_bytes(jac_p_t *res, uint8_t *a);

/// @brief Convert a point to a 32-byte value
/// @param res 
/// @param p 
void pallas_to_bytes(uint8_t *res, const jac_p_t *p);

/// @brief Copy one point to another
/// @param res destination, must be allocated first
/// @param a source
void pallas_copy_jac_bn(jac_p_bn_t *res, const jac_p_bn_t *a);

/// @brief Check if a point is the identity (z = 0)
/// @param a 
/// @return 
bool pallas_is_identity(const jac_p_bn_t *a);

/// @brief Allocates a point in the BN unit
/// @param dest 
void pallas_jac_alloc(jac_p_bn_t *dest);

/// @brief Initializes a point in BN from integer values
/// @param dest Destination must NOT be allocated before
/// @param src 
void pallas_jac_init(jac_p_bn_t *dest, const jac_p_t *src);

/// @brief Copy from a point in BN to its integer values
/// @param dest 
/// @param src BN values are deallocated
void pallas_jac_export(jac_p_t *dest, jac_p_bn_t *src);

/// @brief Add two points
/// @param v 
/// @param a 
/// @param b 
void pallas_add_jac(jac_p_bn_t *v, const jac_p_bn_t *a, const jac_p_bn_t *b);

/// @brief Double a point
/// @param v 
void pallas_double_jac(jac_p_bn_t *v);

/// @brief Multiplies a point (usually a generator point) by a scalar
/// @param res 
/// @param base generator point
/// @param x scalar
void pallas_base_mult(jac_p_t *res, const jac_p_t *base, fv_t *x);

/// @brief Copy a point into another
/// @param res 
/// @param a 
void pallas_copy_jac(jac_p_t *res, const jac_p_t *a);

/// @brief v += a
/// @param v 
/// @param a 
void pallas_add_assign(jac_p_t *v, const jac_p_t *a);

/// @brief Sign a message with a secret key
/// @param signature Returned signature, 64 bytes: r + s
/// @param sk Secret key: scalar 32 bytes
/// @param message Message Hash: 32 bytes
/// @return 
int pallas_sign(uint8_t *signature, fv_t *sk, uint8_t *message);

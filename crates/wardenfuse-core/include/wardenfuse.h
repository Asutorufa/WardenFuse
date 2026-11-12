// WardenFuse core C ABI (implemented in crates/wardenfuse-core/src/ffi.rs).
// Linked statically into WardenFuse.app; Rust and Swift run in the same process.
#ifndef WARDENFUSE_H
#define WARDENFUSE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void *ctx;
    /// New state snapshot (JSON). Called from a core thread.
    void (*state_changed)(void *ctx, const char *json);
    /// Result of wf_command(id, ...). Called from a core thread.
    void (*command_result)(void *ctx, uint64_t id, const char *json);
    /// Authenticate the user and read the protected user key; answer with wf_auth_complete.
    void (*auth_request)(void *ctx, uint64_t id, const char *json);
    /// Invalidate the matching dialog when its caller has disconnected or timed out.
    void (*auth_cancel)(void *ctx, uint64_t id);
    /// Store a Keychain item. protected_item = requires user presence. Returns 0 or OSStatus.
    int32_t (*keychain_store)(void *ctx, const char *account, const uint8_t *data, size_t len,
                              bool protected_item);
    /// Load an unprotected Keychain item into a malloc()ed buffer owned by the core.
    int32_t (*keychain_load)(void *ctx, const char *account, uint8_t **out, size_t *out_len);
    void (*keychain_delete)(void *ctx, const char *account);
    /// 0 = Touch ID available, 1 = not enrolled, 2 = unavailable.
    int32_t (*biometry_state)(void *ctx);
} WFCallbacks;

bool wf_start(const char *config_json, WFCallbacks callbacks);
void wf_command(uint64_t id, const char *json);
/// status: 0 ok (key provided), 1 cancelled, 2 failed, 3 unavailable, 4 key missing, 5 no UI,
/// 6 timed out.
void wf_auth_complete(uint64_t id, int32_t status, const uint8_t *key, size_t len);
void wf_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif

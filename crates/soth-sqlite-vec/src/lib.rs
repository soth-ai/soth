use std::sync::Once;

use rusqlite::ffi::sqlite3_auto_extension;

static REGISTER_VEC_AUTO_EXTENSION: Once = Once::new();

/// Registers sqlite-vec as an auto-extension once per process.
pub fn register_auto_extension() {
    REGISTER_VEC_AUTO_EXTENSION.call_once(|| unsafe {
        sqlite3_auto_extension(Some(std::mem::transmute(
            sqlite_vec::sqlite3_vec_init as *const (),
        )));
    });
}

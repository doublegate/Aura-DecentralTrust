pub mod did_manager;
pub mod key_manager;
pub mod presentation_generator;
pub mod vc_store;
pub mod wallet;

pub use did_manager::*;
pub use key_manager::*;
pub use presentation_generator::*;
pub use vc_store::*;
pub use wallet::*;

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
}

pub mod traits;
pub mod data;
pub mod err;
pub mod bitacora;

pub mod prelude {
    pub use crate::traits::registry::*;
    pub use crate::err::*;
    pub use crate::data::*;
    pub use crate::bitacora::*;
}
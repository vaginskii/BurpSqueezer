//! Data types shared by the pipeline stages.
//!
//! These types carry observations only. Nothing here decides what is
//! interesting; that is the aggregator's job.

pub mod endpoint;
pub mod http;
pub mod report;
pub mod transaction;
pub mod value;

pub use endpoint::{Endpoint, EndpointStats, EndpointTable};
pub use http::HttpMessage;
pub use report::ReportModel;
pub use transaction::{RawTransaction, TxId};
pub use value::{Direction, ObservedValue, StrongValue, ValueLocation};

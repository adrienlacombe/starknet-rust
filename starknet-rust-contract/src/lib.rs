//! Library for deploying and interacting with Starknet contracts.
//!
//! Provides deployment through [`ContractFactory`] and runtime Cairo 1 ABI interaction through
//! [`Contract`]. For compile-time types, use the core codec derives.

#![deny(missing_docs)]

mod factory;
pub use factory::{ContractFactory, DeploymentV3, UdcSelector};

mod abi;
pub use abi::{AbiError, AbiValue, Contract, ContractAbi, ContractCallError};

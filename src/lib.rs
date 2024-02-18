#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![deny(unsafe_code)]

//! Thunda is a highly scalable, user-level TCP/IP stack designed for multicore systems,
//! written entirely in Rust. Thunda aims to provide both a robust framework for handling
//! network protocols and a set of tools for high-performance network programming, without
//! sacrificing safety or efficiency. Unlike traditional stacks that are deeply integrated
//! into the operating system, Thunda operates in user space, offering greater flexibility
//! and customization for applications that demand precise control over their networking capabilities.
//!
//! Thunda is structured around the principles of modularity and efficiency, offering
//! interfaces at various layers of the network stack while maintaining a clear separation
//! between them. This design allows applications to use Thunda at different levels of abstraction,
//! depending on their specific needs, from handling individual packets to managing complex
//! TCP connections.
//!
//! # Core Components
//!
//! Thunda's architecture is divided into several key components, reflecting different aspects
//! of network communication:
//!
//! ## The Protocol Implementations
//! - Located under the `protocols` module, Thunda provides implementations for essential
//!   networking protocols, including IP (both IPv4 and IPv6), ICMP, TCP, and UDP. Each protocol
//!   is implemented with attention to RFC compliance and performance.
//!
//! ## The Networking Interfaces
//! - The `interfaces` module abstracts over the physical and logical networking interfaces,
//!   allowing Thunda to send and receive packets across different mediums, such as Ethernet or
//!   software-based virtual interfaces.
//!
//! ## Utility and Helper Functions
//! - Thunda includes a `utils` module that contains various utility functions and helpers,
//!   designed to aid in packet processing, address manipulation, and other common tasks.
//!
//! ## Logging and Debugging
//! - With an emphasis on usability and debuggability, Thunda incorporates configurable logging
//!   capabilities, enabling detailed inspection of internal operations and facilitating
//!   troubleshooting and performance tuning.
//!
//! # Getting Started
//!
//! To get started with Thunda, include it as a dependency in your Cargo.toml, and refer to the
//! examples provided in the documentation for guidance on integrating Thunda into your application.
//! Thunda is designed to be as configurable as possible, allowing you to tailor the stack to your
//! project's specific requirements.
//!
//! # Minimum Supported Rust Version (MSRV)
//!
//! Thunda is guaranteed to compile on stable Rust 1.56 and up, ensuring compatibility with a wide
//! range of Rust versions and dependencies. It might compile with older versions, but this is not
//! guaranteed in future patch releases.
//!
//! Thunda's design philosophy centers around leveraging Rust's type safety, zero-cost abstractions,
//! and concurrency model to provide a high-performance, safe, and easy-to-use TCP/IP stack for modern
//! networking applications.// For an Actix application


#[cfg(feature = "log")]
extern crate log;

mod config;
pub use config::Config;


pub mod iface;
pub mod io;
pub mod protocols;
pub mod address;
pub mod parsers;

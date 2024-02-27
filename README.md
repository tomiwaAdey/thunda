## Status
In Development: Thunda is currently under active development. Many core features are being implemented, and the software is not yet ready for production use. Contributors and users should expect significant changes and improvements as development progresses.

## Description
Thunda is a highly scalable, user-level TCP/IP stack designed for multicore systems,
written entirely in Rust. Thunda aims to provide both a robust framework for handling
network protocols and a set of tools for high-performance network programming, without
sacrificing safety or efficiency. Unlike traditional stacks that are deeply integrated
into the operating system, Thunda operates in user space, offering greater flexibility
and customization for applications that demand precise control over their networking capabilities.

Thunda is structured around the principles of modularity and efficiency, offering
interfaces at various layers of the network stack while maintaining a clear separation
between them. This design allows applications to use Thunda at different levels of abstraction,
depending on their specific needs, from handling individual packets to managing complex
TCP connections.


## Features

- High Performance: Designed with performance as a priority, utilizing Rust's asynchronous programming model and efficient memory management practices.
- User-Level Networking: Operates in user space, bypassing the kernel's networking stack for faster packet processing.
- Actor Model: Leverages the actor model for concurrency, making network I/O, packet parsing, and other functionalities more robust and scalable.
- Flexible Packet Processing: Supports raw packet input/output via TAP/AF_XDP, with plans to include DPDK support for even faster data plane operations.
- Protocol Support: Initial focus on core protocols such as Ethernet, ARP, IPv4, IPv6, ICMPv4, and ICMPv6, with a modular design for extending protocol support.

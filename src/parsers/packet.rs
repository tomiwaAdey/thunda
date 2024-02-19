// src/parsers/packet.rs
use actix::prelude::*;
use bytes::BytesMut;
use std::result::Result;
use crate::parsers::{ethernet, ipv4, arp, ipv6};

pub struct Packet;

impl Actor for Packet {
    type Context = Context<Self>;
}

// Message to handle raw packet data
pub struct ParsePacket(pub BytesMut);

impl Message for ParsePacket {
    type Result = Result<(), ()>;
}

impl Handler<ParsePacket> for Packet {
    type Result = MessageResult<ParsePacket>;
    // type Result = ResponseActFuture<Self, Result<ParsedPacket, ParsingError>>;

    fn handle(&mut self, msg: ParsePacket, _: &mut Context<Self>) -> Self::Result {
        let packet = msg.0;
        let eth_frame: ethernet::EthernetFrame = ethernet::parse(&packet)
                        .unwrap();

        match eth_frame.ethertype {
            ethernet::ETHERTYPE_IPV4 => {
                // Handle IPv4 packet
                let _ipv4_packet = ipv4::parse(&eth_frame.payload).unwrap();
            },
            ethernet::ETHERTYPE_IPV6 => {
                // Handle IPv4 packet
                let _ipv6_packet = ipv6::parse(&eth_frame.payload).unwrap();
            },
            ethernet::ETHERTYPE_ARP => {
                // Handle ARP packet
                let _arp_packet = arp::parse(&eth_frame.payload).unwrap();
            },
            _ => {
                // Handle unsupported ethertype
            },
        }

        MessageResult(Ok(()))
    }
}


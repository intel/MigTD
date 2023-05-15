// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use byteorder::{ByteOrder, LittleEndian};
use core::convert::{AsMut, AsRef};

use crate::VsockError;

pub const CID_ANY: u64 = 0xffffffff;
pub mod field {
    #![allow(non_snake_case)]
    #![allow(unused)]
    pub type Field = ::core::ops::Range<usize>;
    pub type Rest = ::core::ops::RangeFrom<usize>;

    pub const SRC_CID: Field = 0..8;
    pub const DST_CID: Field = 8..16;
    pub const SRC_PORT: Field = 16..20;
    pub const DST_PORT: Field = 20..24;
    pub const LEN: Field = 24..28;
    pub const TYPE: Field = 28..30;
    pub const OP: Field = 30..32;
    pub const FLAGS: Field = 32..36;
    pub const BUF_ALLOC: Field = 36..40;
    pub const FWD_CNT: Field = 40..44;
    pub const PAYLOAD: Rest = 44..;

    /// connection-oriented streams are defined by the vsock protocol.
    pub const TYPE_STREAM: u16 = 1;

    /// Indicates that the peer will not receive any more data
    pub const FLAG_SHUTDOWN_READ: u32 = 0x1;
    /// Indicates that the peer will not send any more data
    pub const FLAG_SHUTDOWN_WRITE: u32 = 0x2;

    /// Connect operations
    pub const OP_REQUEST: u16 = 1;
    pub const OP_RESPONSE: u16 = 2;
    pub const OP_RST: u16 = 3;
    pub const OP_SHUTDOWN: u16 = 4;
    /// To send payload
    pub const OP_RW: u16 = 5;
    /// Tell the peer our credit info
    pub const OP_CREDIT_UPDATE: u16 = 6;
    /// Request the peer to send the credit info to us
    pub const OP_CREDIT_REQUEST: u16 = 7;

    pub const HEADER_LEN: usize = FWD_CNT.end;
}

pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Create a raw octet buffer with Vsock packet structure.
    pub fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }
    /// Source CID.
    pub fn src_cid(&self) -> u64 {
        let buf = self.buffer.as_ref();
        LittleEndian::read_u64(&buf[field::SRC_CID])
    }
    /// Destination CID.
    pub fn dst_cid(&self) -> u64 {
        let buf = self.buffer.as_ref();
        LittleEndian::read_u64(&buf[field::DST_CID])
    }
    /// Source port.
    pub fn src_port(&self) -> u32 {
        let buf = self.buffer.as_ref();
        LittleEndian::read_u32(&buf[field::SRC_PORT])
    }
    /// Destination port
    pub fn dst_port(&self) -> u32 {
        let buf = self.buffer.as_ref();
        LittleEndian::read_u32(&buf[field::DST_PORT])
    }
    /// Data length (in bytes) - may be 0, if there is no data buffer.
    pub fn data_len(&self) -> u32 {
        let buf = self.buffer.as_ref();
        LittleEndian::read_u32(&buf[field::LEN])
    }
    /// Socket type.
    /// Currently, only support field::TYPE_STREAM.
    pub fn r#type(&self) -> u16 {
        let buf = self.buffer.as_ref();
        LittleEndian::read_u16(&buf[field::TYPE])
    }
    /// Operation ID - one of the field::OP_*; e.g.
    pub fn op(&self) -> u16 {
        let buf = self.buffer.as_ref();
        LittleEndian::read_u16(&buf[field::OP])
    }
    /// Flags - one of the field::FLAG_*; e.g.
    /// Currently, only used with shutdown requests (field::OP_SHUTDOWN).
    pub fn flags(&self) -> u32 {
        let buf = self.buffer.as_ref();
        LittleEndian::read_u32(&buf[field::FLAGS])
    }
    /// Size (in bytes) of the packet sender receive buffer
    /// Exclude header size
    pub fn buf_alloc(&self) -> u32 {
        let buf = self.buffer.as_ref();
        LittleEndian::read_u32(&buf[field::BUF_ALLOC])
    }
    /// Number of bytes the sender has received and consumed.
    /// For Linux implementation, this counter means the total number of bytes
    /// writen to the stream.
    pub fn fwd_cnt(&self) -> u32 {
        let buf = self.buffer.as_ref();
        LittleEndian::read_u32(&buf[field::FWD_CNT])
    }

    /// Create and check the packet
    pub fn new_checked(buffer: T) -> Result<Packet<T>, VsockError> {
        let packet = Self::new_unchecked(buffer);
        packet.check()?;
        Ok(packet)
    }

    /// Check packet
    pub fn check(&self) -> Result<(), VsockError> {
        if self.buffer.as_ref().len() < self.header_len() {
            return Err(VsockError::Truncated);
        }
        if self.r#type() != field::TYPE_STREAM {
            return Err(VsockError::Malformed);
        }
        let op = self.op();
        if op == 0 || op > 7 {
            return Err(VsockError::Malformed);
        }
        Ok(())
    }

    /// header length
    #[inline]
    pub fn header_len(&self) -> usize {
        field::HEADER_LEN
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set Source CID.
    pub fn set_src_cid(&mut self, src_cid: u64) {
        let buf = self.buffer.as_mut();
        LittleEndian::write_u64(&mut buf[field::SRC_CID], src_cid);
    }
    /// Set Destination CID.
    pub fn set_dst_cid(&mut self, dst_cid: u64) {
        let buf = self.buffer.as_mut();
        LittleEndian::write_u64(&mut buf[field::DST_CID], dst_cid);
    }
    /// Set Source port.
    pub fn set_src_port(&mut self, src_port: u32) {
        let buf = self.buffer.as_mut();
        LittleEndian::write_u32(&mut buf[field::SRC_PORT], src_port);
    }
    /// Set Destination port
    pub fn set_dst_port(&mut self, dst_port: u32) {
        let buf = self.buffer.as_mut();
        LittleEndian::write_u32(&mut buf[field::DST_PORT], dst_port);
    }
    /// Set Data length (in bytes) - may be 0, if there is no data buffer.
    pub fn set_data_len(&mut self, data_len: u32) {
        let buf = self.buffer.as_mut();
        LittleEndian::write_u32(&mut buf[field::LEN], data_len);
    }
    /// Set Socket type.
    /// Currently, only support field::TYPE_STREAM.
    pub fn set_type(&mut self, r#type: u16) {
        let buf = self.buffer.as_mut();
        LittleEndian::write_u16(&mut buf[field::TYPE], r#type);
    }
    /// Set Operation ID - one of the field::OP_*; e.g.
    pub fn set_op(&mut self, op: u16) {
        let buf = self.buffer.as_mut();
        LittleEndian::write_u16(&mut buf[field::OP], op);
    }
    /// Set Flags - one of the field::FLAG_*; e.g.
    /// Currently, only used with shutdown requests (field::OP_SHUTDOWN).
    pub fn set_flags(&mut self, flags: u32) {
        let buf = self.buffer.as_mut();
        LittleEndian::write_u32(&mut buf[field::FLAGS], flags);
    }
    /// Set Size (in bytes) of the packet sender receive buffer
    /// Exclude header size
    pub fn set_buf_alloc(&mut self, buf_alloc: u32) {
        let buf = self.buffer.as_mut();
        LittleEndian::write_u32(&mut buf[field::BUF_ALLOC], buf_alloc);
    }
    /// Set Number of bytes the sender has received and consumed.
    /// For Linux implementation, this counter means the total number of bytes
    /// writen to the stream.
    pub fn set_fwd_cnt(&mut self, fwd_cnt: u32) {
        let buf = self.buffer.as_mut();
        LittleEndian::write_u32(&mut buf[field::FWD_CNT], fwd_cnt);
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the payload.
    pub fn payload(&self) -> &'a [u8] {
        &self.buffer.as_ref()[field::PAYLOAD]
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Packet<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    const PACKET_BYTES_C_REQUEST: [u8; 44] = [
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x69, 0x58, 0x3c, 0xc4, 0xd2, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const PACKET_BYTES_S_RESPONSE: [u8; 44] = [
        0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xd2, 0x04, 0x00, 0x00, 0x69, 0x58, 0x3c, 0xc4, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    // payload is  hello\n
    const PACKET_BYTES_C_RW: [u8; 50] = [
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x69, 0x58, 0x3c, 0xc4, 0xd2, 0x04, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68,
        0x65, 0x6c, 0x6c, 0x6f, 0x0a,
    ];
    const PACKET_BYTES_C_SHUTDOWN: [u8; 44] = [
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x69, 0x58, 0x3c, 0xc4, 0xd2, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x04, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const PACKET_BYTES_S_RST: [u8; 44] = [
        0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xd2, 0x04, 0x00, 0x00, 0x69, 0x58, 0x3c, 0xc4, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00,
    ];
    const PACKET_BYTES_C_RST: [u8; 44] = [
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x69, 0x58, 0x3c, 0xc4, 0xd2, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn test_deconstruct() {
        let packet_req = Packet::new_unchecked(&PACKET_BYTES_C_REQUEST[..]);
        assert_eq!(packet_req.src_cid(), 2);
        assert_eq!(packet_req.src_port(), 3292289129);
        assert_eq!(packet_req.dst_cid(), 33);
        assert_eq!(packet_req.dst_port(), 1234);
        assert_eq!(packet_req.data_len(), 0);
        assert_eq!(packet_req.r#type(), field::TYPE_STREAM);
        assert_eq!(packet_req.op(), field::OP_REQUEST);
        assert_eq!(packet_req.flags(), 0);

        let packet_rsp = Packet::new_unchecked(&PACKET_BYTES_S_RESPONSE[..]);
        assert_eq!(packet_rsp.src_cid(), 33);
        assert_eq!(packet_rsp.src_port(), 1234);
        assert_eq!(packet_rsp.dst_cid(), 2);
        assert_eq!(packet_rsp.dst_port(), 3292289129);
        assert_eq!(packet_rsp.data_len(), 0);
        assert_eq!(packet_rsp.r#type(), field::TYPE_STREAM);
        assert_eq!(packet_rsp.op(), field::OP_RESPONSE);
        assert_eq!(packet_rsp.flags(), 0);

        let packet_rw = Packet::new_unchecked(&PACKET_BYTES_C_RW[..]);
        assert_eq!(packet_rw.src_cid(), 2);
        assert_eq!(packet_rw.src_port(), 3292289129);
        assert_eq!(packet_rw.dst_cid(), 33);
        assert_eq!(packet_rw.dst_port(), 1234);
        assert_eq!(packet_rw.data_len(), 6);
        assert_eq!(packet_rw.r#type(), field::TYPE_STREAM);
        assert_eq!(packet_rw.op(), field::OP_RW);
        assert_eq!(packet_rw.flags(), 0);
        assert_eq!(packet_rw.payload(), b"hello\n");

        let packet_shutdown = Packet::new_unchecked(&PACKET_BYTES_C_SHUTDOWN[..]);
        assert_eq!(packet_shutdown.src_cid(), 2);
        assert_eq!(packet_shutdown.src_port(), 3292289129);
        assert_eq!(packet_shutdown.dst_cid(), 33);
        assert_eq!(packet_shutdown.dst_port(), 1234);
        assert_eq!(packet_shutdown.data_len(), 0);
        assert_eq!(packet_shutdown.r#type(), field::TYPE_STREAM);
        assert_eq!(packet_shutdown.op(), field::OP_SHUTDOWN);
        assert_eq!(
            packet_shutdown.flags(),
            field::FLAG_SHUTDOWN_READ | field::FLAG_SHUTDOWN_WRITE
        );
        assert_eq!(packet_shutdown.fwd_cnt(), 0);
        assert_eq!(packet_shutdown.buf_alloc(), 262144);

        let packet_s_rst = Packet::new_unchecked(&PACKET_BYTES_S_RST[..]);
        assert_eq!(packet_s_rst.src_cid(), 33);
        assert_eq!(packet_s_rst.src_port(), 1234);
        assert_eq!(packet_s_rst.dst_cid(), 2);
        assert_eq!(packet_s_rst.dst_port(), 3292289129);
        assert_eq!(packet_s_rst.data_len(), 0);
        assert_eq!(packet_s_rst.r#type(), field::TYPE_STREAM);
        assert_eq!(packet_s_rst.op(), field::OP_RST);
        assert_eq!(packet_s_rst.flags(), 0);
        assert_eq!(packet_s_rst.fwd_cnt(), 6);
        assert_eq!(packet_s_rst.buf_alloc(), 262144);

        let packet_c_rst = Packet::new_unchecked(&PACKET_BYTES_C_RST[..]);
        assert_eq!(packet_c_rst.src_cid(), 2);
        assert_eq!(packet_c_rst.src_port(), 3292289129);
        assert_eq!(packet_c_rst.dst_cid(), 33);
        assert_eq!(packet_c_rst.dst_port(), 1234);
        assert_eq!(packet_c_rst.data_len(), 0);
        assert_eq!(packet_c_rst.r#type(), field::TYPE_STREAM);
        assert_eq!(packet_c_rst.op(), field::OP_RST);
        assert_eq!(packet_c_rst.flags(), 0);
        assert_eq!(packet_c_rst.fwd_cnt(), 0);
        assert_eq!(packet_c_rst.buf_alloc(), 262144);
    }

    #[test]
    fn test_construct() {
        let mut buf = [0x5a; 44];
        let mut packet = Packet::new_unchecked(&mut buf[..]);
        packet.set_src_cid(33);
        packet.set_dst_cid(2);
        packet.set_src_port(1234);
        packet.set_dst_port(3292289129);
        packet.set_type(field::TYPE_STREAM);
        packet.set_op(field::OP_RESPONSE);
        packet.set_data_len(0);
        packet.set_flags(0);
        packet.set_fwd_cnt(0);
        packet.set_buf_alloc(262144);
        assert_eq!(buf, PACKET_BYTES_S_RESPONSE);
    }
}

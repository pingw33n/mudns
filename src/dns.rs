use std::fmt;
use std::fmt::Write;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;

use anyhow::*;
use bit_field::BitField;
use byteorder::{BE, ReadBytesExt, WriteBytesExt};
use byteorder::ByteOrder;
use bytes::{Buf, BufMut, BytesMut};

pub type ResponseCode = u8;
pub const RCODE_NO_ERROR: ResponseCode = 0;
pub const RCODE_FORMAT_ERROR: ResponseCode = 1;
pub const RCODE_SERVER_FAILURE: ResponseCode = 2;
pub const RCODE_NX_DOMAIN: ResponseCode = 3;
pub const RCODE_NOT_IMPLEMENTED: ResponseCode = 4;
pub const RCODE_REFUSED: ResponseCode = 5;
pub const RCODE_YX_DOMAIN: ResponseCode = 6;
pub const RCODE_YX_RR_SET: ResponseCode = 7;
pub const RCODE_NOT_AUTH: ResponseCode = 9;
pub const RCODE_NOT_ZONE: ResponseCode = 10;
pub const RCODE_BAD_SIGNATURE: ResponseCode = 16;
pub const RCODE_BAD_KEY: ResponseCode = 17;
pub const RCODE_BAD_TIME: ResponseCode = 18;
pub const RCODE_BAD_MODE: ResponseCode = 19;
pub const RCODE_BAD_NAME: ResponseCode = 20;
pub const RCODE_BAD_ALGORITHM: ResponseCode = 21;
pub const RCODE_BAD_TRUNCATION: ResponseCode = 22;
pub const RCODE_BAD_COOKIE: ResponseCode = 23;

pub type RRKind = u16;
pub const RRK_A: RRKind = 1;
pub const RRK_NS: RRKind = 2;
pub const RRK_MD: RRKind = 3;
pub const RRK_MF: RRKind = 4;
pub const RRK_CNAME: RRKind = 5;
pub const RRK_SOA: RRKind = 6;
pub const RRK_MB: RRKind = 7;
pub const RRK_MG: RRKind = 8;
pub const RRK_MR: RRKind = 9;
pub const RRK_NULL: RRKind = 10;
pub const RRK_WKS: RRKind = 11;
pub const RRK_PTR: RRKind = 12;
pub const RRK_HINFO: RRKind = 13;
pub const RRK_MINFO: RRKind = 14;
pub const RRK_MX: RRKind = 15;
pub const RRK_TXT: RRKind = 16;
pub const RRK_AAAA: RRKind = 28;
pub const RRKQ_AXFR: RRKind = 252;
pub const RRKQ_MAILB: RRKind = 253;
pub const RRKQ_MAILA: RRKind = 254;
pub const RRKQ_ALL: RRKind = 255;

pub type RRClass = u16;
pub const RRC_IN: RRClass = 1;
pub const RRC_CS: RRClass = 2;
pub const RRC_CH: RRClass = 3;
pub const RRC_HS: RRClass = 4;
pub const RRC_NONE: RRClass = 254;
pub const RRCQ_ANY: RRClass = 255;

#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Name(String);

impl Name {
    fn decode<'a>(pkt: &'a [u8], cursor: &mut &'a [u8]) -> Result<Self> {
        let mut saved_cursor = None;
        let mut r = String::new();
        let mut hops = 0;
        loop {
            let len = cursor.read_u8().map_err(|_| anyhow!("bad name"))?;
            if len == 0 {
                break;
            } else if len & 0xc0 == 0xc0 {
                if hops == MAX_HOPS {
                    bail!("bad name: too many hops");
                }
                hops += 1;
                let pos = u16::from_be_bytes([
                    len & 0x3f,
                    cursor.read_u8().map_err(|_| anyhow!("bad name"))?]) as usize;
                if saved_cursor.is_none() {
                    saved_cursor = Some(*cursor);
                }
                *cursor = pkt.get(pos..)
                    .ok_or_else(|| anyhow!("bad name"))?;

            } else {
                let len = len as usize;
                if len >= cursor.len() {
                    bail!("bad name");
                }
                if !r.is_empty() {
                    r.push('.');
                }
                Self::decode_label(&mut r, &cursor[..len])?;
                cursor.advance(len);
            }
        }
        if let Some(sc) = saved_cursor {
            *cursor = sc;
        }
        Ok(Self(r))
    }

    fn decode_label(s: &mut String, buf: &[u8]) -> Result<()> {
        s.reserve_exact(buf.len());
        for &c in buf {
            if Self::is_valid_label_char(c) {
                s.push(c as char)
            } else {
                bail!("bad label char");
            }
        }
        Ok(())
    }

    fn is_valid_label_char(c: u8) -> bool {
        match c {
            | b'a'..=b'z'
            | b'A'..=b'Z'
            | b'0'..=b'9'
            | b'-'
            => true,
            _ => false,
        }
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        buf.reserve(self.0.len() + 1);
        let mut s = self.0.as_bytes();
        loop {
            let i = s.iter().position(|&b| b == b'.').unwrap_or(s.len());
            assert!(i > 0 && i <= 63);
            buf.put_u8(i as u8);
            buf.put_slice(&s[..i]);
            if i == s.len() {
                break;
            }
            s = &s[i + 1..];
        }
        buf.put_u8(0);
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            f.write_char('.')
        } else {
            f.write_str(&self.0)
        }
    }
}

#[derive(Debug)]
pub struct ParseNameErr(());

impl FromStr for Name {
    type Err = ParseNameErr;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ParseNameErr(()));
        }
        if s == "." {
            return std::result::Result::Ok(Name(String::new()));
        }
        let mut prev_is_sep = true;
        for &c in s.as_bytes() {
            if c == b'.' {
                if prev_is_sep {
                    return Err(ParseNameErr(()));
                }
                prev_is_sep = true;
            } else if !Self::is_valid_label_char(c) {
                return Err(ParseNameErr(()));
            } else {
                prev_is_sep = false;
            }
        }
        std::result::Result::Ok(Name(s.to_string()))
    }
}

const HEADER_LEN: u16 = 12;
const MAX_HOPS: u32 = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketKind {
    Query,
    Response,
}

pub type OpKind = u8;
pub const OP_QUERY: OpKind = 0;
pub const OP_IQUERY: OpKind = 1;
pub const OP_STATUS: OpKind = 2;
pub const OP_UPDATE: OpKind = 5;

#[derive(Clone, Debug)]
pub struct Packet {
    pub id: u16,
    pub kind: PacketKind,
    pub op_kind: OpKind,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub response_code: ResponseCode,
    pub question: Question,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additional_rrs: Vec<ResourceRecord>,
}

impl Packet {
    pub fn new(
        id: u16,
        kind: PacketKind,
        op_kind: OpKind,
        question: Question,
    ) -> Self {
        Self {
            id,
            kind,
            op_kind,
            authoritative: false,
            truncated: false,
            recursion_desired: false,
            recursion_available: false,
            response_code: RCODE_NO_ERROR,
            question,
            answers: vec![],
            authorities: vec![],
            additional_rrs: vec![],
        }
    }

    pub fn decode(pkt: &[u8]) -> Result<Self> {
        if pkt.len() < HEADER_LEN as usize {
            bail!("too short")
        }

        let cursor = &mut &pkt[..];

        let id = cursor.get_u16();

        let flags = cursor.get_u16();
        let kind = if flags.get_bit(15) {
            PacketKind::Response
        } else {
            PacketKind::Query
        };
        let op_kind = flags.get_bits(11..15) as u8;
        let authoritative = flags.get_bit(10);
        let truncated = flags.get_bit(9);
        let recursion_desired = flags.get_bit(8);
        let recursion_available = flags.get_bit(7);
        let response_code = flags.get_bits(0..4) as u8;

        let question_count = cursor.get_u16();
        if question_count == 0 {
            bail!("empty question section");
        }
        let answer_count = cursor.get_u16();
        let authority_count = cursor.get_u16();
        let additional_rr_count = cursor.get_u16();

        let question = Question::decode(pkt, cursor)?;
        for _ in 1..question_count {
            // TODO optimize
            Question::decode(pkt, cursor)?;
        }

        let mut answers = Vec::with_capacity(answer_count as usize);
        for _ in 0..answer_count {
            answers.push(ResourceRecord::decode(pkt, cursor)?)
        }

        let mut authorities = Vec::with_capacity(authority_count as usize);
        for _ in 0..authority_count {
            authorities.push(ResourceRecord::decode(pkt, cursor)?)
        }

        let mut additional_rrs = Vec::with_capacity(additional_rr_count as usize);
        for _ in 0..additional_rr_count {
            additional_rrs.push(ResourceRecord::decode(pkt, cursor)?)
        }

        Ok(Self {
            id,
            kind,
            op_kind,
            authoritative,
            truncated,
            recursion_desired,
            recursion_available,
            response_code,
            question,
            answers,
            authorities,
            additional_rrs,
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        // TODO name compression

        buf.reserve(HEADER_LEN as usize);
        buf.put_u16(self.id);

        let mut flags = 0;
        flags.set_bit(15, matches!(self.kind, PacketKind::Response));
        flags.set_bits(11..15, self.op_kind as u16);
        flags.set_bit(10, self.authoritative);
        flags.set_bit(9, self.truncated);
        flags.set_bit(8, self.recursion_desired);
        flags.set_bit(7, self.recursion_available);
        flags.set_bits(0..4, self.response_code as u16);
        buf.put_u16(flags);

        buf.put_u16(1);
        buf.put_u16(self.answers.len().try_into().unwrap());
        buf.put_u16(self.authorities.len().try_into().unwrap());
        buf.put_u16(self.additional_rrs.len().try_into().unwrap());

        self.question.encode(buf);
        for a in &self.answers {
            a.encode(buf);
        }
        for a in &self.authorities {
            a.encode(buf);
        }
        for a in &self.additional_rrs {
            a.encode(buf);
        }
    }

    pub fn to_response_with_code(&self, response_code: ResponseCode) -> Self {
        let mut r = Self::new(
            self.id,
            PacketKind::Response,
            self.op_kind,
            self.question.clone());
        r.response_code = response_code;
        r
    }

    pub fn to_response(&self) -> Self {
        self.to_response_with_code(RCODE_NO_ERROR)
    }

    pub fn remove_unknown_rrs(&mut self) {
        fn f(rrs: &mut Vec<ResourceRecord>) {
            rrs.retain(|rr| !matches!(rr.data, RRData::Unknown));
        }
        f(&mut self.answers);
        f(&mut self.authorities);
        f(&mut self.additional_rrs);
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Question {
    pub name: Name,
    pub kind: RRKind,
    pub class: RRClass,
}

impl Question {
    fn decode<'a>(pkt: &'a [u8], cursor: &mut &'a [u8]) -> Result<Self> {
        let name = Name::decode(pkt, cursor)?;
        let kind = cursor.read_u16::<BE>().map_err(|_| anyhow!("bad question"))?;
        let class = cursor.read_u16::<BE>().map_err(|_| anyhow!("bad question"))?;
        Ok(Self {
            name,
            kind,
            class,
        })
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        self.name.encode(buf);
        buf.put_u16(self.kind);
        buf.put_u16(self.class);
    }
}

#[derive(Clone, Debug)]
pub struct ResourceRecord {
    pub name: Name,
    pub kind: RRKind,
    pub class: RRClass,
    pub ttl_secs: u32,
    pub data: RRData,
}

impl ResourceRecord {
    fn decode<'a>(pkt: &'a [u8], cursor: &mut &'a [u8]) -> Result<Self> {
        let name = Name::decode(pkt, cursor)?;
        let kind = cursor.read_u16::<BE>().map_err(|_| anyhow!("bad RR"))?;
        let class = cursor.read_u16::<BE>().map_err(|_| anyhow!("bad RR"))?;
        let ttl_secs = cursor.read_u32::<BE>().map_err(|_| anyhow!("bad RR"))?;
        let data_len = cursor.read_u16::<BE>().map_err(|_| anyhow!("bad RR"))? as usize;
        if data_len > cursor.len() {
            bail!("bad RR")
        }
        let data = match (kind, class) {
            (RRK_A, RRC_IN) => {
                let mut b = [0; 4];
                cursor.read_exact(&mut b).map_err(|_| anyhow!("bad RR data"))?;
                RRData::Ipv4Addr(b.into())
            }
            (RRK_AAAA, RRC_IN) => {
                let mut b = [0; 16];
                cursor.read_exact(&mut b).map_err(|_| anyhow!("bad RR data"))?;
                RRData::Ipv6Addr(b.into())
            }
            (RRK_CNAME, RRC_IN) => RRData::Name(Name::decode(pkt, cursor)?),
            (RRK_SOA, RRC_IN) => RRData::Soa(Soa::decode(pkt, cursor)?),
            _ => {
                cursor.advance(data_len);
                RRData::Unknown
            }
        };
        Ok(Self {
            name,
            kind,
            class,
            ttl_secs,
            data,
        })
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        self.name.encode(buf);
        buf.put_u16(self.kind);
        buf.put_u16(self.class);
        buf.put_u32(self.ttl_secs);
        let data_len_pos = buf.len();
        buf.put_u16(0);
        self.data.encode(buf);
        let data_len = buf.len() - data_len_pos - 2;
        BE::write_u16(&mut buf[data_len_pos..data_len_pos + 2],
                      data_len.try_into().unwrap());
    }

    pub fn ttl(&self) -> Duration {
        Duration::from_secs(u64::from(self.ttl_secs))
    }
}

#[derive(Clone, Debug)]
pub enum RRData {
    Name(Name),
    Ipv4Addr(Ipv4Addr),
    Ipv6Addr(Ipv6Addr),
    Soa(Soa),
    Unknown,
}

impl RRData {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Name(v) => v.encode(buf),
            &Self::Ipv4Addr(v) => buf.put(&v.octets()[..]),
            Self::Ipv6Addr(v) => buf.put(&v.octets()[..]),
            Self::Soa(_) => todo!(),
            Self::Unknown => panic!("can't encode unknown RR"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Soa {
    primary_name: Name,
    responsible_name: Name,
    serial: u32,
    refresh_secs: u32,
    retry_secs: u32,
    expire_secs: u32,
    min_ttl_secs: u32,
}

impl Soa {
    fn decode<'a>(pkt: &'a [u8], cursor: &mut &'a [u8]) -> Result<Self> {
        let primary_name = Name::decode(pkt, cursor)?;
        let responsible_name = Name::decode(pkt, cursor)?;
        let serial = cursor.read_u32::<BE>().map_err(|_| anyhow!("bad SOA"))?;
        let refresh_secs = cursor.read_u32::<BE>().map_err(|_| anyhow!("bad SOA"))?;
        let retry_secs = cursor.read_u32::<BE>().map_err(|_| anyhow!("bad SOA"))?;
        let expire_secs = cursor.read_u32::<BE>().map_err(|_| anyhow!("bad SOA"))?;
        let min_ttl_secs = cursor.read_u32::<BE>().map_err(|_| anyhow!("bad SOA"))?;
        Ok(Self {
            primary_name,
            responsible_name,
            serial,
            refresh_secs,
            retry_secs,
            expire_secs,
            min_ttl_secs,
        })
    }
}
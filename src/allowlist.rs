use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AllowlistEntry {
    Ip(IpAddr),
    Cidr(IpCidr),
}

impl AllowlistEntry {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match self {
            Self::Ip(allowed) => *allowed == ip,
            Self::Cidr(cidr) => cidr.contains(ip),
        }
    }
}

impl fmt::Display for AllowlistEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => write!(formatter, "{ip}"),
            Self::Cidr(cidr) => write!(formatter, "{}/{}", cidr.network, cidr.prefix),
        }
    }
}

impl FromStr for AllowlistEntry {
    type Err = AllowlistParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        if let Ok(ip) = value.parse::<IpAddr>() {
            return Ok(Self::Ip(ip));
        }

        let (network, prefix) = value
            .split_once('/')
            .ok_or_else(|| AllowlistParseError::InvalidEntry(value.to_string()))?;
        let network = network
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| AllowlistParseError::InvalidNetwork(network.trim().to_string()))?;
        let prefix = prefix
            .trim()
            .parse::<u8>()
            .map_err(|_| AllowlistParseError::InvalidPrefix(prefix.trim().to_string()))?;

        Ok(Self::Cidr(IpCidr::new(network, prefix)?))
    }
}

impl Serialize for AllowlistEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AllowlistEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

impl IpCidr {
    pub fn new(network: IpAddr, prefix: u8) -> Result<Self, AllowlistParseError> {
        match network {
            IpAddr::V4(_) if prefix <= 32 => Ok(Self { network, prefix }),
            IpAddr::V6(_) if prefix <= 128 => Ok(Self { network, prefix }),
            IpAddr::V4(_) => Err(AllowlistParseError::PrefixOutOfRange { prefix, max: 32 }),
            IpAddr::V6(_) => Err(AllowlistParseError::PrefixOutOfRange { prefix, max: 128 }),
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => contains_v4(network, ip, self.prefix),
            (IpAddr::V6(network), IpAddr::V6(ip)) => contains_v6(network, ip, self.prefix),
            _ => false,
        }
    }
}

fn contains_v4(network: Ipv4Addr, ip: Ipv4Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(network) & mask) == (u32::from(ip) & mask)
}

fn contains_v6(network: Ipv6Addr, ip: Ipv6Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from(network) & mask) == (u128::from(ip) & mask)
}

#[derive(Debug, Error)]
pub enum AllowlistParseError {
    #[error("invalid allowlist entry `{0}`; expected an IP address or CIDR")]
    InvalidEntry(String),
    #[error("invalid CIDR network `{0}`")]
    InvalidNetwork(String),
    #[error("invalid CIDR prefix `{0}`")]
    InvalidPrefix(String),
    #[error("CIDR prefix {prefix} is out of range; max is {max}")]
    PrefixOutOfRange { prefix: u8, max: u8 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_ip_entry_matches_only_that_ip() {
        let entry: AllowlistEntry = "192.0.2.10".parse().unwrap();

        assert!(entry.contains("192.0.2.10".parse().unwrap()));
        assert!(!entry.contains("192.0.2.11".parse().unwrap()));
    }

    #[test]
    fn ipv4_cidr_matches_address_inside_range() {
        let entry: AllowlistEntry = "172.23.16.0/24".parse().unwrap();

        assert!(entry.contains("172.23.16.77".parse().unwrap()));
        assert!(!entry.contains("172.23.17.1".parse().unwrap()));
    }

    #[test]
    fn ipv6_cidr_matches_address_inside_range() {
        let entry: AllowlistEntry = "2001:db8::/32".parse().unwrap();

        assert!(entry.contains("2001:db8::1".parse().unwrap()));
        assert!(!entry.contains("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn rejects_prefix_out_of_range() {
        let error = "192.0.2.0/33".parse::<AllowlistEntry>().unwrap_err();

        assert!(matches!(
            error,
            AllowlistParseError::PrefixOutOfRange {
                prefix: 33,
                max: 32
            }
        ));
    }
}

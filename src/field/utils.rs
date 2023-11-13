use std::net::Ipv6Addr;

pub fn ipv4_from_str(ipv4: &str) -> Result<u32, &'static str> {
    let mut number: u32 = 0;
    let mut desplazamiento = 0;
    for part in ipv4.split('.').rev() {
        if desplazamiento >= 32 {
            return Err("More than 4 dots");
        }
        let parsed = match part.parse::<u8>() {
            Ok(v) => v,
            Err(_) => return Err("Cannot parse as u8"),
        };
        number += (parsed as u32) << desplazamiento;
        desplazamiento += 8;
    }
    return Ok(number);
}

/// Check whether an ASCII character represents an hexadecimal digit
fn is_hex_digit(byte: u8) -> bool {
    match byte {
        b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => true,
        _ => false,
    }
}
/// Convert an ASCII character that represents an hexadecimal digit into this digit
fn hex_to_digit(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => unreachable!(),
    }
}
pub fn ipv4_to_u32_bytes(ipv4: &[u8]) -> Result<u32, &'static str> {
    if ipv4.len() != 4 {
        return Err("Invalid IPV4 length");
    }
    return Ok(((ipv4[0] as u32) << 24)
        + ((ipv4[1] as u32) << 16)
        + ((ipv4[2] as u32) << 8)
        + (ipv4[3] as u32));
}

/// Read up to four ASCII characters that represent hexadecimal digits, and return their value, as
/// well as the number of characters that were read. If not character is read, `(0, 0)` is
/// returned.
fn read_hextet(bytes: &[u8]) -> (usize, u16) {
    let mut count = 0;
    let mut digits: [u8; 4] = [0; 4];

    for b in bytes {
        if is_hex_digit(*b) {
            digits[count] = hex_to_digit(*b);
            count += 1;
            if count == 4 {
                break;
            }
        } else {
            break;
        }
    }

    if count == 0 {
        return (0, 0);
    }

    let mut shift = (count - 1) * 4;
    let mut res = 0;
    for digit in &digits[0..count] {
        res += (*digit as u16) << shift;
        if shift >= 4 {
            shift -= 4;
        } else {
            break;
        }
    }

    (count, res)
}

pub fn ipv6_from_str(s: &str) -> Result<u128, &'static str> {
    // We'll manipulate bytes instead of UTF-8 characters, because the characters that
    // represent an IPv6 address are supposed to be ASCII characters.
    let bytes = s.as_bytes();

    // The maximimum length of a string representing an IPv6 is the length of:
    //
    //      1111:2222:3333:4444:5555:6666:7777:8888
    //
    // The minimum length of a string representing an IPv6 is the length of:
    //
    //      ::
    //
    if bytes.len() > 38 || bytes.len() < 2 {
        return Err("Invalid ipv6 size");
    }

    let mut offset = 0;
    let mut ellipsis: Option<usize> = None;

    // Handle the special case where the IP start with "::"
    if bytes[0] == b':' {
        if bytes[1] == b':' {
            if bytes.len() == 2 {
                return Ok(0);
            }
            ellipsis = Some(0);
            offset += 2;
        } else {
            // An IPv6 cannot start with a single column. It must be a double column.
            // So this is an invalid address
            return Err("An IPv6 cannot start with a single column.");
        }
    }

    // When dealing with IPv6, it's easier to reason in terms of "hextets" instead of octets.
    // An IPv6 is 8 hextets. At the end, we'll convert that array into an u128.
    let mut address: [u16; 8] = [0; 8];

    // Keep track of the number of hextets we process
    let mut hextet_index = 0;

    loop {
        if offset == bytes.len() {
            break;
        }

        // Try to read an hextet
        let (bytes_read, hextet) = read_hextet(&bytes[offset..]);

        // Handle the case where we could not read an hextet
        if bytes_read == 0 {
            match bytes[offset] {
                // We could not read an hextet because the first character in the slace was ":"
                // This may be because we have two consecutive columns.
                b':' => {
                    // Check if already saw an ellipsis. If so, fail parsing, because an IPv6
                    // can only have one ellipsis.
                    if ellipsis.is_some() {
                        return Err("IPv6 can only have one ellipsis");
                    }
                    // Otherwise, remember the position of the ellipsis. We'll need that later
                    // to count the number of zeros the ellipsis represents.
                    ellipsis = Some(hextet_index);
                    offset += 1;
                    // Continue and try to read the next hextet
                    continue;
                }
                // We now the first character does not represent an hexadecimal digit
                // (otherwise read_hextet() would have read at least one character), and that
                // it's not ":", so the string does not represent an IPv6 address
                _ => return Err("IPv6 can only have one ellipsis"),
            }
        }

        // At this point, we know we read an hextet.

        address[hextet_index] = hextet;
        offset += bytes_read;
        hextet_index += 1;

        // If this was the last hextet of if we reached the end of the buffer, we should be
        // done
        if hextet_index == 8 || offset == bytes.len() {
            break;
        }

        // Read the next charachter. After a hextet, we usually expect a column, but there's a special
        // case for IPv6 that ends with an IPv4.
        match bytes[offset] {
            // We saw the column, we can continue
            b':' => offset += 1,
            // Handle the special IPv4 case, ie address like. Note that the hextet we just read
            // is part of that IPv4 address:
            //
            // aaaa:bbbb:cccc:dddd:eeee:ffff:a.b.c.d.
            //                               ^^
            //                               ||
            // hextet we just read, that  ---+|
            // is actually the first byte of  +--- dot we're handling
            // the ipv4.
            b'.' => {
                // The hextet was actually part of the IPv4, so not that we start reading the
                // IPv4 at `offset - bytes_read`.
                let ipv4: u32 = ipv4_to_u32_bytes(&bytes[offset - bytes_read..])?.into();
                // Replace the hextet we just read by the 16 most significant bits of the
                // IPv4 address (a.b in the comment above)
                address[hextet_index - 1] = ((ipv4 & 0xffff_0000) >> 16) as u16;
                // Set the last hextet to the 16 least significant bits of the IPv4 address
                // (c.d in the comment above)
                address[hextet_index] = (ipv4 & 0x0000_ffff) as u16;
                hextet_index += 1;
                // After successfully parsing an IPv4, we should be done.
                // If there are bytes left in the buffer, or if we didn't read enough hextet,
                // we'll fail later.
                break;
            }
            _ => return Err("Unexpected error"),
        }
    } // end of loop

    // If we exited the loop, we should have reached the end of the buffer.
    // If there are trailing characters, parsing should fail.
    if offset < bytes.len() {
        return Err("There are trailing characters");
    }

    if hextet_index == 8 && ellipsis.is_some() {
        // We parsed an address that looks like 1111:2222::3333:4444:5555:6666:7777,
        // ie with an empty ellipsis.
        return Err("Empty elipsis");
    }

    // We didn't parse enough hextets, but this may be due to an ellipsis
    if hextet_index < 8 {
        if let Some(ellipsis_index) = ellipsis {
            // Count how many zeros the ellipsis accounts for
            let nb_zeros = 8 - hextet_index;
            // Shift the hextet that we read after the ellipsis by the number of zeros
            for index in (ellipsis_index..hextet_index).rev() {
                address[index + nb_zeros] = address[index];
                address[index] = 0;
            }
        } else {
            return Err("Error");
        }
    }

    // Build the IPv6 address from the array of hextets
    return Ok(((address[0] as u128) << 112)
        + ((address[1] as u128) << 96)
        + ((address[2] as u128) << 80)
        + ((address[3] as u128) << 64)
        + ((address[4] as u128) << 48)
        + ((address[5] as u128) << 32)
        + ((address[6] as u128) << 16)
        + address[7] as u128);
}

pub fn ipv4_to_str(ipv4: u32) -> String {
    let mut chars = [0, 0, 0, 0];
    let mut ip = ipv4;
    for i in (0..4).rev() {
        chars[i] = ip & 0xFF;
        ip = ip >> 8;
    }
    return format!("{}.{}.{}.{}", chars[0], chars[1], chars[2], chars[3]);
}

pub fn ipv6_to_str(ipv6: u128) -> String {
    Ipv6Addr::from(ipv6).to_string()
}
pub fn is_local_ipv6(ip: u128) -> bool {
    ip >> 120 & 0xfe == 0xfc
}
pub fn is_local_ipv4(ip: u32) -> bool {
    /*
     *
    Range from 10.0.0.0 to 10.255.255.255 — a 10.0.0.0 network with a 255.0.0.0 or an /8 (8-bit) mask
    Range from 172.16.0.0 to 172.31.255.255 — a 172.16.0.0 network with a 255.240.0.0 (or a 12-bit) mask
    A 192.168.0.0 to 192.168.255.255 range, which is a 192.168.0.0 network masked by 255.255.0.0 or /16
    A special range 100.64.0.0 to 100.127.255.255 with a 255.192.0.0 or /10 network mask; this subnet is recommended according to rfc6598 for use as an address pool for CGN (Carrier-Grade NAT)
    */
    let firstnumber = ip >> 24;
    if firstnumber == 10 {
        return true;
    }
    let secondnumber = (ip >> 16) & 0xFF;
    if firstnumber == 172 && secondnumber >= 16 && secondnumber <= 31 {
        return true;
    }
    if firstnumber == 192 && secondnumber == 168 {
        return true;
    }
    if firstnumber == 100 && secondnumber >= 64 && secondnumber <= 127 {
        return true;
    }
    return false;
}

pub fn port_to_u16(port: &str) -> Result<u16, &'static str> {
    return match port.parse::<u16>() {
        Ok(port) => Ok(port),
        Err(_) => Err("Cannot parse port as u16"),
    };
}

pub fn parse_ipv4_port(text: &str) -> Option<(u32, u16)> {
    match text.rfind(":") {
        Some(pos) => match (ipv4_from_str(&text[..pos]), port_to_u16(&text[(pos + 1)..])) {
            (Ok(v1), Ok(v2)) => Some((v1, v2)),
            _ => None,
        },
        None => None,
    }
}

pub fn is_ipv4_port(text: &str) -> bool {
    match text.rfind(":") {
        Some(pos) => match (ipv4_from_str(&text[..pos]), port_to_u16(&text[(pos + 1)..])) {
            (Ok(_), Ok(_)) => true,
            _ => false,
        },
        None => false,
    }
}
pub fn is_ipv4(text: &str) -> bool {
    match ipv4_from_str(text) {
        Ok(_) => true,
        Err(_) => false,
    }
}
pub fn is_ipv6(text: &str) -> bool {
    match ipv6_from_str(text) {
        Ok(_) => true,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_parse_ips() {
        //192.168.1.1 = 3232235777
        assert_eq!(3232235777, ipv4_from_str("192.168.1.1").unwrap());
        //8.8.8.8 = 134744072
        assert_eq!(134744072, ipv4_from_str("8.8.8.8").unwrap());
        //10.127.222.21 = 176152085
        assert_eq!(176152085, ipv4_from_str("10.127.222.21").unwrap());
        //100.64.0.0 = 1681915904
        assert_eq!(1681915904, ipv4_from_str("100.64.0.0").unwrap());
        //10.255.255.255 = 184549375
        assert_eq!(184549375, ipv4_from_str("10.255.255.255").unwrap());
    }

    #[test]
    fn should_parse_ip_from_u8_array() {
        //192.168.1.1 = 3232235777
        assert_eq!(3232235777, ipv4_to_u32_bytes(&[192, 168, 1, 1]).unwrap());
        //8.8.8.8 = 134744072
        assert_eq!(134744072, ipv4_to_u32_bytes(&[8, 8, 8, 8]).unwrap());
        //10.127.222.21 = 176152085
        assert_eq!(176152085, ipv4_to_u32_bytes(&[10, 127, 222, 21]).unwrap());
        //100.64.0.0 = 1681915904
        assert_eq!(1681915904, ipv4_to_u32_bytes(&[100, 64, 0, 0]).unwrap());
        //10.255.255.255 = 184549375
        assert_eq!(184549375, ipv4_to_u32_bytes(&[10, 255, 255, 255]).unwrap());
    }

    #[test]
    fn check_ip_is_local() {
        //192.168.1.1 = 3232235777
        assert_eq!(is_local_ipv4(3232235777), true);
        //8.8.8.8 = 134744072
        assert_eq!(is_local_ipv4(134744072), false);
        //10.127.222.21 = 176152085
        assert_eq!(is_local_ipv4(176152085), true);
        //100.64.0.0 = 1681915904
        assert_eq!(is_local_ipv4(1681915904), true);
        //10.255.255.255 = 184549375
        assert_eq!(is_local_ipv4(184549375), true);
    }

    #[test]
    fn should_parse_socket() {
        assert_eq!(is_ipv4_port("192.168.0.1:1000"), true);
        assert_eq!(is_ipv4_port("192.168.0.1:100000"), false);
        assert_eq!(is_ipv4("256.168.0.1"), false);
        assert_eq!(is_ipv4_port("800.168.0.1:10000"), false);
        assert_eq!(is_ipv4_port("80.0.168.0.1:10000"), false);
    }
}
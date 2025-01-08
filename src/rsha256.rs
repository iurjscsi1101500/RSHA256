use std::convert::TryInto;
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn rotr32(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!(x) & z)
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn s0(x: u32) -> u32 {
    rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3)
}

fn s1(x: u32) -> u32 {
    rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10)
}

fn e0(x: u32) -> u32 {
    rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22)
}

fn e1(x: u32) -> u32 {
    rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25)
}

fn sha256_transform(state: &mut [u32; 8], data: &[u8; 64]) {
    let mut w: [u32; 64] = [0; 64];

    for t in 0..16 {
        w[t] = u32::from_be_bytes(data[t * 4..(t + 1) * 4].try_into().unwrap());
    }

    for t in 16..64 {
        w[t] = s1(w[t - 2]).wrapping_add(w[t - 7])
                .wrapping_add(s0(w[t - 15]))
                .wrapping_add(w[t - 16]);
    }

    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]);

    for t in 0..64 {
        let t1 = h.wrapping_add(e1(e))
                  .wrapping_add(ch(e, f, g))
                  .wrapping_add(K[t])
                  .wrapping_add(w[t]);
        let t2 = e0(a).wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut state = H;

    let mut data = data.to_vec();
    let orig_len = data.len();

    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0x00);
    }

    let len_bits = (orig_len as u64) * 8;
    data.extend_from_slice(&len_bits.to_be_bytes());

    for chunk in data.chunks(64) {
        let mut block = [0u8; 64];
        block.copy_from_slice(chunk);
        sha256_transform(&mut state, &block);
    }

    let mut hash = Vec::with_capacity(32);
    for &value in &state {
        hash.push((value >> 24) as u8);
        hash.push((value >> 16) as u8);
        hash.push((value >> 8) as u8);
        hash.push(value as u8);
    }

    hash
}

pub fn print_hash(hash: &[u8]) {
    for &byte in hash {
        print!("{:02x}", byte);
    }
    println!();
}

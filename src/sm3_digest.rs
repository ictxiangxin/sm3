/////////////////////////////////////
//      [SM3 Digest Programme]     //
// Author: XiangXin                //
// E-mail: ictxiangxin@hotmail.com //
// File: sm3_digest.rs             //
/////////////////////////////////////

use super::sm3_constant::{SM3_BUFFER_BYTE_LENGTH, SM3_DIGEST_BYTE_LENGTH, SM3_DATA_BYTE_MAX_LENGTH};

#[inline(always)]
fn ff_0_16(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[inline(always)]
fn ff_16_64(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | ((x | y) & z)
}

#[inline(always)]
fn gg_0_16(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[inline(always)]
fn gg_16_64(x: u32, y: u32, z: u32) -> u32 {
    z ^ (x & (y ^ z))
}

#[inline(always)]
fn p_0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

#[inline(always)]
fn p_1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}

#[inline(always)]
fn expand(a: u32, b: u32, c: u32, d: u32, e: u32) -> u32 {
    p_1(a ^ b ^ c.rotate_left(15)) ^ d.rotate_left(7) ^ e
}

#[inline(always)]
fn big_endian_word(buffer: &[u8; SM3_BUFFER_BYTE_LENGTH], i: usize) -> u32 {
    u32::from_be_bytes(buffer[(i * 4)..(i * 4 + 4)].try_into().unwrap())
}

#[inline(always)]
fn round_00_16(x1: u32, x2: &mut u32, x3: u32, x4: &mut u32, x5: u32, x6: &mut u32, x7: u32, x8: &mut u32, t: u32, w: u32, ww: u32) {
    let a_rl12 = x1.rotate_left(12);
    let ss1 = a_rl12.wrapping_add(x5).wrapping_add(t).rotate_left(7);
    let ss2 = ss1 ^ a_rl12;
    let tt1 = ff_0_16(x1, *x2, x3).wrapping_add(*x4).wrapping_add(ss2).wrapping_add(ww);
    let tt2 = gg_0_16(x5, *x6, x7).wrapping_add(*x8).wrapping_add(ss1).wrapping_add(w);
    *x2 = x2.rotate_left(9);
    *x4 = tt1;
    *x6 = x6.rotate_left(19);
    *x8 = p_0(tt2)
}

#[inline(always)]
fn round_16_64(x1: u32, x2: &mut u32, x3: u32, x4: &mut u32, x5: u32, x6: &mut u32, x7: u32, x8: &mut u32, t: u32, w: u32, ww: u32) {
    let a_rl12 = x1.rotate_left(12);
    let ss1 = a_rl12.wrapping_add(x5).wrapping_add(t).rotate_left(7);
    let ss2 = ss1 ^ a_rl12;
    let tt1 = ff_16_64(x1, *x2, x3).wrapping_add(*x4).wrapping_add(ss2).wrapping_add(ww);
    let tt2 = gg_16_64(x5, *x6, x7).wrapping_add(*x8).wrapping_add(ss1).wrapping_add(w);
    *x2 = x2.rotate_left(9);
    *x4 = tt1;
    *x6 = x6.rotate_left(19);
    *x8 = p_0(tt2)
}

#[inline(always)]
fn fill_to_bytes(digest_bytes: &mut [u8; SM3_DIGEST_BYTE_LENGTH], x: u32, index: usize) {
    let word_bytes = x.to_be_bytes();
    digest_bytes[index * 4 + 0] = word_bytes[0];
    digest_bytes[index * 4 + 1] = word_bytes[1];
    digest_bytes[index * 4 + 2] = word_bytes[2];
    digest_bytes[index * 4 + 3] = word_bytes[3];
}

#[inline(always)]
fn put_data_length(buffer: &mut [u8; SM3_BUFFER_BYTE_LENGTH], length: u64) {
    let length_bytes = length.to_be_bytes();
    buffer[SM3_BUFFER_BYTE_LENGTH - 1] = length_bytes[7];
    buffer[SM3_BUFFER_BYTE_LENGTH - 2] = length_bytes[6];
    buffer[SM3_BUFFER_BYTE_LENGTH - 3] = length_bytes[5];
    buffer[SM3_BUFFER_BYTE_LENGTH - 4] = length_bytes[4];
    buffer[SM3_BUFFER_BYTE_LENGTH - 5] = length_bytes[3];
    buffer[SM3_BUFFER_BYTE_LENGTH - 6] = length_bytes[2];
    buffer[SM3_BUFFER_BYTE_LENGTH - 7] = length_bytes[1];
    buffer[SM3_BUFFER_BYTE_LENGTH - 8] = length_bytes[0];
}

pub struct SM3Digest {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,
    f: u32,
    g: u32,
    h: u32,
    total_length: u64,
    remains_data: Vec<u8>,
}

impl SM3Digest {
    pub fn new() -> SM3Digest {
        let instance = SM3Digest {
            a: 0x7380166f,
            b: 0x4914b2b9,
            c: 0x172442d7,
            d: 0xda8a0600,
            e: 0xa96f30bc,
            f: 0x163138aa,
            g: 0xe38dee4d,
            h: 0xb0fb0e4e,
            total_length: 0,
            remains_data: Vec::new(),
        };
        instance
    }

    pub fn get_digest_bytes(&mut self) -> [u8; SM3_DIGEST_BYTE_LENGTH] {
        let mut digest_bytes = [0; SM3_DIGEST_BYTE_LENGTH];
        fill_to_bytes(&mut digest_bytes, self.a, 0);
        fill_to_bytes(&mut digest_bytes, self.b, 1);
        fill_to_bytes(&mut digest_bytes, self.c, 2);
        fill_to_bytes(&mut digest_bytes, self.d, 3);
        fill_to_bytes(&mut digest_bytes, self.e, 4);
        fill_to_bytes(&mut digest_bytes, self.f, 5);
        fill_to_bytes(&mut digest_bytes, self.g, 6);
        fill_to_bytes(&mut digest_bytes, self.h, 7);
        digest_bytes
    }

    pub fn compute_digest(&mut self) {
        let remains_data_length = self.remains_data.len();
        let min_padding_byte_length = remains_data_length + SM3_DATA_BYTE_MAX_LENGTH + 1;
        let mut buffer: [u8; SM3_BUFFER_BYTE_LENGTH] = [0; SM3_BUFFER_BYTE_LENGTH];
        for i in 0..self.remains_data.len() {
            buffer[i] = self.remains_data[i];
        }
        self.remains_data.clear();
        buffer[remains_data_length] = 0x80;
        if min_padding_byte_length > SM3_BUFFER_BYTE_LENGTH {
            self.update(&buffer);
            buffer.fill(0x00);
            put_data_length(&mut buffer, self.total_length);
            self.update(&buffer);
        } else {
            put_data_length(&mut buffer, self.total_length);
            self.update(&buffer);
        }
    }

    pub fn push_data(&mut self, data: &[u8]) {
        let data_length = (data.len() as u64) << 3;
        self.total_length += data_length;
        let remains_data_length = self.remains_data.len();
        let mut offset: usize = 0;
        if remains_data_length > 0 && remains_data_length + data.len() >= SM3_BUFFER_BYTE_LENGTH {
            offset = SM3_BUFFER_BYTE_LENGTH - remains_data_length;
            let mut buffer: [u8; SM3_BUFFER_BYTE_LENGTH] = [0; SM3_BUFFER_BYTE_LENGTH];
            for i in 0..self.remains_data.len() {
                buffer[i] = self.remains_data[i];
            }
            self.remains_data.clear();
            for i in remains_data_length..SM3_BUFFER_BYTE_LENGTH {
                buffer[i] = data[i - remains_data_length];
            }
            self.update(&buffer);
        }
        let buffer_count = (data.len() - offset) / SM3_BUFFER_BYTE_LENGTH;
        for i in 0..buffer_count  {
            self.update(data[(i * SM3_BUFFER_BYTE_LENGTH + offset)..(i * SM3_BUFFER_BYTE_LENGTH + offset + SM3_BUFFER_BYTE_LENGTH)].try_into().unwrap());
        }
        for i in (buffer_count * SM3_BUFFER_BYTE_LENGTH + offset)..data.len() {
            self.remains_data.push(data[i]);
        }
    }

    fn update(&mut self, buffer: &[u8; SM3_BUFFER_BYTE_LENGTH]) {
        let mut a = self.a;
        let mut b = self.b;
        let mut c = self.c;
        let mut d = self.d;
        let mut e = self.e;
        let mut f = self.f;
        let mut g = self.g;
        let mut h = self.h;
        let mut w00 = big_endian_word(buffer, 0);
        let mut w01 = big_endian_word(buffer, 1);
        let mut w02 = big_endian_word(buffer, 2);
        let mut w03 = big_endian_word(buffer, 3);
        let mut w04 = big_endian_word(buffer, 4);
        let mut w05 = big_endian_word(buffer, 5);
        let mut w06 = big_endian_word(buffer, 6);
        let mut w07 = big_endian_word(buffer, 7);
        let mut w08 = big_endian_word(buffer, 8);
        let mut w09 = big_endian_word(buffer, 9);
        let mut w10 = big_endian_word(buffer, 10);
        let mut w11 = big_endian_word(buffer, 11);
        let mut w12 = big_endian_word(buffer, 12);
        let mut w13 = big_endian_word(buffer, 13);
        let mut w14 = big_endian_word(buffer, 14);
        let mut w15 = big_endian_word(buffer, 15);
        round_00_16(a, &mut b, c, &mut d, e, &mut f, g, &mut h, 0x79cc4519, w00, w00 ^ w04);
        w00 = expand(w00, w07, w13, w03, w10);
        round_00_16(d, &mut a, b, &mut c, h, &mut e, f, &mut g, 0xf3988a32, w01, w01 ^ w05);
        w01 = expand(w01, w08, w14, w04, w11);
        round_00_16(c, &mut d, a, &mut b, g, &mut h, e, &mut f, 0xe7311465, w02, w02 ^ w06);
        w02 = expand(w02, w09, w15, w05, w12);
        round_00_16(b, &mut c, d, &mut a, f, &mut g, h, &mut e, 0xce6228cb, w03, w03 ^ w07);
        w03 = expand(w03, w10, w00, w06, w13);
        round_00_16(a, &mut b, c, &mut d, e, &mut f, g, &mut h, 0x9cc45197, w04, w04 ^ w08);
        w04 = expand(w04, w11, w01, w07, w14);
        round_00_16(d, &mut a, b, &mut c, h, &mut e, f, &mut g, 0x3988a32f, w05, w05 ^ w09);
        w05 = expand(w05, w12, w02, w08, w15);
        round_00_16(c, &mut d, a, &mut b, g, &mut h, e, &mut f, 0x7311465e, w06, w06 ^ w10);
        w06 = expand(w06, w13, w03, w09, w00);
        round_00_16(b, &mut c, d, &mut a, f, &mut g, h, &mut e, 0xe6228cbc, w07, w07 ^ w11);
        w07 = expand(w07, w14, w04, w10, w01);
        round_00_16(a, &mut b, c, &mut d, e, &mut f, g, &mut h, 0xcc451979, w08, w08 ^ w12);
        w08 = expand(w08, w15, w05, w11, w02);
        round_00_16(d, &mut a, b, &mut c, h, &mut e, f, &mut g, 0x988a32f3, w09, w09 ^ w13);
        w09 = expand(w09, w00, w06, w12, w03);
        round_00_16(c, &mut d, a, &mut b, g, &mut h, e, &mut f, 0x311465e7, w10, w10 ^ w14);
        w10 = expand(w10, w01, w07, w13, w04);
        round_00_16(b, &mut c, d, &mut a, f, &mut g, h, &mut e, 0x6228cbce, w11, w11 ^ w15);
        w11 = expand(w11, w02, w08, w14, w05);
        round_00_16(a, &mut b, c, &mut d, e, &mut f, g, &mut h, 0xc451979c, w12, w12 ^ w00);
        w12 = expand(w12, w03, w09, w15, w06);
        round_00_16(d, &mut a, b, &mut c, h, &mut e, f, &mut g, 0x88a32f39, w13, w13 ^ w01);
        w13 = expand(w13, w04, w10, w00, w07);
        round_00_16(c, &mut d, a, &mut b, g, &mut h, e, &mut f, 0x11465e73, w14, w14 ^ w02);
        w14 = expand(w14, w05, w11, w01, w08);
        round_00_16(b, &mut c, d, &mut a, f, &mut g, h, &mut e, 0x228cbce6, w15, w15 ^ w03);
        w15 = expand(w15, w06, w12, w02, w09);
        round_16_64(a, &mut b, c, &mut d, e, &mut f, g, &mut h, 0x9d8a7a87, w00, w00 ^ w04);
        w00 = expand(w00, w07, w13, w03, w10);
        round_16_64(d, &mut a, b, &mut c, h, &mut e, f, &mut g, 0x3b14f50f, w01, w01 ^ w05);
        w01 = expand(w01, w08, w14, w04, w11);
        round_16_64(c, &mut d, a, &mut b, g, &mut h, e, &mut f, 0x7629ea1e, w02, w02 ^ w06);
        w02 = expand(w02, w09, w15, w05, w12);
        round_16_64(b, &mut c, d, &mut a, f, &mut g, h, &mut e, 0xec53d43c, w03, w03 ^ w07);
        w03 = expand(w03, w10, w00, w06, w13);
        round_16_64(a, &mut b, c, &mut d, e, &mut f, g, &mut h, 0xd8a7a879, w04, w04 ^ w08);
        w04 = expand(w04, w11, w01, w07, w14);
        round_16_64(d, &mut a, b, &mut c, h, &mut e, f, &mut g, 0xb14f50f3, w05, w05 ^ w09);
        w05 = expand(w05, w12, w02, w08, w15);
        round_16_64(c, &mut d, a, &mut b, g, &mut h, e, &mut f, 0x629ea1e7, w06, w06 ^ w10);
        w06 = expand(w06, w13, w03, w09, w00);
        round_16_64(b, &mut c, d, &mut a, f, &mut g, h, &mut e, 0xc53d43ce, w07, w07 ^ w11);
        w07 = expand(w07, w14, w04, w10, w01);
        round_16_64(a, &mut b, c, &mut d, e, &mut f, g, &mut h, 0x8a7a879d, w08, w08 ^ w12);
        w08 = expand(w08, w15, w05, w11, w02);
        round_16_64(d, &mut a, b, &mut c, h, &mut e, f, &mut g, 0x14f50f3b, w09, w09 ^ w13);
        w09 = expand(w09, w00, w06, w12, w03);
        round_16_64(c, &mut d, a, &mut b, g, &mut h, e, &mut f, 0x29ea1e76, w10, w10 ^ w14);
        w10 = expand(w10, w01, w07, w13, w04);
        round_16_64(b, &mut c, d, &mut a, f, &mut g, h, &mut e, 0x53d43cec, w11, w11 ^ w15);
        w11 = expand(w11, w02, w08, w14, w05);
        round_16_64(a, &mut b, c, &mut d, e, &mut f, g, &mut h, 0xa7a879d8, w12, w12 ^ w00);
        w12 = expand(w12, w03, w09, w15, w06);
        round_16_64(d, &mut a, b, &mut c, h, &mut e, f, &mut g, 0x4f50f3b1, w13, w13 ^ w01);
        w13 = expand(w13, w04, w10, w00, w07);
        round_16_64(c, &mut d, a, &mut b, g, &mut h, e, &mut f, 0x9ea1e762, w14, w14 ^ w02);
        w14 = expand(w14, w05, w11, w01, w08);
        round_16_64(b, &mut c, d, &mut a, f, &mut g, h, &mut e, 0x3d43cec5, w15, w15 ^ w03);
        w15 = expand(w15, w06, w12, w02, w09);
        round_16_64(a, &mut b, c, &mut d, e, &mut f, g, &mut h, 0x7a879d8a, w00, w00 ^ w04);
        w00 = expand(w00, w07, w13, w03, w10);
        round_16_64(d, &mut a, b, &mut c, h, &mut e, f, &mut g, 0xf50f3b14, w01, w01 ^ w05);
        w01 = expand(w01, w08, w14, w04, w11);
        round_16_64(c, &mut d, a, &mut b, g, &mut h, e, &mut f, 0xea1e7629, w02, w02 ^ w06);
        w02 = expand(w02, w09, w15, w05, w12);
        round_16_64(b, &mut c, d, &mut a, f, &mut g, h, &mut e, 0xd43cec53, w03, w03 ^ w07);
        w03 = expand(w03, w10, w00, w06, w13);
        round_16_64(a, &mut b, c, &mut d, e, &mut f, g, &mut h, 0xa879d8a7, w04, w04 ^ w08);
        w04 = expand(w04, w11, w01, w07, w14);
        round_16_64(d, &mut a, b, &mut c, h, &mut e, f, &mut g, 0x50f3b14f, w05, w05 ^ w09);
        w05 = expand(w05, w12, w02, w08, w15);
        round_16_64(c, &mut d, a, &mut b, g, &mut h, e, &mut f, 0xa1e7629e, w06, w06 ^ w10);
        w06 = expand(w06, w13, w03, w09, w00);
        round_16_64(b, &mut c, d, &mut a, f, &mut g, h, &mut e, 0x43cec53d, w07, w07 ^ w11);
        w07 = expand(w07, w14, w04, w10, w01);
        round_16_64(a, &mut b, c, &mut d, e, &mut f, g, &mut h, 0x879d8a7a, w08, w08 ^ w12);
        w08 = expand(w08, w15, w05, w11, w02);
        round_16_64(d, &mut a, b, &mut c, h, &mut e, f, &mut g, 0x0f3b14f5, w09, w09 ^ w13);
        w09 = expand(w09, w00, w06, w12, w03);
        round_16_64(c, &mut d, a, &mut b, g, &mut h, e, &mut f, 0x1e7629ea, w10, w10 ^ w14);
        w10 = expand(w10, w01, w07, w13, w04);
        round_16_64(b, &mut c, d, &mut a, f, &mut g, h, &mut e, 0x3cec53d4, w11, w11 ^ w15);
        w11 = expand(w11, w02, w08, w14, w05);
        round_16_64(a, &mut b, c, &mut d, e, &mut f, g, &mut h, 0x79d8a7a8, w12, w12 ^ w00);
        w12 = expand(w12, w03, w09, w15, w06);
        round_16_64(d, &mut a, b, &mut c, h, &mut e, f, &mut g, 0xf3b14f50, w13, w13 ^ w01);
        w13 = expand(w13, w04, w10, w00, w07);
        round_16_64(c, &mut d, a, &mut b, g, &mut h, e, &mut f, 0xe7629ea1, w14, w14 ^ w02);
        w14 = expand(w14, w05, w11, w01, w08);
        round_16_64(b, &mut c, d, &mut a, f, &mut g, h, &mut e, 0xcec53d43, w15, w15 ^ w03);
        w15 = expand(w15, w06, w12, w02, w09);
        round_16_64(a, &mut b, c, &mut d, e, &mut f, g, &mut h, 0x9d8a7a87, w00, w00 ^ w04);
        w00 = expand(w00, w07, w13, w03, w10);
        round_16_64(d, &mut a, b, &mut c, h, &mut e, f, &mut g, 0x3b14f50f, w01, w01 ^ w05);
        w01 = expand(w01, w08, w14, w04, w11);
        round_16_64(c, &mut d, a, &mut b, g, &mut h, e, &mut f, 0x7629ea1e, w02, w02 ^ w06);
        w02 = expand(w02, w09, w15, w05, w12);
        round_16_64(b, &mut c, d, &mut a, f, &mut g, h, &mut e, 0xec53d43c, w03, w03 ^ w07);
        w03 = expand(w03, w10, w00, w06, w13);
        round_16_64(a, &mut b, c, &mut d, e, &mut f, g, &mut h, 0xd8a7a879, w04, w04 ^ w08);
        round_16_64(d, &mut a, b, &mut c, h, &mut e, f, &mut g, 0xb14f50f3, w05, w05 ^ w09);
        round_16_64(c, &mut d, a, &mut b, g, &mut h, e, &mut f, 0x629ea1e7, w06, w06 ^ w10);
        round_16_64(b, &mut c, d, &mut a, f, &mut g, h, &mut e, 0xc53d43ce, w07, w07 ^ w11);
        round_16_64(a, &mut b, c, &mut d, e, &mut f, g, &mut h, 0x8a7a879d, w08, w08 ^ w12);
        round_16_64(d, &mut a, b, &mut c, h, &mut e, f, &mut g, 0x14f50f3b, w09, w09 ^ w13);
        round_16_64(c, &mut d, a, &mut b, g, &mut h, e, &mut f, 0x29ea1e76, w10, w10 ^ w14);
        round_16_64(b, &mut c, d, &mut a, f, &mut g, h, &mut e, 0x53d43cec, w11, w11 ^ w15);
        round_16_64(a, &mut b, c, &mut d, e, &mut f, g, &mut h, 0xa7a879d8, w12, w12 ^ w00);
        round_16_64(d, &mut a, b, &mut c, h, &mut e, f, &mut g, 0x4f50f3b1, w13, w13 ^ w01);
        round_16_64(c, &mut d, a, &mut b, g, &mut h, e, &mut f, 0x9ea1e762, w14, w14 ^ w02);
        round_16_64(b, &mut c, d, &mut a, f, &mut g, h, &mut e, 0x3d43cec5, w15, w15 ^ w03);
        self.a ^= a;
        self.b ^= b;
        self.c ^= c;
        self.d ^= d;
        self.e ^= e;
        self.f ^= f;
        self.g ^= g;
        self.h ^= h;
    }
}

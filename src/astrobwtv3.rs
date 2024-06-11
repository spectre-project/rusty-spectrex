// Public crates.
use rc4::KeyInit;
use rc4::Rc4;
use rc4::StreamCipher;
use salsa20::Salsa20;
use salsa20::cipher::KeyIvInit;
use sha2::Digest;
use sha2::Sha256;
use siphasher::sip::SipHasher24;
use std::hash::Hasher;
use psacak::psacak;

// This is the maximum.
const MAX_LENGTH: u32 = (256 * 384) - 1;

// Calculate and return sha256 hash.
fn sha256_calc(input: &[u8]) -> [u8; 32] {
    let mut output: [u8; 32] = [0; 32];
    let mut hasher = Sha256::new();
    hasher.update(input);

    output.copy_from_slice(hasher.finalize().as_slice());
    output
}

// Encrypt and return salsa20 stream.
fn salsa20_calc(key: &[u8; 32]) -> [u8; 256] {
    let mut output: [u8; 256] = [0; 256];
    let mut cipher = Salsa20::new(key.into(), &[0; 8].into());
    cipher.apply_keystream(&mut output);
    output
}

// Calculate and return fnv1a hash.
fn fnv1a_calc(input: &[u8]) -> u64 {
    let mut hasher = fnv::FnvHasher::default();
    hasher.write(input);
    let output = hasher.finish();
    output
}

// Calculate and return xxh64 hash.
fn xxh64_calc(input: &[u8]) -> u64 {
    let output = xxhash_rust::xxh64::xxh64(input, 0);
    output
}

// Calculate and return sip24 hash.
fn sip24_calc(input: &[u8], k0: u64, k1: u64) -> u64 {
    let hasher = SipHasher24::new_with_keys(k0, k1);
    let output = hasher.hash(input);
    output
}

// The AstroBWTv3 calculation.
pub fn astrobwtv3_hash(input: &[u8]) -> [u8; 32] {

    // Step 1+2: calculate sha256 and expand data using Salsa20.
    let mut data: [u8; 256] = salsa20_calc(&(sha256_calc(input)));

    // Step 3: rc4.
    let mut rc4 = Rc4::new(&data.into());
    let mut stream = data.to_vec();
    rc4.apply_keystream(&mut stream);
    data.copy_from_slice(&stream);

    // Step 4: fnv1a.
    let mut lhash = fnv1a_calc(&data);

    // Step 5: branchy loop to avoid GPU/FPGA optimizations.
    let mut scratch_data = [0u8; (MAX_LENGTH + 64) as usize];
    let mut prev_lhash = lhash;
    let mut tries: u64 = 0;
    loop {
        tries += 1;
        let random_switcher = prev_lhash ^ lhash ^ tries;

        let op: u8 = random_switcher as u8;
        let mut pos1: u8 = random_switcher.wrapping_shr(8) as u8;
        let mut pos2: u8 = random_switcher.wrapping_shr(16) as u8;

        if pos1 > pos2 {
            std::mem::swap(&mut pos1, &mut pos2);
        }

        // Give wave or wavefronts an optimization.
        if pos2 - pos1 > 32 {
            pos2 = pos1 + ((pos2 - pos1) & 0x1f);
        }

        // Bounds check elimination.
        let _ = &data[pos1 as usize..pos2 as usize];

        match op {
            0 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];

                    tmp ^= tmp.count_ones() as u8;                         // ones count bits
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp.wrapping_mul(tmp);                           // *
                    tmp = tmp.rotate_left(tmp as u32);                     // rotate bits by random
                    data[i as usize] = tmp;
                    data[pos1 as usize] = data[pos1 as usize].reverse_bits();
                    data[pos2 as usize] = data[pos2 as usize].reverse_bits();
                    data.swap(pos1 as usize, pos2 as usize);
                }
            }
            1 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shl((tmp & 3) as u32);              // shift left
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp & data[pos2 as usize];                       // AND
                    tmp = tmp.wrapping_add(tmp);                           // +
                    data[i as usize] = tmp;
                }
            }
            2 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    data[i as usize] = tmp ^ tmp.count_ones() as u8;       // ones count bits
                }
            }
            3 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    data[i as usize] = tmp;
                }
            }
            4 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    data[i as usize] = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                }
            }
            5 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    data[i as usize] = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                }
            }
            6 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = !tmp;                                            // binary NOT operator
                    data[i as usize] = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                }
            }
            7 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    data[i as usize] = !tmp;                                            // binary NOT operator
                }
            }
            8 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    data[i as usize] = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                }
            }
            9 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    data[i as usize] = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                }
            }
            10 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    data[i as usize] = tmp.wrapping_mul(tmp);              // *
                }
            }
            11 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp & data[pos2 as usize];                       // AND
                    data[i as usize] = tmp.rotate_left(tmp as u32);        // rotate bits by random
                }
            }
            12 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    data[i as usize] = !tmp;                                            // binary NOT operator
                }
            }
            13 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    data[i as usize] = tmp.rotate_left(5);                              // rotate bits by 5
                }
            }
            14 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.wrapping_mul(tmp);              // *
                    data[i as usize] = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                }
            }
            15 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp & data[pos2 as usize];                       // AND
                    data[i as usize] = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                }
            }
            16 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    data[i as usize] = !tmp;                                            // binary NOT operator
                }
            }
            17 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    data[i as usize] = !tmp;                                            // binary NOT operator
                }
            }
            18 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    data[i as usize] = tmp.rotate_left(5);                              // rotate bits by 5
                }
            }
            19 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    data[i as usize] = tmp.wrapping_add(tmp);              // +
                }
            }
            20 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp & data[pos2 as usize];                       // AND
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp.reverse_bits();                              // reverse bits
                    data[i as usize] = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                }
            }
            21 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp.wrapping_add(tmp);              // +
                    data[i as usize] = tmp & data[pos2 as usize];                       // AND
                }
            }
            22 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp.wrapping_mul(tmp);              // *
                    data[i as usize] = tmp.rotate_left(1);                              // rotate bits by 1
                }
            }
            23 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    data[i as usize] = tmp & data[pos2 as usize];                       // AND
                }
            }
            24 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    data[i as usize] = tmp.rotate_left(5);                              // rotate bits by 5
                }
            }
            25 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    data[i as usize] = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                }
            }
            26 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp.wrapping_add(tmp);              // +
                    data[i as usize] = tmp.reverse_bits();                              // reverse bits
                }
            }
            27 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp & data[pos2 as usize];                       // AND
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    data[i as usize] = tmp.rotate_left(5);                              // rotate bits by 5
                }
            }
            28 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.wrapping_add(tmp);              // +
                    data[i as usize] = tmp.rotate_left(5);                              // rotate bits by 5
                }
            }
            29 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    data[i as usize] = tmp.wrapping_add(tmp);              // +
                }
            }
            30 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp & data[pos2 as usize];                       // AND
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    data[i as usize] = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                }
            }
            31 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    data[i as usize] = tmp.wrapping_mul(tmp);              // *
                }
            }
            32 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    data[i as usize] = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                }
            }
            33 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp.reverse_bits();                              // reverse bits
                    data[i as usize] = tmp.wrapping_mul(tmp);              // *
                }
            }
            34 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    data[i as usize] = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                }
            }
            35 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    data[i as usize] = tmp ^ data[pos2 as usize];                       // XOR
                }
            }
            36 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    data[i as usize] = tmp.rotate_left(1);                              // rotate bits by 1
                }
            }
            37 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    data[i as usize] = tmp.wrapping_mul(tmp);              // *
                }
            }
            38 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    data[i as usize] = tmp.rotate_left(tmp as u32);        // rotate bits by random
                }
            }
            39 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    data[i as usize] = tmp & data[pos2 as usize];                       // AND
                }
            }
            40 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    data[i as usize] = tmp ^ data[pos2 as usize];                       // XOR
                }
            }
            41 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    data[i as usize] = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                }
            }
            42 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    data[i as usize] = tmp.rotate_left(tmp as u32);        // rotate bits by random
                }
            }
            43 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp & data[pos2 as usize];                       // AND
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp & data[pos2 as usize];                       // AND
                    data[i as usize] = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                }
            }
            44 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    data[i as usize] = tmp.rotate_left(tmp as u32);        // rotate bits by random
                }
            }
            45 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp & data[pos2 as usize];                       // AND
                    data[i as usize] = tmp ^ tmp.count_ones() as u8;       // ones count bits
                }
            }
            46 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    data[i as usize] = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                }
            }
            47 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp & data[pos2 as usize];                       // AND
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    data[i as usize] = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                }
            }
            48 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = !tmp;                                            // binary NOT operator
                    data[i as usize] = tmp.rotate_left(5);                              // rotate bits by 5
                }
            }
            49 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.reverse_bits();                              // reverse bits
                    data[i as usize] = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                }
            }
            50 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp.wrapping_add(tmp);              // +
                    data[i as usize] = tmp.rotate_left(1);                              // rotate bits by 1
                }
            }
            51 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    data[i as usize] = tmp.rotate_left(5);                              // rotate bits by 5
                }
            }
            52 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = !tmp;                                            // binary NOT operator
                    data[i as usize] = tmp ^ tmp.count_ones() as u8;       // ones count bits
                }
            }
            53 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    data[i as usize] = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                }
            }
            54 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = !tmp;                                            // binary NOT operator
                    data[i as usize] = !tmp;                                            // binary NOT operator
                }
            }
            55 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    data[i as usize] = tmp.rotate_left(1);                              // rotate bits by 1
                }
            }
            56 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = !tmp;                                            // binary NOT operator
                    data[i as usize] = tmp.rotate_left(1);                              // rotate bits by 1
                }
            }
            57 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    data[i as usize] = tmp.reverse_bits();                              // reverse bits
                }
            }
            58 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp & data[pos2 as usize];                       // AND
                    data[i as usize] = tmp.wrapping_add(tmp);              // +
                }
            }
            59 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    data[i as usize] = !tmp;                                            // binary NOT operator
                }
            }
            60 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp.wrapping_mul(tmp);              // *
                    data[i as usize] = tmp.rotate_left(3);                              // rotate bits by 3
                }
            }
            61 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    data[i as usize] = tmp.rotate_left(5);                              // rotate bits by 5
                }
            }
            62 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp & data[pos2 as usize];                       // AND
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    data[i as usize] = tmp.wrapping_add(tmp);              // +
                }
            }
            63 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    data[i as usize] = tmp.wrapping_add(tmp);              // +
                }
            }
            64 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    data[i as usize] = tmp.wrapping_mul(tmp);              // *
                }
            }
            65 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    data[i as usize] = tmp.wrapping_mul(tmp);              // *
                }
            }
            66 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    data[i as usize] = tmp.rotate_left(1);                              // rotate bits by 1
                }
            }
            67 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    data[i as usize] = tmp.rotate_left(5);                              // rotate bits by 5
                }
            }
            68 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp & data[pos2 as usize];                       // AND
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    data[i as usize] = tmp ^ data[pos2 as usize];                       // XOR
                }
            }
            69 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = tmp.reverse_bits();                              // reverse bits
                    data[i as usize] = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                }
            }
            70 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    data[i as usize] = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                }
            }
            71 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp.wrapping_mul(tmp);              // *
                    data[i as usize] = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                }
            }
            72 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    data[i as usize] = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                }
            }
            73 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    data[i as usize] = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                }
            }
            74 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp.reverse_bits();                              // reverse bits
                    data[i as usize] = tmp & data[pos2 as usize];                       // AND
                }
            }
            75 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp & data[pos2 as usize];                       // AND
                    data[i as usize] = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                }
            }
            76 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    data[i as usize] = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                }
            }
            77 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    data[i as usize] = tmp ^ tmp.count_ones() as u8;       // ones count bits
                }
            }
            78 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp.wrapping_mul(tmp);              // *
                    data[i as usize] = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                }
            }
            79 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp.wrapping_add(tmp);              // +
                    data[i as usize] = tmp.wrapping_mul(tmp);              // *
                }
            }
            80 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.wrapping_add(tmp);              // +
                    data[i as usize] = tmp & data[pos2 as usize];                       // AND
                }
            }
            81 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    data[i as usize] = tmp ^ tmp.count_ones() as u8;       // ones count bits
                }
            }
            82 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = !tmp;                                            // binary NOT operator
                    data[i as usize] = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                }
            }
            83 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    data[i as usize] = tmp.reverse_bits();                              // reverse bits
                }
            }
            84 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    data[i as usize] = tmp.wrapping_add(tmp);              // +
                }
            }
            85 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    data[i as usize] = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                }
            }
            86 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    data[i as usize] = !tmp;                                            // binary NOT operator
                }
            }
            87 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    data[i as usize] = tmp.wrapping_add(tmp);              // +
                }
            }
            88 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp.wrapping_mul(tmp);              // *
                    data[i as usize] = !tmp;                                            // binary NOT operator
                }
            }
            89 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = !tmp;                                            // binary NOT operator
                    data[i as usize] = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                }
            }
            90 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    data[i as usize] = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                }
            }
            91 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp & data[pos2 as usize];                       // AND
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    data[i as usize] = tmp.reverse_bits();                              // reverse bits
                }
            }
            92 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    data[i as usize] = tmp & data[pos2 as usize];                       // AND
                }
            }
            93 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = tmp & data[pos2 as usize];                       // AND
                    data[i as usize] = tmp.wrapping_add(tmp);              // +
                }
            }
            94 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp & data[pos2 as usize];                       // AND
                    data[i as usize] = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                }
            }
            95 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    data[i as usize] = tmp.rotate_left(5);                              // rotate bits by 5
                }
            }
            96 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    data[i as usize] = tmp.rotate_left(1);                              // rotate bits by 1
                }
            }
            97 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    data[i as usize] = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                }
            }
            98 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    data[i as usize] = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                }
            }
            99 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    tmp = tmp.reverse_bits();                              // reverse bits
                    data[i as usize] = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                }
            }
            100 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.reverse_bits();                              // reverse bits
                    data[i as usize] = tmp ^ tmp.count_ones() as u8;       // ones count bits
                }
            }
            101 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    data[i as usize] = !tmp;                                            // binary NOT operator
                }
            }
            102 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    tmp = tmp.wrapping_add(tmp);              // +
                    data[i as usize] = tmp.rotate_left(3);                              // rotate bits by 3
                }
            }
            103 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    data[i as usize] = tmp.rotate_left(tmp as u32);        // rotate bits by random
                }
            }
            104 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    data[i as usize] = tmp.wrapping_add(tmp);              // +
                }
            }
            105 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    data[i as usize] = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                }
            }
            106 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    data[i as usize] = tmp.wrapping_mul(tmp);              // *
                }
            }
            107 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    data[i as usize] = tmp.rotate_left(1);                              // rotate bits by 1
                }
            }
            108 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp & data[pos2 as usize];                       // AND
                    data[i as usize] = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                }
            }
            109 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    data[i as usize] = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                }
            }
            110 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    data[i as usize] = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                }
            }
            111 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp.wrapping_mul(tmp);              // *
                    data[i as usize] = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                }
            }
            112 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    data[i as usize] = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                }
            }
            113 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    data[i as usize] = !tmp;                                            // binary NOT operator
                }
            }
            114 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    data[i as usize] = !tmp;                                            // binary NOT operator
                }
            }
            115 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp & data[pos2 as usize];                       // AND
                    data[i as usize] = tmp.rotate_left(3);                              // rotate bits by 3
                }
            }
            116 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp & data[pos2 as usize];                       // AND
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    data[i as usize] = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                }
            }
            117 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    data[i as usize] = tmp & data[pos2 as usize];                       // AND
                }
            }
            118 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    data[i as usize] = tmp.rotate_left(5);                              // rotate bits by 5
                }
            }
            119 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = !tmp;                                            // binary NOT operator
                    data[i as usize] = tmp ^ data[pos2 as usize];                       // XOR
                }
            }
            120 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    data[i as usize] = tmp.reverse_bits();                              // reverse bits
                }
            }
            121 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    data[i as usize] = tmp.wrapping_mul(tmp);              // *
                }
            }
            122 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    data[i as usize] = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                }
            }
            123 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp & data[pos2 as usize];                       // AND
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    data[i as usize] = tmp.rotate_left(3);                              // rotate bits by 3
                }
            }
            124 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    data[i as usize] = !tmp;                                            // binary NOT operator
                }
            }
            125 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp.wrapping_add(tmp);              // +
                    data[i as usize] = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                }
            }
            126 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    data[i as usize] = tmp.reverse_bits();                              // reverse bits
                }
            }
            127 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = tmp & data[pos2 as usize];                       // AND
                    data[i as usize] = tmp ^ data[pos2 as usize];                       // XOR
                }
            }
            128 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    data[i as usize] = tmp.rotate_left(5);                              // rotate bits by 5
                }
            }
            129 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    data[i as usize] = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                }
            }
            130 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    data[i as usize] = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                }
            }
            131 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    data[i as usize] = tmp.wrapping_mul(tmp);              // *
                }
            }
            132 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp & data[pos2 as usize];                       // AND
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    data[i as usize] = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                }
            }
            133 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    data[i as usize] = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                }
            }
            134 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    data[i as usize] = tmp & data[pos2 as usize];                       // AND
                }
            }
            135 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp.wrapping_add(tmp);              // +
                    data[i as usize] = tmp.reverse_bits();                              // reverse bits
                }
            }
            136 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    data[i as usize] = tmp.rotate_left(5);                              // rotate bits by 5
                }
            }
            137 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp.reverse_bits();                              // reverse bits
                    data[i as usize] = tmp.rotate_left(tmp as u32);        // rotate bits by random
                }
            }
            138 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp.wrapping_add(tmp);              // +
                    data[i as usize] = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                }
            }
            139 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    data[i as usize] = tmp.rotate_left(3);                              // rotate bits by 3
                }
            }
            140 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    data[i as usize] = tmp.rotate_left(5);                              // rotate bits by 5
                }
            }
            141 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    data[i as usize] = tmp.wrapping_add(tmp);              // +
                }
            }
            142 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp & data[pos2 as usize];                       // AND
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp.reverse_bits();                              // reverse bits
                    data[i as usize] = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                }
            }
            143 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp & data[pos2 as usize];                       // AND
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    data[i as usize] = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                }
            }
            144 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = !tmp;                                            // binary NOT operator
                    data[i as usize] = tmp.rotate_left(tmp as u32);        // rotate bits by random
                }
            }
            145 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    data[i as usize] = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                }
            }
            146 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp & data[pos2 as usize];                       // AND
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp & data[pos2 as usize];                       // AND
                    data[i as usize] = tmp ^ tmp.count_ones() as u8;       // ones count bits
                }
            }
            147 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    data[i as usize] = tmp.wrapping_mul(tmp);              // *
                }
            }
            148 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp & data[pos2 as usize];                       // AND
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    data[i as usize] = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                }
            }
            149 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    data[i as usize] = tmp.wrapping_add(tmp);              // +
                }
            }
            150 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    data[i as usize] = tmp & data[pos2 as usize];                       // AND
                }
            }
            151 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.wrapping_mul(tmp);              // *
                    data[i as usize] = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                }
            }
            152 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    data[i as usize] = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                }
            }
            153 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    // TODO !tmp two time = tmp
                    tmp = !tmp;                                            // binary NOT operator
                    data[i as usize] = !tmp;                                            // binary NOT operator
                }
            }
            154 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    data[i as usize] = tmp ^ tmp.count_ones() as u8;       // ones count bits
                }
            }
            155 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    data[i as usize] = tmp ^ data[pos2 as usize];                       // XOR
                }
            }
            156 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    data[i as usize] = tmp.rotate_left(1);                              // rotate bits by 1
                }
            }
            157 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    data[i as usize] = tmp.rotate_left(1);                              // rotate bits by 1
                }
            }
            158 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp.wrapping_add(tmp);              // +
                    data[i as usize] = tmp.rotate_left(1);                              // rotate bits by 1
                }
            }
            159 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    data[i as usize] = tmp ^ data[pos2 as usize];                       // XOR
                }
            }
            160 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    data[i as usize] = tmp.rotate_left(3);                              // rotate bits by 3
                }
            }
            161 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    data[i as usize] = tmp.rotate_left(tmp as u32);        // rotate bits by random
                }
            }
            162 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    data[i as usize] = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                }
            }
            163 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    data[i as usize] = tmp.rotate_left(1);                              // rotate bits by 1
                }
            }
            164 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    data[i as usize] = !tmp;                                            // binary NOT operator
                }
            }
            165 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    data[i as usize] = tmp.wrapping_add(tmp);              // +
                }
            }
            166 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    data[i as usize] = !tmp;                                            // binary NOT operator
                }
            }
            167 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp.wrapping_mul(tmp);              // *
                    data[i as usize] = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                }
            }
            168 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp & data[pos2 as usize];                       // AND
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    data[i as usize] = tmp.rotate_left(1);                              // rotate bits by 1
                }
            }
            169 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    data[i as usize] = tmp & data[pos2 as usize];                       // AND
                }
            }
            170 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    data[i as usize] = tmp.wrapping_mul(tmp);              // *
                }
            }
            171 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    data[i as usize] = tmp.reverse_bits();                              // reverse bits
                }
            }
            172 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    data[i as usize] = tmp.rotate_left(1);                              // rotate bits by 1
                }
            }
            173 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.wrapping_mul(tmp);              // *
                    data[i as usize] = tmp.wrapping_add(tmp);              // +
                }
            }
            174 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    data[i as usize] = tmp ^ tmp.count_ones() as u8;       // ones count bits
                }
            }
            175 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    tmp = tmp.wrapping_mul(tmp);              // *
                    data[i as usize] = tmp.rotate_left(5);                              // rotate bits by 5
                }
            }
            176 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    data[i as usize] = tmp.rotate_left(5);                              // rotate bits by 5
                }
            }
            177 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    data[i as usize] = tmp & data[pos2 as usize];                       // AND
                }
            }
            178 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp & data[pos2 as usize];                       // AND
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = !tmp;                                            // binary NOT operator
                    data[i as usize] = tmp.rotate_left(1);                              // rotate bits by 1
                }
            }
            179 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    data[i as usize] = tmp.reverse_bits();                              // reverse bits
                }
            }
            180 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    data[i as usize] = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                }
            }
            181 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    data[i as usize] = tmp.rotate_left(5);                              // rotate bits by 5
                }
            }
            182 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    data[i as usize] = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                }
            }
            183 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    data[i as usize] = tmp.wrapping_mul(tmp);              // *
                }
            }
            184 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    data[i as usize] = tmp ^ data[pos2 as usize];                       // XOR
                }
            }
            185 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    data[i as usize] = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                }
            }
            186 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    data[i as usize] = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                }
            }
            187 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp.wrapping_add(tmp);              // +
                    data[i as usize] = tmp.rotate_left(3);                              // rotate bits by 3
                }
            }
            188 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    data[i as usize] = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                }
            }
            189 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    data[i as usize] = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                }
            }
            190 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp & data[pos2 as usize];                       // AND
                    data[i as usize] = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                }
            }
            191 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    data[i as usize] = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                }
            }
            192 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.wrapping_add(tmp);              // +
                    data[i as usize] = tmp.wrapping_mul(tmp);              // *
                }
            }
            193 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp & data[pos2 as usize];                       // AND
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    data[i as usize] = tmp.rotate_left(1);                              // rotate bits by 1
                }
            }
            194 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp & data[pos2 as usize];                       // AND
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    data[i as usize] = tmp & data[pos2 as usize];                       // AND
                }
            }
            195 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    data[i as usize] = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                }
            }
            196 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    data[i as usize] = tmp.rotate_left(1);                              // rotate bits by 1
                }
            }
            197 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp.wrapping_mul(tmp);              // *
                    data[i as usize] = tmp.wrapping_mul(tmp);              // *
                }
            }
            198 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp.reverse_bits();                              // reverse bits
                    data[i as usize] = tmp.rotate_left(1);                              // rotate bits by 1
                }
            }
            199 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.wrapping_mul(tmp);              // *
                    data[i as usize] = tmp ^ data[pos2 as usize];                       // XOR
                }
            }
            200 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp.reverse_bits();                              // reverse bits
                    data[i as usize] = tmp.reverse_bits();                              // reverse bits
                }
            }
            201 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    data[i as usize] = !tmp;                                            // binary NOT operator
                }
            }
            202 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    data[i as usize] = tmp.rotate_left(5);                              // rotate bits by 5
                }
            }
            203 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp & data[pos2 as usize];                       // AND
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    data[i as usize] = tmp.rotate_left(tmp as u32);        // rotate bits by random
                }
            }
            204 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    data[i as usize] = tmp ^ data[pos2 as usize];                       // XOR
                }
            }
            205 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    data[i as usize] = tmp.wrapping_add(tmp);              // +
                }
            }
            206 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp.reverse_bits();                              // reverse bits
                    data[i as usize] = tmp ^ tmp.count_ones() as u8;       // ones count bits
                }
            }
            207 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    data[i as usize] = tmp ^ tmp.count_ones() as u8;       // ones count bits
                }
            }
            208 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    data[i as usize] = tmp.rotate_left(3);                              // rotate bits by 3
                }
            }
            209 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    data[i as usize] = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                }
            }
            210 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    data[i as usize] = !tmp;                                            // binary NOT operator
                }
            }
            211 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    data[i as usize] = tmp.rotate_left(tmp as u32);        // rotate bits by random
                }
            }
            212 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    data[i as usize] = tmp ^ data[pos2 as usize];                       // XOR
                }
            }
            213 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    data[i as usize] = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                }
            }
            214 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    data[i as usize] = !tmp;                                            // binary NOT operator
                }
            }
            215 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp & data[pos2 as usize];                       // AND
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    data[i as usize] = tmp.wrapping_mul(tmp);              // *
                }
            }
            216 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    data[i as usize] = tmp & data[pos2 as usize];                       // AND
                }
            }
            217 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    data[i as usize] = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                }
            }
            218 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp.wrapping_mul(tmp);              // *
                    data[i as usize] = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                }
            }
            219 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp & data[pos2 as usize];                       // AND
                    data[i as usize] = tmp.reverse_bits();                              // reverse bits
                }
            }
            220 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.reverse_bits();                              // reverse bits
                    data[i as usize] = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                }
            }
            221 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = !tmp;                                            // binary NOT operator
                    data[i as usize] = tmp.reverse_bits();                              // reverse bits
                }
            }
            222 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    data[i as usize] = tmp.wrapping_mul(tmp);              // *
                }
            }
            223 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    data[i as usize] = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                }
            }
            224 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    data[i as usize] = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                }
            }
            225 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp.reverse_bits();                              // reverse bits
                    data[i as usize] = tmp.rotate_left(3);                              // rotate bits by 3
                }
            }
            226 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    tmp = tmp.wrapping_mul(tmp);              // *
                    data[i as usize] = tmp ^ data[pos2 as usize];                       // XOR
                }
            }
            227 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    data[i as usize] = tmp & data[pos2 as usize];                       // AND
                }
            }
            228 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp.wrapping_add(tmp);              // +
                    data[i as usize] = tmp ^ tmp.count_ones() as u8;       // ones count bits
                }
            }
            229 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    data[i as usize] = tmp ^ tmp.count_ones() as u8;       // ones count bits
                }
            }
            230 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = tmp & data[pos2 as usize];                       // AND
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    data[i as usize] = tmp.rotate_left(tmp as u32);        // rotate bits by random
                }
            }
            231 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    data[i as usize] = tmp.reverse_bits();                              // reverse bits
                }
            }
            232 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    data[i as usize] = tmp.rotate_left(5);                              // rotate bits by 5
                }
            }
            233 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    data[i as usize] = tmp ^ tmp.count_ones() as u8;       // ones count bits
                }
            }
            234 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp & data[pos2 as usize];                       // AND
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    data[i as usize] = tmp ^ data[pos2 as usize];                       // XOR
                }
            }
            235 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp.wrapping_mul(tmp);              // *
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    data[i as usize] = !tmp;                                            // binary NOT operator
                }
            }
            236 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp & data[pos2 as usize];                       // AND
                    data[i as usize] = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                }
            }
            237 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    data[i as usize] = tmp.rotate_left(3);                              // rotate bits by 3
                }
            }
            238 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    data[i as usize] = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                }
            }
            239 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp.wrapping_mul(tmp);              // *
                    data[i as usize] = tmp & data[pos2 as usize];                       // AND
                }
            }
            240 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp & data[pos2 as usize];                       // AND
                    data[i as usize] = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                }
            }
            241 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    data[i as usize] = tmp.rotate_left(1);                              // rotate bits by 1
                }
            }
            242 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    data[i as usize] = tmp ^ data[pos2 as usize];                       // XOR
                }
            }
            243 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    data[i as usize] = tmp.rotate_left(1);                              // rotate bits by 1
                }
            }
            244 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp.reverse_bits();                              // reverse bits
                    data[i as usize] = tmp.rotate_left(5);                              // rotate bits by 5
                }
            }
            245 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    data[i as usize] = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                }
            }
            246 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    tmp = tmp.wrapping_shr((tmp & 3) as u32); // shift right
                    data[i as usize] = tmp.wrapping_add(tmp);              // +
                }
            }
            247 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    data[i as usize] = !tmp;                                            // binary NOT operator
                }
            }
            248 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = !tmp;                                            // binary NOT operator
                    tmp = tmp.wrapping_sub(tmp ^ 97);         // XOR and -
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    data[i as usize] = tmp.rotate_left(5);                              // rotate bits by 5
                }
            }
            249 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    data[i as usize] = tmp.rotate_left(tmp as u32);        // rotate bits by random
                }
            }
            250 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp & data[pos2 as usize];                       // AND
                    tmp = tmp.rotate_left(tmp as u32);        // rotate bits by random
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    data[i as usize] = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                }
            }
            251 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.wrapping_add(tmp);              // +
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp.reverse_bits();                              // reverse bits
                    data[i as usize] = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                }
            }
            252 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.reverse_bits();                              // reverse bits
                    tmp = tmp ^ tmp.rotate_left(4);           // rotate bits by 4
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    data[i as usize] = tmp.wrapping_shl((tmp & 3) as u32); // shift left
                }
            }
            253 => {
                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    tmp = tmp ^ data[pos2 as usize];                       // XOR
                    data[i as usize] = tmp.rotate_left(3);                              // rotate bits by 3

                    // More deviations.
                    prev_lhash = prev_lhash.wrapping_add(lhash);
                    lhash = xxh64_calc(&data[..pos2 as usize]);
                }
            }
            254 | 255 => {

                // Use a new key.
                rc4 = Rc4::new(&data.into());

                for i in pos1..pos2 {
                    let mut tmp = data[i as usize];
                    tmp = tmp ^ tmp.count_ones() as u8;       // ones count bits
                    tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    tmp = tmp ^ tmp.rotate_left(2);           // rotate bits by 2
                    data[i as usize] = tmp.rotate_left(3);                              // rotate bits by 3
                }
            }
        }

        let dp1 = data[pos1 as usize];
        let dp2 = data[pos2 as usize];
        let dp_minus = dp1.wrapping_sub(dp2);

        // 6.25 % probability.
        if dp_minus < 0x10 {

            // More deviations.
            prev_lhash = prev_lhash.wrapping_add(lhash);
            lhash = xxh64_calc(&data[..pos2 as usize]);
        }

        // 12.5 % probability.
        if dp_minus < 0x20 {

            // More deviations.
            prev_lhash = prev_lhash.wrapping_add(lhash);
            lhash = fnv1a_calc(&data[..pos2 as usize]);
        }

        // 18.75 % probability.
        if dp_minus < 0x30 {

            // More deviations.
            prev_lhash = prev_lhash.wrapping_add(lhash);
            lhash = sip24_calc(&data[..pos2 as usize], tries, prev_lhash);
        }

        // 25% probablility.
        if dp_minus <= 0x40 {

            // Do the rc4.
            stream = data.to_vec();
            rc4.apply_keystream(&mut stream);
            data.copy_from_slice(&stream);
        }

        data[255] ^= data[pos1 as usize] ^ data[pos2 as usize];

        // Copy all the tmp states.
        scratch_data[((tries - 1) * 256) as usize..(tries * 256) as usize].copy_from_slice(&data);

        // Keep looping until condition is satisfied.
        if tries > 260+16 || (data[255] >= 0xf0 && tries > 260) {
            break;
        }
    }

    // We may discard up to ~ 1KiB data from the stream to ensure that wide number of variants exists.
    let data_len = (tries - 4) as u32 * 256 + (((data[253] as u64) << 8 | (data[254] as u64)) as u32 & 0x3ff);

    // Step 6: build our suffix array.
    let scratch_sa = psacak(&scratch_data[..data_len as usize]);
    let mut scratch_sa_bytes: Vec<u8> = vec![];
    for vector in &scratch_sa {

        // Little and big endian.
        if cfg!(target_endian = "little") {
            scratch_sa_bytes.extend_from_slice(&vector.to_le_bytes());
        } else {
            scratch_sa_bytes.extend_from_slice(&vector.to_be_bytes());
        }
    }

    // Step 7: calculate the final sha256 hash.
    let output: [u8; 32] = sha256_calc(&scratch_sa_bytes);

    // Return AstroBWTv3 hash.
    output
}

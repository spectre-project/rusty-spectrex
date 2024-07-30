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
use suffix_array::SuffixArray;

// This is the maximum.
const MAX_LENGTH: u32 = (256 * 384) - 1;

// The base for the following code was contributed by @Wolf9466 on Discord.
const BRANCH_TABLE: [u32; 256] = [
    0x090F020A, 0x060B0500, 0x09080609, 0x0A0D030B, 0x04070A01, 0x09030607, 0x060D0401, 0x000A0904,
    0x040F0F06, 0x030E070C, 0x04020D02, 0x0B0F050A, 0x0C020C04, 0x0B03070F, 0x07060206, 0x0C060501,
    0x0E020B04, 0x03020F04, 0x0E0D0B0F, 0x010F0600, 0x0503080C, 0x0B030005, 0x0608020B, 0x0D0B0905,
    0x00070E0F, 0x090D0A01, 0x02090008, 0x0F050E0F, 0x0600000F, 0x02030700, 0x050E0F06, 0x040C0602,
    0x0C080D0C, 0x0A0E0802, 0x01060601, 0x00040B03, 0x090B0C0B, 0x0A070702, 0x070D090A, 0x0C030705,
    0x0A030903, 0x0F010D0E, 0x0B0D0C0A, 0x05000501, 0x09090D0A, 0x0F0F0509, 0x09000F0E, 0x0F050F06,
    0x0A04040F, 0x0900080E, 0x080D000B, 0x030E0E0F, 0x0A070409, 0x00090E0E, 0x08030404, 0x080E0E0B,
    0x0C02040B, 0x0A0F0D08, 0x080C0500, 0x0B020A04, 0x0304020D, 0x0F060D0F, 0x05040C00, 0x0F090100,
    0x03080E02, 0x0F0D0C02, 0x0C080E0B, 0x0B090C0F, 0x05040E03, 0x00020807, 0x0302070E, 0x0F040206,
    0x08090306, 0x09080F01, 0x020D0805, 0x0209050E, 0x0A0C0F07, 0x0D000609, 0x0A080201, 0x0E0C0002,
    0x0A060005, 0x0E060A09, 0x03040407, 0x06080D08, 0x010B0600, 0x07030A06, 0x0E0A0E04, 0x000D0E00,
    0x0C0B0204, 0x0002040C, 0x080F0B07, 0x09050E08, 0x09040905, 0x0C020500, 0x0B0A0506, 0x0B040F0F,
    0x0C0C090B, 0x0B060907, 0x0E06070E, 0x0E010807, 0x0A060809, 0x07090704, 0x0D01000D, 0x0B08030A,
    0x08090F00, 0x060D0A0C, 0x080E0B02, 0x070C0F0B, 0x0304050C, 0x020A030C, 0x000C0C07, 0x02080207,
    0x0D040F01, 0x0F0B0904, 0x0B080A04, 0x0A0F050D, 0x05030906, 0x060D0605, 0x0700060F, 0x080C0403,
    0x0C020308, 0x07000902, 0x0E0A0F0C, 0x05040D0D, 0x0C0C0304, 0x080C0007, 0x0D0B0F08, 0x06020503,
    0x0A0C0C0F, 0x04090907, 0x070A0B0E, 0x010B0902, 0x05080F0C, 0x030F0C06, 0x040E0B05, 0x070C0008,
    0x0701030F, 0x0F07080A, 0x03030001, 0x0F0D0C0D, 0x0B0C030F, 0x0B010900, 0x050F080C, 0x050D0706,
    0x0A06040A, 0x080E0C0E, 0x05060509, 0x04060E02, 0x050F0601, 0x03080100, 0x06060605, 0x00060206,
    0x0704060C, 0x0B0D0404, 0x0F040309, 0x01030903, 0x07070D0B, 0x07060A0B, 0x090D000B, 0x01030A03,
    0x07080B0D, 0x03030F0A, 0x02080C01, 0x06010E0B, 0x02090104, 0x0E030600, 0x0D000C04, 0x04040207,
    0x0A050A0B, 0x0B060E05, 0x01080102, 0x0D010908, 0x0E01060B, 0x04060200, 0x040A0909, 0x0D01020F,
    0x0302030F, 0x090C0C05, 0x0500040B, 0x0C000708, 0x070E0301, 0x04060C0F, 0x030B0F0E, 0x00010102,
    0x06020F03, 0x040E0F07, 0x0C0E0107, 0x0304000D, 0x0E090E0E, 0x0F0E0301, 0x0F07050C, 0x000D0A07,
    0x00060002, 0x05060A0B, 0x050A0605, 0x090C030E, 0x0D08060B, 0x0E0A0202, 0x0707080B, 0x04000203,
    0x07090808, 0x0D0C0E04, 0x03040A0F, 0x03050B0A, 0x0F0C0A03, 0x090E0600, 0x0E080809, 0x0F0D0909,
    0x0000070D, 0x0F080901, 0x0C0A0F04, 0x0E00010A, 0x0A0C0303, 0x00060D01, 0x03010704, 0x03050602,
    0x0A040105, 0x0F000B0E, 0x08040201, 0x0E0D0508, 0x0B060806, 0x0F030408, 0x07060302, 0x0D030A01,
    0x0C0B0D06, 0x0407080D, 0x08010203, 0x04060105, 0x00070009, 0x0D0A0C09, 0x02050A0A, 0x0D070308,
    0x02020E0F, 0x0B090D09, 0x05020703, 0x0C020D04, 0x03000501, 0x0F060C0D, 0x00000D01, 0x0F0B0205,
    0x04000506, 0x0E09030B, 0x00000103, 0x0F0C090B, 0x040C080F, 0x010F0C07, 0x000B0700, 0x0F0C0F04,
    0x0401090F, 0x080E0E0A, 0x050A090E, 0x0009080C, 0x080E0C06, 0x0D0C030D, 0x090D0C0D, 0x090D0C0D
];

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

        let branch: u8 = random_switcher as u8;
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

        let opcode = BRANCH_TABLE[branch as usize];
        if branch == 254 || branch == 255 {

            // Use a new key.
            rc4 = Rc4::new(&data.into());
        }
        for i in pos1..pos2 {
            let mut tmp = data[i as usize];
            for j in (0..=3).rev() {
                let op = (opcode >> (j * 8)) & 0xFF;
                match op {
                    0x00 => {
                        tmp = tmp.wrapping_add(tmp);                           // +
                    }
                    0x01 => {
                        tmp = tmp.wrapping_sub(tmp ^ 97);                      // XOR and -
                    }
                    0x02 => {
                        tmp = tmp.wrapping_mul(tmp);                           // *
                    }
                    0x03 => {
                        tmp = tmp ^ data[pos2 as usize];                       // XOR
                    }
                    0x04 => {
                        tmp = !tmp;                                            // binary NOT operator
                    }
                    0x05 => {
                        tmp = tmp & data[pos2 as usize];                       // AND
                    }
                    0x06 => {
                        tmp = tmp.wrapping_shl((tmp & 3) as u32);              // shift left
                    }
                    0x07 => {
                        tmp = tmp.wrapping_shr((tmp & 3) as u32);              // shift right
                    }
                    0x08 => {
                        tmp = tmp.reverse_bits();                              // reverse bits
                    }
                    0x09 => {
                        tmp = tmp ^ tmp.count_ones() as u8;                    // ones count bits
                    }
                    0x0A => {
                        tmp = tmp.rotate_left(tmp as u32);                     // rotate bits by random
                    }
                    0x0B => {
                        tmp = tmp.rotate_left(1);                              // rotate bits by 1
                    }
                    0x0C => {
                        tmp = tmp ^ tmp.rotate_left(2);                        // rotate bits by 2
                    }
                    0x0D => {
                        tmp = tmp.rotate_left(3);                              // rotate bits by 3
                    }
                    0x0E => {
                        tmp = tmp ^ tmp.rotate_left(4);                        // rotate bits by 4
                    }
                    0x0F => {
                        tmp = tmp.rotate_left(5);                              // rotate bits by 5
                    }
                    _ => {
                        unreachable!();
                    }
                }

            }
            data[i as usize] = tmp;
            if branch == 0 {
                if (pos2 - pos1) % 2 == 1 {

                    // Reverse.
                    data[pos1 as usize] = data[pos1 as usize].reverse_bits();
                    data[pos2 as usize] = data[pos2 as usize].reverse_bits();
                    data.swap(pos1 as usize, pos2 as usize);
                }
            }
            if branch == 253 {

                // More deviations.
                prev_lhash = prev_lhash.wrapping_add(lhash);
                lhash = xxh64_calc(&data[..pos2 as usize]);
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
    let scratch_sa = SuffixArray::new(&scratch_data[..data_len as usize]);
    let mut scratch_sa_bytes: Vec<u8> = vec![];
    for vector in &scratch_sa.into_parts().1[1..(data_len as usize + 1)] {

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

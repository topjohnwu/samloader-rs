// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use rand::RngExt;

fn luhn_checksum(imei_prefix: &str) -> u32 {
    let mut sum = 0;
    let parity = (imei_prefix.len() + 1) % 2;
    for (i, c) in imei_prefix.chars().enumerate() {
        let mut d = c.to_digit(10).unwrap();
        if i % 2 == parity {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    (10 - (sum % 10)) % 10
}

pub fn generate_random_imei(tac: &str) -> String {
    if tac.len() == 15 {
        return tac.to_string();
    }
    if tac.len() != 8 {
        panic!("Invalid TAC length");
    }

    let mut rng = rand::rng();
    let r1 = [0, 5, 7][rng.random_range(0..3)];
    let r2 = rng.random_range(4..=9);
    let r3 = [0, 1, 3, 5, 6, 7][rng.random_range(0..6)];
    let r4 = rng.random_range(0..=9);
    let r56 = rng.random_range(0..100);

    let tac_rng = format!("{}{}{}{}{}{:02}", tac, r1, r2, r3, r4, r56);
    let check = luhn_checksum(&tac_rng);
    format!("{}{}", tac_rng, check)
}

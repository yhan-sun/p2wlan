//! Systematic Cauchy Reed–Solomon over GF(256), using x^8 + x^4 + x^3 + x^2 + 1.
use super::wire::{DATA, MAX_PARITY};

const fn multiply(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        let high = a & 0x80 != 0;
        a <<= 1;
        if high {
            a ^= 0x1d;
        }
        b >>= 1;
    }
    product
}

const fn inverse(value: u8) -> u8 {
    let mut power = value;
    let mut exponent = 254;
    let mut result = 1;
    while exponent > 0 {
        if exponent & 1 != 0 {
            result = multiply(result, power);
        }
        power = multiply(power, power);
        exponent >>= 1;
    }
    result
}

fn coefficient(rows: usize, row: usize, column: usize) -> u8 {
    if rows == 1 {
        1
    } else {
        COEFFICIENTS[row][column]
    }
}

const COEFFICIENTS: [[u8; DATA]; MAX_PARITY] = cauchy();

const fn cauchy() -> [[u8; DATA]; MAX_PARITY] {
    // The row and column point sets are disjoint. Every square submatrix
    // of this parity matrix can be inverted, including mixed data/parity loss.
    let mut result = [[0; DATA]; MAX_PARITY];
    let mut row = 0;
    while row < MAX_PARITY {
        let mut column = 0;
        while column < DATA {
            result[row][column] = inverse(row as u8 ^ (16 + column as u8));
            column += 1;
        }
        row += 1;
    }
    result
}

const fn multiplication_row(factor: u8) -> [u8; 256] {
    let mut table = [0; 256];
    let mut value = 0;
    while value < 256 {
        table[value] = multiply(factor, value as u8);
        value += 1;
    }
    table
}

static SCALERS: [[[u8; 256]; DATA]; MAX_PARITY] = {
    let mut tables = [[[0; 256]; DATA]; MAX_PARITY];
    let mut row = 0;
    while row < MAX_PARITY {
        let mut column = 0;
        while column < DATA {
            tables[row][column] = multiplication_row(COEFFICIENTS[row][column]);
            column += 1;
        }
        row += 1;
    }
    tables
};

// Sources can end before the parity width. Missing suffix bytes are zero.
pub(super) fn accumulate(rows: usize, row: usize, column: usize, input: &[u8], target: &mut [u8]) {
    if rows == 1 {
        for (place, byte) in target.iter_mut().zip(input) {
            *place ^= byte;
        }
    } else {
        let table = &SCALERS[row][column];
        for (place, byte) in target.iter_mut().zip(input) {
            *place ^= table[usize::from(*byte)];
        }
    }
}

pub(super) fn restore(
    rows: usize,
    data: [Option<&[u8]>; DATA],
    parity: [Option<Vec<u8>>; MAX_PARITY],
    width: usize,
) -> [Option<Vec<u8>>; DATA] {
    let mut absent = [0; MAX_PARITY];
    let mut count = 0;
    for (index, shard) in data.iter().enumerate() {
        if shard.is_none() {
            if count == rows {
                return std::array::from_fn(|_| None);
            }
            absent[count] = index;
            count += 1;
        }
    }

    let mut reduced = [[0u8; 2 * MAX_PARITY]; MAX_PARITY];
    let mut residual: [Option<Vec<u8>>; MAX_PARITY] = std::array::from_fn(|_| None);
    let mut collected = 0;
    for (index, share) in parity.into_iter().enumerate() {
        if collected == count {
            break;
        }
        let Some(mut rhs) = share else { continue };
        for (column, known) in data.into_iter().enumerate() {
            if let Some(shard) = known {
                accumulate(rows, index, column, shard, &mut rhs);
            }
        }
        for (place, column) in reduced[collected].iter_mut().zip(&absent[..count]) {
            *place = coefficient(rows, index, *column);
        }
        reduced[collected][count + collected] = 1;
        residual[collected] = Some(rhs);
        collected += 1;
    }

    let mut output = std::array::from_fn(|_| None);
    if collected != count || !invert(&mut reduced, count) {
        return output;
    }
    for (index, original) in absent[..count].iter().copied().enumerate() {
        let mut restored = vec![0; width];
        for (factor, source) in reduced[index][count..2 * count].iter().zip(&residual) {
            let Some(source) = source.as_ref() else {
                continue;
            };
            let table = multiplication_row(*factor);
            for (place, byte) in restored.iter_mut().zip(source) {
                *place ^= table[usize::from(*byte)];
            }
        }
        output[original] = Some(restored);
    }
    output
}

fn invert(matrix: &mut [[u8; 2 * MAX_PARITY]; MAX_PARITY], size: usize) -> bool {
    for column in 0..size {
        let Some(pivot) = (column..size).find(|&row| matrix[row][column] != 0) else {
            return false;
        };
        matrix.swap(pivot, column);
        let scale = inverse(matrix[column][column]);
        for value in &mut matrix[column][..2 * size] {
            *value = multiply(*value, scale);
        }
        let pivot = matrix[column];
        for (index, row) in matrix[..size].iter_mut().enumerate() {
            if index == column {
                continue;
            }
            let factor = row[column];
            for (value, base) in row[..2 * size].iter_mut().zip(pivot) {
                *value ^= multiply(factor, base);
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_correctable_data_and_parity_erasure_restores_variable_lengths() {
        const WIDTH: usize = 121;
        let data: [Vec<u8>; DATA] = std::array::from_fn(|column| {
            (0..WIDTH - column * 3)
                .map(|index| ((index * 79 + column * 31) % 251) as u8)
                .collect()
        });
        for rows in [1, MAX_PARITY] {
            let stripes: [Vec<u8>; MAX_PARITY] = std::array::from_fn(|row| {
                let mut parity = vec![0; WIDTH];
                if row < rows {
                    for (column, shard) in data.iter().enumerate() {
                        accumulate(rows, row, column, shard, &mut parity);
                    }
                }
                parity
            });
            for mask in 1u32..(1 << (DATA + rows)) {
                if mask.count_ones() as usize > rows {
                    continue;
                }
                let survivors = std::array::from_fn(|column| {
                    (mask & (1 << column) == 0).then(|| data[column].as_slice())
                });
                let parity = std::array::from_fn(|row| {
                    (row < rows && mask & (1 << (DATA + row)) == 0).then(|| stripes[row].clone())
                });
                let restored = restore(rows, survivors, parity, WIDTH);
                for (column, shard) in restored.into_iter().enumerate() {
                    if mask & (1 << column) == 0 {
                        assert!(shard.is_none());
                    } else {
                        let shard = shard.unwrap();
                        let size = data[column].len();
                        assert_eq!(&shard[..size], &data[column]);
                        assert!(shard[size..].iter().all(|&byte| byte == 0));
                    }
                }
            }
        }
    }
}

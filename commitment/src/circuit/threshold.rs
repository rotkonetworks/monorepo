//! Threshold signature verification circuit.
//!
//! Proves that at least `threshold` out of `n` validators signed a
//! message. The polynomial encodes signature bits and a binary adder
//! tree constrains the popcount.
//!
//! # Why not pure sumcheck?
//!
//! In GF(2^k), addition is XOR: 1+1=0. So `Σ W(x)` over the boolean
//! hypercube gives the *parity* of set bits, not the *count*. Integer
//! popcount requires carry propagation, which means circuit constraints
//! (the adder tree). The accidental computer still helps because the
//! DA encoding provides the polynomial commitment for free — the adder
//! tree is only the marginal cost on top.
//!
//! Over a large-characteristic field (e.g. Goldilocks, BN254 scalar
//! field) where char > n, field addition IS integer addition for small
//! values and `Σ W(x) = count` would work directly via sumcheck — no
//! adder tree needed. The binary field choice (GF(2^32)/GF(2^128)) is
//! driven by the fast additive FFT and efficient DA encoding in the
//! Ligerito/ZODA stack.
//!
//! # GKR optimization (future work)
//!
//! The binary adder tree is a layered arithmetic circuit. The GKR
//! protocol (Goldwasser-Kalai-Rothblum 2008) can verify layered
//! circuits via one sumcheck per layer, reducing to a single polynomial
//! evaluation at the input layer. The Accidental Computer paper
//! (Evans-Angeris 2025, §3-4) shows this evaluation is exactly what
//! the ZODA partial evaluation provides for free:
//!
//! > "The GKR protocol reduces verifying C(X̃) = z to verifying a
//! >  multilinear polynomial evaluation [...] This is exactly what
//! >  the ZODA sampler already computes."
//! >  — The Accidental Computer, §3
//!
//! A GKR-based threshold proof would:
//! 1. Express the adder tree as a layered circuit (same structure)
//! 2. Run GKR sumcheck layer-by-layer from output to input
//! 3. Reduce to a single claim W(r) at the input layer
//! 4. Verify W(r) via the DA encoding's partial evaluation — free
//!
//! For the threshold circuit (depth O(log n), width O(n)), GKR gives
//! the same O(n) prover work but better composability with other
//! GKR-verified computations. See Thaler, "Proofs, Arguments, and
//! Zero-Knowledge" §4.6 for the GKR-sumcheck connection.
//!
//! # Soundness
//!
//! 1. Each signature bit ∈ {0,1}: `bit·(bit+1) = 0` in GF(2^32).
//!    Sound because GF(2^32) is a field (no zero divisors).
//!
//! 2. Popcount computed by binary adder tree (half-adders + full-adders)
//!    with all intermediate wires constrained. Malicious prover cannot
//!    claim a count different from the actual popcount.
//!
//! 3. `count ≥ threshold` via bit decomposition of `count - threshold`.
//!
//! # Witness layout
//!
//! - Wire 0: count (public)
//! - Wire 1: threshold (public)
//! - Wire 2: difference = count - threshold (public, ≥ 0)
//! - Wires 3..n+3: signature bits (private)
//! - Remaining: adder intermediates + difference bit decomposition

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use super::constraint::{CircuitBuilder, Constraint, Operand, Witness, WireId};

/// Wire layout for the threshold circuit.
pub struct ThresholdWires {
    pub sig_bits: Vec<WireId>,
    pub count: WireId,
    pub threshold: WireId,
    pub difference: WireId,
    adder_ops: Vec<AdderOp>,
    popcount_bits: Vec<WireId>,
    diff_bits: Vec<WireId>,
}

#[derive(Clone)]
enum AdderOp {
    Half { a: WireId, b: WireId, sum: WireId, carry: WireId },
    Full { a: WireId, b: WireId, cin: WireId, sum: WireId, cout: WireId, s1: WireId, c1: WireId, c2: WireId },
}

fn add_bits(builder: &mut CircuitBuilder, a: WireId, b: WireId) -> (WireId, WireId, AdderOp) {
    let sum = builder.add_witness();
    let carry = builder.add_witness();
    builder.assert_xor(Operand::new().with_wire(a), Operand::new().with_wire(b), Operand::new().with_wire(sum));
    builder.assert_and(Operand::new().with_wire(a), Operand::new().with_wire(b), Operand::new().with_wire(carry));
    (sum, carry, AdderOp::Half { a, b, sum, carry })
}

fn full_adder(builder: &mut CircuitBuilder, a: WireId, b: WireId, cin: WireId) -> (WireId, WireId, AdderOp) {
    let s1 = builder.add_witness();
    let c1 = builder.add_witness();
    let sum = builder.add_witness();
    let c2 = builder.add_witness();
    let cout = builder.add_witness();
    builder.assert_xor(Operand::new().with_wire(a), Operand::new().with_wire(b), Operand::new().with_wire(s1));
    builder.assert_and(Operand::new().with_wire(a), Operand::new().with_wire(b), Operand::new().with_wire(c1));
    builder.assert_xor(Operand::new().with_wire(s1), Operand::new().with_wire(cin), Operand::new().with_wire(sum));
    builder.assert_and(Operand::new().with_wire(s1), Operand::new().with_wire(cin), Operand::new().with_wire(c2));
    builder.assert_xor(Operand::new().with_wire(c1), Operand::new().with_wire(c2), Operand::new().with_wire(cout));
    (sum, cout, AdderOp::Full { a, b, cin, sum, cout, s1, c1, c2 })
}

fn add_multi_bit(builder: &mut CircuitBuilder, a_bits: &[WireId], b_bits: &[WireId], ops: &mut Vec<AdderOp>) -> Vec<WireId> {
    let n = a_bits.len().max(b_bits.len());
    let mut result = Vec::with_capacity(n + 1);
    let mut carry: Option<WireId> = None;
    for i in 0..n {
        let aw = if i < a_bits.len() { a_bits[i] } else { let z = builder.add_witness(); builder.assert_const(z, 0); z };
        let bw = if i < b_bits.len() { b_bits[i] } else { let z = builder.add_witness(); builder.assert_const(z, 0); z };
        match carry {
            None => { let (s, c, op) = add_bits(builder, aw, bw); ops.push(op); result.push(s); carry = Some(c); }
            Some(cin) => { let (s, c, op) = full_adder(builder, aw, bw, cin); ops.push(op); result.push(s); carry = Some(c); }
        }
    }
    if let Some(c) = carry { result.push(c); }
    result
}

fn popcount_tree(builder: &mut CircuitBuilder, bits: &[WireId], ops: &mut Vec<AdderOp>) -> Vec<WireId> {
    if bits.is_empty() { return vec![]; }
    if bits.len() == 1 { return vec![bits[0]]; }
    let mut numbers: Vec<Vec<WireId>> = bits.iter().map(|&b| vec![b]).collect();
    while numbers.len() > 1 {
        let mut next = Vec::with_capacity((numbers.len() + 1) / 2);
        let mut i = 0;
        while i + 1 < numbers.len() {
            let sum = add_multi_bit(builder, &numbers[i], &numbers[i + 1], ops);
            next.push(sum); i += 2;
        }
        if i < numbers.len() { next.push(numbers[i].clone()); }
        numbers = next;
    }
    numbers.into_iter().next().unwrap_or_default()
}

/// Build a threshold circuit for `n` validators.
pub fn build_threshold_circuit(n: usize) -> (super::constraint::Circuit, ThresholdWires) {
    let mut builder = CircuitBuilder::new();
    let count_bits_needed = ((n + 1) as f64).log2().ceil() as usize + 1;

    let count = builder.add_public();
    let threshold = builder.add_public();
    let difference = builder.add_public();
    let sig_bits: Vec<WireId> = (0..n).map(|_| builder.add_witness()).collect();

    // Boolean: bit·(bit+1) = 0 via FieldMul(bit, bit, bit).
    for &bit in &sig_bits {
        builder.add_constraint(Constraint::FieldMul { a: bit, b: bit, result: bit });
    }

    // Popcount via adder tree.
    let mut adder_ops = Vec::new();
    let popcount_bits = popcount_tree(&mut builder, &sig_bits, &mut adder_ops);
    builder.add_constraint(Constraint::RangeDecomposed { wire: count, bits: popcount_bits.clone() });

    // Difference bit decomposition (proves count - threshold ≥ 0).
    let diff_bits: Vec<WireId> = (0..count_bits_needed).map(|_| builder.add_witness()).collect();
    for &bit in &diff_bits { builder.add_constraint(Constraint::FieldMul { a: bit, b: bit, result: bit }); }
    builder.add_constraint(Constraint::RangeDecomposed { wire: difference, bits: diff_bits.clone() });

    (builder.build(), ThresholdWires { sig_bits, count, threshold, difference, adder_ops, popcount_bits, diff_bits })
}

/// Populate witness, replaying adder tree for intermediate values.
pub fn build_threshold_witness(wires: &ThresholdWires, signatures: &[bool], threshold: u64) -> Witness {
    let n = wires.sig_bits.len();
    assert_eq!(signatures.len(), n);
    let count: u64 = signatures.iter().filter(|&&s| s).count() as u64;
    let diff = count.saturating_sub(threshold);

    let max_wire = [wires.count.0, wires.threshold.0, wires.difference.0].iter().copied()
        .chain(wires.sig_bits.iter().map(|w| w.0))
        .chain(wires.popcount_bits.iter().map(|w| w.0))
        .chain(wires.diff_bits.iter().map(|w| w.0))
        .chain(wires.adder_ops.iter().flat_map(|op| match op {
            AdderOp::Half { sum, carry, .. } => vec![sum.0, carry.0],
            AdderOp::Full { sum, cout, s1, c1, c2, .. } => vec![sum.0, cout.0, s1.0, c1.0, c2.0],
        }))
        .max().unwrap_or(0) + 1;

    let mut witness = Witness::new(max_wire, 3);
    witness.set(wires.count, count);
    witness.set(wires.threshold, threshold);
    witness.set(wires.difference, diff);
    for (i, &signed) in signatures.iter().enumerate() { witness.set(wires.sig_bits[i], if signed { 1 } else { 0 }); }

    // Replay adder tree.
    for op in &wires.adder_ops {
        match op {
            AdderOp::Half { a, b, sum, carry } => {
                let (va, vb) = (witness.get(*a), witness.get(*b));
                witness.set(*sum, va ^ vb); witness.set(*carry, va & vb);
            }
            AdderOp::Full { a, b, cin, sum, cout, s1, c1, c2 } => {
                let (va, vb, vc) = (witness.get(*a), witness.get(*b), witness.get(*cin));
                let vs1 = va ^ vb; let vc1 = va & vb;
                let vsum = vs1 ^ vc; let vc2 = vs1 & vc;
                witness.set(*s1, vs1); witness.set(*c1, vc1);
                witness.set(*sum, vsum); witness.set(*c2, vc2); witness.set(*cout, vc1 ^ vc2);
            }
        }
    }
    for (j, &bw) in wires.diff_bits.iter().enumerate() { witness.set(bw, (diff >> j) & 1); }
    witness
}

/// Light client threshold check.
pub fn verify_threshold(public_inputs: &[u32], expected_threshold: u32) -> bool {
    if public_inputs.len() < 3 { return false; }
    let (count, threshold, difference) = (public_inputs[0], public_inputs[1], public_inputs[2]);
    count >= threshold && threshold >= expected_threshold && count == threshold.wrapping_add(difference)
}

pub fn check_threshold(count: u32, threshold: u32, expected: u32) -> bool {
    count >= threshold && threshold >= expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_satisfied() {
        let n = 10;
        let (circuit, wires) = build_threshold_circuit(n);
        let sigs = vec![true, true, false, true, true, true, false, true, false, true];
        let witness = build_threshold_witness(&wires, &sigs, 6);
        assert!(circuit.check(&witness.values).is_ok());
    }

    #[test]
    fn test_malicious_count_rejected() {
        let n = 4;
        let (circuit, wires) = build_threshold_circuit(n);
        let sigs = vec![true, false, true, false];
        let mut witness = build_threshold_witness(&wires, &sigs, 1);
        witness.set(wires.count, 4); // lie about count
        witness.set(wires.difference, 3);
        assert!(circuit.check(&witness.values).is_err());
    }

    #[test]
    fn test_boolean_violation() {
        let n = 4;
        let (circuit, wires) = build_threshold_circuit(n);
        let sigs = vec![true, true, false, true];
        let mut witness = build_threshold_witness(&wires, &sigs, 2);
        witness.set(wires.sig_bits[0], 2); // not boolean
        assert!(circuit.check(&witness.values).is_err());
    }

    #[test]
    fn test_exact_threshold() {
        let n = 5;
        let (circuit, wires) = build_threshold_circuit(n);
        let sigs = vec![true, false, true, true, false];
        let witness = build_threshold_witness(&wires, &sigs, 3);
        assert!(circuit.check(&witness.values).is_ok());
        assert!(verify_threshold(&[3, 3, 0], 3));
    }

    #[test]
    fn test_below_threshold() {
        assert!(!verify_threshold(&[2, 3, 0], 3));
    }

    #[test]
    fn test_verify_public() {
        assert!(verify_threshold(&[7, 6, 1], 6));
        assert!(verify_threshold(&[6, 6, 0], 6));
        assert!(!verify_threshold(&[5, 6, 0], 6));
        assert!(!verify_threshold(&[7, 4, 3], 6));
    }

    #[test]
    fn test_prove_verify_e2e() {
        let n = 8;
        let (circuit, wires) = build_threshold_circuit(n);
        let sigs = vec![true, true, true, false, true, false, true, true];
        let witness = build_threshold_witness(&wires, &sigs, 5);
        assert!(circuit.check(&witness.values).is_ok());
        // Public inputs: count=6, threshold=5, difference=1.
        assert!(verify_threshold(&[6, 5, 1], 5));
    }
}

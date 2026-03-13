mod common;

use std::time::Instant;

use ark_bn254::Fr;
use toy_zkvm::{
    backend::{FriOptions, Transcript},
    test_utils::{pick_coset_shift, pick_domain},
    vm::VmAir,
    zkvm::{ZkvmPublicParameters, prove, verify},
};

use crate::common::{assert_trace_satisfies_air, run_program_to_trace};

#[test]
fn prove_and_verify_const_halt_vm_trace() {
    let source = r#"
        const r0, 7
        halt
    "#;

    let trace = run_program_to_trace(source, 16, 16);
    let air = VmAir::<Fr>::default();
    assert_trace_satisfies_air(&trace, &air);

    let blowup = 16usize;
    let lde_size = trace.n() * blowup;
    let shift = pick_coset_shift(lde_size);
    let trace_domain = pick_domain(trace.n());
    let lde_domain = pick_domain(lde_size);

    let public_params = ZkvmPublicParameters {
        trace_domain,
        lde_domain,
        shift,
        fri_options: FriOptions {
            max_degree: trace.n() * 2,
            max_remainder_degree: 1,
            query_number: 64,
            shift,
        },
    };

    let label = b"transcript";
    let seed = b"vm_const_halt";

    let mut prover_tx = Transcript::new(label, seed);
    let proof = prove(&trace, &air, &mut prover_tx, &public_params)
        .expect("proof generation should succeed");

    let mut verifier_tx = Transcript::new(label, seed);
    verify(&proof, &air, &mut verifier_tx, &public_params).expect("verification should succeed");
}

#[test]
fn prove_and_verify_fibonacci_vm_trace_with_current_air() {
    let source = r#"
        const r0, 0
        const r1, 1
        const r3, 20

        loop:
        mov r2, r1
        add r1, r0
        mov r0, r2
        const r2, 1
        sub r3, r2
        jnz r3, loop
        halt
    "#;

    let trace = run_program_to_trace(source, 128, 128);
    let air = VmAir::<Fr>::default();

    let blowup = 16usize;
    let lde_size = trace.n() * blowup;
    let shift = pick_coset_shift(lde_size);
    let trace_domain = pick_domain(trace.n());
    let lde_domain = pick_domain(lde_size);

    let public_params = ZkvmPublicParameters {
        trace_domain,
        lde_domain,
        shift,
        fri_options: FriOptions {
            max_degree: trace.n() * 2,
            max_remainder_degree: 1,
            query_number: 64,
            shift,
        },
    };

    let label = b"transcript";
    let seed = b"vm_fibonacci_current_air";

    let mut prover_tx = Transcript::new(label, seed);
    let prove_start = Instant::now();
    let proof = prove(&trace, &air, &mut prover_tx, &public_params)
        .expect("proof generation should succeed");
    let prove_duration = prove_start.elapsed();

    let verify_start = Instant::now();
    let mut verifier_tx = Transcript::new(label, seed);

    verify(&proof, &air, &mut verifier_tx, &public_params).expect("verification should succeed");

    let verify_duration = verify_start.elapsed();

    println!("prove time:  {:?}", prove_duration);
    println!("verify time: {:?}", verify_duration);
}

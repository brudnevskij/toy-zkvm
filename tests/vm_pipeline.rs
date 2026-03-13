use ark_bn254::Fr;
use ark_ff::{One, Zero};
use thiserror::Error;
use toy_zkvm::{
    dsl::{CompileError, ResolveError, compile},
    vm::{ExecutionRow, VmError, VmState, rows_to_trace_table, run_rows},
};

#[derive(Error, Debug)]
pub enum PipelineError {
    #[error("compile error: {0}")]
    Compile(#[from] CompileError),

    #[error("vm error: {0}")]
    Vm(#[from] VmError),
}

fn run_program_text(
    source: &str,
    trace_len: usize,
    max_steps: usize,
) -> Result<Vec<ExecutionRow<Fr>>, PipelineError> {
    let program = compile(source)?;

    let initial_state = VmState {
        pc: 0,
        regs: [Fr::zero(); 4],
        halted: false,
    };
    let rows = run_rows(initial_state, &program, trace_len, max_steps)?;
    Ok(rows)
}

fn fr(x: u64) -> Fr {
    Fr::from(x)
}

#[test]
fn const_then_halt_pipeline_runs() {
    let source = r#"
        const r0, 7
        halt
    "#;

    let rows = run_program_text(source, 4, 8).unwrap();

    assert_eq!(rows.len(), 4);

    // row 0 = before executing const r0 7
    assert_eq!(rows[0].pc, fr(0));
    assert_eq!(rows[0].regs[0], fr(0));
    assert_eq!(rows[0].halted, Fr::zero());
    assert_eq!(rows[0].s_const, Fr::one());
    assert_eq!(rows[0].a, fr(0));
    assert_eq!(rows[0].imm, fr(7));

    // row 1 = before executing halt, after const already applied
    assert_eq!(rows[1].pc, fr(1));
    assert_eq!(rows[1].regs[0], fr(7));
    assert_eq!(rows[1].halted, Fr::zero());
    assert_eq!(rows[1].s_halt, Fr::one());

    // padded halted rows
    assert_eq!(rows[2].pc, fr(1));
    assert_eq!(rows[2].regs[0], fr(7));
    assert_eq!(rows[2].halted, Fr::one());
    assert_eq!(rows[2].s_halt, Fr::one());

    assert_eq!(rows[3].pc, fr(1));
    assert_eq!(rows[3].regs[0], fr(7));
    assert_eq!(rows[3].halted, Fr::one());
    assert_eq!(rows[3].s_halt, Fr::one());
}

#[test]
fn add_pipeline_updates_register() {
    let source = r#"
        const r0, 2
        const r1, 3
        add r0, r1
        halt
    "#;

    let rows = run_program_text(source, 8, 16).unwrap();

    assert_eq!(rows[0].pc, fr(0));
    assert_eq!(rows[0].s_const, Fr::one());
    assert_eq!(rows[0].a, fr(0));
    assert_eq!(rows[0].imm, fr(2));

    assert_eq!(rows[1].pc, fr(1));
    assert_eq!(rows[1].regs[0], fr(2));
    assert_eq!(rows[1].s_const, Fr::one());
    assert_eq!(rows[1].a, fr(1));
    assert_eq!(rows[1].imm, fr(3));

    assert_eq!(rows[2].pc, fr(2));
    assert_eq!(rows[2].regs[0], fr(2));
    assert_eq!(rows[2].regs[1], fr(3));
    assert_eq!(rows[2].s_add, Fr::one());
    assert_eq!(rows[2].a, fr(0));
    assert_eq!(rows[2].b, fr(1));

    // halt row sees updated r0 = 5
    assert_eq!(rows[3].pc, fr(3));
    assert_eq!(rows[3].regs[0], fr(5));
    assert_eq!(rows[3].regs[1], fr(3));
    assert_eq!(rows[3].s_halt, Fr::one());
}

#[test]
fn mov_pipeline_copies_register() {
    let source = r#"
        const r1, 9
        mov r0, r1
        halt
    "#;

    let rows = run_program_text(source, 4, 8).unwrap();

    assert_eq!(rows[0].s_const, Fr::one());
    assert_eq!(rows[1].s_mov, Fr::one());

    // before mov: r1 already set, r0 still zero
    assert_eq!(rows[1].regs[0], fr(0));
    assert_eq!(rows[1].regs[1], fr(9));
    assert_eq!(rows[1].a, fr(0));
    assert_eq!(rows[1].b, fr(1));

    // halt row sees copied value
    assert_eq!(rows[2].s_halt, Fr::one());
    assert_eq!(rows[2].regs[0], fr(9));
    assert_eq!(rows[2].regs[1], fr(9));
}

#[test]
fn jmp_pipeline_skips_instruction() {
    let source = r#"
        jmp end
        const r0, 99
        end:
        halt
    "#;

    let rows = run_program_text(source, 8, 8).unwrap();

    // row 0 executes jmp
    assert_eq!(rows[0].pc, fr(0));
    assert_eq!(rows[0].s_jmp, Fr::one());

    // next executed instruction should be halt at pc = 2
    assert_eq!(rows[1].pc, fr(2));
    assert_eq!(rows[1].s_halt, Fr::one());

    // r0 was never set
    assert_eq!(rows[1].regs[0], fr(0));
    assert_eq!(rows[2].regs[0], fr(0));
}

#[test]
fn jnz_taken_pipeline_jumps() {
    let source = r#"
        const r0, 1
        jnz r0, target
        const r1, 99
        target:
        halt
    "#;

    let rows = run_program_text(source, 8, 12).unwrap();

    assert_eq!(rows[0].s_const, Fr::one());
    assert_eq!(rows[1].s_jnz, Fr::one());

    // jnz sees r0 = 1, so it should jump to halt and skip const r1 99
    assert_eq!(rows[1].regs[0], fr(1));
    assert_eq!(rows[2].s_halt, Fr::one());
    assert_eq!(rows[2].regs[1], fr(0));
}

#[test]
fn jnz_not_taken_pipeline_falls_through() {
    let source = r#"
        jnz r0, target
        const r1, 5
        target:
        halt
    "#;

    let rows = run_program_text(source, 8, 12).unwrap();

    // r0 starts as zero, so branch is not taken
    assert_eq!(rows[0].pc, fr(0));
    assert_eq!(rows[0].s_jnz, Fr::one());
    assert_eq!(rows[0].regs[0], fr(0));

    // falls through to const r1 5
    assert_eq!(rows[1].pc, fr(1));
    assert_eq!(rows[1].s_const, Fr::one());
    assert_eq!(rows[1].a, fr(1));
    assert_eq!(rows[1].imm, fr(5));

    // halt sees updated r1
    assert_eq!(rows[2].pc, fr(2));
    assert_eq!(rows[2].s_halt, Fr::one());
    assert_eq!(rows[2].regs[1], fr(5));
}

#[test]
fn compile_error_for_missing_label() {
    let source = r#"
        jmp nowhere
        halt
    "#;

    let err = run_program_text(source, 4, 8).unwrap_err();

    match err {
        PipelineError::Compile(CompileError::Resolve(ResolveError::MissingLabel { .. })) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn vm_error_for_step_limit_exceeded() {
    let source = r#"
        loop:
        jmp loop
    "#;

    let err = run_program_text(source, 16, 3).unwrap_err();

    match err {
        PipelineError::Vm(VmError::StepLimitExceeded { .. }) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

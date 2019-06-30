use circom2_compiler::algebra::{Value, FS, LC};
use circom2_compiler::evaluator::{Evaluator,check_constrains_eval_zero};
use circom2_compiler::storage;
use circom2_compiler::storage::{Constraints, Signals};
use circom2_parser::ast::SignalType;

use std::io::{Read, Write};
use std::marker::PhantomData;

use pairing::bn256::{Bn256, Fr};
use pairing::Engine;

use bellman::{Circuit, ConstraintSystem, LinearCombination, SynthesisError};
use bellman::groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof, Proof,
};

use ff::PrimeField;

use rand::thread_rng;

use super::error::Result;
use super::ethereum;
use super::format;

pub struct CircomCircuit<'a, E: Engine> {
    constraints: &'a Constraints,
    signals: &'a Signals,
    phantom: PhantomData<E>,
}

impl<'a, E: Engine> CircomCircuit<'a, E> {}

fn value_to_bellman<E: Engine>(value: &Value) -> E::Fr {
    match value {
        Value::FieldScalar(fs) => fe_to_bellman::<E>(fs),
        _ => panic!("Invalid signal value"),
    }
}

fn fe_to_bellman<E: Engine>(fe: &FS) -> E::Fr {
    E::Fr::from_str(&fe.0.to_str_radix(10)).unwrap()
}

fn lc_to_bellman<E: Engine>(
    mut base: LinearCombination<E>,
    signals: &[bellman::Variable],
    lc: &LC,
) -> LinearCombination<E> {
    use std::ops::Add;
    for (s, v) in &lc.0 {
        base = base.add((fe_to_bellman::<E>(&v), signals[*s]));
    }
    base
}

fn map_storage_error<V>(
    e: std::result::Result<V, storage::Error>,
) -> std::result::Result<V, SynthesisError> {
    match e {
        Ok(v) => Ok(v),
        _ => Err(SynthesisError::Unsatisfiable),
    }
}

fn is_public_input(signal: &circom2_compiler::storage::Signal) -> bool {
    let component_len = signal.full_name.0.chars().filter(|ch| *ch == '.').count();
    component_len == 1
        && (signal.xtype == SignalType::Output || signal.xtype == SignalType::PublicInput)
}

impl<'a, E: Engine> Circuit<E> for CircomCircuit<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS,
    ) -> std::result::Result<(), SynthesisError> {
        let mut signals = Vec::new();
        signals.push(CS::one());

        // register signals
        for n in 1..map_storage_error(self.signals.len())? {
            let s = map_storage_error(self.signals.get_by_id(n))?.unwrap();
            let signal = if is_public_input(&s) {
                cs.alloc_input(
                    || (*s.full_name.0).clone(),
                    || {
                        s.value
                            .clone()
                            .map(|vv| value_to_bellman::<E>(&vv))
                            .ok_or(SynthesisError::AssignmentMissing)
                    },
                )?
            } else {
                cs.alloc(
                    || (*s.full_name.0).clone(),
                    || {
                        s.value
                            .clone()
                            .map(|vv| value_to_bellman::<E>(&vv))
                            .ok_or(SynthesisError::AssignmentMissing)
                    },
                )?
            };
            signals.push(signal);
        }

        // register constrains
        for n in 0..map_storage_error(self.constraints.len())? {
            let constraint = map_storage_error(self.constraints.get(n))?;
            let name = format!("c{}", n);
            cs.enforce(
                || name,
                |lc| lc_to_bellman(lc, &signals, &constraint.a),
                |lc| lc_to_bellman(lc, &signals, &constraint.b),
                |lc| lc_to_bellman(lc, &signals, &-&constraint.c),
            );
        }
        Ok(())
    }
}

pub fn setup<S: Signals, C: Constraints, WP: Write, WV: Write>(
    eval: &Evaluator<S, C>,
    out_pk: WP,
    mut out_vk: WV,
) -> Result<()> {
    let rng = &mut thread_rng();
    let circuit = CircomCircuit::<Bn256> {
        signals: &eval.signals,
        constraints: &eval.constraints,
        phantom: PhantomData,
    };

    // perform setup
    let params = generate_random_parameters(circuit, rng)?;

    format::write_pk(out_pk, &eval.constraints, &params)?;
    ethereum::generate_solidity(&params.vk, &mut out_vk)?;

    Ok(())
}

pub fn proof<S: Signals, R: Read, W: Write>(
    signals: S,
    in_pk: R,
    out_proof: &mut W
) -> Result<Vec<(String,FS)>> {

    let rng = &mut thread_rng();

    let (constraints, params) = format::read_pk(in_pk)?;

    check_constrains_eval_zero(&constraints,&signals)
        .expect("check_constrains_eval_zero failed");

    let circuit = CircomCircuit::<Bn256> {
        signals: &signals,
        constraints: &constraints,
        phantom: PhantomData,
    };

    // Create proof
    let proof = create_random_proof(circuit, &params, rng).expect("cannot create proof");
    format::write_proof(proof, out_proof)?;

    let mut public_inputs = Vec::new();
    for i in 0..signals.len()? {
        let signal = signals.get_by_id(i)?.unwrap();
        if is_public_input(&signal) {
            let fs = (&*signal).clone().value.unwrap().try_into_fs().unwrap();
            let name = signal.full_name.0.to_string();
            public_inputs.push((name,fs));
        }
    }

    Ok(public_inputs)
}

pub fn verify<RPK: Read, RPR: Read>(
    in_pk: RPK,
    in_proof: RPR,
    in_public_input: &Vec<FS>,
) -> Result<bool> {
    let proof: Proof<Bn256> = format::read_proof(in_proof)?;

    let (_, params) = format::read_pk(in_pk)?;
    let vk = prepare_verifying_key(&params.vk);

    let in_public_input = in_public_input
        .into_iter()
        .map(|n| Fr::from_str(&n.0.to_string())
            .expect("cannot parse fe"))
        .collect::<Vec<_>>();

    Ok(verify_proof(&vk, &proof, &in_public_input)?)
}

#[cfg(test)]
mod test {
    use super::*;

    use bellman::groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    };
    use circom2_compiler::evaluator::{Evaluator, Mode, Scope};
    use circom2_compiler::storage::Ram;
    use circom2_compiler::storage::StorageFactory;
    use pairing::bn256::{Bn256, Fr};
    use rand::thread_rng;
    use std::fs::File;

    use std::marker::PhantomData;

    #[test]
    fn test_generate_internal() {
        let circuit = "
            template t() {
                signal private input a;
                signal private input b;  
                signal output c;

                c <== a * b;  
            }
            component main = t();
        ";

        let mut ram = Ram::default();
        let mut ev_r1cs = Evaluator::new(
            Mode::GenConstraints,
            ram.new_signals().unwrap(),
            ram.new_constraints().unwrap(),
        );

        ev_r1cs
            .eval_inline(&mut Scope::new(true, None, "root".to_string()), circuit)
            .unwrap();

        let rng = &mut thread_rng();

        // Create parameters for our circuit
        println!("Run setup ---------------------------------");
        let params = {
            let circuit = CircomCircuit::<Bn256> {
                signals: &ev_r1cs.signals,
                constraints: &ev_r1cs.constraints,
                phantom: PhantomData,
            };

            generate_random_parameters(circuit, rng).unwrap()
        };


        // Prepare the verification key (for proof verification)
        let pvk = prepare_verifying_key(&params.vk);

        // Compute witness
        let mut ram = Ram::default();
        let mut ev_witness = Evaluator::new(
            Mode::GenWitness,
            ram.new_signals().unwrap(),
            ram.new_constraints().unwrap(),
        );

        ev_witness.set_deferred_value("main.a".to_string(), Value::from(7));
        ev_witness.set_deferred_value("main.b".to_string(), Value::from(3));
        ev_witness
            .eval_inline(&mut Scope::new(true, None, "root".to_string()), circuit)
            .unwrap();

        // check constraints
        check_constrains_eval_zero(&ev_r1cs.constraints,&ev_witness.signals)
            .expect("cannot check all constraints = 0");

        println!("Creating proofs --------------------------------- ");
        let circuit = CircomCircuit::<Bn256> {
            signals: &ev_witness.signals,
            constraints: &ev_r1cs.constraints,
            phantom: PhantomData,
        };

        // Create proof
        let proof = create_random_proof(circuit, &params, rng).expect("cannot create proof");

        // Verify with valid public input
        let public_input = Fr::from_str("21");
        let success =
            verify_proof(&pvk, &proof, &[public_input.unwrap()]).expect("cannot verify proof");

        assert!(success);

        // Verify with invalid public input
        let public_input = Fr::from_str("22");
        let success =
            verify_proof(&pvk, &proof, &[public_input.unwrap()]).expect("cannot verify proof");

        assert!(!success);
    }

    #[test]
    fn test_generate_helper() {
        let circuit = "
            template t() {
                signal private input a;
                signal private input b;  
                signal output c;

                c <== a * b;
            }
            component main = t();
        ";

        let mut ram = Ram::default();
        let mut ev_r1cs = Evaluator::new(
            Mode::GenConstraints,
            ram.new_signals().unwrap(),
            ram.new_constraints().unwrap(),
        );
        ev_r1cs
            .eval_inline(&mut Scope::new(true, None, "root".to_string()), circuit)
            .unwrap();

        // setup -----------------------------------------------------

        let (pk, vk) = (
            File::create("/tmp/pk").unwrap(),
            File::create("/tmp/ver.sol").unwrap(),
        );
        setup(&ev_r1cs, pk, vk).expect("cannot setup");

        // Compute witness -------------------------------------------
        let mut ram = Ram::default();
        let mut ev_witness = Evaluator::new(
            Mode::GenWitness,
            ram.new_signals().unwrap(),
            ram.new_constraints().unwrap(),
        );

        ev_witness.set_deferred_value("main.a".to_string(), Value::from(7));
        ev_witness.set_deferred_value("main.b".to_string(), Value::from(3));
        ev_witness
            .eval_inline(&mut Scope::new(true, None, "root".to_string()), circuit)
            .unwrap();

        check_constrains_eval_zero(&ev_r1cs.constraints,&ev_witness.signals)
            .expect("cannot check all constraints = 0");

        // Create proof
        let mut proof_out = Vec::new();
        let pk = File::open("/tmp/pk").unwrap();
        let public_input = proof(ev_witness.signals, pk, &mut proof_out).unwrap();
        assert_eq!("[(\"main.c\", 21)]", format!("{:?}", public_input));

        // Verify with valid public input
        let public_input_values = public_input.into_iter().map(|(_,v)| v).collect::<Vec<_>>();
        let pk = File::open("/tmp/pk").unwrap();
        assert_eq!(
            verify(pk, proof_out.as_slice(), &public_input_values)
            .expect("cannot verify proof1"),
            true
        );

        // Verify with invalid public input
        let pk = File::open("/tmp/pk").unwrap();
        assert_eq!(
            verify(pk, proof_out.as_slice(), &vec![FS::from(22)])
            .expect("cannot verify proof2"),
            false
        );
    }

}
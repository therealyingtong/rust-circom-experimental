extern crate rand;

use pairing::bn256::Bn256;
use regex::Regex;

use circom2_compiler::algebra::{FS,QEQ};
use circom2_compiler::storage::Ram;
use circom2_compiler::storage::RamConstraints;
use circom2_compiler::storage::StorageFactory;
use circom2_compiler::storage::{Constraints};

use std::io::{Read, Write};

use bellman::groth16::{Proof,Parameters};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use serde_cbor::{from_slice, to_vec};
use error::{Error,Result};

use super::error;

#[derive(Serialize, Deserialize)]
struct JsonProof {
    a : Vec<String>,
    b : Vec<Vec<String>>,
    c : Vec<String>,
}

/*
Taken from Thibaut Schaeffer's ZoKrates
https://github.com/Zokrates/ZoKrates/commit/20790b72fff3b48a518dd7b910f7e005612faf95
*/

lazy_static! {
    static ref G2_REGEX: Regex = Regex::new(r"G2\(x=Fq2\(Fq\((?P<x0>0[xX][0-9a-fA-F]{64})\) \+ Fq\((?P<x1>0[xX][0-9a-fA-F]{64})\) \* u\), y=Fq2\(Fq\((?P<y0>0[xX][0-9a-fA-F]{64})\) \+ Fq\((?P<y1>0[xX][0-9a-fA-F]{64})\) \* u\)\)").unwrap();
}

lazy_static! {
    static ref G1_REGEX: Regex = Regex::new(
        r"G1\(x=Fq\((?P<x>0[xX][0-9a-fA-F]{64})\), y=Fq\((?P<y>0[xX][0-9a-fA-F]{64})\)\)"
    )
    .unwrap();
}

lazy_static! {
    static ref FR_REGEX: Regex = Regex::new(r"Fr\((?P<x>0[xX][0-9a-fA-F]{64})\)").unwrap();
}

fn parse_g1(e: &<Bn256 as bellman::pairing::Engine>::G1Affine) -> (String, String) {
    let raw_e = e.to_string();

    let captures = G1_REGEX.captures(&raw_e).unwrap();

    (
        captures.name(&"x").unwrap().as_str().to_string(),
        captures.name(&"y").unwrap().as_str().to_string(),
    )
}

fn parse_g2(e: &<Bn256 as bellman::pairing::Engine>::G2Affine) -> (String, String, String, String) {
    let raw_e = e.to_string();

    let captures = G2_REGEX.captures(&raw_e).unwrap();

    (
        captures.name(&"x1").unwrap().as_str().to_string(),
        captures.name(&"x0").unwrap().as_str().to_string(),
        captures.name(&"y1").unwrap().as_str().to_string(),
        captures.name(&"y0").unwrap().as_str().to_string(),
    )
}

pub fn parse_g1_hex(e: &<Bn256 as bellman::pairing::Engine>::G1Affine) -> String {
    let parsed = parse_g1(e);

    format!("{}, {}", parsed.0, parsed.1)
}

pub fn parse_g2_hex(e: &<Bn256 as bellman::pairing::Engine>::G2Affine) -> String {
    let parsed = parse_g2(e);

    format!("[{}, {}], [{}, {}]", parsed.0, parsed.1, parsed.2, parsed.3,)
}

pub fn flatten_json(prefix: &str, json :&str) -> Result<Vec<(String,FS)>> {
    fn flatten(prefix: &str, v:& serde_json::Value, result : &mut Vec<(String,FS)>) -> Result<()> {
        match v {
            serde_json::Value::Array(values) => {
                for (i,value) in values.iter().enumerate() {
                    flatten(&format!("{}[{}]",prefix,i),value,result)?;
                }
                Ok(())
            }
            serde_json::Value::Object(values) => {
                for (key,value) in values.iter() {
                    flatten(&format!("{}.{}",prefix,key),value,result)?;
                }
                Ok(())
            }
            serde_json::Value::String(value) => {
                result.push((prefix.to_string(),FS::parse(value)?));
                Ok(())
            }
            serde_json::Value::Number(value) => {
                let value = value.as_u64()
                    .ok_or_else(|| Error::Unexpected(format!("bad value {:?}",value)))?;
                result.push((prefix.to_string(),FS::from(value)));
                Ok(())
            }
            _ => Err(Error::Unexpected(format!("Cannot decode value {:?}",v)))         
        }
    }

    let json : serde_json::Value = serde_json::from_str(json)?;

    let mut result = Vec::new();
    flatten(prefix,&json,&mut result)?;
    Ok(result)
}

pub fn write_proof<W:Write>(proof : Proof<Bn256>, out: &mut W) -> Result<()> {
    Ok(proof.write(out)?)
    /*
    let a = parse_g1(&proof.a);
    let b = parse_g2(&proof.b);
    let c = parse_g1(&proof.c);

    let json = serde_json::to_string(&JsonProof {
        a: vec![a.0,a.1],
        b: vec![vec![b.0,b.1],vec![b.2,b.3]],
        c: vec![c.0,c.1],
    })?;

    out.write(json.as_bytes())?;
    Ok(())
    */
}

pub fn read_proof<R:Read>(reader: R) -> Result<Proof<Bn256>> {
    let proof : Proof<Bn256> = Proof::read(reader)?;
    Ok(proof)

/*
    let proof: JsonProof = serde_json::from_reader(reader)?;
    bn256::Bn256::G1Affine
    
    let a = parse_g1(&proof.a);
    let b = parse_g2(&proof.b);
    let c = parse_g1(&proof.c);

    let json = serde_json::to_string(&JsonProof {
        a: vec![a.0,a.1],
        b: vec![vec![b.0,b.1],vec![b.2,b.3]],
        c: vec![c.0,c.1],
    })?;

    out.write(json.as_bytes())?;
    Ok(())
*/
}


pub fn write_pk<W: Write, C: Constraints>(
    mut pk: W,
    constraints: &C,
    params: &Parameters<Bn256>,
) -> Result<()> {
    // write constratins & proving key
    pk.write_u32::<BigEndian>(constraints.len()? as u32)?;
    for i in 0..constraints.len()? {
        let qeq = to_vec(&constraints.get(i)?)?;
        pk.write_u32::<BigEndian>(qeq.len() as u32)?;
        pk.write(&qeq)?;
    }
    
    params.write(pk)?;
    Ok(())
}

pub fn read_pk<R: Read>(mut pk: R) -> Result<(RamConstraints, Parameters<Bn256>)> {
    let mut buffer = Vec::with_capacity(1024);
    let mut constraints = Ram::default().new_constraints()?;
    let count = pk.read_u32::<BigEndian>()?;

    for _ in 0..count {
        let len = pk.read_u32::<BigEndian>()? as usize;
        if len > buffer.capacity() {
            buffer.reserve(len - buffer.capacity());
        }
        buffer.resize(len, 0u8);
        pk.read_exact(&mut buffer)?;
        let qeq = from_slice::<QEQ>(&buffer)?;
        constraints.push(qeq,None)?;
    }

    let params: Parameters<Bn256> = Parameters::read(pk, true)?;

    Ok((constraints, params))
}

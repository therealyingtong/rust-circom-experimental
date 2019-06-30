use pairing::bn256::Bn256;
use bellman::groth16::VerifyingKey;
use std::io::Write;

use super::format;
use super::error::Result;

const CONTRACT_TEMPLATE: &str = r#"
contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gammaABC;
    }
    struct Proof {
        Pairing.G1Point A;
        Pairing.G2Point B;
        Pairing.G1Point C;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.a = Pairing.G1Point(<%vk_a%>);
        vk.b = Pairing.G2Point(<%vk_b%>);
        vk.gamma = Pairing.G2Point(<%vk_gamma%>);
        vk.delta = Pairing.G2Point(<%vk_delta%>);
        vk.gammaABC = new Pairing.G1Point[](<%vk_gammaABC_length%>);
        <%vk_gammaABC_pts%>
    }
    function verify(uint[] memory input, Proof memory proof) internal returns (uint) {
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gammaABC.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++)
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gammaABC[i + 1], input[i]));
        vk_x = Pairing.addition(vk_x, vk.gammaABC[0]);
        if(!Pairing.pairingProd4(
             proof.A, proof.B,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.C), vk.delta,
             Pairing.negate(vk.a), vk.b)) return 1;
        return 0;
    }
    event Verified(string s);
    function verifyTx(
            uint[2] memory a,
            uint[2][2] memory b,
            uint[2] memory c,
            uint[<%vk_input_length%>] memory input
        ) public returns (bool r) {
        Proof memory proof;
        proof.A = Pairing.G1Point(a[0], a[1]);
        proof.B = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.C = Pairing.G1Point(c[0], c[1]);
        uint[] memory inputValues = new uint[](input.length);
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            emit Verified("Transaction successfully verified.");
            return true;
        } else {
            return false;
        }
    }
}
"#;

pub fn generate_solidity<W : Write>(vk: &VerifyingKey<Bn256>, out: &mut W) -> Result<()> {

    let mut contract = String::from(CONTRACT_TEMPLATE);
    contract = contract.replace("<%vk_a%>", &format::parse_g1_hex(&vk.alpha_g1));
    contract = contract.replace("<%vk_b%>", &format::parse_g2_hex(&vk.beta_g2));
    contract = contract.replace("<%vk_gamma%>", &format::parse_g2_hex(&vk.gamma_g2));
    contract = contract.replace("<%vk_delta%>", &format::parse_g2_hex(&vk.delta_g2));
    contract = contract.replace(
        "<%vk_gammaABC_length%>",
        &format!("{}", &vk.ic.len()),
    );
    contract = contract.replace(
        "<%vk_gammaABC_pts%>",
            &vk
            .ic
            .iter()
            .enumerate()
            .map(|(i, x)| format!("vk.gammaABC[{}] = {}", i, format::parse_g1_hex(x)))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    out.write_all(contract.as_bytes())?;

    Ok(())
}
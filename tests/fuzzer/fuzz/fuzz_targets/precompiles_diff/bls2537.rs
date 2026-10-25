#![no_main]
#![feature(allocator_api)]
//! EIP-2537 (BLS12-381 precompiles) reachability + spec edge semantics.
use basic_bootloader::bootloader::block_flow::ethereum::hooks::eip_2537::*;
use libfuzzer_sys::fuzz_target;
use std::alloc::Global;
use zk_ee::reference_implementations::{BaseResources, DecreasingNative};
use zk_ee::system::{Resource, SystemFunction};

fn call<P>(input: &[u8]) -> (bool, Vec<u8>)
where
    P: SystemFunction<BaseResources<DecreasingNative>, Bls12PrecompileErrors>,
{
    let mut out = Vec::new();
    let mut res = <BaseResources<DecreasingNative> as Resource>::FORMAL_INFINITE;
    let r = P::execute(input, &mut out, &mut res, Global);
    (r.is_ok(), out)
}

fn fuzz(data: &[u8]) {
    let _ = call::<Bls12381G1AdditionPrecompile>(data);
    let _ = call::<Bls12381G2AdditionPrecompile>(data);
    let _ = call::<Bls12381G1MSMPrecompile>(data);
    let _ = call::<Bls12381G2MSMPrecompile>(data);
    let _ = call::<Bls12381PairingCheckPrecompile>(data);
    let _ = call::<Bls12381G1MappingPrecompile>(data);
    let _ = call::<Bls12381G2MappingPrecompile>(data);

    if data.is_empty() {
        let (ok1, out1) = call::<Bls12381G1MSMPrecompile>(data);
        let (ok2, out2) = call::<Bls12381G2MSMPrecompile>(data);
        let (ok3, out3) = call::<Bls12381PairingCheckPrecompile>(data);
        let mut expect = [0u8; 32];
        expect[31] = 1;
        assert!(ok1, "G1MSM(empty) rejected, EIP-2537 wants infinity");
        assert_eq!(out1, vec![0u8; 128], "G1MSM(empty) wrong result");
        assert!(ok2, "G2MSM(empty) rejected, EIP-2537 wants infinity");
        assert_eq!(out2, vec![0u8; 256], "G2MSM(empty) wrong result");
        assert!(ok3, "PAIRING(empty) rejected, EIP-2537 wants true");
        assert_eq!(out3, expect.to_vec(), "PAIRING(empty) wrong result");
    }
}

fuzz_target!(|data: &[u8]| { fuzz(data); });

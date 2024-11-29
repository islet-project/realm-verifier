mod parser;

pub mod hash;
use std::collections::HashMap;

pub use parser::json as parser_json;

use log::{debug, error, warn};
use ratls::{InternalTokenVerifier, RaTlsError};
use rust_rsi::{verify_token, RealmClaims, CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS};
use tinyvec::ArrayVec;
use hash::HashAlgo;

pub const MAX_MEASUREMENT_SIZE: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MeasurementValue {
    value: ArrayVec<[u8; MAX_MEASUREMENT_SIZE]>,
}

impl MeasurementValue {
    pub fn init(len: usize) -> Self {
        let mut av = ArrayVec::new();
        av.resize(len, 0);
        Self {
            value: av
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        self.value.as_slice()
    }

    pub fn as_mut_slice(&mut self) -> &mut[u8] {
        self.value.as_mut_slice()
    }
}

#[derive(Debug, Clone)]
pub struct RealmMeasurements {
    pub initial: MeasurementValue,
    pub extensible: Vec<[MeasurementValue; CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS]>,
    pub hash_algo: HashAlgo,
}

type RealmID = Vec<u8>;

#[derive(Debug)]
pub struct RealmVerifier {
    reference_measurements: HashMap<RealmID, RealmMeasurements>,
}

impl RealmVerifier {
    pub fn init(realm_measurements: Vec<RealmMeasurements>) -> Self {
        debug!("Reference values: {:02x?}", realm_measurements);
        let input_len = realm_measurements.len();
        let reference_measurements: HashMap<_, _> = realm_measurements
            .into_iter()
            .map(|m| (m.initial.as_slice().to_vec(), m))
            .collect();

        if reference_measurements.len() < input_len {
            warn!("Multiple reference values for the same RIM found!");
        }
        Self {
            reference_measurements,
        }
    }

    fn check(&self, rim: &[u8], rems: &[Vec<u8>], hash_algo: &str) -> bool {
        let Some(reference) = self.reference_measurements.get(&rim.to_vec()) else {
            error!("No reference for RIM {:02x?}", rim);
            return false;
        };

        if rems.len() != CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS {
            error!("Wrong count of REMs: is ({}), should be ({})",
                   rems.len(), CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS);
            return false;
        }

        if hash_algo != reference.hash_algo.name() {
            error!("Hash algorithm does not match: is ({}), should be ({})",
                   hash_algo, reference.hash_algo.name());
        }

        for reference_rems in &reference.extensible {
            let mut match_count = 0;
            for (i, rem) in rems.iter().enumerate() {
                if reference_rems[i].as_slice() == rem {
                    match_count += 1;
                }
            }
            if match_count == reference_rems.len() {
                debug!("REMs match");
                return true;
            }
        }
        error!("Could not find matching reference REMs");
        return false;
    }
}

impl InternalTokenVerifier for RealmVerifier {
    fn verify(&self, token: &[u8]) -> Result<(), RaTlsError> {
        let attestation_claims = verify_token(token, None)
            .map_err(|e| RaTlsError::GenericTokenVerifierError(e.into()))?;
        let claims = RealmClaims::from_raw_claims(
            &attestation_claims.realm_claims.token_claims,
            &attestation_claims.realm_claims.measurement_claims,
        )
        .map_err(|e| RaTlsError::GenericTokenVerifierError(e.into()))?;
        debug!("{:?}", claims);
        debug!("token rim: {}", hex::encode(&claims.rim));
        for (rem_idx, rem) in claims.rems.iter().enumerate() {
            debug!("token rem[{}]: {}", rem_idx, hex::encode(&rem));
        }

        match self.check(&claims.rim, &claims.rems, &claims.hash_algo)
        {
            true => Ok(()),
            false => Err(RaTlsError::GenericTokenVerifierError(
                "Token measurements do not match reference values".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::{BufReader, Read}, path::Path};
    use super::*;

    fn load_token(path: impl AsRef<Path>) -> Vec<u8> {
        let mut token = Vec::<u8>::with_capacity(128);
        File::open(path).unwrap().read_to_end(&mut token).unwrap();
        token.shrink_to_fit();
        token
    }

    fn load_reference_values(path: impl AsRef<Path>) -> RealmMeasurements {
        let file = File::open(path).unwrap();
        let reader = BufReader::new(file);

        let reference_json: serde_json::Value = serde_json::from_reader(reader).unwrap();
        let reference_values_json = reference_json["realm"]["reference-values"].clone();
        crate::parser_json::parse_value(reference_values_json).unwrap()
    }

    #[test]
    fn verify_token() {
        let token = load_token("tests/token.bin");
        let reference_values = load_reference_values("tests/realm.json");

        let verifier = RealmVerifier::init(vec![reference_values]);
        let verification_result = verifier.verify(&token);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn no_matching_rim() {
        let token = load_token("tests/token2.bin");
        let reference_values = load_reference_values("tests/realm.json");

        let verifier = RealmVerifier::init(vec![reference_values]);
        let verification_result = verifier.verify(&token);

        assert!(verification_result.is_err());
    }

    #[test]
    fn verify_multiple() {
        let token = load_token("tests/token.bin");
        let reference_values = load_reference_values("tests/realm.json");

        let token2 = load_token("tests/token2.bin");
        let reference_values2 = load_reference_values("tests/realm2.json");

        let verifier = RealmVerifier::init(vec![reference_values, reference_values2]);

        assert!(verifier.verify(&token).is_ok());
        assert!(verifier.verify(&token2).is_ok());

    }
}

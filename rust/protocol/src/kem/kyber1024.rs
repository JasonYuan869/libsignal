//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use pqc_kyber::{KYBER_CIPHERTEXTBYTES, KYBER_PUBLICKEYBYTES, KYBER_SECRETKEYBYTES, KYBER_SSBYTES};

use crate::Result;

use super::{KeyMaterial, Public, Secret};

pub(crate) struct Parameters;

impl super::Parameters for Parameters {
    const PUBLIC_KEY_LENGTH: usize = KYBER_PUBLICKEYBYTES;
    const SECRET_KEY_LENGTH: usize = KYBER_SECRETKEYBYTES;
    const CIPHERTEXT_LENGTH: usize = KYBER_CIPHERTEXTBYTES;
    const SHARED_SECRET_LENGTH: usize = KYBER_SSBYTES;

    fn generate() -> (KeyMaterial<Public>, KeyMaterial<Secret>) {
        let mut rng = rand::rngs::OsRng::default();
        let keys = pqc_kyber::keypair(&mut rng).expect("error generating random numbers");
        (
            KeyMaterial::new(keys.public.into()),
            KeyMaterial::new(keys.secret.into()),
        )
    }

    fn encapsulate(pub_key: &KeyMaterial<Public>) -> (super::SharedSecret, super::RawCiphertext) {
        let mut rng = rand::rngs::OsRng::default();
        let encapsulated = pqc_kyber::encapsulate(&pub_key, &mut rng).expect("could not encapsulate");
        (encapsulated.1.into(), encapsulated.0.into())
    }

    fn decapsulate(
        secret_key: &KeyMaterial<Secret>,
        ciphertext: &[u8],
    ) -> Result<super::SharedSecret> {
        let decapsulated = pqc_kyber::decapsulate(&ciphertext, &secret_key).expect("could not decapsulate");
        Ok(decapsulated.into())
    }
}

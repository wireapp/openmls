use crate::ciphersuite::Secret;
use crate::codec::*;

use super::PathSecret;

impl Codec for PathSecret {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.secret.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let secret = Secret::decode(cursor)?;
        Ok(PathSecret { secret })
    }
}

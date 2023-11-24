import { Field, Nullifier, PublicKey, Signature } from 'o1js';
import { verifyEncryption } from './encryption';

const verifyPubKeyOwnership = (
  sig: Signature,
  pubKey: PublicKey,
  proposalId: Field
) => {
  sig.verify(pubKey, [proposalId]).assertTrue();
};

const verifyNullifier = (
  nullifier: Nullifier,
  nullifierKey: Field,
  msg: Field[]
) => {
  nullifier.key().assertEquals(nullifierKey);
  nullifier.verify(msg);
};

export { verifyEncryption, verifyPubKeyOwnership, verifyNullifier };

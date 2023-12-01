import { Field, MerkleMapWitness, Nullifier, PublicKey, Signature } from 'o1js';
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

const assertNullifierUnused = (
  _key: Field,
  witness: MerkleMapWitness,
  root: Field
) => {
  let [impliedRoot, key] = witness.computeRootAndKey(Field(0));
  _key.assertEquals(key);
  impliedRoot.assertEquals(root);
};

const setNullifierUsed = (_key: Field, witness: MerkleMapWitness) => {
  let [newRoot, key] = witness.computeRootAndKey(Field(1));
  key.assertEquals(_key);
  return newRoot;
};

export {
  verifyEncryption,
  verifyPubKeyOwnership,
  verifyNullifier,
  assertNullifierUnused,
  setNullifierUsed,
};

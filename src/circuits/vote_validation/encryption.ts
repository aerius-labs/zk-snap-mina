import { Field, Provable } from 'o1js';
import { EncryptionPublicKey } from '../utils/paillier';

const verifyEncryption = (
  pubKey: EncryptionPublicKey,
  cipher: Field,
  msg: Field,
  r: Field
) => {
  pubKey.encrypt(msg, r).assertEquals(cipher);
};

export { verifyEncryption };

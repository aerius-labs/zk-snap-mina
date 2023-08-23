import * as paillierBigint from 'paillier-bigint';

export const generateEncryptionKeyPair = async () => {
  const { publicKey, privateKey } = await paillierBigint.generateRandomKeys(
    126
  );
  return { publicKey, privateKey };
};

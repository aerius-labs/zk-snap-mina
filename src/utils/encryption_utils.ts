import * as paillierBigint from 'paillier-bigint';

const generateEncryptionKeyPair = async (
  nBits: number
): Promise<[paillierBigint.PublicKey, paillierBigint.PrivateKey]> => {
  const { publicKey, privateKey } = await paillierBigint.generateRandomKeys(
    nBits
  );
  return [publicKey, privateKey];
};

const getRandomNBitNumber = (bits: number): bigint => {
  let randomBigInt = BigInt(0);
  for (let i = 0; i < bits; i++) {
    randomBigInt |= BigInt(Math.floor(Math.random() * 2)) << BigInt(i);
  }
  return randomBigInt;
};

export { generateEncryptionKeyPair, getRandomNBitNumber };

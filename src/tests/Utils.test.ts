import { Experimental, Field, Provable } from 'o1js';
import { exp, getRandomNBitNumber, mod, modPow } from '../utils/Utils';
import { generateEncryptionKeyPair } from '../utils/Pallier';
import { EncryptionPublicKey } from '../utils/PallierZK';

describe('Utils Test', () => {
  it('should mod correctly', async () => {
    const circuit = Experimental.ZkProgram({
      publicInput: undefined,

      methods: {
        modCircuit: {
          privateInputs: [Field, Field, Field],

          method(num: Field, modulus: Field, res: Field) {
            const inRes = mod(num, modulus);
            inRes.assertEquals(res);
          },
        },
      },
    });

    await circuit.compile();

    const num = Field(1316936452737303443133476541626866889n);
    const modulus = Field(1223463659138257670348186115088493175n);
    const res = Field(93472793599045772785290426538373714n);

    const proof = await circuit.modCircuit(num, modulus, res);
    await circuit.verify(proof);
  });

  it('should find correct exp', async () => {
    const circit = Experimental.ZkProgram({
      publicInput: undefined,

      methods: {
        expCircuit: {
          privateInputs: [Field, Field, Field, Field],

          method(base: Field, expo: Field, modulus: Field, result: Field) {
            const res = exp(base, expo, modulus);
            res.assertEquals(result);
          },
        },
      },
    });

    await circit.compile();

    const numBits = 63;
    const base = Field(getRandomNBitNumber(numBits));
    const expo = Field(getRandomNBitNumber(numBits));
    const modulus = Field(getRandomNBitNumber(numBits * 2));
    const result = Field(
      modPow(base.toBigInt(), expo.toBigInt(), modulus.toBigInt())
    );

    const proof = await circit.expCircuit(base, expo, modulus, result);
    await circit.verify(proof);
  });

  it('should correctly add 2 cipher texts', async () => {
    const { publicKey, privateKey } = await generateEncryptionKeyPair();
    let encryptionPrivateKey = privateKey;
    let encryptionPublicKey = publicKey;

    const r1: Field = Field(6942);
    const r2: Field = Field(4269);
    const c1 = Field(encryptionPublicKey.encrypt(4269n, r1.toBigInt()));
    const c2 = Field(encryptionPublicKey.encrypt(6942n, r2.toBigInt()));

    const cSum = Field(
      encryptionPublicKey.addition(c1.toBigInt(), c2.toBigInt())
    );

    const circuit = Experimental.ZkProgram({
      publicInput: undefined,

      methods: {
        addCipherTexts: {
          privateInputs: [EncryptionPublicKey, Field, Field, Field],

          method(
            encryptionPublicKey: EncryptionPublicKey,
            c1: Field,
            c2: Field,
            result: Field
          ) {
            const res = encryptionPublicKey.add(c1, c2);
            res.assertEquals(result);
          },
        },
      },
    });

    await circuit.compile();

    const proof = await circuit.addCipherTexts(
      EncryptionPublicKey.create(
        Field(encryptionPublicKey.n),
        Field(encryptionPublicKey.g),
        Field(encryptionPublicKey._n2)
      ),
      c1,
      c2,
      cSum
    );
    await circuit.verify(proof);
  });
});

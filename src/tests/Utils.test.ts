import { Experimental, Field, Provable } from 'o1js';
import { exp, mod } from '../utils/Utils';

describe('Utils Test', () => {
  xit('should mod correctly', async () => {
    const circuit = Experimental.ZkProgram({
      publicInput: undefined,

      methods: {
        modCircuit: {
          privateInputs: [Field, Field, Field],

          method(num: Field, modulus: Field, res: Field) {
            const inRes = mod(num, modulus);
            Provable.log('inRes', inRes);
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
            Provable.log('res', res);
            res.assertEquals(result);
          },
        },
      },
    });

    await circit.compile();

    const base = Field(2n);
    const expo = Field(10n);
    const modulus = Field(10240n);
    const result = Field(1024n);

    const proof = await circit.expCircuit(base, expo, modulus, result);
    await circit.verify(proof);
  });
});

import { Field, Struct } from 'o1js';
import { exp, mulMod } from './arithmetic';

class EncryptionPublicKey extends Struct({
  n: Field,
  g: Field,
  n_2: Field,
}) {
  assertEquals(other: EncryptionPublicKey): void {
    this.n.assertEquals(other.n);
    this.g.assertEquals(other.g);
    this.n_2.assertEquals(other.n_2);
  }

  // TODO: Support >63 bit security after ForeignField support
  encrypt(msg: Field, r: Field): Field {
    const g_m = exp(this.g, msg, this.n_2);
    const r_n = exp(r, this.n, this.n_2);
    const c = mulMod(g_m, r_n, this.n_2);

    return c;
  }

  add(c1: Field, c2: Field): Field {
    return mulMod(c1, c2, this.n_2);
  }
}

export { EncryptionPublicKey };

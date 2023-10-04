import { Field, Struct, Provable } from 'o1js';
import { exp, mulMod } from './Utils';

export class EncryptionPublicKey extends Struct({
  n: Field,
  g: Field,
  n_2: Field,
}) {
  static create(n: Field, g: Field, n_2: Field) {
    return new EncryptionPublicKey({ n, g, n_2 });
  }

  encrypt(msg: Field, r: Field) {
    const g_m = exp(this.g, msg, this.n_2);
    const r_n = exp(r, this.n, this.n_2);
    const c = mulMod(g_m, r_n, this.n_2);

    return c;
  }

  add(c1: Field, c2: Field) {
    return mulMod(c1, c2, this.n_2);
  }
}

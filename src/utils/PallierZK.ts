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
    Provable.log('n_2', this.n_2);
    const g_m = exp(this.g, msg, this.n_2);
    Provable.log('g_m', g_m);
    const r_n = exp(r, this.n, this.n_2);
    Provable.log('r_n', r_n);
    const c = mulMod(g_m, r_n, this.n_2);
    Provable.log('c', c);

    return c;
  }
}

export class PaillierCipher extends Struct({
  c: Field,
  n_squared: Field,
}) {
  add(c: PaillierCipher, n_squared: Field): PaillierCipher {
    this.n_squared.assertEquals(n_squared);

    let product = this.c.mul(c.c);
    let res = Provable.if(
      product.greaterThanOrEqual(n_squared),
      product.sub(n_squared),
      product
    );
    return new PaillierCipher({ c: res, n_squared });
  }
}

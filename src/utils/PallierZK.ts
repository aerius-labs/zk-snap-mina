import { Field, Struct, Provable } from 'snarkyjs';

export class EncryptionPublicKey extends Struct({
  n: Field,
  g: Field,
}) {
  static create(n: Field, g: Field) {
    return new EncryptionPublicKey({ n, g });
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

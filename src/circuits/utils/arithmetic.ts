import { Bool, Field, Provable } from 'o1js';

const exp = (base: Field, exponent: Field, mod: Field) => {
  let bits = exponent.toBits(63);
  let n_base = base;

  let start = Bool(false);

  for (let i = 62; i >= 0; i--) {
    let bit = bits[i];

    let isOne = start.and(bit.equals(false));
    let isZero = start.and(bit.equals(true));

    let square = squareMod(n_base, mod);
    n_base = Provable.switch([isOne, isZero, start.not()], Field, [
      square,
      mulMod(square, base, mod),
      n_base,
    ]);

    start = Provable.if(bit.equals(true).and(start.not()), Bool(true), start);
  }

  n_base = Provable.if(exponent.equals(Field(0)), Field(1), n_base);

  return n_base;
};

const divMod = (num: Field, mod: Field) => {
  let x = num;
  let y_ = mod;

  if (num.isConstant() && y_.isConstant()) {
    let xn = x.toBigInt();
    let yn = y_.toBigInt();
    let q = xn / yn;
    let r = xn - q * yn;
    return {
      quotient: Field(q),
      rest: Field(r),
    };
  }

  y_ = y_.seal();

  let q = Provable.witness(
    Field,
    () => new Field(x.toBigInt() / y_.toBigInt())
  );

  q.rangeCheckHelper(192).assertEquals(q);

  // TODO: Could be a bit more efficient
  let r = x.sub(q.mul(y_)).seal();
  r.rangeCheckHelper(192).assertEquals(r);

  let r_ = r;
  let q_ = q;

  // TODO: remove when sufficient performance
  // r_.assertLessThan(y_);

  return { quotient: q_, rest: r_ };
};

const mod = (num: Field, mod: Field) => {
  return divMod(num, mod).rest;
};

const mulMod = (a: Field, b: Field, m: Field) => {
  return mod(a.mul(b), m);
};

const squareMod = (a: Field, m: Field) => {
  return mod(a.square(), m);
};

export { exp, divMod, mod, mulMod, squareMod };

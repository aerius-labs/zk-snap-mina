import { Field, Bool, Provable, UInt64 } from 'o1js';

export const exp = (base: Field, exponent: Field, mod: Field) => {
  let bits = exponent.toBits();
  let n = base;

  // this keeps track of when we can start accumulating
  let start = Bool(false);

  // we have to go in reverse order here because .toBits is in LSB representation, but we need MSB for the algorithm to function
  for (let i = 254; i >= 0; i--) {
    let bit = bits[i];

    // we utilize the square and multiply algorithm
    // if the current bit = 0, square and multiply
    // if bit = 1, just square
    let isOne = start.and(bit.equals(false));
    let isZero = start.and(bit.equals(true));

    // let square = n.square();
    // Provable.log('n', n);
    let square = squareMod(n, mod);
    // Provable.log('square', square);
    // we choose what computation to apply next
    n = Provable.switch([isOne, isZero, start.not()], Field, [
      square,
      // square.mul(base),
      mulMod(square, base, mod),
      n,
    ]);

    // toggle start to accumulate; we only start accumulating once we have reached the first 1
    start = Provable.if(bit.equals(true).and(start.not()), Bool(true), start);
  }

  return n;
};

export const mulMod = (a: Field, b: Field, m: Field) => {
  return mod(a.mul(b), m);
};

export const squareMod = (a: Field, m: Field) => {
  return mod(a.square(), m);
};

export const divMod = (num: Field, mod: Field) => {
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

  q.rangeCheckHelper(240).assertEquals(q);

  // TODO: Could be a bit more efficient
  let r = x.sub(q.mul(y_)).seal();
  r.rangeCheckHelper(240).assertEquals(r);

  let r_ = r;
  let q_ = q;

  // r_.assertLessThan(y_);

  return { quotient: q_, rest: r_ };
};

export const mod = (num: Field, mod: Field) => {
  return divMod(num, mod).rest;
};

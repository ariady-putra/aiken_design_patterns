//// @hidden
//// An interval bound type module to avoid potential name clashing in the future.

use aiken/interval.{IntervalBoundType, NegativeInfinity, PositiveInfinity}

pub const positive_infinity = PositiveInfinity

pub const negative_infinity = NegativeInfinity

pub fn to_finite(time: Int) -> IntervalBoundType<Int> {
  interval.Finite(time)
}

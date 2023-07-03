extern crate core;

use long_int::LongInt;
use random_generator::RandGen;
use wrapper::{Group, Point};

pub struct SharedSecret {
    secret_key: LongInt,
    group: Group,
}

impl SharedSecret {
    pub fn new() -> SharedSecret {
        let a = LongInt::new(); // 0
        let b = LongInt::from_hex("7"); // 7
        let p =
            LongInt::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"); // 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1

        let mut group = Group::new(&a, &b, &p);

        let gen_point = Point::from_string(&group, "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
        let order =
            LongInt::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
        let cofactor = LongInt::from_hex("01");

        group.set_generator(&gen_point, &order, &cofactor);

        Self::new_with_group(group)
    }

    pub fn new_with_group(group: Group) -> SharedSecret {
        let n = group.get_order();
        let mut gen = RandGen::new_from_time();
        let one = LongInt::from_hex("1");
        SharedSecret {
            secret_key: gen.next_long_int(&one, &(&n - &one)),
            group,
        }
    }

    fn calc(scalar: &LongInt, point: &Point) -> Point {
        scalar * point
    }

    pub fn generate_pub_key(&self) -> Point {
        Self::calc(&self.secret_key, &self.group.get_generator())
    }

    pub fn generate_shared_secret(&self, other_public_key: &Point) -> Point {
        Self::calc(&self.secret_key, other_public_key)
    }
}

#[cfg(test)]
mod tests {
    use crate::SharedSecret;

    #[test]
    fn general() {
        let alice = SharedSecret::new();
        let bob = SharedSecret::new();

        let alice_pk = alice.generate_pub_key();
        let bob_pk = bob.generate_pub_key();

        let alice_ss = alice.generate_shared_secret(&bob_pk);
        let bob_ss = bob.generate_shared_secret(&alice_pk);

        assert_eq!(alice_ss.to_string(), bob_ss.to_string());
    }
}

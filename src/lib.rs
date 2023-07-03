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
        let p = LongInt::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");

        let group = Group::new(&a, &b, &p);

        Self::new_with_group(&group)
    }

    pub fn new_with_group(group: &Group) -> SharedSecret {
        let n = group.degree();
        let mut gen = RandGen::new_from_time();
        let one = LongInt::from_hex("1");
        SharedSecret {
            secret_key: gen.next_long_int(&one, &(&n - &one)),
            group: group.clone(),
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
    use core::panicking::assert_failed;
    use crate::SharedSecret;

    #[test]
    fn general() {
        let alice = SharedSecret::new();
        let bob = SharedSecret::new();

        let alice_pk = alice.generate_pub_key();
        let bob_pk = bob.generate_pub_key();

        let alice_ss = alice.generate_shared_secret(&bob_pk);
        let bob_ss = bob.generate_shared_secret(&alice_pk);

        assert_eq!(alice_ss, bob_ss);
    }
}
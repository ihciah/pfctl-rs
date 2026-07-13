// Copyright 2025 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use zerocopy::FromZeros;

use crate::{
    Interface, Ip,
    conversion::{CopyTo, TryCopyTo},
    ffi,
};
use std::{ptr, vec::Vec};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolAddr {
    interface: Interface,
    ip: Ip,
    dynamic_interface: Option<Interface>,
}

impl PoolAddr {
    pub fn new<INTERFACE: Into<Interface>, IP: Into<Ip>>(interface: INTERFACE, ip: IP) -> Self {
        PoolAddr {
            interface: interface.into(),
            ip: ip.into(),
            dynamic_interface: None,
        }
    }

    /// Represents PF's dynamic interface-address syntax, for example `(en0)`.
    /// The address is resolved and updated by PF as the interface changes.
    pub fn dynamic_interface_address<T: Into<Interface>>(interface: T) -> Self {
        let interface = interface.into();
        PoolAddr {
            interface: interface.clone(),
            // PF derives the optional dynamic-interface prefix from this
            // mask. `-> (en0)` has no prefix, which PF represents as /128;
            // `Ip::Any` would encode /0 and print as `(en0)/0`.
            ip: Ip::from(std::net::Ipv6Addr::UNSPECIFIED),
            dynamic_interface: Some(interface),
        }
    }
}

impl From<Interface> for PoolAddr {
    fn from(interface: Interface) -> Self {
        PoolAddr {
            interface,
            ip: Ip::Any,
            dynamic_interface: None,
        }
    }
}

impl From<Ip> for PoolAddr {
    fn from(ip: Ip) -> Self {
        PoolAddr {
            interface: Interface::Any,
            ip,
            dynamic_interface: None,
        }
    }
}

impl TryCopyTo<ffi::pfvar::pf_pooladdr> for PoolAddr {
    type Error = crate::Error;

    fn try_copy_to(&self, pf_pooladdr: &mut ffi::pfvar::pf_pooladdr) -> Result<(), Self::Error> {
        self.interface.try_copy_to(&mut pf_pooladdr.ifname)?;
        self.ip.copy_to(&mut pf_pooladdr.addr);
        if let Some(interface) = &self.dynamic_interface {
            pf_pooladdr.addr.type_ = ffi::pfvar::PF_ADDR_DYNIFTL as u8;
            // SAFETY: `ifname` is the active union member when using
            // PF_ADDR_DYNIFTL, and Interface validates its fixed-size buffer.
            interface.try_copy_to(unsafe { &mut pf_pooladdr.addr.v.ifname })?;
        }
        Ok(())
    }
}

/// Represents a list of IPs used to set up a table of addresses for traffic redirection in PF.
///
/// See pf_rule.rpool.list for more info.
///
/// Owns the `pf_pooladdr` storage referenced by a PF address-pool list.
///
/// The caller must retain this value until the ioctl consuming the populated
/// `pf_palist` has returned.
pub struct PoolAddrList {
    pool: Box<[ffi::pfvar::pf_pooladdr]>,
}

impl PoolAddrList {
    pub fn new(pool_addrs: &[PoolAddr]) -> Result<Self, crate::Error> {
        let mut pool = Self::init_pool(pool_addrs)?.into_boxed_slice();
        Self::link_elements(&mut pool);
        Ok(PoolAddrList { pool })
    }

    /// Writes a BSD tail queue backed by this object's stable heap storage.
    pub(crate) fn write_to(&mut self, list: &mut ffi::pfvar::pf_palist) {
        *list = ffi::pfvar::pf_palist::new_zeroed();
        if self.pool.is_empty() {
            list.tqh_last = &mut list.tqh_first;
            return;
        }

        let pool = self.pool.as_mut_ptr();
        unsafe {
            let first = pool;
            let last = pool.add(self.pool.len() - 1);
            list.tqh_first = first;
            list.tqh_last = &mut (*last).entries.tqe_next;
            (*first).entries.tqe_prev = &mut list.tqh_first;
            (*last).entries.tqe_next = ptr::null_mut();
        }
    }

    /// Links adjacent pool entries in their stable heap allocation.
    fn link_elements(pool: &mut [ffi::pfvar::pf_pooladdr]) {
        let entries = pool.as_mut_ptr();
        unsafe {
            for index in 1..pool.len() {
                let previous = entries.add(index - 1);
                let current = entries.add(index);
                (*previous).entries.tqe_next = current;
                (*current).entries.tqe_prev = &mut (*previous).entries.tqe_next;
            }
        }
    }

    fn init_pool(pool_addrs: &[PoolAddr]) -> Result<Vec<ffi::pfvar::pf_pooladdr>, crate::Error> {
        let mut pool = Vec::with_capacity(pool_addrs.len());
        for pool_addr in pool_addrs {
            let mut pf_pooladdr = ffi::pfvar::pf_pooladdr::new_zeroed();
            pool_addr.try_copy_to(&mut pf_pooladdr)?;
            pool.push(pf_pooladdr);
        }
        Ok(pool)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_interface_address_uses_a_full_length_mask() {
        let pool_addr = PoolAddr::dynamic_interface_address("lo0");
        let mut pf_pooladdr = ffi::pfvar::pf_pooladdr::new_zeroed();
        pool_addr.try_copy_to(&mut pf_pooladdr).unwrap();

        assert_eq!(pf_pooladdr.addr.type_, ffi::pfvar::PF_ADDR_DYNIFTL as u8);
        let mask = unsafe { pf_pooladdr.addr.v.a.mask.pfa._addr8 };
        assert!(mask.iter().all(|byte| *byte == u8::MAX));
    }

    #[test]
    fn new_links_the_owned_pool_storage() {
        let mut pool = PoolAddrList::new(&[
            PoolAddr::from(Ip::Any),
            PoolAddr::from(Ip::from(std::net::Ipv4Addr::new(192, 0, 2, 1))),
        ])
        .unwrap();

        let first = pool.pool.as_mut_ptr();
        let second = unsafe { first.add(1) };
        let first_next = unsafe { std::ptr::addr_of_mut!((*first).entries.tqe_next) };
        assert_eq!(unsafe { (*first).entries.tqe_next }, second);
        assert_eq!(unsafe { (*second).entries.tqe_prev }, first_next);

        let mut palist = ffi::pfvar::pf_palist::new_zeroed();
        pool.write_to(&mut palist);
        let second_next = unsafe { std::ptr::addr_of_mut!((*second).entries.tqe_next) };
        assert_eq!(palist.tqh_first, first);
        assert_eq!(palist.tqh_last, second_next);
    }
}

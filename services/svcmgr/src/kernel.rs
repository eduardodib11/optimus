//! [`Caps`] sobre as syscalls do `ostd`: o que o binário passa ao corretor.

use kabi::{Badge, Error, Handle, ObjectType, Rights};

use crate::broker::Caps;

/// As operações do corretor feitas no kernel, no `CapSpace` do `svcmgr`.
pub struct Kernel;

impl Caps for Kernel {
    fn create_endpoint(&mut self, quota: Handle) -> Result<Handle, Error> {
        ostd::cap::create(quota, ObjectType::Endpoint, 0)
    }

    fn mint(
        &mut self,
        src: Handle,
        rights: Rights,
        badge: Badge,
        dest: Option<Handle>,
    ) -> Result<Handle, Error> {
        ostd::cap::mint(src, rights, badge, dest)
    }

    fn delete(&mut self, h: Handle) -> Result<(), Error> {
        ostd::cap::delete(h)
    }
}

// Copyright (C) 2019 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Manage virtual device's legacy interrupts based on Linux KVM framework.
//!
//! On x86 platforms, legacy interrupts are those managed by the Master PIC, the slave PIC and
//! IOAPICs.

use super::*;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Maximum number of legacy interrupts supported.
pub const MAX_LEGACY_IRQS: u32 = 24;

pub(super) struct LegacyIrq {
    base: u32,
    vmfd: Arc<VmFd>,
    irqfd: EventFd,
    status: AtomicUsize,
}

impl LegacyIrq {
    #[allow(clippy::new_ret_no_self)]
    pub(super) fn new(
        base: InterruptIndex,
        count: InterruptIndex,
        vmfd: Arc<VmFd>,
        _routes: Arc<KvmIrqRouting>,
    ) -> Result<Arc<dyn InterruptSourceGroup>> {
        if count != 1 {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }

        if base >= MAX_LEGACY_IRQS {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }

        Ok(Arc::new(LegacyIrq {
            base,
            vmfd,
            irqfd: EventFd::new(0)?,
            status: AtomicUsize::new(0),
        }))
    }
}

impl InterruptSourceGroup for LegacyIrq {
    fn get_type(&self) -> InterruptSourceType {
        InterruptSourceType::LegacyIrq
    }

    fn len(&self) -> u32 {
        1
    }

    fn get_base(&self) -> u32 {
        self.base
    }

    fn get_irqfd(&self, index: InterruptIndex) -> Option<&EventFd> {
        if index != 0 {
            None
        } else {
            Some(&self.irqfd)
        }
    }

    fn enable(&self, configs: &[InterruptSourceConfig]) -> Result<()> {
        if configs.len() != 1 {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }
        // The IRQ routings for legacy IRQs have been configured during
        // KvmIrqManager::initialize(), so only need to register irqfd to the KVM driver.
        self.vmfd.register_irqfd(self.irqfd.as_raw_fd(), self.base)
    }

    fn disable(&self) -> Result<()> {
        self.vmfd
            .unregister_irqfd(self.irqfd.as_raw_fd(), self.base)
    }

    fn modify(&self, index: InterruptIndex, _config: &InterruptSourceConfig) -> Result<()> {
        // For legacy interrupts, the routing configuration is managed by the PIC/IOAPIC interrupt
        // controller drivers, so nothing to do here.
        if index != 0 {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }
        Ok(())
    }

    fn trigger(&self, index: InterruptIndex, flags: u32) -> Result<()> {
        if index != 0 {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }
        // Set interrupt status bits before writing to the irqfd.
        self.status.fetch_or(flags as usize, Ordering::SeqCst);
        self.irqfd.write(1)
    }

    fn ack(&self, index: InterruptIndex, flags: u32) -> Result<()> {
        if index != 0 {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }
        // Clear interrupt status bits.
        self.status.fetch_and(!(flags as usize), Ordering::SeqCst);
        Ok(())
    }

    fn get_flags(&self, index: InterruptIndex) -> u32 {
        if index == 0 {
            self.status.load(Ordering::SeqCst) as u32
        } else {
            0
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use kvm_ioctls::{Kvm, VmFd};

    fn create_vm_fd() -> VmFd {
        let kvm = Kvm::new().unwrap();
        kvm.create_vm().unwrap()
    }

    #[test]
    fn test_legacy_interrupt_group() {
        let vmfd = Arc::new(create_vm_fd());
        let rounting = Arc::new(KvmIrqRouting::new(vmfd.clone()));
        let base = 0;
        let count = 1;
        let group = LegacyIrq::new(base, count, vmfd.clone(), rounting.clone()).unwrap();

        let mut legacy_fds = Vec::with_capacity(1);
        legacy_fds.push(InterruptSourceConfig::LegacyIrq(LegacyIrqSourceConfig {}));

        match group.get_type() {
            InterruptSourceType::LegacyIrq => {}
            _ => {
                panic!();
            }
        }
        assert_eq!(group.len(), 1);
        assert_eq!(group.get_base(), base);
        assert!(group.enable(&legacy_fds).is_ok());
        assert!(group.get_irqfd(0).unwrap().write(1).is_ok());
        assert!(group.trigger(0, 0x168).is_ok());
        assert!(group.ack(0, 0x168).is_ok());
        assert!(group.trigger(1, 0x168).is_err());
        assert!(group.ack(1, 0x168).is_err());
        assert!(group
            .modify(
                0,
                &InterruptSourceConfig::LegacyIrq(LegacyIrqSourceConfig {})
            )
            .is_ok());
        assert!(group.disable().is_ok());

        assert!(LegacyIrq::new(base, 2, vmfd.clone(), rounting.clone()).is_err());
        assert!(LegacyIrq::new(110, 1, vmfd.clone(), rounting.clone()).is_err());
    }
}

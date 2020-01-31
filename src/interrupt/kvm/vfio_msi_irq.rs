// Copyright (C) 2019-2020 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

//! Manage virtual device's PCI MSIx/Generic MSI interrupts based on Linux KVM and VFIO framework.
//!
//! The InterruptSourceGroup trait provides methods to inject virtual device interrupts into the
//! target virtual machine, so it's a type of interrupt event sink and doesn't handle the way to
//! generate interrupt events. On the other hand, a VFIO device may generate interrupt events, so
//! it's a type interrupt event source.
//! There are special optimizations to deliver an interrupt from a VFIO device to a virutal machine.
//! - Basic Mode. The virtual device driver register and eventfd to the VFIO driver, register
//!   another irqfd to the KVM driver, and relays events from the eventfd to the irqfd. This is
//!   not optimal for performance because every interrupt will cause a round-trip into the
//!   userspace.
//! - Better Mode. The virtual device driver creates an irqfd, and register the irqfd to both the
//!   VFIO driver and KVM driver. So an interrupt event will be relayed but the host kernel, but
//!   it still causes VMExit for each interrupt.
//! - Best Mode. On x86 platforms with Posted Interrupt capability, the hardware could help to
//!   deliver an hardware interrupt to a specific virtual machine, bypass the host kernel.

use vfio_ioctls::VfioError;

use super::msi_generic::{create_msi_routing_entries, new_msi_routing_entry, MsiConfig};
use super::*;

pub(super) struct VfioMsiIrq {
    base: InterruptIndex,
    count: InterruptIndex,
    vmfd: Arc<VmFd>,
    irq_routing: Arc<KvmIrqRouting>,
    vfio_device: Arc<VfioDevice>,
    vfio_index: u32,
    msi_configs: Vec<MsiConfig>,
}

impl VfioMsiIrq {
    #[allow(clippy::new_ret_no_self)]
    pub(super) fn new(
        base: InterruptIndex,
        count: InterruptIndex,
        max_msi_irqs: InterruptIndex,
        vmfd: Arc<VmFd>,
        irq_routing: Arc<KvmIrqRouting>,
        vfio_device: Arc<VfioDevice>,
        vfio_index: u32,
    ) -> Result<Self> {
        if count > max_msi_irqs || base >= MAX_IRQS || base + count > MAX_IRQS {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }
        match vfio_device.get_irq_info(vfio_index) {
            Some(ref info) => {
                if info.count < count {
                    return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
                }
            }
            None => return Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
        }

        let mut msi_configs = Vec::with_capacity(count as usize);
        for _ in 0..count {
            msi_configs.push(MsiConfig::new());
        }

        Ok(VfioMsiIrq {
            base,
            count,
            vmfd,
            irq_routing,
            vfio_device,
            vfio_index,
            msi_configs,
        })
    }
}

impl InterruptSourceGroup for VfioMsiIrq {
    fn interrupt_type(&self) -> InterruptSourceType {
        InterruptSourceType::VfioMsiIrq(self.vfio_device.clone(), self.vfio_index)
    }

    fn len(&self) -> u32 {
        self.count
    }

    fn base(&self) -> u32 {
        self.base
    }

    fn enable(&self, configs: &[InterruptSourceConfig]) -> Result<()> {
        if configs.len() != self.count as usize {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }

        // First add IRQ routings for all the MSI interrupts.
        let entries = create_msi_routing_entries(self.base, configs)?;
        self.irq_routing.add(&entries)?;

        // Then register irqfds to the KVM module.
        for i in 0..self.count {
            let irqfd = &self.msi_configs[i as usize].irqfd;
            self.vmfd
                .register_irqfd(irqfd, self.base + i)
                .map_err(from_sys_util_errno)?;
        }

        // At last configure the VFIO hardware device.
        let mut fds = Vec::with_capacity(self.count as usize);
        for i in 0..self.count {
            fds.push(&self.msi_configs[i as usize].irqfd);
        }
        self.vfio_device
            .enable_irq(self.vfio_index, fds)
            .map_err(map_vfio_error)?;

        Ok(())
    }

    fn disable(&self) -> Result<()> {
        // First disable interrupts from the VFIO hardware device
        self.vfio_device
            .disable_irq(self.vfio_index)
            .map_err(map_vfio_error)?;

        // Then unregister all irqfds, so it won't trigger anymore.
        for i in 0..self.count {
            let irqfd = &self.msi_configs[i as usize].irqfd;
            self.vmfd
                .unregister_irqfd(irqfd, self.base + i)
                .map_err(from_sys_util_errno)?;
        }

        // At last tear down the IRQ routings for all the MSI interrupts.
        let mut entries = Vec::with_capacity(self.count as usize);
        for i in 0..self.count {
            // Safe to unwrap because there's no legal way to break the mutex.
            let msicfg = self.msi_configs[i as usize].config.lock().unwrap();
            let entry = new_msi_routing_entry(self.base + i, &*msicfg);
            entries.push(entry);
        }
        self.irq_routing.remove(&entries)?;

        Ok(())
    }

    fn update(&self, index: InterruptIndex, config: &InterruptSourceConfig) -> Result<()> {
        if index >= self.count {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }

        if let InterruptSourceConfig::MsiIrq(ref cfg) = config {
            // Safe to unwrap because there's no legal way to break the mutex.
            let entry = {
                let mut msicfg = self.msi_configs[index as usize].config.lock().unwrap();
                msicfg.high_addr = cfg.high_addr;
                msicfg.low_addr = cfg.low_addr;
                msicfg.data = cfg.data;

                // Only need to update the KVM IRQ routings, no need to touch the VFIO device.
                new_msi_routing_entry(self.base + index, &*msicfg)
            };
            self.irq_routing.modify(&entry)
        } else {
            Err(std::io::Error::from_raw_os_error(libc::EINVAL))
        }
    }

    fn notifier(&self, index: InterruptIndex) -> Option<&EventFd> {
        if index >= self.count {
            None
        } else {
            let msi_config = &self.msi_configs[index as usize];
            Some(&msi_config.irqfd)
        }
    }

    fn trigger(&self, index: InterruptIndex) -> Result<()> {
        // Assume that the caller will maintain the interrupt states and only call this function
        // when suitable.
        if index >= self.count {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }
        self.vfio_device
            .trigger_irq(self.vfio_index, index)
            .map_err(map_vfio_error)
    }
}

impl std::fmt::Debug for VfioMsiIrq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "VFIO MSI Irq, base {}, vfio_index {} ",
            self.base, self.vfio_index
        )
    }
}

fn map_vfio_error(err: VfioError) -> std::io::Error {
    match err {
        VfioError::OpenContainer(e) => e,
        VfioError::OpenGroup(e, _f) => e,
        VfioError::KvmSetDeviceAttr(e) => from_sys_util_errno(e),
        _ => std::io::Error::from_raw_os_error(libc::EIO),
    }
}

// Following unit test cases depend on hardware configuration, disabled by default.
#[cfg(test_disabled)]
mod test {
    use super::*;
    use kvm_ioctls::{DeviceFd, Kvm, VmFd};
    use std::path::Path;
    use vfio_ioctls::{VfioContainer, VfioDevice};

    const VFIO_PCI_INTX_IRQ_INDEX: u32 = 0;
    const VFIO_PCI_MSI_IRQ_INDEX: u32 = 1;
    const VFIO_PCI_MSIX_IRQ_INDEX: u32 = 2;

    const BASE: u32 = 0;

    fn create_vm_fd() -> VmFd {
        let kvm = Kvm::new().unwrap();
        kvm.create_vm().unwrap()
    }

    fn create_kvm_device(vm: Arc<VmFd>) -> DeviceFd {
        let mut vfio_dev = kvm_bindings::kvm_create_device {
            type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_VFIO,
            fd: 0,
            flags: 0,
        };

        vm.create_device(&mut vfio_dev).unwrap()
    }

    fn vfio_msi_group_prepare(
        vfio_index: u32,
        pic_sys_path: &str,
    ) -> (Arc<dyn InterruptSourceGroup>, u32) {
        let vmfd = Arc::new(create_vm_fd());
        assert!(vmfd.create_irq_chip().is_ok());
        let kvm_device = Arc::new(create_kvm_device(vmfd.clone()));
        let sysfspath_eth1: &Path = Path::new(pic_sys_path);
        let container = Arc::new(VfioContainer::new(kvm_device).unwrap());
        let vfio_device = Arc::new(
            VfioDevice::new(sysfspath_eth1, container)
                .map_err(|err| println!("{}", err))
                .unwrap(),
        );

        let count = match vfio_device.get_irq_info(vfio_index) {
            Some(ref info) => info.count,
            None => 0,
        };

        let rounting = Arc::new(KvmIrqRouting::new(vmfd.clone()));

        assert!(VfioMsiIrq::new(
            BASE,
            33,
            32,
            vmfd.clone(),
            rounting.clone(),
            vfio_device.clone(),
            vfio_index
        )
        .is_err());
        assert!(VfioMsiIrq::new(
            1100,
            1,
            32,
            vmfd.clone(),
            rounting.clone(),
            vfio_device.clone(),
            vfio_index
        )
        .is_err());
        (
            Arc::new(
                VfioMsiIrq::new(
                    BASE,
                    count,
                    32,
                    vmfd.clone(),
                    rounting.clone(),
                    vfio_device.clone(),
                    vfio_index,
                )
                .unwrap(),
            ),
            count,
        )
    }

    fn vfio_msi_interrupt_group_opt(group: Arc<dyn InterruptSourceGroup>, count: u32, index: u32) {
        let mmio_base: u32 = 0xd000_0000;
        let mut msi_fds: Vec<InterruptSourceConfig> = Vec::with_capacity(count as usize);
        if index == VFIO_PCI_INTX_IRQ_INDEX {
            msi_fds.push(InterruptSourceConfig::LegacyIrq(LegacyIrqSourceConfig {}));
        } else {
            for i in 0..count {
                let msi_source_config = MsiIrqSourceConfig {
                    high_addr: 0,
                    low_addr: mmio_base + i * 0x1000,
                    data: 0x1000,
                };
                msi_fds.push(InterruptSourceConfig::MsiIrq(msi_source_config));
            }
        }
        assert!(group.enable(&msi_fds).is_ok());
        assert_eq!(group.len(), count);
        assert_eq!(group.base(), BASE);

        for i in 0..count {
            assert!(group.irqfd(i).unwrap().write(1).is_ok());
            assert!(group.trigger(i, 0x168).is_err());
            assert!(group.trigger(i, 0).is_ok());
            assert!(group.ack(i, 0x168).is_err());
            assert!(group.ack(i, 0).is_ok());

            if index == VFIO_PCI_INTX_IRQ_INDEX {
                assert!(group
                    .update(
                        0,
                        &InterruptSourceConfig::LegacyIrq(LegacyIrqSourceConfig {})
                    )
                    .is_ok());
            } else {
                let msi_source_config = MsiIrqSourceConfig {
                    high_addr: 0,
                    low_addr: mmio_base + i * 0x1000,
                    data: i + 0x1000,
                };
                assert!(group
                    .update(i, &InterruptSourceConfig::MsiIrq(msi_source_config))
                    .is_ok());
            }
        }
        assert!(group.trigger(33, 0x168).is_err());
        assert!(group.ack(33, 0x168).is_err());
        assert!(group.disable().is_ok());
    }

    #[test]
    fn test_vfio_msi_interrupt_group_intx() {
        let (group0, count) = vfio_msi_group_prepare(
            VFIO_PCI_INTX_IRQ_INDEX,
            "/sys/bus/pci/devices/0000:5c:00.0/",
        );
        if count != 0 {
            vfio_msi_interrupt_group_opt(group0, count, VFIO_PCI_INTX_IRQ_INDEX);
        }
        let (group1, count) = vfio_msi_group_prepare(
            VFIO_PCI_INTX_IRQ_INDEX,
            "/sys/bus/pci/devices/0000:5d:00.0/",
        );
        if count != 0 {
            vfio_msi_interrupt_group_opt(group1, count, VFIO_PCI_INTX_IRQ_INDEX);
        }
    }

    #[test]
    fn test_vfio_msi_interrupt_group_msi() {
        let (group0, count) =
            vfio_msi_group_prepare(VFIO_PCI_MSI_IRQ_INDEX, "/sys/bus/pci/devices/0000:5c:00.0/");
        if count != 0 {
            vfio_msi_interrupt_group_opt(group0, count, VFIO_PCI_MSI_IRQ_INDEX);
        }
        let (group1, count) =
            vfio_msi_group_prepare(VFIO_PCI_MSI_IRQ_INDEX, "/sys/bus/pci/devices/0000:5d:00.0/");
        if count != 0 {
            vfio_msi_interrupt_group_opt(group1, count, VFIO_PCI_MSI_IRQ_INDEX);
        }
    }

    #[test]
    #[ignore]
    fn test_vfio_msi_interrupt_group_msix() {
        let (group0, count) = vfio_msi_group_prepare(
            VFIO_PCI_MSIX_IRQ_INDEX,
            "/sys/bus/pci/devices/0000:5c:00.0/",
        );
        if count != 0 {
            vfio_msi_interrupt_group_opt(group0, count, VFIO_PCI_MSIX_IRQ_INDEX);
        }
        let (group1, count) = vfio_msi_group_prepare(
            VFIO_PCI_MSIX_IRQ_INDEX,
            "/sys/bus/pci/devices/0000:5d:00.0/",
        );
        if count != 0 {
            vfio_msi_interrupt_group_opt(group1, count, VFIO_PCI_MSIX_IRQ_INDEX);
        }
    }
}

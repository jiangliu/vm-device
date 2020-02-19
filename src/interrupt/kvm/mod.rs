// Copyright (C) 2019 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Manage virtual device's interrupts based on the Linux KVM framework.
//!
//! When updaing KVM IRQ routing by ioctl(KVM_SET_GSI_ROUTING), all interrupts of the virtual
//! machine must be updated all together. The [KvmIrqRouting](struct.KvmIrqRouting.html)
//! structure is to maintain the global interrupt routing table.
//!
//! It deserves a good documentation about the way that KVM based vmms manages interrupts.
//! From the KVM hypervisor side, it provides three mechanism to support injecting interrupts into
//! guests:
//! 1) Irqfd. When data is written to an irqfd, it triggers KVM to inject an interrupt into guest.
//! 2) Irq routing. Irq routing determines the way to inject an irq into guest.
//! 3) Signal MSI. Vmm can inject an MSI interrupt into guest by issuing KVM_SIGNAL_MSI ioctl.
//!
//! Most VMMs use irqfd + irq routing to support interrupt injecting, so we will focus on this mode.
//! The flow to enable interrupt injecting is:
//! 1) VMM creates an irqfd
//! 2) VMM invokes KVM_IRQFD to bind the irqfd to an interrupt source
//! 3) VMM invokes KVM_SET_GSI_ROUTING to configure the way to inject the interrupt into guest
//! 4) device backend driver writes to the irqfd
//! 5) an interurpt is injected into the guest
//!
//! So far so good, right? Let's move on to mask/unmask/get_pending_state. That's the real tough
//! part. To support mask/unmask/get_peding_state, we must have a way to break the interrupt
//! delivery chain and maintain the pending state. Let's see how it's implemented by each VMM.
//! - Firecracker. It's very simple, it doesn't support mask/unmask/get_pending_state at all.
//! - Cloud Hypervisor. It builds the interrupt delivery path as:
//!    vhost-backend-driver -> EeventFd -> CLH -> Irqfd -> Irqrouting -> Guest OS
//!   It also maintains a masked/pending pair for each interrupt. When masking an interrupt, it
//!   sets the masked flag and remove IrqRouting for the interrupt.
//!   The CLH design has two shortcomings:
//!   - it's inefficient for the hot interrupt delivery path.
//!   - it may lose in-flight interrupts after removing IRQ routing entry for an interrupt due irqfd
//!     implementation details. Buy me a cup of coffee if you wants to knwo the detail.
//! - Qemu. Qemu has a smart design, which supports:
//!   - A fast path: driver -> irqfd -> Irqrouting -> Guest OS
//!   - A slow path: driver -> eventfd -> qemu -> irqfd -> Irqrouting -> Guest OS
//!   When masking an interrupt, it switches from fast path to slow path and vice versa when
//!   unmasking an interrupt.
//! - Dragonball V1. We doesn't support mask/unmask/get_pending_state at all, we have also enhanced
//!   the Virtio MMIO spec, we could use the fast path: driver -> irqfd -> Irqrouting -> Guest OS.
//! - Dragonball V2. When enabling PCI device passthrough, mask/unmask/get_pending_state is a must
//!   to support PCI MSI/MSIx. Unlike Qemu fast path/slow path design, Dragonball V2 implements
//!   mask/unmask/get_pending_state with fast path only. It works as follow:
//!   1) When masking an interrupt, unbind the irqfd from the interrupt by KVM_IRQFD. After that,
//!      all writes to the irqfd won't trigger injecting anymore, and irqfd maintains count for
//!      following write operations.
//!   2) When unmasking an interrupt, bind the irqfd to the interrupt again by KVM_IRQFD. When
//!      rebinding, an interrupt will be injected into guest if the irqfd has a non-zero count.
//!   3) When getting pending state, peek the count of the irqfd. But the irqfd doesn't support
//!      peek, so simulate peek by reading and writing back the count read.
//!   By this design, we use the irqfd count to maintain interrupt pending state, and auto-inject
//!   pending interrupts when rebinding. So we don't need to maintain the pending status bit.
//!
//! Why Qemu needs a slow path but Dragonball V2 doesn't need slow path?
//! Qemu needs to support a broad ranges of guest OSes and all kinds of device drivers. And some
//! legacy device drivers mask/unmask interrupt when handling each interrupt.
//! For Dragonball, we don't expect guest device driver exhibits such behaviors, and treat
//! mask/unmask/get_pending_state as cold path. We optimize for the hot interrupt delivery path
//! and avoid the complexity to introduce a slow path. The penalty is that get_pending_state()
//! will be much more expensive.

use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::{Arc, Mutex};

use kvm_bindings::{kvm_irq_routing, kvm_irq_routing_entry};
use kvm_ioctls::VmFd;

use super::*;

#[cfg(feature = "kvm-legacy-irq")]
mod legacy_irq;
#[cfg(feature = "kvm-legacy-irq")]
use self::legacy_irq::LegacyIrq;
#[cfg(feature = "kvm-msi-generic")]
mod msi_generic;
#[cfg(feature = "kvm-msi-irq")]
mod msi_irq;
#[cfg(feature = "kvm-msi-irq")]
use self::msi_irq::MsiIrq;

#[cfg(feature = "kvm-vfio-msi-irq")]
mod vfio_msi_irq;
#[cfg(feature = "kvm-vfio-msi-irq")]
use self::vfio_msi_irq::VfioMsiIrq;

/// Maximum number of global interrupt sources.
pub const MAX_IRQS: InterruptIndex = 1024;

/// Default maximum number of Message Signaled Interrupts per device.
pub const DEFAULT_MAX_MSI_IRQS_PER_DEVICE: InterruptIndex = 128;

/// Structure to manage interrupt sources for a virtual machine based on the Linux KVM framework.
///
/// The KVM framework provides methods to inject interrupts into the target virtual machines,
/// which uses irqfd to notity the KVM kernel module for injecting interrupts. When the interrupt
/// source, usually a virtual device backend in userspace, writes to the irqfd file descriptor,
/// the KVM kernel module will inject a corresponding interrupt into the target VM according to
/// the IRQ routing configuration.
pub struct KvmIrqManager {
    mgr: Mutex<KvmIrqManagerObj>,
}

impl KvmIrqManager {
    /// Create a new interrupt manager based on the Linux KVM framework.
    ///
    /// # Arguments
    /// * `vmfd`: The KVM VM file descriptor, which will be used to access the KVM subsystem.
    pub fn new(vmfd: Arc<VmFd>) -> Self {
        let vmfd2 = vmfd.clone();
        KvmIrqManager {
            mgr: Mutex::new(KvmIrqManagerObj {
                vmfd,
                groups: HashMap::new(),
                routes: Arc::new(KvmIrqRouting::new(vmfd2)),
                max_msi_irqs: DEFAULT_MAX_MSI_IRQS_PER_DEVICE,
            }),
        }
    }

    /// Prepare the interrupt manager for generating interrupts into the target VM.
    pub fn initialize(&self) -> Result<()> {
        // Safe to unwrap because there's no legal way to break the mutex.
        let mgr = self.mgr.lock().unwrap();
        mgr.initialize()
    }

    /// Set maximum supported MSI interrupts per device.
    pub fn set_max_msi_irqs(&self, max_msi_irqs: InterruptIndex) {
        let mut mgr = self.mgr.lock().unwrap();
        mgr.max_msi_irqs = max_msi_irqs;
    }
}

impl InterruptManager for KvmIrqManager {
    fn create_group(
        &self,
        ty: InterruptSourceType,
        base: InterruptIndex,
        count: u32,
    ) -> Result<Arc<Box<dyn InterruptSourceGroup>>> {
        // Safe to unwrap because there's no legal way to break the mutex.
        let mut mgr = self.mgr.lock().unwrap();
        mgr.create_group(ty, base, count)
    }

    fn destroy_group(&self, group: Arc<Box<dyn InterruptSourceGroup>>) -> Result<()> {
        // Safe to unwrap because there's no legal way to break the mutex.
        let mut mgr = self.mgr.lock().unwrap();
        mgr.destroy_group(group)
    }
}

struct KvmIrqManagerObj {
    vmfd: Arc<VmFd>,
    routes: Arc<KvmIrqRouting>,
    groups: HashMap<InterruptIndex, Arc<Box<dyn InterruptSourceGroup>>>,
    max_msi_irqs: InterruptIndex,
}

impl KvmIrqManagerObj {
    fn initialize(&self) -> Result<()> {
        self.routes.initialize()?;
        Ok(())
    }

    fn create_group(
        &mut self,
        ty: InterruptSourceType,
        base: InterruptIndex,
        count: u32,
    ) -> Result<Arc<Box<dyn InterruptSourceGroup>>> {
        #[allow(unreachable_patterns)]
        let group: Arc<Box<dyn InterruptSourceGroup>> = match ty {
            #[cfg(feature = "kvm-legacy-irq")]
            InterruptSourceType::LegacyIrq => Arc::new(Box::new(LegacyIrq::new(
                base,
                count,
                self.vmfd.clone(),
                self.routes.clone(),
            )?)),
            #[cfg(feature = "kvm-msi-irq")]
            InterruptSourceType::MsiIrq => Arc::new(Box::new(MsiIrq::new(
                base,
                count,
                self.max_msi_irqs,
                self.vmfd.clone(),
                self.routes.clone(),
            )?)),
            #[cfg(feature = "kvm-vfio-msi-irq")]
            InterruptSourceType::VfioMsiIrq(vfio_device, vfio_index) => {
                Arc::new(Box::new(VfioMsiIrq::new(
                    base,
                    count,
                    self.max_msi_irqs,
                    self.vmfd.clone(),
                    self.routes.clone(),
                    vfio_device,
                    vfio_index,
                )?))
            }
            _ => return Err(Error::from(ErrorKind::InvalidInput)),
        };

        self.groups.insert(base, group.clone());

        Ok(group)
    }

    fn destroy_group(&mut self, group: Arc<Box<dyn InterruptSourceGroup>>) -> Result<()> {
        self.groups.remove(&group.base());
        Ok(())
    }
}

// Use (entry.type, entry.gsi) as the hash key because entry.gsi can't uniquely identify an
// interrupt source on x86 platforms. The PIC and IOAPIC may share the same GSI on x86 platforms.
fn hash_key(entry: &kvm_irq_routing_entry) -> u64 {
    let type1 = match entry.type_ {
        #[cfg(feature = "kvm-legacy-irq")]
        kvm_bindings::KVM_IRQ_ROUTING_IRQCHIP => unsafe { entry.u.irqchip.irqchip },
        _ => 0u32,
    };
    (u64::from(type1) << 48 | u64::from(entry.type_) << 32) | u64::from(entry.gsi)
}

pub(super) struct KvmIrqRouting {
    vm_fd: Arc<VmFd>,
    routes: Mutex<HashMap<u64, kvm_irq_routing_entry>>,
}

impl KvmIrqRouting {
    pub(super) fn new(vm_fd: Arc<VmFd>) -> Self {
        KvmIrqRouting {
            vm_fd,
            routes: Mutex::new(HashMap::new()),
        }
    }

    pub(super) fn initialize(&self) -> Result<()> {
        // Safe to unwrap because there's no legal way to break the mutex.
        #[allow(unused_mut)]
        let mut routes = self.routes.lock().unwrap();

        #[cfg(feature = "kvm-legacy-irq")]
        LegacyIrq::initialize_legacy(&mut *routes)?;

        self.set_routing(&*routes)
    }

    fn set_routing(&self, routes: &HashMap<u64, kvm_irq_routing_entry>) -> Result<()> {
        // Allocate enough buffer memory.
        let elem_sz = std::mem::size_of::<kvm_irq_routing>();
        let total_sz = std::mem::size_of::<kvm_irq_routing_entry>() * routes.len() + elem_sz;
        let elem_cnt = (total_sz + elem_sz - 1) / elem_sz;
        let mut irq_routings = Vec::<kvm_irq_routing>::with_capacity(elem_cnt);
        irq_routings.resize_with(elem_cnt, Default::default);

        // Prepare the irq_routing header.
        let mut irq_routing = &mut irq_routings[0];
        irq_routing.nr = routes.len() as u32;
        irq_routing.flags = 0;

        // Safe because we have just allocated enough memory above.
        let irq_routing_entries = unsafe { irq_routing.entries.as_mut_slice(routes.len()) };
        for (idx, entry) in routes.values().enumerate() {
            irq_routing_entries[idx] = *entry;
        }

        self.vm_fd
            .set_gsi_routing(irq_routing)
            .map_err(from_sys_util_errno)?;

        Ok(())
    }
}

#[cfg(feature = "kvm-msi-generic")]
impl KvmIrqRouting {
    pub(super) fn add(&self, entries: &[kvm_irq_routing_entry]) -> Result<()> {
        // Safe to unwrap because there's no legal way to break the mutex.
        let mut routes = self.routes.lock().unwrap();
        for entry in entries {
            if entry.gsi >= MAX_IRQS {
                return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
            } else if routes.contains_key(&hash_key(entry)) {
                return Err(std::io::Error::from_raw_os_error(libc::EEXIST));
            }
        }

        for entry in entries {
            let _ = routes.insert(hash_key(entry), *entry);
        }
        self.set_routing(&routes)
    }

    pub(super) fn remove(&self, entries: &[kvm_irq_routing_entry]) -> Result<()> {
        // Safe to unwrap because there's no legal way to break the mutex.
        let mut routes = self.routes.lock().unwrap();
        for entry in entries {
            let _ = routes.remove(&hash_key(entry));
        }
        self.set_routing(&routes)
    }

    pub(super) fn modify(&self, entry: &kvm_irq_routing_entry) -> Result<()> {
        // Safe to unwrap because there's no legal way to break the mutex.
        let mut routes = self.routes.lock().unwrap();
        if !routes.contains_key(&hash_key(entry)) {
            return Err(std::io::Error::from_raw_os_error(libc::ENOENT));
        }

        let _ = routes.insert(hash_key(entry), *entry);
        self.set_routing(&routes)
    }
}

/// Helper function convert from vmm_sys_util::errno::Error to std::io::Error.
pub fn from_sys_util_errno(e: vmm_sys_util::errno::Error) -> std::io::Error {
    std::io::Error::from_raw_os_error(e.errno())
}

#[cfg(any(target = "x86", target = "x86_64"))]
#[cfg(test)]
mod test {
    use super::*;
    use kvm_ioctls::{Kvm, VmFd};

    //const VFIO_PCI_MSI_IRQ_INDEX: u32 = 1;

    fn create_vm_fd() -> VmFd {
        let kvm = Kvm::new().unwrap();
        kvm.create_vm().unwrap()
    }

    fn create_irq_group(
        manager: Arc<KvmIrqManager>,
        _vmfd: Arc<VmFd>,
    ) -> Arc<Box<dyn InterruptSourceGroup>> {
        let base = 0;
        let count = 1;

        manager
            .create_group(InterruptSourceType::LegacyIrq, base, count)
            .unwrap()
    }

    fn create_msi_group(
        manager: Arc<KvmIrqManager>,
        _vmfd: Arc<VmFd>,
    ) -> Arc<Box<dyn InterruptSourceGroup>> {
        let base = 168;
        let count = 32;

        manager
            .create_group(InterruptSourceType::MsiIrq, base, count)
            .unwrap()
    }

    const MASTER_PIC: usize = 7;
    const SLAVE_PIC: usize = 8;
    const IOAPIC: usize = 23;

    #[test]
    fn test_create_kvmirqmanager() {
        let vmfd = Arc::new(create_vm_fd());
        let manager = KvmIrqManager::new(vmfd.clone());
        assert!(vmfd.create_irq_chip().is_ok());
        assert!(manager.initialize().is_ok());
    }

    #[test]
    fn test_kvmirqmanager_opt() {
        let vmfd = Arc::new(create_vm_fd());
        assert!(vmfd.create_irq_chip().is_ok());
        let manager = Arc::new(KvmIrqManager::new(vmfd.clone()));
        assert!(manager.initialize().is_ok());
        //irq
        let group = create_irq_group(manager.clone(), vmfd.clone());
        let _ = group.clone();
        assert!(manager.destroy_group(group).is_ok());
        //msi
        let group = create_msi_group(manager.clone(), vmfd.clone());
        let _ = group.clone();
        assert!(manager.destroy_group(group).is_ok());
    }

    #[test]
    fn test_irqrouting_initialize_legacy() {
        let vmfd = Arc::new(create_vm_fd());
        let routing = KvmIrqRouting::new(vmfd.clone());
        assert!(routing.initialize().is_err());
        assert!(vmfd.create_irq_chip().is_ok());
        assert!(routing.initialize().is_ok());
        let routes = &routing.routes.lock().unwrap();
        assert_eq!(routes.len(), MASTER_PIC + SLAVE_PIC + IOAPIC);
    }

    #[test]
    fn test_routing_opt() {
        // pub(super) fn modify(&self, entry: &kvm_irq_routing_entry) -> Result<()> {
        let vmfd = Arc::new(create_vm_fd());
        let routing = KvmIrqRouting::new(vmfd.clone());
        assert!(routing.initialize().is_err());
        assert!(vmfd.create_irq_chip().is_ok());
        assert!(routing.initialize().is_ok());

        let mut entry = kvm_irq_routing_entry {
            gsi: 8,
            type_: KVM_IRQ_ROUTING_IRQCHIP,
            ..Default::default()
        };

        // Safe because we are initializing all fields of the `irqchip` struct.
        unsafe {
            entry.u.irqchip.irqchip = 0;
            entry.u.irqchip.pin = 3;
        }

        let entrys = vec![entry.clone()];

        assert!(routing.modify(&entry).is_err());
        assert!(routing.add(&entrys).is_ok());
        unsafe {
            entry.u.irqchip.pin = 4;
        }
        assert!(routing.modify(&entry).is_ok());
        assert!(routing.remove(&entrys).is_ok());
        assert!(routing.modify(&entry).is_err());
    }

    #[test]
    fn test_routing_commit() {
        let vmfd = Arc::new(create_vm_fd());
        let routing = KvmIrqRouting::new(vmfd.clone());

        assert!(routing.initialize().is_err());
        assert!(vmfd.create_irq_chip().is_ok());
        assert!(routing.initialize().is_ok());

        let mut entry = kvm_irq_routing_entry {
            gsi: 8,
            type_: KVM_IRQ_ROUTING_IRQCHIP,
            ..Default::default()
        };
        unsafe {
            entry.u.irqchip.irqchip = 0;
            entry.u.irqchip.pin = 3;
        }

        routing
            .routes
            .lock()
            .unwrap()
            .insert(hash_key(&entry), entry);
        let routes = routing.routes.lock().unwrap();
        assert!(routing.commit(&routes).is_ok());
    }

    #[test]
    fn test_has_key() {
        let gsi = 4;
        let mut entry = kvm_irq_routing_entry {
            gsi,
            type_: KVM_IRQ_ROUTING_IRQCHIP,
            ..Default::default()
        };
        // Safe because we are initializing all fields of the `irqchip` struct.
        unsafe {
            entry.u.irqchip.irqchip = KVM_IRQCHIP_PIC_MASTER;
            entry.u.irqchip.pin = gsi;
        }
        assert_eq!(hash_key(&entry), 0x0001_0000_0004);
    }
}

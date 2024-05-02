// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//            Virtio Structure PCI Capabilities
/*             +-------------+
               |--cap_vndr---| ------------> Read first cap_vndr value at 0x34,if the value is 0x09 it is capabilities
               |--cap_next---| -----------------+ cap_next
               |--cap_len----|                  |
               |--cfg_type---|                  |
               |----bar------|                  |
               |--padding[3]-|                  |
 +-----------  |--offset-----|                  |
 | +---------  |--length-----|                  |
 | |           |             |                  |
 | |           |--cap_vndr---| <----------------+
 | |           |--cap_next---| -----------------+ cap_next
 | |           |     ...     |                  |
 | | +-------  |--offset-----|                  |
 | | | +-----  |--length-----|                  |
 | | | |       |             |                  |
 | | | |       |--cap_vndr---| <----------------+
 | | | |       |--cap_next---|
 | | | |       |     ...     |
 | | | |       |--offset-----|
 | | | |       |--length-----|
 | | | |
 | | | |
 | | | |       Address = device.bars[usize::from(bar)].address;
 | | | |
 | | | |       +-------------+ <= Address
 | | | |       |             |   |-- offset
 +---------->  |-------------| <-+
   | | |       |             |   |
   | | |       |   region    |   |-- length
   | | |       |             |   |
   +-------->  |-------------| <-+
     | |
     | |
     | |       +-------------+ <= Address
     | |       |             |   |-- offset
     + ----->  |-------------| <-+
       |       |             |   |
       |       |   region    |   |-- length
       |       |             |   |
       +---->  |-------------| <-+

            Checked Items:
                1. address + offset should not overflow.
                2. address + offset + length should not overflow.
                3. each [address, address + offset + length] should not overlap.
                4. offset + length should be smaller than BAR size allocated by hardware.
                5. offset + length should be smaller than the expected data structure size,
                    if the data structure is known. If the structure is device specific and unknown here,
                    the check should be added to the device specific driver when the device driver consumes the data.
                6. [address, address + offset + length] region does not overlap with DRAM size in TD.

*/

use crate::consts::*;
use crate::mem;
use crate::{Result, VirtioError, VirtioTransport};
use pci::PciDevice;

const VIRTIO_PCI_MAX_CAP_TYPE: usize = 6;

#[allow(clippy::enum_variant_names)]
enum VirtioPciCapabilityType {
    CommonConfig = 1,
    NotifyConfig = 2,
    #[allow(unused)]
    IsrConfig = 3,
    DeviceConfig = 4,
    #[allow(unused)]
    PciConfig = 5,
}

#[derive(Default)]
struct CheckRegionOverlap {
    flag: [bool; VIRTIO_PCI_MAX_CAP_TYPE], // VirtioPciCapabilityType max value
    interval: [[u64; 2]; VIRTIO_PCI_MAX_CAP_TYPE], // VirtioPciCapabilityType max value
}

impl CheckRegionOverlap {
    fn set_region(&mut self, index: usize, base: u64, length: u64) -> Result<()> {
        if index >= VIRTIO_PCI_MAX_CAP_TYPE {
            return Err(VirtioError::InvalidParameter);
        }

        self.flag[index] = true;
        self.interval[index][0] = base;
        self.interval[index][1] = base + length;

        Ok(())
    }
}

#[derive(Default)]
pub struct VirtioPciTransport {
    device: PciDevice,
    region: mem::MemoryRegion,               // common configuration region
    notify_region: mem::MemoryRegion,        // notify region
    notify_off_multiplier: u32,              // from notify config cap
    device_config_region: mem::MemoryRegion, // device specific region
    msix_table: mem::MemoryRegion,
    msix_table_free: u16,
}

impl VirtioPciTransport {
    pub fn new(device: PciDevice) -> VirtioPciTransport {
        VirtioPciTransport {
            device,
            ..Default::default()
        }
    }

    fn set_msix_entry(&mut self, vector: u8) -> Result<u16> {
        if self.msix_table_free == 0 {
            return Err(VirtioError::SetDeviceNotification);
        }

        let msix_index = self.msix_table_free - 1;

        // MSI-X table entry
        // Bits 127-96 	Vector Control (0)
        // Bits 95-64 	Message Data (0)
        // Bits 63-32 	Message Address High (0)
        // Bits 31-0    Message Address Low (0)
        self.msix_table
            .mmio_write_u32(msix_index as u64 * 16, 0xfee0_0000)?;
        self.msix_table
            .mmio_write_u32(msix_index as u64 * 16 + 8, vector as u32)?;
        self.msix_table
            .mmio_write_u32(msix_index as u64 * 16 + 12, 0)?;
        self.msix_table_free -= 1;

        Ok(msix_index)
    }
}

// Common Configuration registers:
/// le32 device_feature_select;     // 0x00 // read-write
/// le32 device_feature;            // 0x04 // read-only for driver
/// le32 driver_feature_select;     // 0x08 // read-write
/// le32 driver_feature;            // 0x0C // read-write
/// le16 msix_config;               // 0x10 // read-write
/// le16 num_queues;                // 0x12 // read-only for driver
/// u8 device_status;               // 0x14 // read-write (driver_status)
/// u8 config_generation;           // 0x15 // read-only for driver
/// ** About a specific virtqueue.
/// le16 queue_select;              // 0x16 // read-write
/// le16 queue_size;                // 0x18 // read-write, power of 2, or 0.
/// le16 queue_msix_vector;         // 0x1A // read-write
/// le16 queue_enable;              // 0x1C // read-write (Ready)
/// le16 queue_notify_off;          // 0x1E // read-only for driver
/// le64 queue_desc;                // 0x20 // read-write
/// le64 queue_avail;               // 0x28 // read-write
/// le64 queue_used;                // 0x30 // read-write
impl VirtioTransport for VirtioPciTransport {
    fn init(&mut self, _device_type: u32) -> Result<()> {
        self.device.init().map_err(|_| VirtioError::IoError)?;
        let mut check_region = CheckRegionOverlap::default();

        let mut cycle_flag = 0usize;
        let mut cycle_list = [0u8; CYCLE_LEN];
        // Read status register
        let status = self.device.read_u16(STATUS_OFFSET);
        let device_id = self.device.read_u16(DEVICE_OFFSET);
        // bit 4 of status is capability bit
        if status & 1 << 4 == 0 {
            return Err(VirtioError::VirtioUnsupportedDevice);
        }

        // capabilities list offset is at 0x34
        let mut cap_next = self.device.read_u8(PCI_CAP_POINTER);

        while cap_next <= u8::MAX - CAP_LEN + 1 && cap_next > 0 {
            if cycle_list.contains(&cap_next) {
                return Err(VirtioError::InvalidParameter);
            }
            cycle_list[cycle_flag] = cap_next;

            let capability = self.device.read_u8(cap_next);
            // vendor specific capability
            if capability == VIRTIO_CAPABILITIES_SPECIFIC {
                // These offsets are into the following structure:
                // struct virtio_pci_cap {
                //         u8 cap_vndr;    /* Generic PCI field: PCI_CAP_ID_VNDR */
                //         u8 cap_next;    /* Generic PCI field: next ptr. */
                //         u8 cap_len;     /* Generic PCI field: capability length */
                //         u8 cfg_type;    /* Identifies the structure. */
                //         u8 bar;         /* Where to find it. */
                //         u8 padding[3];  /* Pad to full dword. */
                //         le32 offset;    /* Offset within bar. */
                //         le32 length;    /* Length of the structure, in bytes. */
                // };

                if cap_next % core::mem::size_of::<u32>() as u8 != 0 {
                    return Err(VirtioError::InvalidParameter);
                }

                let cfg_type = self.device.read_u8(cap_next + VIRTIO_CFG_TYPE_OFFSET);
                #[allow(clippy::disallowed_names)]
                let bar = self.device.read_u8(cap_next + VIRTIO_BAR_OFFSET);
                let offset = self.device.read_u32(cap_next + VIRTIO_CAP_OFFSET);
                let length = self.device.read_u32(cap_next + VIRTIO_CAP_LENGTH_OFFSET);

                if bar > MAX_BARS_INDEX {
                    return Err(VirtioError::InvalidParameter);
                }

                let address = self.device.bars[usize::from(bar)].address;

                if address >> 32 != 0 {
                    if address.checked_add(u64::from(offset)).is_some() {
                        if (address + u64::from(offset))
                            .checked_add(u64::from(length))
                            .is_none()
                        {
                            return Err(VirtioError::InvalidParameter);
                        }
                    } else {
                        return Err(VirtioError::InvalidParameter);
                    }
                } else if (address as u32).checked_add(offset).is_some()
                    && offset.checked_add(length).is_some()
                {
                    if (address as u32 + offset).checked_add(length).is_none() {
                        return Err(VirtioError::InvalidParameter);
                    }
                } else {
                    return Err(VirtioError::InvalidParameter);
                }

                if cfg_type == VirtioPciCapabilityType::CommonConfig as u8 {
                    if address == 0 || length < COMMON_CONFIGURATION_REGISTERS_OFFSET {
                        return Err(VirtioError::InvalidParameter);
                    }
                    check_region.set_region(
                        cfg_type as usize,
                        address + u64::from(offset),
                        u64::from(length),
                    )?;
                    self.region =
                        mem::MemoryRegion::new(address + u64::from(offset), u64::from(length))
                            .ok_or(VirtioError::InvalidParameter)?;
                }

                if cfg_type == VirtioPciCapabilityType::NotifyConfig as u8 {
                    if cap_next == u8::MAX - CAP_LEN + 1 {
                        return Err(VirtioError::InvalidParameter);
                    }
                    if address == 0 || length < core::mem::size_of::<u32>() as u32 {
                        return Err(VirtioError::InvalidParameter);
                    }
                    check_region.set_region(
                        cfg_type as usize,
                        address + u64::from(offset),
                        u64::from(length),
                    )?;
                    self.notify_region =
                        mem::MemoryRegion::new(address + u64::from(offset), u64::from(length))
                            .ok_or(VirtioError::InvalidParameter)?;

                    // struct virtio_pci_notify_cap {
                    //         struct virtio_pci_cap cap;
                    //         le32 notify_off_multiplier; /* Multiplier for queue_notify_off. */
                    // };
                    self.notify_off_multiplier = self.device.read_u32(cap_next + CAP_LEN);
                }

                fn device_length_check(device_id: u16, length: u32) -> Option<u32> {
                    match device_id {
                        NETWORK_CARD => length.checked_sub(NETWORK_DEVICE_LENGTH),
                        BLOCK_DEVICE => length.checked_sub(BLOCK_DEVICE_LENGTH),
                        CONSOLE_DEVICE => length.checked_sub(CONSOLE_DEVICE_LENGTH),
                        MEMORY_BALLOON_DEVICE => length.checked_sub(MEMORY_BALLOON_DEVICE_LENGTH),
                        SCSI_HOST_DEVICE => length.checked_sub(SCSI_HOST_DEVICE_LENGTH),
                        GPU_DEVICE => length.checked_sub(GPU_DEVICE_LENGTH),
                        INPUT_DEVICE => length.checked_sub(INPUT_DEVICE_LENGTH),
                        SOCKET_DEVICE => length.checked_sub(SOCKET_DEVICE_LENGTH),
                        _ => None,
                    }
                }
                if cfg_type == VirtioPciCapabilityType::DeviceConfig as u8 {
                    if device_length_check(device_id, length).is_none() {
                        return Err(VirtioError::InvalidParameter);
                    }

                    if address == 0 {
                        return Err(VirtioError::InvalidParameter);
                    }

                    check_region.set_region(
                        cfg_type as usize,
                        address + u64::from(offset),
                        u64::from(length),
                    )?;
                    self.device_config_region =
                        mem::MemoryRegion::new(address + u64::from(offset), u64::from(length))
                            .ok_or(VirtioError::InvalidParameter)?;
                }

                // Check the integrity of the ISR status and PCI cfg capabilities, but they will not be used.
                if cfg_type == VirtioPciCapabilityType::PciConfig as u8
                    || cfg_type == VirtioPciCapabilityType::IsrConfig as u8
                {
                    check_region.set_region(
                        cfg_type as usize,
                        address + u64::from(offset),
                        u64::from(length),
                    )?;
                }
            } else if capability == MSIX_CAPABILITY_ID {
                let mcr = self.device.read_u16(cap_next + MSIX_MESSAGE_CONTROL_OFFSET);
                let bir = (self.device.read_u32(cap_next + MSIX_BIR_OFFSET) & 0x7) as u8;

                // BIR specifies which BAR is used for the Message Table, which should be less than 6
                if bir as usize >= self.device.bars.len() {
                    return Err(VirtioError::InvalidParameter);
                }

                let table_offset = self.device.read_u32(cap_next + MSIX_BIR_OFFSET) >> 3;
                // Message Control:
                // Bit 15 	Bit 14 	Bits 13-11 	Bits 10-0
                // Enable 	Function Mask 	Reserved 	Table Size
                let table_size = mcr & 0x7ff;

                // Table Offset is an offset into that BAR where the Message Table lives.
                // Note that it is 8-byte aligned - so simply mask BIR.
                if table_offset & 8 != 0 || table_size > MSIX_MAX_VECTORS {
                    return Err(VirtioError::InvalidParameter);
                }

                self.msix_table_free = table_size + 1;
                self.msix_table = mem::MemoryRegion::new(
                    self.device.bars[bir as usize].address + u64::from(table_offset),
                    u64::from(table_size + 1) * 16,
                )
                .ok_or(VirtioError::InvalidParameter)?;

                // Update Message Control to enable MSI-X
                self.device
                    .write_u16(cap_next + MSIX_MESSAGE_CONTROL_OFFSET, mcr | 1 << 15);
            }

            cycle_flag += 1;
            if cycle_flag >= CYCLE_LEN {
                return Err(VirtioError::InvalidParameter);
            }
            cap_next = self.device.read_u8(cap_next + 1)
        }

        // According to virtio-v1.1 section 4.1.4 Virtio Structure PCI Capabilities
        // The virtio device configuration layout includes several structures:
        // Common configuration
        // Notifications
        // ISR Status
        // Device-specific configuration (optional)
        // PCI configuration access
        if check_region.flag[VirtioPciCapabilityType::CommonConfig as usize]
            && check_region.flag[VirtioPciCapabilityType::NotifyConfig as usize]
            && check_region.flag[VirtioPciCapabilityType::IsrConfig as usize]
            && check_region.flag[VirtioPciCapabilityType::PciConfig as usize]
        {
            check_region.interval.sort_by(|a, b| a[0].cmp(&b[0]));
            for i in 1..check_region.interval.len() {
                if check_region.interval[i][0] == 0 || check_region.interval[i][1] == 0 {
                    continue;
                }
                if check_region.interval[i][0] < check_region.interval[i - 1][1] {
                    return Err(VirtioError::InvalidParameter);
                }
            }
        } else {
            return Err(VirtioError::InvalidParameter);
        }

        Ok(())
    }

    fn get_status(&self) -> Result<u8> {
        // device_status: 0x14
        let status = self.region.mmio_read_u8(VIRTIO_DEVICE_STATUS_OFFSET)?;
        Ok(status)
    }

    fn set_status(&self, value: u8) -> Result<()> {
        // device_status: 0x14
        self.region
            .mmio_write_u8(VIRTIO_DEVICE_STATUS_OFFSET, value)?;
        Ok(())
    }

    fn add_status(&self, value: u8) -> Result<()> {
        self.set_status(self.get_status()? | value)
    }

    fn reset(&self) -> Result<()> {
        self.set_status(0)
    }

    fn get_features(&self) -> Result<u64> {
        // device_feature_select: 0x00
        self.region
            .mmio_write_u32(VIRTIO_DEVICE_FEATURE_SELECT_OFFSET, 0)?;
        // device_feature: 0x04
        let mut device_features: u64 =
            u64::from(self.region.mmio_read_u32(VIRTIO_DEVICE_FEATURE_OFFSET)?);
        // device_feature_select: 0x00
        self.region
            .mmio_write_u32(VIRTIO_DEVICE_FEATURE_SELECT_OFFSET, 1)?;
        // device_feature: 0x04
        device_features |=
            u64::from(self.region.mmio_read_u32(VIRTIO_DEVICE_FEATURE_OFFSET)?) << 32;

        Ok(device_features)
    }

    fn set_features(&self, features: u64) -> Result<()> {
        // driver_feature_select: 0x08
        self.region
            .mmio_write_u32(VIRTIO_DRIVER_FEATURE_SELECT_OFFSET, 0)?;
        // driver_feature: 0x0c
        self.region
            .mmio_write_u32(VIRTIO_DRIVER_FEATURE_OFFSET, features as u32)?;
        // driver_feature_select: 0x08
        self.region
            .mmio_write_u32(VIRTIO_DRIVER_FEATURE_SELECT_OFFSET, 1)?;
        // driver_feature: 0x0c
        self.region
            .mmio_write_u32(VIRTIO_DRIVER_FEATURE_OFFSET, (features >> 32) as u32)?;

        Ok(())
    }

    fn set_queue(&self, queue: u16) -> Result<()> {
        // queue_select: 0x16
        self.region
            .mmio_write_u16(VIRTIO_QUEUE_SELECT_OFFSET, queue)?;
        Ok(())
    }

    #[cfg(feature = "fuzz")]
    fn get_queue_max_size(&self) -> Result<u16> {
        Ok(0x18)
    }
    #[cfg(not(feature = "fuzz"))]
    fn get_queue_max_size(&self) -> Result<u16> {
        // queue_size: 0x18
        let queue_size = self.region.mmio_read_u16(VIRTIO_QUEUE_SIZE_OFFSET)?;
        Ok(queue_size)
    }

    fn set_queue_size(&self, queue_size: u16) -> Result<()> {
        // queue_size: 0x18
        self.region
            .mmio_write_u16(VIRTIO_QUEUE_SIZE_OFFSET, queue_size)?;
        Ok(())
    }

    fn set_descriptors_address(&self, addr: u64) -> Result<()> {
        // queue_desc: 0x20
        self.region.mmio_write_u64(VIRTIO_QUEUE_DESC_OFFSET, addr)?;
        Ok(())
    }

    fn set_avail_ring(&self, addr: u64) -> Result<()> {
        // queue_avail: 0x28
        self.region
            .mmio_write_u64(VIRTIO_QUEUE_AVAIL_OFFSET, addr)?;
        Ok(())
    }

    fn set_used_ring(&self, addr: u64) -> Result<()> {
        // queue_used: 0x30
        self.region.mmio_write_u64(VIRTIO_QUEUE_USED_OFFSET, addr)?;
        Ok(())
    }

    fn set_queue_enable(&self) -> Result<()> {
        // queue_enable: 0x1c
        self.region
            .mmio_write_u16(VIRTIO_QUEUE_ENABLE_OFFSET, 0x1)?;
        Ok(())
    }

    fn set_interrupt_vector(&mut self, vector: u8) -> Result<u16> {
        self.set_msix_entry(vector)
    }

    fn set_config_notify(&mut self, index: u16) -> Result<()> {
        self.region
            .mmio_write_u16(VIRTIO_MSIX_CONFIG_OFFSET, index)?;

        let result = self.region.mmio_read_u16(VIRTIO_MSIX_CONFIG_OFFSET)?;
        if result != index {
            return Err(VirtioError::SetDeviceNotification);
        }

        Ok(())
    }

    fn set_queue_notify(&mut self, index: u16) -> Result<()> {
        self.region
            .mmio_write_u16(VIRTIO_QUEUE_MSIX_VECTOR_OFFSET, index)?;

        let result = self.region.mmio_read_u16(VIRTIO_QUEUE_MSIX_VECTOR_OFFSET)?;
        if result != index {
            return Err(VirtioError::SetDeviceNotification);
        }

        Ok(())
    }

    fn notify_queue(&self, queue: u16) -> Result<()> {
        // queue_notify_off: 0x1e
        let queue_notify_off = self.region.mmio_read_u16(VIRTIO_QUEUE_NOTIFY_OFF_OFFSET)?;
        self.notify_region.mmio_write_u32(
            queue_notify_off as u64 * self.notify_off_multiplier as u64,
            u32::from(queue),
        )?;

        Ok(())
    }

    fn read_device_config(&self, offset: u64) -> Result<u32> {
        let config = self.device_config_region.mmio_read_u32(offset)?;
        Ok(config)
    }
}

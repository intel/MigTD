// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

// Specification Definition
// block is defined in https://docs.oasis-open.org/virtio/virtio/v1.1/cs01/virtio-v1.1-cs01.html#x1-1090004
const VIRTIO_COMMON_CONFIGURATION: u8 = 1;
const VIRTIO_CAPABILITIES_SPECIFIC: u8 = 0x09;
const VIRTIO_CFG_TYPE_OFFSET: u8 = 3;
const VIRTIO_BAR_OFFSET: u8 = 4;
const VIRTIO_CAP_OFFSET: u8 = 8;
const VIRTIO_DEVICE_FEATURE_SELECT_OFFSET: usize = 0x0;
const VIRTIO_DEVICE_FEATURE_OFFSET: usize = 0x4;
const VIRTIO_DRIVER_FEATURE_SELECT_OFFSET: usize = 0x8;
const VIRTIO_DRIVER_FEATURE_OFFSET: usize = 0xc;
const VIRTIO_MSIX_CONFIG_OFFSET: usize = 0x10;
const VIRTIO_NUM_QUEUES_OFFSET: usize = 0x12;
const VIRTIO_DEVICE_STATUS_OFFSET: usize = 0x14;
const VIRTIO_CONFIG_GENERATION_OFFSET: usize = 0x15;
const VIRTIO_QUEUE_SELECT_OFFSET: usize = 0x16;
const VIRTIO_QUEUE_SIZE_OFFSET: usize = 0x18;
const VIRTIO_QUEUE_MSIX_VECTOR_OFFSET: usize = 0x1A;
const VIRTIO_QUEUE_ENABLE_OFFSET: usize = 0x1c;
const VIRTIO_QUEUE_NOTIFY_OFF_OFFSET: usize = 0x1e;
const VIRTIO_QUEUE_DESC_OFFSET: usize = 0x20;
const VIRTIO_QUEUE_AVAIL_OFFSET: usize = 0x28;
const VIRTIO_QUEUE_USED_OFFSET: usize = 0x30;

// block is defined in https://wiki.osdev.org/PCI#Base_Address_Registers
const PCI_BAR_START: u16 = 0x10;
const PCI_BAR_END: u16 = 0x24;
const PCI_SPEC_PCI_VAL: u32 = 0xffff_fffc;
const PCI_SPEC_PCI_VAL1: u32 = 0xffff_fff0;
const PCI_CAP_POINTER: u16 = 0x34;

// block is defined in https://docs.oasis-open.org/virtio/virtio/v1.1/cs01/virtio-v1.1-cs01.html#x1-320005
const VIRTIO_DESC_ADDR: usize = 8;
const VIRTIO_DESC_LEN: usize = 4;
const VIRTIO_DESC_FLAGS: usize = 2;
const VIRTIO_DESC_NEXT: usize = 2;

// block is defined in https://docs.oasis-open.org/virtio/virtio/v1.1/cs01/virtio-v1.1-cs01.html#x1-380006
const VIRTIO_AVAIL_FLAGS: usize = 2;
const VIRTIO_AVAIL_IDX: usize = 2;
const VIRTIO_AVAIL_RING_ELEMENT: usize = 2;
const VIRTIO_AVAIL_USED_EVENT: usize = 2;

// block is defined in https://docs.oasis-open.org/virtio/virtio/v1.1/cs01/virtio-v1.1-cs01.html#x1-430008
const VIRTIO_USED_FLAGS: usize = 2;
const VIRTIO_USED_IDX: usize = 2;
const VIRTIO_USED_USEDELEM: usize = 8;
const VIRTIO_USEDELEM_ID: usize = 4;
const VIRTIO_USEDELEM_LEN: usize = 4;
const VIRTIO_USED_AVAIL_EVENT: usize = 2;

// implementation specific
const CAP_NEXT_MAX: u8 = 0xff;
const BUF_LEN: usize = 0x800;

#[derive(Default)]
struct BarAddress {
    bars: [u64; 6],
}

impl BarAddress {
    pub fn read<T: Copy + Clone>(&self, offset: u16) -> T {
        let device = 1;
        pci::ConfigSpacePciEx::read::<T>(0, device, 0, offset)
    }

    pub fn bars(&mut self) {
        let mut current_bar_offset = PCI_BAR_START;
        let mut current_bar = 0;

        //0x24 offset is last bar
        while current_bar_offset < PCI_BAR_END {
            let bar = self.read::<u32>(current_bar_offset);

            // lsb is 1 for I/O space bars
            if bar & 1 == 1 {
                self.bars[current_bar] = u64::from(bar & PCI_SPEC_PCI_VAL);
            } else {
                // bits 2-1 are the type 0 is 32-but, 2 is 64 bit
                match bar >> 1 & 3 {
                    0 => {
                        self.bars[current_bar] = u64::from(bar & PCI_SPEC_PCI_VAL1);
                    }
                    2 => {
                        self.bars[current_bar] = u64::from(bar & PCI_SPEC_PCI_VAL1);
                        current_bar_offset += core::mem::size_of::<u32>() as u16;

                        let bar = self.read::<u32>(current_bar_offset);
                        self.bars[current_bar] += u64::from(bar) << 32;
                    }
                    _ => panic!("Unsupported BAR type"),
                }
            }
            current_bar += 1;
            current_bar_offset += core::mem::size_of::<u32>() as u16;
        }
    }

    pub fn common_addr(&mut self) -> Option<usize> {
        let mut cap_next = self.read::<u8>(PCI_CAP_POINTER);

        while cap_next < CAP_NEXT_MAX && cap_next > 0 {
            // vendor specific capability
            if self.read::<u8>(cap_next.into()) == VIRTIO_CAPABILITIES_SPECIFIC {
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
                let cfg_type = self.read::<u8>((cap_next + VIRTIO_CFG_TYPE_OFFSET).into());
                #[allow(clippy::disallowed_names)]
                let bar = self.read::<u8>((cap_next + VIRTIO_BAR_OFFSET).into());
                let offset = self.read::<u32>((cap_next + VIRTIO_CAP_OFFSET).into());

                if cfg_type == VIRTIO_COMMON_CONFIGURATION {
                    return Some((self.bars[usize::from(bar)] + u64::from(offset)) as usize);
                }
            }
            cap_next = self.read::<u8>((cap_next + 1).into());
        }
        None
    }
}

fn dump_common_single<T: Copy + Clone>(base: usize, offset: usize) -> T {
    #[cfg(feature = "fuzz")]
    {
        unsafe { core::ptr::read_volatile::<T>((base + offset) as *const T) }
    }

    #[cfg(not(feature = "fuzz"))]
    {
        tdx_tdcall::tdx::tdvmcall_mmio_read(base + offset)
    }
}

pub fn dump_config_space() -> (u16, u64, u64, u64) {
    let mut bars_addr = BarAddress::default();
    bars_addr.bars();
    let common_addr = match bars_addr.common_addr() {
        Some(addr) => addr,
        None => panic!("The common config address was not found."),
    };

    log::trace!("common config space\n");
    log::trace!(
        "device_feature_select: {:x}\n",
        dump_common_single::<u32>(common_addr, VIRTIO_DEVICE_FEATURE_SELECT_OFFSET)
    );
    log::trace!(
        "device_feature: {:x}\n",
        dump_common_single::<u32>(common_addr, VIRTIO_DEVICE_FEATURE_OFFSET)
    );
    log::trace!(
        "driver_feature_select: {:x}\n",
        dump_common_single::<u32>(common_addr, VIRTIO_DRIVER_FEATURE_SELECT_OFFSET)
    );
    log::trace!(
        "driver_feature: {:x}\n",
        dump_common_single::<u32>(common_addr, VIRTIO_DRIVER_FEATURE_OFFSET)
    );
    log::trace!(
        "msix_config: {:x}\n",
        dump_common_single::<u16>(common_addr, VIRTIO_MSIX_CONFIG_OFFSET)
    );
    log::trace!(
        "num_queues: {:x}\n",
        dump_common_single::<u16>(common_addr, VIRTIO_NUM_QUEUES_OFFSET)
    );
    log::trace!(
        "device_status: {:x}\n",
        dump_common_single::<u8>(common_addr, VIRTIO_DEVICE_STATUS_OFFSET)
    );
    log::trace!(
        "config_generation: {:x}\n",
        dump_common_single::<u8>(common_addr, VIRTIO_CONFIG_GENERATION_OFFSET)
    );
    log::trace!(
        "queue_select: {:x}\n",
        dump_common_single::<u16>(common_addr, VIRTIO_QUEUE_SELECT_OFFSET)
    );
    log::trace!(
        "queue_size: {:x}\n",
        dump_common_single::<u16>(common_addr, VIRTIO_QUEUE_SIZE_OFFSET)
    );
    log::trace!(
        "queue_msix_vector: {:x}\n",
        dump_common_single::<u16>(common_addr, VIRTIO_QUEUE_MSIX_VECTOR_OFFSET)
    );
    log::trace!(
        "queue_enable: {:x}\n",
        dump_common_single::<u16>(common_addr, VIRTIO_QUEUE_ENABLE_OFFSET)
    );
    log::trace!(
        "queue_notify_off: {:x}\n",
        dump_common_single::<u16>(common_addr, VIRTIO_QUEUE_NOTIFY_OFF_OFFSET)
    );
    log::trace!(
        "queue_desc: {:x}\n",
        dump_common_single::<u64>(common_addr, VIRTIO_QUEUE_DESC_OFFSET)
    );
    log::trace!(
        "queue_avail: {:x}\n",
        dump_common_single::<u64>(common_addr, VIRTIO_QUEUE_AVAIL_OFFSET)
    );
    log::trace!(
        "queue_used: {:x}\n",
        dump_common_single::<u64>(common_addr, VIRTIO_QUEUE_USED_OFFSET)
    );
    (
        dump_common_single::<u16>(common_addr, VIRTIO_QUEUE_SIZE_OFFSET),
        dump_common_single::<u64>(common_addr, VIRTIO_QUEUE_DESC_OFFSET),
        dump_common_single::<u64>(common_addr, VIRTIO_QUEUE_AVAIL_OFFSET),
        dump_common_single::<u64>(common_addr, VIRTIO_QUEUE_USED_OFFSET),
    )
}

pub fn dump_virtioqueue(queue_size: u16, desc: u64, avail: u64, used: u64) {
    // Virtio defintion desc and the length of the array is queue_size
    // addr: Volatile<u64>,
    // len: Volatile<u32>,
    // flags: Volatile<DescFlags>, DescFlags: u16
    // next: Volatile<u16>
    let desc_len = VIRTIO_DESC_ADDR + VIRTIO_DESC_LEN + VIRTIO_DESC_FLAGS + VIRTIO_DESC_NEXT;
    let desc_total_len = desc_len * queue_size as usize;
    // Virtio defintion avail ring and the ring length is queue_size
    // flags: Volatile<u16>,
    // idx: Volatile<u16>,
    // ring: [Volatile<u16>; MAX_QUEUE_SIZE], // actual size: queue_size
    // used_event: Volatile<u16>,             // unused
    let avail_len = (VIRTIO_AVAIL_FLAGS + VIRTIO_AVAIL_IDX + VIRTIO_AVAIL_RING_ELEMENT)
        + VIRTIO_AVAIL_USED_EVENT * queue_size as usize;
    //  Virtio defintion avail ring and the ring length is queue_size
    // flags: Volatile<u16>,
    // idx: Volatile<u16>,
    // ring: [UsedElem; MAX_QUEUE_SIZE], // UsedElem{id: Volatile<u32>,len: Volatile<u32>} actual size: queue_size
    // avail_event: Volatile<u16>,       // unused
    let used_len = (VIRTIO_USED_FLAGS + VIRTIO_USED_IDX + VIRTIO_USED_AVAIL_EVENT)
        + VIRTIO_USED_USEDELEM * queue_size as usize;
    log::trace!("desc\n");
    let mut buf = [0u8; BUF_LEN];
    unsafe {
        for (i, item) in buf.iter_mut().enumerate().take(desc_total_len) {
            *item = core::ptr::read_volatile((desc + i as u64) as *const u8);
        }
    }
    for i in 0..queue_size as usize {
        let buf = &buf[i * desc_len..i * desc_len + desc_len];
        let mut addr = [0u8; VIRTIO_DESC_ADDR];
        let mut len = [0u8; VIRTIO_DESC_LEN];
        let mut flags = [0u8; VIRTIO_DESC_FLAGS];
        let mut next = [0u8; VIRTIO_DESC_NEXT];
        addr.copy_from_slice(&buf[..VIRTIO_DESC_ADDR]);
        let buf = &buf[VIRTIO_DESC_ADDR..];
        len.copy_from_slice(&buf[..VIRTIO_DESC_LEN]);
        let buf = &buf[VIRTIO_DESC_LEN..];
        flags.copy_from_slice(&buf[..VIRTIO_DESC_FLAGS]);
        let buf = &buf[VIRTIO_DESC_FLAGS..];
        next.copy_from_slice(&buf[..VIRTIO_DESC_NEXT]);
        let addr = u64::from_le_bytes(addr);
        let mut len = u32::from_le_bytes(len);
        let flags = u16::from_le_bytes(flags);
        let next = u16::from_le_bytes(next);
        log::trace!(
            "addr: {:x?}, len: {:x}, flags: {:x?}, next: {:x?}\n",
            addr,
            len,
            flags,
            next
        );
        if addr != 0 {
            let mut buf = [0u8; BUF_LEN];
            if len > BUF_LEN as u32 {
                len = BUF_LEN as u32;
            }
            for (i, item) in buf.iter_mut().enumerate().take(len as usize) {
                unsafe {
                    *item = core::ptr::read_volatile((addr + i as u64) as *const u8);
                }
            }
            log::trace!("{:x?}\n", &buf[..len as usize]);
        }
    }

    log::trace!("desc end\n\n");

    log::trace!("avail ring start\n");
    let mut avail_buf = [0; BUF_LEN];
    for (i, item) in avail_buf.iter_mut().enumerate().take(avail_len) {
        unsafe {
            *item = core::ptr::read_volatile((avail + i as u64) as *const u8);
        }
    }
    let mut flags = [0u8; VIRTIO_AVAIL_FLAGS];
    let mut idx = [0u8; VIRTIO_AVAIL_IDX];
    let mut availitem = [0u8; VIRTIO_AVAIL_RING_ELEMENT];
    flags.copy_from_slice(&avail_buf[..VIRTIO_AVAIL_FLAGS]);
    let avail_buf = &avail_buf[VIRTIO_AVAIL_FLAGS..];
    idx.copy_from_slice(&avail_buf[..VIRTIO_AVAIL_IDX]);
    let avail_buf = &avail_buf[VIRTIO_AVAIL_IDX..];
    let flags = u16::from_le_bytes(flags);
    let idx = u16::from_le_bytes(idx);

    log::trace!("avail flags: {:x} avail idx: {:x}\n", flags, idx);
    for i in 0..queue_size as usize {
        availitem.copy_from_slice(
            &avail_buf[i * VIRTIO_AVAIL_RING_ELEMENT
                ..i * VIRTIO_AVAIL_RING_ELEMENT + VIRTIO_AVAIL_RING_ELEMENT],
        );
        log::trace!("avail ring {}: {:x?}\n", i, u16::from_le_bytes(availitem));
    }

    log::trace!("avail ring end\n\n");

    log::trace!("used ring start\n");
    let mut used_buf = [0; BUF_LEN];
    for (i, item) in used_buf.iter_mut().enumerate().take(used_len) {
        unsafe {
            *item = core::ptr::read_volatile((used + i as u64) as *const u8);
        }
    }

    let mut flags = [0; VIRTIO_USED_FLAGS];
    let mut idx = [0; VIRTIO_USED_IDX];
    let mut useditem = [0u8; VIRTIO_USEDELEM_ID];
    flags.copy_from_slice(&used_buf[0..VIRTIO_USED_FLAGS]);
    let used_buf = &used_buf[VIRTIO_USED_FLAGS..];
    idx.copy_from_slice(&used_buf[..VIRTIO_USED_IDX]);
    let used_buf = &used_buf[VIRTIO_USED_IDX..];
    let flags = u16::from_le_bytes(flags);
    let idx = u16::from_le_bytes(idx);

    log::trace!("flags: {:x} idx: {:x}\n", flags, idx);
    for i in 0..queue_size as usize {
        useditem.copy_from_slice(
            &used_buf[i * VIRTIO_USED_USEDELEM..i * VIRTIO_USED_USEDELEM + VIRTIO_USEDELEM_ID],
        );
        log::trace!("used ring:{} id: {:x?} ", i, u32::from_le_bytes(useditem));
        useditem.copy_from_slice(
            &used_buf[i * VIRTIO_USED_USEDELEM + VIRTIO_USEDELEM_ID
                ..i * VIRTIO_USED_USEDELEM + VIRTIO_USEDELEM_ID + VIRTIO_USEDELEM_LEN],
        );

        log::trace!(" len: {:x?}\n", u32::from_le_bytes(useditem));
    }
    log::trace!("used ring end \n\n");
}

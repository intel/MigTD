// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

pub const VIRTIO_SUBSYSTEM_BLOCK: u32 = 2;
pub const VIRTIO_SUBSYSTEM_VSOCK: u32 = 19;

pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;

pub const VIRTIO_STATUS_RESET: u8 = 0;
pub const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
pub const VIRTIO_STATUS_DRIVER: u8 = 2;
pub const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
pub const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
pub const VIRTIO_STATUS_FAILED: u8 = 128;

// implementation specific
pub const COMMON_CONFIGURATION_REGISTERS_OFFSET: u32 = 0x38;
pub const CAP_LEN: u8 = 0x10;
// CYCLE_LEN: cap_next is a u8, the maximum value is 256, the capabilities length is 16,
// and a maximum of 16 capabilities can be placed.
pub const CYCLE_LEN: usize = 0x10;

// block is defined in https://wiki.osdev.org/PCI#Base_Address_Registers
pub const DEVICE_OFFSET: u8 = 0x02;
pub const NETWORK_CARD: u16 = 0x1041;
pub const NETWORK_DEVICE_LENGTH: u32 = 12;
pub const BLOCK_DEVICE: u16 = 0x1042;
pub const BLOCK_DEVICE_LENGTH: u32 = 60;
pub const CONSOLE_DEVICE: u16 = 0x1043;
pub const CONSOLE_DEVICE_LENGTH: u32 = 12;
pub const MEMORY_BALLOON_DEVICE: u16 = 0x1045;
pub const MEMORY_BALLOON_DEVICE_LENGTH: u32 = 8;
pub const SCSI_HOST_DEVICE: u16 = 0x1048;
pub const SCSI_HOST_DEVICE_LENGTH: u32 = 36;
pub const GPU_DEVICE: u16 = 0x1050;
pub const GPU_DEVICE_LENGTH: u32 = 16;
pub const INPUT_DEVICE: u16 = 0x1052;
pub const INPUT_DEVICE_LENGTH: u32 = 294;
pub const SOCKET_DEVICE: u16 = 0x1053;
pub const SOCKET_DEVICE_LENGTH: u32 = 8;
pub const STATUS_OFFSET: u8 = 0x06;
pub const PCI_CAP_POINTER: u8 = 0x34;

// Common Configuration offset
// block is defined in https://docs.oasis-open.org/virtio/virtio/v1.1/cs01/virtio-v1.1-cs01.html#x1-1090004
pub const MAX_BARS_INDEX: u8 = 5;
pub const VIRTIO_CAPABILITIES_SPECIFIC: u8 = 0x09;
pub const VIRTIO_CFG_TYPE_OFFSET: u8 = 3;
pub const VIRTIO_BAR_OFFSET: u8 = 4;
pub const VIRTIO_CAP_OFFSET: u8 = 8;
pub const VIRTIO_CAP_LENGTH_OFFSET: u8 = 12;
pub const VIRTIO_DEVICE_FEATURE_SELECT_OFFSET: u64 = 0x0;
pub const VIRTIO_DEVICE_FEATURE_OFFSET: u64 = 0x04;
pub const VIRTIO_DRIVER_FEATURE_SELECT_OFFSET: u64 = 0x08;
pub const VIRTIO_DRIVER_FEATURE_OFFSET: u64 = 0x0c;
pub const VIRTIO_MSIX_CONFIG_OFFSET: u64 = 0x10;
pub const VIRTIO_DEVICE_STATUS_OFFSET: u64 = 0x14;
pub const VIRTIO_QUEUE_SELECT_OFFSET: u64 = 0x16;
pub const VIRTIO_QUEUE_SIZE_OFFSET: u64 = 0x18;
pub const VIRTIO_QUEUE_MSIX_VECTOR_OFFSET: u64 = 0x1a;
pub const VIRTIO_QUEUE_ENABLE_OFFSET: u64 = 0x1c;
pub const VIRTIO_QUEUE_NOTIFY_OFF_OFFSET: u64 = 0x1e;
pub const VIRTIO_QUEUE_DESC_OFFSET: u64 = 0x20;
pub const VIRTIO_QUEUE_AVAIL_OFFSET: u64 = 0x28;
pub const VIRTIO_QUEUE_USED_OFFSET: u64 = 0x30;

// MSI-X Configuration
pub const MSIX_CAPABILITY_ID: u8 = 0x11;
pub const MSIX_MESSAGE_CONTROL_OFFSET: u8 = 0x2;
pub const MSIX_BIR_OFFSET: u8 = 0x4;
pub const MSIX_MAX_VECTORS: u16 = 0x800;

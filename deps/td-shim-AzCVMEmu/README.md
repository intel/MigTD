# TDX TDCALL TCP Emulation for Azure CVM

This crate provides a drop-in replacement for the original `tdx-tdcall` crate that emulates TDX VMCALL operations using TCP transport. This enables MigTD development and testing in non-TDX environments.

## Architecture

The emulation library:
- **Re-exports all standard tdx-tdcall functions** unchanged for compatibility
- **Emulates only MigTD-specific vmcalls** via TCP transport
- **Maintains the exact same API** as the original tdx-tdcall
- **Uses feature flags** to enable/disable emulation

## Usage

### 1. Building with TCP Emulation

To build MigTD with TCP emulation instead of real TDX vmcalls:

```bash
# Build with AzCVMEmu emulation
cargo image --no-default-features --features stack-guard,vmcall-raw,azcvm-emulation

# Or set in Cargo.toml dependencies
[dependencies.tdx-tdcall]
path = "../deps/td-shim-AzCVMEmu/tdx-tdcall"
```

### 2. Configuration

The TCP emulation connects to a configurable endpoint:

```rust
// Default configuration
TcpEmulationConfig {
    remote_addr: "127.0.0.1:9001",  // TCP server address
    connection_timeout: Duration::from_secs(10),
    operation_timeout: Duration::from_secs(30),
    max_retries: 3,
}
```

### 3. Protocol

The emulation uses a simple TCP protocol with serialized packets:

```rust
struct MigTdTcpPacket {
    operation: MigTdOperation,      // Send/Receive/WaitForRequest/ReportStatus
    mig_request_id: u64,           // Migration context ID
    sequence_id: u32,              // Packet sequence number
    status: u32,                   // Operation status
    data_length: u32,              // Payload length
    payload: Vec<u8>,              // Actual data
}
```

## Emulated Functions

The following TDX MigTD vmcalls are emulated via TCP:

- `tdvmcall_migtd_send()` - Sends data to remote MigTD
- `tdvmcall_migtd_receive()` - Receives data from remote MigTD  
- `tdvmcall_migtd_waitforrequest()` - Waits for migration requests
- `tdvmcall_migtd_reportstatus()` - Reports migration status

All other tdx-tdcall functions pass through to the original implementation.

## Integration with MigTD

To use this emulation in MigTD:

### 1. Update vmcall_raw dependency

In `src/devices/vmcall_raw/Cargo.toml`:

```toml
[dependencies.tdx-tdcall]
# Use emulated version for AzCVMEmu builds
path = "../../../deps/td-shim-AzCVMEmu/tdx-tdcall"

# Or use original for real TDX builds  
# path = "../../../deps/td-shim/tdx-tdcall"
```

### 2. Add build feature

In main `Cargo.toml`:

```toml
[features]
azcvm-emulation = ["vmcall_raw/AzCVMEmu"]
```

### 3. Build commands

```bash
# Real TDX build
cargo image --no-default-features --features stack-guard,vmcall-raw

# AzCVMEmu emulation build  
cargo image --no-default-features --features stack-guard,vmcall-raw,azcvm-emulation
```

## Testing

You can test the emulation by running a simple TCP server that responds to MigTD packets:

```bash
# Start a test server on port 9001
nc -l 9001

# Or use the existing MigTD TCP transport implementation
# in src/devices/tcp_transport as a reference
```

## Benefits

1. **No code changes** to vmcall_raw or other MigTD components
2. **Drop-in replacement** - same API as original tdx-tdcall
3. **Feature-gated** - can switch between real and emulated at build time
4. **Development-friendly** - enables testing without TDX hardware
5. **Clean separation** - emulation code isolated from main MigTD

## Architecture Diagram

```
MigTD vmcall_raw
       ↓
tdx-tdcall (this emulation crate)
       ↓
[Real TDX] OR [TCP Transport]
       ↓
    VMM/Host   ←→   Remote MigTD
```

This design allows the same MigTD code to work in both real TDX environments and emulated TCP environments without any modifications.

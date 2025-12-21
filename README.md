# RustSend

A high-performance TUI-based packet crafting and network security tool written in Rust.

## Overview

RustSend is a powerful command-line tool for network security professionals, penetration testers, and security researchers. It provides an intuitive vim-like interface for crafting and sending custom network packets with real-time response tracking.

## Features

### Protocol Support
- **TCP**: SYN, Connect, FIN, NULL, XMAS, ACK scans with customizable flags
- **UDP**: Standard UDP scanning with service detection
- **ICMP**: Echo requests with proper raw socket support when available
- **HTTP/HTTPS**: Full HTTP request crafting with method, path, and header control
- **DNS**: Query building with support for A, AAAA, MX, TXT, NS, CNAME record types
- **NTP**: Network Time Protocol packet construction

### User Interface
- Vim-style navigation and keybindings
- Which-key style help popup (press `?`)
- Multiple panes for configuration, responses, and packet capture
- Real-time statistics with success rate visualization
- Multi-session support (`Space+n` to create new sessions)

### Performance
- Async/await with Tokio for high throughput
- Configurable worker threads and batch sizes
- Socket reuse and buffer pooling for optimized sending
- Connection timeout controls

### Advanced Features
- Raw socket support with automatic capability detection
- Flood mode for stress testing (`:flood` command)
- Packet templates for common protocols
- TCP flag visualization and custom flag combinations
- Service name lookup for common ports

## Installation

### Prerequisites
- Rust 1.70 or later
- For raw socket features (SYN scan, ICMP): root/sudo privileges or CAP_NET_RAW capability

### Building from Source

```bash
git clone https://github.com/0x00nier/RustSend.git
cd RustSend
cargo build --release
```

### Running

```bash
# Standard mode (connect scans, UDP)
./target/release/rustsend

# With raw socket support (Linux)
sudo ./target/release/rustsend

# Or set capabilities once
sudo setcap cap_net_raw+ep ./target/release/rustsend
./target/release/rustsend
```

## Usage

### Command Line Options

```
rustsend [OPTIONS]

Options:
  -d, --debug              Enable debug logging
  -l, --log-file <PATH>    Log file path [default: rustsend.log]
  -w, --workers <N>        Number of worker threads [default: CPU count]
  -b, --batch-size <N>     Batch size for concurrent sending [default: 1000]
  -t, --timeout <MS>       Connection timeout in milliseconds [default: 3000]
  -H, --host <HOST>        Target host (optional, can be set in TUI)
  -p, --port <PORT>        Target port (optional, can be set in TUI)
  -h, --help               Print help
  -V, --version            Print version
```

### Keybindings

#### Normal Mode
| Key | Action |
|-----|--------|
| `j` / `k` | Scroll down/up in current pane |
| `h` / `l` | Switch to previous/next pane |
| `Ctrl+h/j/k/l` | Directional pane navigation |
| `Tab` / `Shift+Tab` | Cycle through panes |
| `Enter` | Select/toggle current item |
| `s` | Send packet(s) |
| `r` | Retry last failed |
| `c` | Clear logs |
| `i` | Enter Insert mode (edit target) |
| `:` | Enter Command mode |
| `/` | Enter Search mode |
| `?` | Toggle help popup |
| `q` | Quit |

#### Protocol Selection
| Key | Protocol |
|-----|----------|
| `1` | TCP |
| `2` | UDP |
| `3` | ICMP |
| `4` | HTTP |
| `5` | HTTPS |
| `6` | DNS |
| `7` | NTP |

#### Scan Type Selection
| Key | Scan Type |
|-----|-----------|
| `F1` | SYN Scan |
| `F2` | Connect Scan |
| `F3` | FIN Scan |
| `F4` | NULL Scan |
| `F5` | XMAS Scan |
| `F6` | ACK Scan |
| `F7` | UDP Scan |

#### Session Management
| Key Sequence | Action |
|--------------|--------|
| `Space n` | Create new session |
| `Space ]` | Next session |
| `Space [` | Previous session |
| `Space x` | Close current session |

### Commands

Enter command mode with `:` and type:

| Command | Description |
|---------|-------------|
| `:target <host>` | Set target host |
| `:port <port>` | Set target port(s) |
| `:count <n>` | Set packet count |
| `:scan <type>` | Set scan type (syn, connect, fin, etc.) |
| `:send` | Send packets |
| `:flood [rate]` | Start flood mode (optionally limit rate) |
| `:stop` | Stop flood mode |
| `:stats` | Show statistics |
| `:ports top20` | Set top 20 common ports |
| `:ports top100` | Set top 100 common ports |
| `:dns` | Build DNS query packet |
| `:http` | Build HTTP request packet |
| `:clear` | Clear logs and captures |
| `:help` | Show help |
| `:quit` | Exit |

## Architecture

```
src/
  app.rs          - Application state management
  cli.rs          - Command-line argument parsing
  config.rs       - Configuration and protocol definitions
  logging.rs      - Logging configuration with tracing
  main.rs         - Application entry point
  lib.rs          - Library exports for benchmarks

  network/
    mod.rs        - Network module exports
    sender.rs     - Packet sending logic with raw socket support
    raw_socket.rs - Raw socket capability detection
    batch_sender.rs - High-performance batch sending
    packet.rs     - Packet construction (TCP, UDP, ICMP)
    protocols.rs  - Protocol-specific builders (DNS, NTP, SNMP)
    http.rs       - HTTP request/response handling

  tui/
    mod.rs        - Terminal UI main loop
    handler.rs    - Keyboard/mouse event handling

  ui/
    mod.rs        - UI rendering with ratatui
    help.rs       - Help system and key hints
    widgets.rs    - Custom UI widgets
```

## Dependencies

Key external dependencies:

- **tokio** - Async runtime for high-performance I/O
- **ratatui** - Terminal UI framework
- **crossterm** - Cross-platform terminal manipulation
- **pnet** - Raw socket and packet construction
- **clap** - Command-line argument parsing
- **tracing** - Structured logging
- **anyhow** - Error handling
- **chrono** - Timestamp handling
- **parking_lot** - Faster synchronization primitives

## Security Considerations

This tool is designed for authorized security testing and educational purposes:

- Only use against systems you own or have explicit authorization to test
- Raw socket operations require elevated privileges
- Flood mode can generate significant network traffic
- Some scans (SYN, FIN, etc.) may be detected by firewalls/IDS

## Contributing

Contributions are welcome. Please ensure:

1. Code compiles with no warnings (`cargo build` should be clean)
2. All tests pass (`cargo test`)
3. Format code with `cargo fmt`
4. Run clippy checks (`cargo clippy`)

## License

MIT License - See LICENSE file for details.

## Author

RustSend Contributors

---

For bug reports and feature requests, please open an issue on the GitHub repository.

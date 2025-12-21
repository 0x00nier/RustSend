//! Benchmarks for packet building and sending
//!
//! Run with: cargo bench

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use std::net::{IpAddr, Ipv4Addr};

// Import the actual packet building code
use rustsend::network::protocols::{DnsQuery, DnsType, NtpPacket};
use rustsend::network::batch_sender::{BufferPool, PacketBuffer, BatchSender};

fn benchmark_buffer_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer_pool");

    for pool_size in [10, 100, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(pool_size),
            pool_size,
            |b, &size| {
                let pool = BufferPool::new(size, 4096);
                b.iter(|| {
                    let buf = pool.acquire();
                    black_box(&buf);
                    pool.release(buf);
                })
            },
        );
    }

    group.finish();
}

fn benchmark_packet_buffer(c: &mut Criterion) {
    c.bench_function("packet_buffer_new", |b| {
        b.iter(|| {
            let buf = PacketBuffer::new(4096);
            black_box(buf)
        })
    });

    c.bench_function("packet_buffer_write", |b| {
        let mut buf = PacketBuffer::new(4096);
        let data = vec![0u8; 1000];
        b.iter(|| {
            buf.buffer()[..data.len()].copy_from_slice(&data);
            buf.set_len(data.len());
            black_box(buf.as_slice().len())
        })
    });
}

fn benchmark_dns_packet_building(c: &mut Criterion) {
    let mut group = c.benchmark_group("dns_packet");
    group.throughput(Throughput::Elements(1));

    // Benchmark DNS query packet building
    c.bench_function("build_dns_a_query", |b| {
        b.iter(|| {
            let query = DnsQuery::new()
                .add_question("example.com", DnsType::A);
            let packet = query.build();
            black_box(packet.len())
        })
    });

    c.bench_function("build_dns_aaaa_query", |b| {
        b.iter(|| {
            let query = DnsQuery::new()
                .add_question("example.com", DnsType::Aaaa);
            let packet = query.build();
            black_box(packet.len())
        })
    });

    c.bench_function("build_dns_mx_query", |b| {
        b.iter(|| {
            let query = DnsQuery::new()
                .add_question("example.com", DnsType::Mx);
            let packet = query.build();
            black_box(packet.len())
        })
    });

    group.finish();
}

fn benchmark_ntp_packet_building(c: &mut Criterion) {
    c.bench_function("build_ntp_packet", |b| {
        b.iter(|| {
            let ntp = NtpPacket::new();
            let packet = ntp.build();
            black_box(packet.len())
        })
    });
}

fn benchmark_udp_probe_generation(c: &mut Criterion) {
    use rustsend::network::sender::PacketSender;

    let mut group = c.benchmark_group("udp_probes");

    for port in [53u16, 123, 161, 1900, 137, 5060, 69, 80].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(port),
            port,
            |b, &port| {
                b.iter(|| {
                    let probe = PacketSender::get_udp_probe(port);
                    black_box(probe.len())
                })
            },
        );
    }

    group.finish();
}

fn benchmark_batch_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_processing");
    group.sample_size(50);

    for size in [100, 500, 1000, 5000].iter() {
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                // Simulate batch processing with pre-allocated vector
                let mut batch: Vec<u16> = Vec::with_capacity(size);
                for i in 0..size {
                    batch.push(i as u16 + 1);
                }
                black_box(batch.len())
            })
        });
    }

    group.finish();
}

fn benchmark_checksum(c: &mut Criterion) {
    // Benchmark ICMP checksum calculation
    c.bench_function("icmp_checksum_64bytes", |b| {
        let data: Vec<u8> = (0..64).map(|i| i as u8).collect();
        b.iter(|| {
            let mut sum: u32 = 0;
            let mut i = 0;
            while i + 1 < data.len() {
                sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
                i += 2;
            }
            if i < data.len() {
                sum += (data[i] as u32) << 8;
            }
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            black_box(!sum as u16)
        })
    });

    c.bench_function("icmp_checksum_1024bytes", |b| {
        let data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        b.iter(|| {
            let mut sum: u32 = 0;
            let mut i = 0;
            while i + 1 < data.len() {
                sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
                i += 2;
            }
            if i < data.len() {
                sum += (data[i] as u32) << 8;
            }
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            black_box(!sum as u16)
        })
    });
}

fn benchmark_ip_parsing(c: &mut Criterion) {
    c.bench_function("parse_ipv4", |b| {
        let ip_str = "192.168.1.100";
        b.iter(|| {
            let ip: IpAddr = ip_str.parse().unwrap();
            black_box(ip)
        })
    });

    c.bench_function("create_ipv4", |b| {
        b.iter(|| {
            let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
            black_box(ip)
        })
    });
}

criterion_group!(
    benches,
    benchmark_buffer_pool,
    benchmark_packet_buffer,
    benchmark_dns_packet_building,
    benchmark_ntp_packet_building,
    benchmark_udp_probe_generation,
    benchmark_batch_sizes,
    benchmark_checksum,
    benchmark_ip_parsing,
);

criterion_main!(benches);

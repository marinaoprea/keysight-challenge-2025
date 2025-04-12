#include <array>
#include <vector>
#include <iostream>
#include <string.h>
#include <filesystem>
#include <unistd.h>

#include <sycl/sycl.hpp>

#include <tbb/parallel_for.h>
#include <tbb/parallel_reduce.h>

#include <tbb/blocked_range.h>
#include <tbb/global_control.h>
#include <tbb/flow_graph.h>
#include <pcap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h> 
#include "dpc_common.hpp"

#define PACKET_SIZE 64

char Pcap_file[1024];
char Result_file[1024];
pcap_t *pcap = nullptr;
pcap_dumper_t *dumper = nullptr;

const size_t burst_size = 32;
size_t total_packets = 0;
size_t total_bursts = 0;

using namespace std;

#define PACKET_BUFF_SIZE 4096

struct Stats {
    uint32_t arp_packets;
    uint32_t ipv4_packets;
    uint32_t ipv6_packets;
    uint32_t icmp_packets;
    uint32_t tcp_packets;
    uint32_t udp_packets;
} stats;

// Structură pentru stocarea pachetelor și metadatelor lor
struct PacketData {
    struct pcap_pkthdr header;
    u_char data[PACKET_BUFF_SIZE];  // Buffer pentru datele pachetului
};

std::vector<PacketData> packets;


// Funcție pentru citirea unui grup de pachete
std::vector<PacketData> read_packet_burst(pcap_t *pcap, size_t burst_size) {
    std::vector<PacketData> packets;
    struct pcap_pkthdr header;
    const u_char *packet;
    
    // Citim până la burst_size pachete
    for (size_t i = 0; i < burst_size; i++) {
        packet = pcap_next(pcap, &header);
        
        // Dacă nu mai sunt pachete, ieșim din buclă
        if (packet == nullptr) {
            break;
        }
        
        // Creăm un nou pachet și îl adăugăm la vector
        PacketData pkt;
        pkt.header = header;
        std::memcpy(pkt.data, packet, header.caplen);
        pkt.data[header.caplen] = '\0';  // Asigurăm terminarea șirului
        
        packets.push_back(pkt);
    }
    
    return packets;
}

int routing = 0;

int init() {
    strcpy(Pcap_file, "/custom-directory-name/keysight-challenge-2025/src/capture3.pcap\0");
    strcpy(Result_file, "/custom-directory-name/keysight-challenge-2025/src/result.pcap\0");

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap = pcap_open_offline(Pcap_file, errbuf);
    
    if (pcap == nullptr) {
        std::cerr << "Eroare la deschiderea fișierului PCAP: " << errbuf << "\n";
        return 2;
    } else {    
        std::cout << "Opened pcap file: " << Pcap_file << "\n";
    }

    dumper = pcap_dump_open(pcap, Result_file);
    if (dumper == nullptr) {
        std::cerr << "Eroare la deschiderea fișierului dumper: " << pcap_geterr(pcap) << "\n";
        return 2;
    } else {
        std::cout << "Opened dumper file: " << Result_file << "\n";
    }
    return 0;
}

std::mutex mtx;

int main() {
    init();    

    sycl::queue q;

    std::cout << "Using device: " <<
        q.get_device().get_info<sycl::info::device::name>() << std::endl;

    int nth = 10;  // number of threads
    auto mp = tbb::global_control::max_allowed_parallelism;
    tbb::global_control gc(mp, nth);
    tbb::flow::graph g;

    std::cout << "Director curent: " << std::filesystem::current_path() << std::endl;

    // Input node: get packets from the socket or from the packet capture
    tbb::flow::input_node<vector<PacketData>> in_node{g,
        [&](tbb::flow_control& fc) -> vector<PacketData> {
            int nr_packets = 0;
	        char* packet;

            std::cout << "Input node running " << std::endl;
    
                packets = read_packet_burst(pcap, burst_size);
                
                if (packets.empty()) {
                    pcap_close(pcap);
                    fc.stop();  // Oprim graful dacă nu mai sunt pachete
                    return vector<PacketData>();  // Nu mai sunt pachete
                }
                
                total_bursts++;
                total_packets += packets.size();
                
                std::cout << "Citit burst #" << total_bursts 
                          << " cu " << packets.size() << " pachete\n";
                
                // Exemplu de afișare a informațiilor despre primul pachet din burst
                if (!packets.empty()) {
                    std::cout << "  Primul pachet din burst: " 
                              << strlen((char *)packets[0].data) << " bytes\n";
                }

                return packets;
        }
    };

    // Packet inspection node
    tbb::flow::function_node<vector<PacketData>, vector<PacketData>> inspect_packet_node {
        g, tbb::flow::unlimited, [](vector<PacketData> packets) ->vector<PacketData> {
            // By including all the SYCL work in a {} block, we ensure
            // all SYCL tasks must complete before exiting the block
            {
                sycl::queue gpuQ(sycl::default_selector_v, dpc_common::exception_handler);

                std::cout << "Selected GPU Device Name: " <<
                    gpuQ.get_device().get_info<sycl::info::device::name>() << "\n";

                std::cout << "Number of packets: " << packets.size() << std::endl;

                size_t nr_packets = packets.size();
    
                // Buffer pentru datele pachetelor
                sycl::buffer<PacketData, 1> packet_buf(packets.data(), sycl::range<1>(nr_packets));
                
                // Buffer pentru rezultate (1 pentru IPv4, 0 pentru alte tipuri)
                std::vector<int> is_ipv4(nr_packets, 0);
                sycl::buffer<int, 1> result_buf(is_ipv4.data(), sycl::range<1>(nr_packets));

                std::vector<PacketData> new_ipv4;
                
                gpuQ.submit([&](sycl::handler& h) {
                    auto packet_acc = packet_buf.get_access<sycl::access::mode::read>(h);
                    auto result_acc = result_buf.get_access<sycl::access::mode::write>(h);
                    
                    h.parallel_for(sycl::range<1>(nr_packets), [=](sycl::id<1> idx) {
                        uint16_t etherType = (packet_acc[idx].data[12] << 8) | packet_acc[idx].data[13];
                        if (etherType == 0x0800) {
                            result_acc[idx] = 1;  // Marcăm pachetul ca fiind IPv4
                        }
                        else {
                            result_acc[idx] = 0;  // Marcăm pachetul ca fiind alt tip
                        }});
                    }).wait_and_throw();
                    

                for (int i = 0; i < nr_packets; i++) {
                    if (is_ipv4[i] == 1) {
                        PacketData new_pkt;
                        new_pkt.header = packets[i].header;  // Copiem pachetul IPv4
                        std::memcpy(new_pkt.data, packets[i].data, packets[i].header.caplen);
                        new_ipv4.push_back(new_pkt);  // Adăugăm pachetul la vectorul de pachete IPv4
                    }
                }

                auto total = tbb::parallel_reduce( 
                    tbb::blocked_range<int>(0, is_ipv4.size()),
                    0,
                    [&](tbb::blocked_range<int> r, int running_total)
                    {
                        for (int i=r.begin(); i<r.end(); ++i)
                        {
                            running_total += is_ipv4[i];
                        }

                        return running_total;
                    }, std::plus<int>() );
                std::cout << "Numărul de pachete IPv4: " << total << std::endl;

                stats.ipv4_packets += total;

                std::vector<int> is_udp(nr_packets, 0);
                sycl::buffer<int, 1> result_buf_udp(is_udp.data(), sycl::range<1>(nr_packets));
                gpuQ.submit([&](sycl::handler& h) {
                    auto packet_acc = packet_buf.get_access<sycl::access::mode::read>(h);
                    auto result_acc = result_buf_udp.get_access<sycl::access::mode::write>(h);

                    h.parallel_for(sycl::range<1>(nr_packets), [=](sycl::id<1> idx) {
                        uint8_t protocol = packet_acc[idx].data[23];  // Protocolul din header-ul IPv4
                        if (protocol == 17) {
                            result_acc[idx] = 1;  // Marcăm pachetul ca fiind UDP
                        }
                        else {
                            result_acc[idx] = 0;  // Marcăm pachetul ca fiind alt tip
                        }
                    });
                }).wait_and_throw();

                auto total2 = tbb::parallel_reduce( 
                    tbb::blocked_range<int>(0, is_udp.size()),
                    0,
                    [&](tbb::blocked_range<int> r, int running_total)
                    {
                        for (int i=r.begin(); i<r.end(); ++i)
                        {
                            running_total += is_udp[i];
                        }

                        return running_total;
                    }, std::plus<int>() );
                stats.udp_packets += total2;
                std::cout << "Numărul de pachete UDP: " << total2 << std::endl;

                std::vector<int> is_tcp(nr_packets, 0);  // Vector pentru a marca pachetele TCP
                sycl::buffer<int, 1> result_buf_tcp(is_tcp.data(), sycl::range<1>(nr_packets));

                gpuQ.submit([&](sycl::handler& h) {
                    auto packet_acc = packet_buf.get_access<sycl::access::mode::read>(h);
                    auto result_acc = result_buf_tcp.get_access<sycl::access::mode::write>(h);
                
                    h.parallel_for(sycl::range<1>(nr_packets), [=](sycl::id<1> idx) {
                        uint8_t protocol = packet_acc[idx].data[23];  // Protocolul din header-ul IPv4
                        if (protocol == 6) {  // 6 este valoarea pentru TCP
                            result_acc[idx] = 1;  // Marcăm pachetul ca fiind TCP
                        }
                        else {
                            result_acc[idx] = 0;  // Marcăm pachetul ca fiind alt tip
                        }
                    });
                }).wait_and_throw();

                auto total3 = tbb::parallel_reduce( 
                    tbb::blocked_range<int>(0, is_tcp.size()),
                    0,
                    [&](tbb::blocked_range<int> r, int running_total)
                    {
                        for (int i=r.begin(); i<r.end(); ++i)
                        {
                            running_total += is_tcp[i];
                        }

                        return running_total;
                    }, std::plus<int>() );
                stats.tcp_packets += total3;
                std::cout << "Numărul de pachete TCP: " << total3 << std::endl;

                return new_ipv4;  // Return the packets for further processing
            }  // End of the scope for SYCL code; the queue has completed the work
        }};

        tbb::flow::function_node<vector<PacketData>, vector<PacketData>> route_packet_node {
            g, tbb::flow::unlimited, [](vector<PacketData> packets) ->vector<PacketData> {
                // By including all the SYCL work in a {} block, we ensure
                // all SYCL tasks must complete before exiting the block
                {
                    sycl::queue gpuQ(sycl::default_selector_v, dpc_common::exception_handler);
    
                    std::cout << "Selected GPU Device Name: " <<
                        gpuQ.get_device().get_info<sycl::info::device::name>() << "\n";
    
                    std::cout << "Number of packets in routing: " << packets.size() << std::endl;
    
                    size_t nr_packets = packets.size();

                    routing += nr_packets;
    
                    sycl::buffer<PacketData, 1> packet_buf(packets.data(), sycl::range<1>(nr_packets));
                    
                    gpuQ.submit([&](sycl::handler& h) {
                        auto packet_acc = packet_buf.get_access<sycl::access::mode::read_write>(h);
                        h.parallel_for(sycl::range<1>(nr_packets), [=](sycl::id<1> idx) {
                            // Modificăm adresa de destinație
                            uint32_t ip_dst_offset = 14 + 16; // Ethernet header + offset dest IP in IP header

                            packet_acc[idx].data[ip_dst_offset + 0] += 1;
                            packet_acc[idx].data[ip_dst_offset + 1] += 1;
                            packet_acc[idx].data[ip_dst_offset + 2] += 1;
                            packet_acc[idx].data[ip_dst_offset + 3] += 1;
                        }
                        );
                    }).wait_and_throw();
    
                }  // End of the scope for SYCL code; the queue has completed the work
                return packets;  // Return the packets for further processing
            }};

            tbb::flow::function_node<vector<PacketData>, int> send_sock_node {
                g, tbb::flow::unlimited, [](vector<PacketData> packets) -> int {
                    // By including all the SYCL work in a {} block, we ensure
                    // all SYCL tasks must complete before exiting the block
                    { 
                        /*int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
                        if (sock < 0) {
                            perror("Error creating socket");
                            return -1;
                        }
                        struct sockaddr_ll device;
                        memset(&device, 0, sizeof(device));
                        device.sll_family = AF_PACKET;
                        device.sll_protocol = htons(ETH_P_ALL);
                        device.sll_ifindex = if_nametoindex("eth0");
                        if (device.sll_ifindex == 0) {
                            perror("Interface not found");
                            close(sock);
                            return -1;
                        }
                    
                        for (int i = 0; i < packets.size(); i++) {
                            PacketData *pkt = &packets[i];
                            ssize_t sent = sendto(sock, pkt, sizeof(pkt), 0,
                                                  reinterpret_cast<struct sockaddr*>(&device), sizeof(device));
                            if (sent < 0) {
                                perror("Error sending packet");
                            } else {
                                std::cout << "Packet dimension: " << sent << " bytes" << std::endl;
                            }
                        }
                        close(sock);*/

                        for (auto packet : packets) {
                            mtx.lock();
                            pcap_dump((u_char *)dumper, &packet.header, packet.data);
                            std::cout << "Sent packet: " << packet.header.len << " bytes\n";
                            mtx.unlock();
                        }
                        pcap_dump_flush(dumper);
                }}};

    // construct graph
    tbb::flow::make_edge<vector<PacketData>>(in_node, inspect_packet_node);
    tbb::flow::make_edge<vector<PacketData>>(inspect_packet_node, route_packet_node);
    tbb::flow::make_edge<vector<PacketData>>(route_packet_node, send_sock_node);

    in_node.activate();
    g.wait_for_all();

    pcap_dump_close(dumper);

    std::cout << "Done waiting" << std::endl;

    std::cout << "Final stats";
    std::cout << "Total ipv4 packets: " << stats.ipv4_packets << std::endl;
    std::cout << "Total udp packets: " << stats.udp_packets << std::endl;
    std::cout << "Total tcp packets: " << stats.tcp_packets << std::endl;
    std::cout << routing << " packets routed" << std::endl;
}

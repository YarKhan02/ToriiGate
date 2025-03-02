package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/YarKhan02/ToriiGate/suspiciousSites"
	"github.com/YarKhan02/ToriiGate/processing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func sites() ([]string, error) {
	suspiciousSites, err := suspiciousSites.FetchSuspiciousSites("https://urlhaus.abuse.ch/downloads/text/")
	if err != nil {
		log.Fatal(err)
	}

	return suspiciousSites, nil
}

func monitorPacket([]string) {
	device := "en0"
	var snaplen int32 = 1024
	var promisc bool = false
	var timeout time.Duration = 30 * time.Second

	handle, err := pcap.OpenLive(device, snaplen, promisc, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Apply BPF filter to capture only HTTP (port 80) and HTTPS (port 443) packets
	_ = handle.SetBPFFilter("tcp port 80 or tcp port 443")

	// Fetch network interface details
	iface, err := net.InterfaceByName(device)
	if err != nil {
		log.Fatal(err)
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())

	httpProcessor := processing.HTTPProcessor{}
    ipv4Processor := processing.IPv4Processor{}
    tcpProcessor := processing.TCPProcessor{}

	for packet := range source.Packets() {
		layer := packet.Layer(layers.LayerTypeEthernet) // Retrieves ethernet layer
		ethernet, _ := layer.(*layers.Ethernet) // Extracts ethernet frame details
		if !bytes.Equal(ethernet.SrcMAC, iface.HardwareAddr) {
			continue
		}
		httpInfo := httpProcessor.Process(packet)
		if httpInfo != nil {
			fmt.Println(httpInfo)

            if ipv4Info := ipv4Processor.Process(packet); ipv4Info != nil {
                fmt.Println(ipv4Info)
            }
            if tcpInfo := tcpProcessor.Process(packet); tcpInfo != nil {
                fmt.Println(tcpInfo)
            }
		}
	}
}

func main() {
	suspiciousSites, err := sites()

	if err != nil {
		log.Fatal(err)
	}

	monitorPacket(suspiciousSites)
}
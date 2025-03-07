package processing

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/YarKhan02/ToriiGate/model"
)

// LayerProcessor defines an interface for processing packet layers
type LayerProcessor interface {
	Process(packet gopacket.Packet) *model.PacketInfo
}

// IPv4Processor processes IPv4 layers
type IPv4Processor struct {}

func (p IPv4Processor) Process(packet gopacket.Packet) *model.PacketInfo {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}

	ip, _ := ipLayer.(*layers.IPv4)
	return &model.PacketInfo {
		PacketType: "IPv4",
		SrcIP: ip.SrcIP.String(),
		DstIP: ip.DstIP.String(),
		Size: len(packet.Data()),
	}
}

// TCPProcessor processes TCP layers
type TCPProcessor struct {}

func (p TCPProcessor) Process(packet gopacket.Packet) *model.PacketInfo {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}

	tcp, _ := tcpLayer.(*layers.TCP)
	return &model.PacketInfo {
		PacketType: "TCP",
		SrcIP: tcp.SrcPort.String(),
		DstIP: tcp.DstPort.String(),
		Size: len(packet.Data()),
	}
}

// HTTPProcessor processes HTTP layers
type HTTPProcessor struct{}

func (p HTTPProcessor) Process(packet gopacket.Packet, sus_sites []string) *model.PacketInfo {
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return nil
	}

	// Convert payload to string and extract host
	payload := string(appLayer.Payload())
	fmt.Println(payload)
	
	urlRegex := regexp.MustCompile(`(?i)(https?://[^\s]+|Host:\s*([^\s]+))`)
	matches := urlRegex.FindAllString(payload, -1)

	// Precompile regex patterns for suspicious sites
	susPatterns := make([]*regexp.Regexp, len(sus_sites))
	for i, site := range sus_sites {
		susPatterns[i] = regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(site) + `\b`)
	}

	// Check for suspicious URLs/hosts
	for _, match := range matches {
		cleanMatch := regexp.MustCompile(`[^\x20-\x7E]`).ReplaceAllString(match, "") // Remove non-ASCII characters
		cleanMatch = strings.TrimSpace(cleanMatch)

		for _, pattern := range susPatterns {
			if pattern.MatchString(cleanMatch) {
				return &model.PacketInfo{
					PacketType: "HTTP",
					Host:       cleanMatch,
				}
			}
		}
	}

	return nil
}
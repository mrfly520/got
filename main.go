package main

import (
	"fmt"
	"github.com/google/gopacket/layers"
	"log"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type IfaceInfo struct {
	NPFName     string
	Description string
	NickName    string
	IPv4        string
}

func get_if_list() []IfaceInfo {
	var ifaceInfoList []IfaceInfo

	// 得到所有的(网络)设备
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	interface_list, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}

	for _, i := range interface_list {
		byName, err := net.InterfaceByName(i.Name)
		if err != nil {
			log.Fatal(err)
		}
		address, err := byName.Addrs()
		ifaceInfoList = append(ifaceInfoList, IfaceInfo{NickName: byName.Name, IPv4: address[1].String()})
	}

	// 打印设备信息
	// fmt.Println("Devices found:")
	// for _, device := range devices {
	// 	fmt.Println("\nName: ", device.Name)
	// 	fmt.Println("Description: ", device.Description)
	// 	fmt.Println("Devices addresses: ", device.Description)
	// 	for _, address := range device.Addresses {
	// 		fmt.Println("- IP address: ", address.IP)
	// 		fmt.Println("- Subnet mask: ", address.Netmask)
	// 	}
	// }
	var vaildIfaces []IfaceInfo
	for _, device := range devices {
		for _, address := range device.Addresses {
			for _, ifaceinfo := range ifaceInfoList {
				if strings.Contains(ifaceinfo.IPv4, address.IP.String()) {
					vaildIfaces = append(vaildIfaces, IfaceInfo{NPFName: device.Name, Description: device.Description, NickName: ifaceinfo.NickName, IPv4: ifaceinfo.IPv4})
					break
				}
			}
		}
	}

	return vaildIfaces
}

var (
	device       string = "\\Device\\NPF_Loopback"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
)

func main() {
	ll := get_if_list()
	fmt.Println(ll)

	// 监听在线 网卡， en0是我的笔记本网卡名称。
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	handle.SetBPFFilter("dst host 172.30.123.111 and tcp port 8083")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// 循环抓包，并打印
	for packet := range packetSource.Packets() {

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			fmt.Println("This is a TCP packet!")
			// Get actual TCP data from this layer
			tcp, _ := tcpLayer.(*layers.TCP)
			fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
		}
		//fmt.Println(packet)
	}
}

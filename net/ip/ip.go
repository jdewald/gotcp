package ip 

import (
	"fmt"
	"log"
	"bytes"
    "strings"
    "strconv"
	"encoding/binary"
	"github.com/songgao/water"
	"github.com/jdewald/gotcp/net"
)

const LEN_IPHDR = 20;

type IPHeader struct {
	VersionData			uint16
	TotalLength			uint16
	Ident				uint16
	FlagsAndFrag		uint16
	TTL 				byte
	Protocol 			byte
	Checksum 			uint16  // byte 10
	SourceIP 			[4]byte  // byte 12
	DestIP				[4]byte  // byte 16

}

type IPPacket struct {
	Header		IPHeader
	Packet		[]byte
}

type IPStack struct {
	ifce 		*water.Interface
}

func (hdr *IPHeader) Version() byte {
    return byte(hdr.VersionData >> 12);
}

func (hdr *IPHeader) SetVersion(ver uint16) (*IPHeader) {
    hdr.VersionData |= (0xF000 & (ver << 12))
    return hdr
}

// Bytes
func (hdr *IPHeader) SetHeaderLen(len uint16) (*IPHeader) {
    hdr.VersionData |= 0xF00 & ((len / 4) << 8)
    return hdr
}

// Bytes
func (hdr *IPHeader) HeaderLen() byte {
    return 4 * byte(0xFF & (hdr.VersionData >> 8))
}


func (hdr *IPHeader) SetDSCP(dscp byte) (*IPHeader) {
    hdr.VersionData |= uint16(0x3F & (dscp << 2))
    return hdr
}

func (hdr *IPHeader) SetECN(ecn byte) (*IPHeader) {
    hdr.VersionData |= uint16(0x3 & (ecn))
    return hdr
}

func (hdr *IPHeader) SetNoFrag() (*IPHeader) {
    hdr.FlagsAndFrag = 0x0FFF & hdr.FlagsAndFrag
    hdr.FlagsAndFrag |= (0x2 << 13)
    return hdr
}

func (ipHdr *IPHeader) Display() {
	fmt.Printf("------ IP Header -------\n")
    fmt.Printf("Version Data: %d\n", ipHdr.Version())
    fmt.Printf("Len (bytes): %d\n", ipHdr.HeaderLen())
    fmt.Printf("DSCP: %d\n", 0x3F & (ipHdr.VersionData >> 2))
    fmt.Printf("ECN: %d\n", 0x03 & (ipHdr.VersionData))
    fmt.Printf("Ident: %d\n", ipHdr.Ident)
    fmt.Printf("Flags: %d\n", 0x7 & (ipHdr.FlagsAndFrag >> 13))
    fmt.Printf("TTL: %d\n", ipHdr.TTL)
    fmt.Printf("Proto: %d\n", ipHdr.Protocol)
	fmt.Printf("Source IP: %d\n", ipHdr.SourceIP)
	fmt.Printf("Destination IP: %d\n", ipHdr.DestIP)
    fmt.Printf("IP Proto: %d\n", ipHdr.Protocol)
    fmt.Printf("IP Data Length: %d\n", ipHdr.TotalLength)
    fmt.Printf("-----------------------\n")
}

func DottedIP(addr [4]byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", addr[0],addr[1], addr[2], addr[3])	
}

func IP4Bytes(addr string) (returnAddr [4]byte, err error) {

    fields := strings.Split(addr, ".")

    var tmp int
    for i := 0; i < 4; i++ {
        tmp, err = strconv.Atoi(fields[i])
        if err != nil {
            return
        }
        returnAddr[i] = byte(tmp)

    }

    return 
}


func (packet *IPPacket) Source() string {
	return DottedIP(packet.Header.SourceIP)
}

func (packet *IPPacket) Destination() string {
	return DottedIP(packet.Header.DestIP)
}

var ifce *water.Interface

func Start() (*IPStack, error) {
	ifce, err := water.NewTUN("gotcptun")
    fmt.Printf("%v, %v\n\n", err, ifce)
    fmt.Printf("TUN? %v\n", ifce.IsTUN())

    ipstack := &IPStack{ifce}
    return ipstack, err
}

func (ipstack *IPStack) Receive() (packet *IPPacket, err error) {

    buf := make([]byte, 1024)

    fmt.Printf("IP=>Reading with %v\n", ipstack.ifce)
    numBytes, err := ipstack.ifce.Read(buf)
    if err != nil {
    	return nil,err
    }

    fmt.Printf("IP=>Read %d octets\n", numBytes)

    iphdrOnly := buf[0:LEN_IPHDR] 

    fmt.Printf("IP=>IP Packet data %v\n", iphdrOnly)
    verified := net.VerifyChecksum(iphdrOnly)
    if ! verified {
    	log.Fatal("Unable to verify IP Checksum")
    }

//    tcpLen := numBytes - LEN_IPHDR;
    reader := bytes.NewReader(buf[0:LEN_IPHDR])

    ipPacket := new(IPPacket)

    fmt.Printf("IP=>Parsing Header\n")
    err = binary.Read(reader, binary.BigEndian, &ipPacket.Header)
    if err != nil {
    	return nil, err
    }

    ipPacket.Header.Display()

    ipPacket.Packet = buf[LEN_IPHDR:ipPacket.Header.TotalLength]

    return ipPacket,nil

}

func (ipstack *IPStack) send(data []byte) (int, error) {

	return ipstack.ifce.Write(data)

}

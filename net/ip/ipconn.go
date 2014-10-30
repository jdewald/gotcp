package ip

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"encoding/binary"
	"github.com/jdewald/gotcp/net"
)

type IPConn struct {
	RemoteIP	[4]byte
	LocalIP		[4]byte
	modelHeader	IPHeader
	ipStack		*IPStack
}


func (ipconn *IPConn) Send(packet []byte) (int, error) {

	var IP IPPacket

	IP.Header = ipconn.modelHeader
	IP.Header.Checksum = 0

	IP.Header.TotalLength = uint16(len(packet) + LEN_IPHDR)


	var hdrBuf bytes.Buffer
	hw := bufio.NewWriter(&hdrBuf)
	binary.Write(hw, binary.BigEndian, IP.Header)
	hw.Flush()

	IP.Header.Checksum = net.Checksum(hdrBuf.Bytes()) 


	// TODO: Use a "free list" so we don't keep allocating
	var outPacket bytes.Buffer
	w := bufio.NewWriter(&outPacket)
	binary.Write(w, binary.BigEndian, IP.Header)
	binary.Write(w, binary.BigEndian, packet)

	w.Flush()

	fmt.Printf("IPConn=>Packet is %v\n", outPacket.Bytes())
	return ipconn.ipStack.send(outPacket.Bytes())	
}

func NewIPConn(localIP string, remoteIP string, ipStack *IPStack) (ipConn *IPConn, err error) {

	remoteBytes, err := IP4Bytes(remoteIP)
	if err != nil {
		log.Fatal(err)
	}
	localBytes, err := IP4Bytes(localIP)

	if err != nil {
		log.Fatal(err)
	}

	ipConn = &IPConn{RemoteIP: remoteBytes, 
					 LocalIP:  localBytes ,
					 ipStack:  ipStack}
/*type IPHeader struct {
	VersionData			uint16
	TotalLength			uint16
	Ident				uint16
	FlagsAndFrag		uint16
	TTL 				byte
	Protocol 			byte
	Checksum 			uint16  // byte 10
	SourceIP 			[4]byte  // byte 12
	DestIP				[4]byte  // byte 16

}*/
	var hdr IPHeader
	hdr.SetVersion(4)
	hdr.SetHeaderLen(20)
	hdr.SetDSCP(0)
	hdr.SetECN(0)
	hdr.SetNoFrag()
	hdr.TTL = 64	
	hdr.Protocol = 6
	hdr.SourceIP = localBytes
	hdr.DestIP = remoteBytes

	ipConn.modelHeader = hdr;

	err = nil
	return
}
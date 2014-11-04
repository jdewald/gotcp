package tcp 


// http://www.rfc-editor.org/rfc/rfc793.txt

import (
	"fmt"
	"bytes"
	"encoding/binary"
)

const CTRL_URG = 1 << 5		// Urgent
const CTRL_ACK = 1 << 4
const CTRL_PSH = 1 << 3
const CTRL_RST = 1 << 2
const CTRL_SYN = 1 << 1
const CTRL_FIN = 1

const FOUR_BITS = 0xF;

const LEN_HDR_PRE_OPTIONS = 20;


type TCPHeader struct {
	SourcePort			uint16  // 0
	DestPort			uint16  // 2

	Seq					uint32  // 4

	Ack					uint32 	// 8 Last seen SEQ + 1

	DataOffsetAndFlags	uint16  // 12 Data offset = 4 (number of 32 bit words before data), reserved = 6, control bits = 6 
	Window				uint16  // 14 how many octets we can handle

	Checksum			uint16	// 16 16-bit 1s complement sum of 16 bit words in header and text
								// 	if odd number of octets, then last octet padded with 0s
								//  to get to 16-bit words (this pad is not sent) 
								//  checksum field considered 0 during checksum operation
								//  checksum also applies to the IP data:
								//		32 bit source and destination addresses
								//		8 0s, the protocol and tcp length (16 bits)
	UrgentPointer		uint16	// 18 If URG set, then this is the index to octet after urgent data
}

type TCPPacket struct {
	Header 				*TCPHeader
	OptionsAndPadding   []byte  // 20
	Data 				[]byte

}

func (packet *TCPPacket) Display() {
	fmt.Printf("----- TCP Packet -----\n")
	packet.Header.Display()
    fmt.Printf("Options and Padding: %v\n", packet.OptionsAndPadding)
	fmt.Printf("Data length: %d\n", len(packet.Data))
	fmt.Printf("----------------------\n")

}

func (packet *TCPPacket) IsSYN() bool {
	return packet.Header.DataOffsetAndFlags & CTRL_SYN != 0
}

func (packet *TCPPacket) IsACK() bool {
	return packet.Header.DataOffsetAndFlags & CTRL_ACK != 0
}

// Acknowledge the up to the given sequence number
// This is not SACK
func (packet TCPPacket) ACK(seq uint32) (*TCPPacket) {
	packet.Header.Ack = seq	
	packet.Header.DataOffsetAndFlags |= CTRL_ACK

	return &packet
}

// TODO: Move these printers to another file
func (hdr *TCPHeader) Display() {
	fmt.Printf("----- TCP Header -----\n")
    fmt.Printf("Source: %d\n", hdr.SourcePort)
    fmt.Printf("Destination: %d\n", hdr.DestPort)
    fmt.Printf("SEQ: %d\n", hdr.Seq)
    fmt.Printf("ACK: %d\n", hdr.Ack)
    fmt.Printf("SYN? %t\n", hdr.DataOffsetAndFlags & CTRL_SYN != 0)
    fmt.Printf("ACK? %t\n", hdr.DataOffsetAndFlags & CTRL_ACK != 0)
    fmt.Printf("PSH? %t\n", hdr.DataOffsetAndFlags & CTRL_PSH != 0)
    fmt.Printf("FIN? %t\n", hdr.DataOffsetAndFlags & CTRL_FIN != 0)
    fmt.Printf("Window: %d %x\n", hdr.Window, hdr.Window)
    fmt.Printf("Checksum: %d (%x) %b\n", hdr.Checksum, hdr.Checksum, hdr.Checksum)
    fmt.Printf("-----------------------\n")
}

func Parse(data []byte) (packet *TCPPacket, err error) {
	packet = new(TCPPacket)

	var hdr TCPHeader
	packet.Header = &hdr

	numBytes := len(data)

	fmt.Printf("Have %d bytes of TCP Packet data\n", numBytes)
	// 20 is where the options start
	reader := bytes.NewReader(data[0:20])

	err = binary.Read(reader, binary.BigEndian, &hdr)
	if err != nil {
		return nil, err
	}

	offsetBytes := 4 * (hdr.DataOffsetAndFlags >> 12)

	fmt.Printf("Data Offset: %d bytes\n", offsetBytes)
    // offsetBytes = length of header
    // options start at byte 20 (0-indexed, so start of 21st byte)
	optionsAndPaddingSize := offsetBytes - 20
	fmt.Printf("Options and Padding Size: %d\n", optionsAndPaddingSize)
	packet.OptionsAndPadding = data[20:(20 + optionsAndPaddingSize)]

	packet.Data = data[offsetBytes:]
	fmt.Printf("Length of TCP Segment: %d\n", numBytes)

	//packet.Display()

	return packet, nil
}


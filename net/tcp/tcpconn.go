package tcp 

import (
	"log"
	"fmt"
	//"net"
	"bytes"
	"bufio"
	"encoding/binary"
	"math/rand"
	"github.com/jdewald/gotcp/net"
	"github.com/jdewald/gotcp/net/ip"
)


const (
	STATE_CLOSED = iota
	STATE_SYN_RECEIVED = iota
	STATE_SYN_SENT = iota
	STATE_ESTABLISHED = iota
)


type TCPConn struct
{
	localIP 	string
	localPort  uint16
	remoteIP 		string
	remotePort 	uint16
	state       int

	recvWindow		uint16
	recvNextSeq		uint32 "RCV.NXT"
	sendNextSeq		uint32 "SND.NXT"
	sendWindow		uint16
	unacked			uint32 "SND.UNA"

	ipConn 			*ip.IPConn
}

func (conn *TCPConn) ident() string {
	return fmt.Sprintf("%s,%d,%s,%d", conn.localIP, conn.localPort, conn.remoteIP, conn.remotePort)
}

func (conn *TCPConn) Send(tcpPacket *TCPPacket) (written int, err error) {

	// TODO: Pull this from Free List? SYN/ACK's will be set lengths likely
	// So we don't want to keep allocating space when we can just have
	// it pre-allocated

	tcpPacket.Display()

	packet := new(bytes.Buffer) 
	w := bufio.NewWriter(packet)
	if tcpPacket.Header.Checksum == 0 {

		binary.Write(w, binary.BigEndian, conn.buildPseudoHeader(tcpPacket))
		binary.Write(w, binary.BigEndian, tcpPacket.Header)
		binary.Write(w, binary.BigEndian, tcpPacket.OptionsAndPadding)
		binary.Write(w, binary.BigEndian, tcpPacket.Data)

		w.Flush()

		fmt.Printf("TCPConn=>Packet For Checksum is %v\n", packet.Bytes())

		checksum := net.Checksum(packet.Bytes())

		packet = nil

	// TODO: Obviously this is horrible, horrible
		tcpPacket.Header.Checksum = checksum

		packet = new(bytes.Buffer) 
		w = bufio.NewWriter(packet)
	}

	binary.Write(w, binary.BigEndian, tcpPacket.Header)
	binary.Write(w, binary.BigEndian, tcpPacket.OptionsAndPadding)
	binary.Write(w, binary.BigEndian, tcpPacket.Data)

	w.Flush()

	// TODO: Store/use []byte version or better an IPAddr object (re-use the stuff from net?)
	written, err = conn.ipConn.Send(packet.Bytes()) 
	if err != nil {
		log.Fatal(err)
	}
	return
}

// Create the "header" made up of Source and Dest IP, protocoll and tcp length
// This is not included in the packet but is used as part of the checksum
// this may be optional as it gets offloaded
func (conn *TCPConn) buildPseudoHeader(tcpPacket *TCPPacket) []byte {

	var hdrBuffer bytes.Buffer
	w := bufio.NewWriter(&hdrBuffer)

	tcpLen := 20 + len(tcpPacket.OptionsAndPadding) + len(tcpPacket.Data)
	binary.Write(w, binary.BigEndian, conn.ipConn.LocalIP)
	binary.Write(w, binary.BigEndian, conn.ipConn.RemoteIP)
	binary.Write(w, binary.BigEndian, uint16(6)) // 6 = tcp
	binary.Write(w, binary.BigEndian, uint16(tcpLen))


	w.Flush()

	fmt.Printf("TCPConn=>buildPseudoHeader=>bytes %v\n", hdrBuffer.Bytes())
	fmt.Printf("TCPConn=>buildPseudoHeader=>tcpLen %d\n", tcpLen)

	return hdrBuffer.Bytes()
}

type TCPListener struct 
{
	localIP			string
	localPort		uint16
	connChannel		chan *TCPConn
}



// Wait for an incoming connection to the listening IP and Port
func (tl *TCPListener) Accept() (*TCPConn, error) {
	// Wait for a connection in the ESTABLISHED state for the given IP/port combination
	// This in effect means going through the full 3-way Handshake when a SYN packet
	// comes in for the port

	return <- tl.connChannel, nil
}

var connections map[string]*TCPConn
var listeners   map[string]*TCPListener

var ipStack 	*ip.IPStack

func Listen(localIP string, port uint16) (*TCPListener, error) {

	lChan := make(chan *TCPConn, 5)
	tl := TCPListener{localIP, port, lChan}

	listeners[localIP + string(port)] = &tl

	return &tl, nil

}

func Start() (error) {

	var err error
	ipStack, err = ip.Start()

	if err != nil {
		return err
	} else  {
		listeners   = make(map[string]*TCPListener)
		connections = make(map[string]*TCPConn)
		go listenForPackets()
		return nil
	}

}



func listenForPackets() {
	for {
		packet,err := ipStack.Receive()		

		if err != nil {
			log.Fatal(err)
		}


		fmt.Printf("TCP=>Parsing Packet\n")
		tcpPacket, err := Parse(packet.Packet)
		if err != nil {
			log.Fatal(err)
		}

		tl := listeners[packet.Destination() + string(tcpPacket.Header.DestPort)]
		ident := fmt.Sprintf("%s,%d,%s,%d", packet.Destination(), tcpPacket.Header.DestPort,packet.Source(), tcpPacket.Header.SourcePort)
		fmt.Printf("TCPConn=>ident = %s\n", ident)
		tcpConn := connections[ident]

		if tcpConn == nil { // Start of a new connection
			if tcpPacket.IsSYN() && tl != nil {
				fmt.Printf("We have a listener, attempting to establish connection\n")

				tcpConn = &TCPConn{ localIP: tl.localIP, 
									 localPort: tl.localPort,
									 remoteIP: packet.Source(), 
									 remotePort: tcpPacket.Header.SourcePort, 
									 state: STATE_SYN_RECEIVED}
				fmt.Printf("TCP=>Generating an IP Connection\n")									
				tcpConn.ipConn, err = ip.NewIPConn( tl.localIP, tcpConn.remoteIP, ipStack )									 

				if err != nil {
					log.Fatal(err)
				}

				connections[tcpConn.ident()] = tcpConn
				fmt.Printf("TCPConn=>New Ident is: %s\n", tcpConn.ident())

			} else if tcpPacket.IsSYN(){
				fmt.Printf("**This is a SYN packet, but we don't have any listeneres!\n")
				continue
					// Send RST
			}
		}

		fmt.Printf("TCP=>Connection is %v\n", tcpConn)
		switch tcpConn.state {
		case STATE_SYN_SENT, STATE_SYN_RECEIVED:
			tcpConn.recvNextSeq = tcpPacket.Header.Seq + 1    // The SYN is considered to have occupied the first one
			tcpConn.recvWindow = tcpPacket.Header.Window // TODO: Figure out our own
												// This is aprt of congestion management
			if tcpPacket.IsACK() {
				fmt.Println("TCP=>Moving to ESTABLISHED State")
				tcpConn.state = STATE_ESTABLISHED
				tl.connChannel <- tcpConn 
			} else {

				err = SendSynAck(tcpConn)
				if err != nil {
					fmt.Println("TCP=>Unable to perform SynAck")
					log.Fatal(err)
				}
			}

		default:
			fmt.Printf("What're we doing with state %s:%v\n", tcpConn.ident(), tcpConn.state)	
		}


 //   ipHdr.SourceIP = net.ParseIP(addr.String()) 
/*
		pseudohdr := buildPseudoHeader(&ipHdr, uint16(numBytes))


		chkbuf := make([]byte, 12 + numBytes)
		copy(chkbuf, pseudohdr)
//    copy(chkbuf[12:], buf[LEN_IPHDR:(numBytes + LEN_IPHDR)])
		copy(chkbuf[12:], buf[0:numBytes])

		chkbuf[28] = 0
		chkbuf[29] = 0
		fmt.Printf("Check buffer: %d, %v\n", len(chkbuf), chkbuf)
		chksum := net.Checksum(chkbuf)
		fmt.Printf("Calculated checksum: %d %x %b\n", chksum, chksum, chksum)
    // It seems that the TCP checksum is getting set to a constant value when 
    // trying to telnet locally, so potentially it doesn't get updated
    // until it actually tries to leave the network
		ipHdr.Display()
		hdr.Display(optionsAndPadding)

 //   fmt.Printf("Remaining bytes to data: %d\n", offsetBytes - LEN_HDR_PRE_OPTIONS)
		fmt.Printf("Data Size: %d\n", uint16(numBytes) - offsetBytes)
		fmt.Printf("TCP=>Received packet from %s ")




    SendSynAck(ifce, &ipHdr, &hdr, optionsAndPadding)

    // Get final ack
    numBytes, err = ifce.Read(buf)
    if err != nil {
    	log.Fatal(err)
    }
    fmt.Printf("Read another %d bytes\n", numBytes)

    SendSynAck(ifce, &ipHdr, &hdr, optionsAndPadding)
		*/
	}
}


func initialSequenceNumber() uint32 {
	return rand.Uint32()
}




func SendSynAck(conn *TCPConn) (err error) {

	// TODO: Pull from a "Free list"?
	var ackPacket TCPPacket

	var hdr TCPHeader

	ackPacket.Header = &hdr

	hdr.SourcePort = conn.localPort 
	hdr.DestPort = conn.remotePort 

	hdr.Seq = initialSequenceNumber()

	dataOffset := uint16(20)

	hdr.Ack = conn.recvNextSeq 							// Roger that!

	hdr.DataOffsetAndFlags = CTRL_SYN | CTRL_ACK  // we'll add the data offset 
	hdr.DataOffsetAndFlags |= ((dataOffset / 4) << 12)	    // Number of words 
	hdr.Window = conn.recvWindow					// TODO: Set appropriately
	hdr.Checksum = 0 								// Should get calcualted automatically?
	hdr.UrgentPointer = 0

	ackPacket.OptionsAndPadding = make([]byte,0) // no options
	ackPacket.Data = make([]byte, 0)

	// sequence management
	conn.sendNextSeq = hdr.Seq + 1
	conn.unacked = hdr.Seq

	written, err := conn.Send(&ackPacket)


	fmt.Printf("Wrote %d bytes with error %v\n", written, err)

	return err
}
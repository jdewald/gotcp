package tcp 

import (
	"log"
	"fmt"
	"math"
	//"net"
	"bytes"
	"bufio"
	"encoding/binary"
	"math/rand"
	"github.com/jdewald/gotcp/net"
	"github.com/jdewald/gotcp/net/ip"
	"github.com/eapache/channels"
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
	readChan 		channels.Channel	
	sem   			chan bool
}

func (conn *TCPConn) ident() string {
	return fmt.Sprintf("%s,%d,%s,%d", conn.localIP, conn.localPort, conn.remoteIP, conn.remotePort)
}

func (conn *TCPConn) Send(tcpPacket *TCPPacket) (written int, err error) {

	// TODO: Pull this from Free List? SYN/ACK's will be set lengths likely
	// So we don't want to keep allocating space when we can just have
	// it pre-allocated

	//tcpPacket.Display()

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

func (conn *TCPConn) Read(buf []byte) (read int, err error) {
	amountToRead := int(math.Min(float64(cap(buf)), float64(channels.Buffer(conn.readChan).Len())))

	conn.sem <- true

	for i := 0; i < amountToRead; i++ {
		buf[i] = (<- conn.readChan.Out()).(byte)
	}

	<- conn.sem

	return amountToRead, nil

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

	//fmt.Printf("TCPConn=>buildPseudoHeader=>bytes %v\n", hdrBuffer.Bytes())
	//fmt.Printf("TCPConn=>buildPseudoHeader=>tcpLen %d\n", tcpLen)

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

// Because we're using the /dev/tun interface we need to basically bootstrap
// our network and then we can use it as normal
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


// This is essentially our "run loop"
func listenForPackets() {
	for {
		packet,err := ipStack.Receive()		

		if err != nil {
			log.Fatal(err)
		}


		tcpPacket, err := Parse(packet.Packet)
		if err != nil {
			log.Fatal(err)
		}

		tl := listeners[packet.Destination() + string(tcpPacket.Header.DestPort)]
		ident := fmt.Sprintf("%s,%d,%s,%d", packet.Destination(), tcpPacket.Header.DestPort,packet.Source(), tcpPacket.Header.SourcePort)
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

		switch tcpConn.state {
		case STATE_SYN_SENT, STATE_SYN_RECEIVED:
			tcpConn.recvNextSeq = tcpPacket.Header.Seq + 1    // The SYN is considered to have occupied the first one
			tcpConn.recvWindow = tcpPacket.Header.Window // TODO: Figure out our own
												// This is aprt of congestion management
			if tcpPacket.IsACK() {
				fmt.Println("TCP=>Moving to ESTABLISHED State")
				tcpConn.state = STATE_ESTABLISHED
				tcpConn.readChan = channels.NewNativeChannel(1024 * 10) // 10K
				tcpConn.sem = make(chan bool, 1)
				tl.connChannel <- tcpConn 
			} else {

				err = sendSynAck(tcpConn)
				if err != nil {
					fmt.Println("TCP=>Unable to perform SynAck")
					log.Fatal(err)
				}
			}
		case STATE_ESTABLISHED:
			// TODO: We actually have to see how much we were able to write into our buffer
			tcpConn.recvNextSeq = tcpPacket.Header.Seq + uint32(len(tcpPacket.Data))
			tcpConn.recvWindow = tcpPacket.Header.Window // TODO: Figure out our own

			err = sendAck(tcpConn)
			if err != nil {
				log.Fatal(err)
			}

			tcpConn.sem <- true
			fmt.Println("Writing data to read channel")
			for _, val := range tcpPacket.Data {
				tcpConn.readChan.In() <- val 
			}

			<- tcpConn.sem
			fmt.Println("Done writing")

		default:
			fmt.Printf("What're we doing with state %s:%v\n", tcpConn.ident(), tcpConn.state)	
		}

	}
}


func initialSequenceNumber() uint32 {
	return rand.Uint32()
}

func sendAck(conn *TCPConn) (err error) {

	// TODO: Pull from a "Free list"?
	var ackPacket TCPPacket

	var hdr TCPHeader

	ackPacket.Header = &hdr

	hdr.SourcePort = conn.localPort 
	hdr.DestPort = conn.remotePort 

	hdr.Seq = conn.sendNextSeq 

	dataOffset := uint16(20)

	ackPacket.ACK(conn.recvNextSeq)

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

func sendSynAck(conn *TCPConn) (err error) {

	// TODO: Pull from a "Free list"?
	var ackPacket TCPPacket

	var hdr TCPHeader

	ackPacket.Header = &hdr

	hdr.SourcePort = conn.localPort 
	hdr.DestPort = conn.remotePort 

	hdr.Seq = initialSequenceNumber()

	dataOffset := uint16(20)

	ackPacket.ACK(conn.recvNextSeq)

	hdr.DataOffsetAndFlags = CTRL_SYN   // we'll add the data offset 
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
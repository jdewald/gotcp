package main

// http://www.darkcoding.net/uncategorized/raw-sockets-in-go-ip-layer/
// https://golang.org/ref/spec
// http://golang.org/pkg/net/
// ARP Spoofing so we can try to get packets not RST: http://jvns.ca/blog/2013/10/29/day-18-in-ur-connection/
import (
	"log"
	"fmt"
	"github.com/jdewald/gotcp/net/tcp"
)

// 20 octets


func main() {

	tcp.Start()


    tl, err := tcp.Listen("10.0.0.2", 23)

    if err != nil {
    	log.Fatal(err)
    }

    _,err = tl.Accept()

    if err != nil {
    	log.Fatal(err)
    }

    fmt.Println("Connected!")

	//myAddr := "10.0.3.15"
    //protocol := "tcp"
    //netaddr, err := net.ResolveIPAddr("ip4", myAddr)
    //conn, err := net.ListenIP("ip4:"+protocol, netaddr)
//    conn, err := net.ListenPacket("ip", "127.0.0.1")
//    conn, _ := net.ListenIP("ip", netaddr)
   
//    conn, err := net.ListenIP("ip4", netaddr)



}

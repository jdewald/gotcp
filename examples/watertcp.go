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

    tc,err := tl.Accept()

    if err != nil {
    	log.Fatal(err)
    }

    fmt.Println("Connected!")

    // using a "standard" interface
    buf := make([]byte, 1024)

    read := 0
    for {
        read, err = tc.Read(buf)


        if err != nil {
            log.Fatal(err)
        }
    
        if read > 0 {
            fmt.Printf("Read: %s\n", string(buf[:read]))
        }
    }

}

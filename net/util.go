package net

func VerifyChecksum(data []byte) bool {
	return Checksum(data) == 0
}

// Calculate 16-bit 1s complement additive checksum
func Checksum(data []byte) uint16 {
 	var chksum uint32

	var lsb uint16
	var msb uint16

	// 32-bit sum (2's complement sum of 16 bits with carry)
	for i := 0; i < len(data) -1; i+=2 {
		msb = uint16(data[i])
		lsb = uint16(data[i+1])
		chksum += uint32(lsb + (msb << 8))
	}


	// 1's complement 16-bit sum via "end arround carry" of 2's complement
	chksum = ((chksum >> 16) & 0xFFFF) + (chksum & 0xFFFF)

	return uint16(0xFFFF & (^chksum)) 
}
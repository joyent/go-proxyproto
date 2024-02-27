package proxyproto

import (
	"encoding/binary"
	"fmt"
	"math"
)

const (
	PP2_TYPE_SPC PP2Type = 0xE1

	PP2_SUBTYPE_SPC_VPC_ENDPOINT_ID uint16 = 0x1
	PP2_SUBTYPE_SPC_VPC_ID          uint16 = 0x2

	PPV_SUBTLV_VERSION byte = 0x01
)

type SubTlvHeader struct {
	Version byte
	Count   byte
}

type SubTlv struct {
	Type   uint16 // host order
	Length uint16 // host order
	Value  []byte
}

type SpcTlv struct {
	Header SubTlvHeader
	Tlvs   []*SubTlv
}

func NewSpcTlv() *SpcTlv {
	spcTlv := &SpcTlv{
		Header: SubTlvHeader{
			Version: PPV_SUBTLV_VERSION,
		},
		Tlvs: make([]*SubTlv, 0),
	}

	return spcTlv
}

func (subtlv *SubTlv) AddValue(data string) {
	subtlv.Value = []byte(data)
	subtlv.Length = uint16(len(subtlv.Value))
}

func (spcTlv *SpcTlv) AddSubTlv(subtlv *SubTlv) error {
	spcTlv.Tlvs = append(spcTlv.Tlvs, subtlv)
	spcTlv.Header.Count++

	return nil
}

func (spcTlv *SpcTlv) BuildTlv() (*TLV, error) {
	tlv := &TLV{
		Type: PP2_TYPE_SPC,
	}

	tval := make([]byte, 0)
	subvalue := make([]byte, 0)

	var tcnt uint8

	for _, subtlv := range spcTlv.Tlvs {
		l := len(subtlv.Value)
		if l > math.MaxUint16 {
			return nil, fmt.Errorf("proxyproto: cannot format SubTLV %v with length %d", subtlv.Type, len(subtlv.Value))
		} else if uint16(l) != subtlv.Length {
			return nil, fmt.Errorf("proxyproto: mismatch SubTLV %v with length %d:%d", subtlv.Type, len(subtlv.Value), subtlv.Length)
		}

		var typ [2]byte
		var length [2]byte

		binary.BigEndian.PutUint16(typ[:], subtlv.Type)
		binary.BigEndian.PutUint16(length[:], subtlv.Length)

		subvalue = append(subvalue, typ[:]...)
		subvalue = append(subvalue, length[:]...)
		subvalue = append(subvalue, subtlv.Value...)
		tcnt++
	}

	if spcTlv.Header.Count != tcnt {
		return nil, fmt.Errorf("proxyproto: mismatch TLV Count: %d:%d", spcTlv.Header.Count, tcnt)
	}

	tval = append(tval, spcTlv.Header.Version)
	tval = append(tval, byte(tcnt))
	tval = append(tval, subvalue[:]...)

	tlv.Value = tval

	return tlv, nil
}

func (spcTlv *SpcTlv) DecodeSubTlv(raw []byte) {
	spcTlv.Header.Version = raw[0]
	cnt := raw[1]

	raw = raw[2:]

	for i := 0; i < int(cnt); {
		if len(raw) < 4 {
			break
		}

		tlv := &SubTlv{
			Type:   binary.BigEndian.Uint16(raw[0:2]), // Max length = 65K
			Length: binary.BigEndian.Uint16(raw[2:4]), // Max length = 65K
		}

		if len(raw) < int(tlv.Length+4) {
			break
		}

		tlv.Value = make([]byte, tlv.Length)
		copy(tlv.Value, raw[4:tlv.Length+4])

		spcTlv.AddSubTlv(tlv)

		raw = raw[tlv.Length+4:]
	}

	if cnt != spcTlv.Header.Count {
		fmt.Printf("Mismatch count: cnt=%d, Count=%d \n", cnt, spcTlv.Header.Count)
	}
}

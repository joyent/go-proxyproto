package proxyproto

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
)

const (
	PP2_TYPE_SPC PP2Type = 0xE1

	PP2_SUBTYPE_SPC_VPC_ENDPOINT_ID uint16 = 0x1
	PP2_SUBTYPE_SPC_VPC_ID          uint16 = 0x2

	SPCTLV_VERSION       byte = 0x01
	SPCTLV_ENCODE_BASE64 byte = 'B'
	SPCTLV_ENCODE_PLAIN  byte = 'P'
)

/*
Encoded: encode type
	- encode data from the second byte
	- 'B'ase64
	- 'P'lain: no encode
*/

type SpcTlvHeader struct {
	Encode byte // 'B': Base64 Encode, 'P': Plain Hex Data
	// Encoded
	Version byte
	Flag    byte
	Count   byte // count of subtlvs
}

type SpcTlv struct {
	Header  SpcTlvHeader
	SubTlvs []*SpcSubTlv
}

type SpcSubTlv struct {
	Type   uint16 // host order => network order
	Length uint16 // host order => network order
	Value  []byte
}

func NewSpcTlv() *SpcTlv {
	spcTlv := &SpcTlv{
		Header: SpcTlvHeader{
			Encode:  SPCTLV_ENCODE_PLAIN,
			Version: SPCTLV_VERSION,
		},

		SubTlvs: make([]*SpcSubTlv, 0),
	}

	return spcTlv
}

func NewSpcSubTlv(typ uint16) *SpcSubTlv {
	return &SpcSubTlv{
		Type: typ,
	}
}

func (spcsubtlv *SpcSubTlv) AddValue(data string) {
	spcsubtlv.Value = []byte(data)
	spcsubtlv.Length = uint16(len(spcsubtlv.Value))
}

func (spcTlv *SpcTlv) EnableBase64Encode() {
	spcTlv.Header.Encode = SPCTLV_ENCODE_BASE64
}

func (spcTlv *SpcTlv) EnablePlainEncode() {
	spcTlv.Header.Encode = SPCTLV_ENCODE_PLAIN
}

func (spcTlv *SpcTlv) PutSubTlv(subtlv *SpcSubTlv) error {
	spcTlv.SubTlvs = append(spcTlv.SubTlvs, subtlv)
	spcTlv.Header.Count++

	return nil
}

func (spcTlv *SpcTlv) AddSubTlvValue(typ uint16, value string) error {
	subtlv := NewSpcSubTlv(typ)
	subtlv.AddValue(value)

	return spcTlv.PutSubTlv(subtlv)
}

func (spcTlv *SpcTlv) BuildTlv() (*TLV, error) {
	tlv := &TLV{
		Type:  PP2_TYPE_SPC,
		Value: make([]byte, 0),
	}

	tval := make([]byte, 0)
	subvalue := make([]byte, 0)

	var tcnt uint8

	for _, subtlv := range spcTlv.SubTlvs {
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
	tval = append(tval, spcTlv.Header.Flag)
	tval = append(tval, byte(tcnt))
	tval = append(tval, subvalue[:]...)

	// not encoding
	tlv.Value = append(tlv.Value, spcTlv.Header.Encode)

	if spcTlv.Header.Encode == SPCTLV_ENCODE_BASE64 {
		tval64 := base64.StdEncoding.EncodeToString(tval)
		tlv.Value = append(tlv.Value, []byte(tval64)...)
	} else if spcTlv.Header.Encode == SPCTLV_ENCODE_PLAIN {
		tlv.Value = append(tlv.Value, tval...)
	} else {
		return nil, fmt.Errorf("Not supported Encode type: %c", spcTlv.Header.Encode)
	}

	return tlv, nil
}

func (spcTlv *SpcTlv) DecodeTlv(raw []byte) error {
	// not encoded
	spcTlv.Header.Encode = raw[0]

	if spcTlv.Header.Encode == SPCTLV_ENCODE_BASE64 {
		tmp, err := base64.StdEncoding.DecodeString(string(raw[1:]))
		if err != nil {
			return err
		}

		raw = tmp
	} else if spcTlv.Header.Encode == SPCTLV_ENCODE_PLAIN {
		raw = raw[1:]
	}

	spcTlv.Header.Version = raw[0]
	spcTlv.Header.Flag = raw[1]

	cnt := raw[2]
	raw = raw[3:]

	for i := 0; i < int(cnt); {
		if len(raw) < 4 {
			break
		}

		tlv := &SpcSubTlv{
			Type:   binary.BigEndian.Uint16(raw[0:2]), // Max length = 65K
			Length: binary.BigEndian.Uint16(raw[2:4]), // Max length = 65K
		}

		if len(raw) < int(tlv.Length+4) {
			break
		}

		tlv.Value = make([]byte, tlv.Length)
		copy(tlv.Value, raw[4:tlv.Length+4])

		spcTlv.PutSubTlv(tlv)

		raw = raw[tlv.Length+4:]
	}

	if cnt != spcTlv.Header.Count {
		return fmt.Errorf("Mismatch Sub TLV Count: expected=%d, count=%d \n", spcTlv.Header.Count, cnt)
	}

	return nil
}

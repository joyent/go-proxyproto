package proxyproto

import (
	"fmt"
	"testing"
)

func TestSubTlv(t *testing.T) {
	spctlv := NewSpcTlv()
	vpce_id := "vpce-1234567890"

	if spctlv == nil {
		fmt.Printf("cannot alloc spctlv \n")
		return
	}

	subtlv := &SubTlv{
		Type: PP2_SUBTYPE_SPC_VPC_ENDPOINT_ID,
	}

	subtlv.AddValue(vpce_id)
	spctlv.AddSubTlv(subtlv)
	fmt.Printf("Count: %d \n", spctlv.Header.Count)

	tlv, err := spctlv.BuildTlv()
	if err != nil {
		t.Errorf("build error: %s", err)
		return
	}

	spctlv1 := NewSpcTlv()
	spctlv1.DecodeSubTlv(tlv.Value)

	if string(spctlv.Tlvs[0].Value) != vpce_id {
		fmt.Printf("mismatch value: %s != %s \n", spctlv.Tlvs[0].Value, vpce_id)
	}

	if string(spctlv1.Tlvs[0].Value) != vpce_id {
		fmt.Printf("mismatch value: %s != %s \n", spctlv1.Tlvs[0].Value, vpce_id)
	}

	fmt.Printf("Count: %d:%d \n", spctlv.Header.Count, spctlv1.Header.Count)
}

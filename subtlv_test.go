package proxyproto

import (
	"testing"
)

func TestSubTlv(t *testing.T) {
	spctlv := NewSpcTlv()
	vpce_id := "vpce-1234567890"
	vpc_id := "vpc-abscdeffdhg1"

	if spctlv == nil {
		t.Logf("cannot alloc spctlv \n")
		return
	}

	// use base64 encoding
	// for HAProxy Config
	spctlv.EnableBase64Encode()
	// use plain hex
	//spctlv.EnablePlainEncode()

	// vpcendpoint-id
	spctlv.AddSubTlvValue(PP2_SUBTYPE_SPC_VPC_ENDPOINT_ID, vpce_id)
	// vpc-id
	spctlv.AddSubTlvValue(PP2_SUBTYPE_SPC_VPC_ID, vpc_id)

	t.Logf("SubTLV Count: %d", spctlv.Header.Count)
	for i, subtlv := range spctlv.SubTlvs {
		t.Logf("%d: subtlv.type=%d, len=%d, value=%s(%d)", i, subtlv.Type, subtlv.Length, string(subtlv.Value), len(subtlv.Value))
	}

	tlv, err := spctlv.BuildTlv()
	if err != nil {
		t.Errorf("build error: %s", err)
		return
	}

	t.Logf("TLV: Type=0x%X, Len=%d, Value: %s", tlv.Type, len(tlv.Value), string(tlv.Value))

	spctlv1 := NewSpcTlv()
	spctlv1.DecodeTlv(tlv.Value)

	if spctlv.Header.Count != spctlv1.Header.Count {
		t.Fatalf("mismatch count value: %d != %d", spctlv.Header.Count, spctlv1.Header.Count)
	}

	if string(spctlv1.SubTlvs[0].Value) != vpce_id {
		t.Fatalf("mismatch value: %s != %s", spctlv.SubTlvs[0].Value, vpce_id)
	}

	if string(spctlv1.SubTlvs[1].Value) != vpc_id {
		t.Fatalf("mismatch value: %s != %s", spctlv1.SubTlvs[1].Value, vpc_id)
	}

	t.Logf("Count: org=%d, new=%d \n", spctlv.Header.Count, spctlv1.Header.Count)
	for i, subtlv := range spctlv1.SubTlvs {
		t.Logf("%d: subtlv.type=%d, len=%d, value=%s(%d)", i, subtlv.Type, subtlv.Length, string(subtlv.Value), len(subtlv.Value))
	}
}

package control

import (
	"encoding/json"
	"testing"
)

func TestPingRequestDataMarshalsFalseNoCloud(t *testing.T) {
	data, err := json.Marshal(PingRequestData{})
	if err != nil {
		t.Fatalf("marshal ping request: %v", err)
	}
	if string(data) != `{"noCloud":false}` {
		t.Fatalf("unexpected ping request JSON: %s", data)
	}
}

func TestWgRegisterDataMarshalsBackwardsCompatible(t *testing.T) {
	data, err := json.Marshal(WgRegisterData{
		PublicKey:           "pub",
		BackwardsCompatible: true,
	})
	if err != nil {
		t.Fatalf("marshal wg register: %v", err)
	}
	if string(data) != `{"publicKey":"pub","backwardsCompatible":true}` {
		t.Fatalf("unexpected wg register JSON: %s", data)
	}
}

func TestMessageMarshalsNullData(t *testing.T) {
	data, err := json.Marshal(Message{Type: "test"})
	if err != nil {
		t.Fatalf("marshal message: %v", err)
	}
	if string(data) != `{"type":"test","data":null}` {
		t.Fatalf("unexpected message JSON: %s", data)
	}
}

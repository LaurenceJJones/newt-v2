package forwarder

import "testing"

func TestCloseIsIdempotentAndDisablesQueuedReplies(t *testing.T) {
	handler, err := NewHandlerWithFlags(true, true, true, 1280)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	if err := handler.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := handler.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if handler.engine.QueueICMPReply([]byte{1, 2, 3}) {
		t.Fatal("expected queue to reject replies after close")
	}
	if got := handler.engine.ReadOutgoingPacket(); got != nil {
		t.Fatal("expected no packet after close")
	}
}

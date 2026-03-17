package docker

import (
	"errors"
	"testing"

	"github.com/fosrl/newt/internal/control"
)

func TestSocketContainersPayloadWrapsContainers(t *testing.T) {
	containers := []control.DockerContainerData{
		{
			ID:       "abc123",
			Name:     "web",
			Ports:    []control.DockerContainerPortData{},
			Labels:   map[string]string{},
			Networks: map[string]control.DockerNetworkData{},
		},
	}

	payload := socketContainersPayload(containers, nil)

	gotContainers, ok := payload["containers"].([]control.DockerContainerData)
	if !ok {
		t.Fatalf("expected typed containers slice, got %T", payload["containers"])
	}
	if len(gotContainers) != 1 || gotContainers[0].ID != "abc123" {
		t.Fatalf("unexpected containers payload: %#v", gotContainers)
	}
	if _, ok := payload["error"]; ok {
		t.Fatal("did not expect error key on success payload")
	}
}

func TestSocketContainersPayloadIncludesEmptySliceAndError(t *testing.T) {
	payload := socketContainersPayload(nil, errors.New("boom"))

	gotContainers, ok := payload["containers"].([]any)
	if !ok {
		t.Fatalf("expected empty []any containers slice, got %T", payload["containers"])
	}
	if len(gotContainers) != 0 {
		t.Fatalf("expected empty containers slice, got %#v", gotContainers)
	}
	if got := payload["error"]; got != "boom" {
		t.Fatalf("unexpected error payload: %#v", got)
	}
}

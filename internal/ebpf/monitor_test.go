package ebpf

import (
	"testing"
	"time"
)

func TestNewMonitor(t *testing.T) {
	m := NewMonitor(ProbeConfig{
		TraceSyscalls: true,
		TraceNetwork:  true,
	})
	if m == nil {
		t.Fatal("expected non-nil monitor")
	}
	if m.IsRunning() {
		t.Error("expected monitor to not be running initially")
	}
}

func TestMonitor_Emit(t *testing.T) {
	m := NewMonitor(ProbeConfig{})
	// Manually open the events channel for testing without Start
	var received []Event

	m.OnEvent(func(e Event) {
		received = append(received, e)
	})

	// Emit directly to test the stats tracking
	m.Emit(Event{Type: EventSyscall, Comm: "test"})
	m.Emit(Event{Type: EventNetConnect, Comm: "test"})
	m.Emit(Event{Type: EventFileOpen, Comm: "test"})

	stats := m.Stats()
	if stats.EventsTotal != 3 {
		t.Errorf("expected 3 total events, got %d", stats.EventsTotal)
	}
	if stats.EventsByType[EventSyscall] != 1 {
		t.Errorf("expected 1 syscall event, got %d", stats.EventsByType[EventSyscall])
	}
	if stats.EventsByType[EventNetConnect] != 1 {
		t.Errorf("expected 1 net_connect event, got %d", stats.EventsByType[EventNetConnect])
	}
}

func TestMonitor_OnEvent(t *testing.T) {
	m := NewMonitor(ProbeConfig{})
	called := false
	m.OnEvent(func(e Event) {
		called = true
	})
	if called {
		t.Error("handler should not be called before events")
	}
}

func TestMonitor_Stats(t *testing.T) {
	m := NewMonitor(ProbeConfig{})
	stats := m.Stats()
	if stats.EventsTotal != 0 {
		t.Errorf("expected 0 events, got %d", stats.EventsTotal)
	}
}

func TestMonitor_Stop_NotRunning(t *testing.T) {
	m := NewMonitor(ProbeConfig{})
	// Should not panic
	m.Stop()
}

func TestEvent_Types(t *testing.T) {
	types := []EventType{EventSyscall, EventNetConnect, EventNetBind, EventFileOpen, EventFileWrite, EventProcessExec}
	for _, et := range types {
		if et == "" {
			t.Error("event type should not be empty")
		}
	}
}

func TestMonitor_EmitDropped(t *testing.T) {
	m := NewMonitor(ProbeConfig{})

	// Fill the buffer (4096 capacity)
	for i := 0; i < 5000; i++ {
		m.Emit(Event{Type: EventSyscall, Timestamp: time.Now()})
	}

	stats := m.Stats()
	if stats.DroppedEvents == 0 {
		t.Error("expected some dropped events when buffer is full")
	}
	if stats.EventsTotal+stats.DroppedEvents != 5000 {
		t.Errorf("expected total+dropped = 5000, got %d+%d=%d",
			stats.EventsTotal, stats.DroppedEvents, stats.EventsTotal+stats.DroppedEvents)
	}
}

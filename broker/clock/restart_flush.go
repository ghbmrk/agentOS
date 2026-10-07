package clock

// Flusher waits for queued owner texts. *Guard implements it via Flush.
type Flusher interface {
	Flush()
}

// BeforePlannedRestart drains queued owner texts before a planned restart
// or update so a text is not lost (P2-9 security W on #68; TIM-1). Call
// sites: agentosd before applying an update or stopping for a planned
// reboot. A nil Flusher is a no-op (tests).
func BeforePlannedRestart(f Flusher) {
	if f == nil {
		return
	}
	f.Flush()
}

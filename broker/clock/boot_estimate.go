package clock

import (
	"encoding/json"
	"time"
)

// BootEstimateBytes is BootEstimate over already-read state bytes (HOST-1b O1:
// the boot helper opens the path once with O_NOFOLLOW and passes that read).
func BootEstimateBytes(b []byte, rtc time.Time, hostID string) (time.Time, bool) {
	var v saved
	if json.Unmarshal(b, &v) != nil || !v.HaveOffset || !validOffset(v.Offset) {
		return time.Time{}, false
	}
	if h := HostKey(hostID); h == "" || h != v.OffsetHost {
		return time.Time{}, false // learned on another PC, or this one unnamed (L3 on #177)
	}
	return rtc.Add(-v.Offset), true
}

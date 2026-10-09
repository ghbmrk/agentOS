package clock

// REQ: TIM-1, HW-8

import (
	"os"
	"testing"
)

func TestHW8RTCReadsSysfs(t *testing.T) {
	// The answer depends on the host; a host with a hardware clock gives a
	// time after 2000, read without privilege.
	if _, err := os.Stat("/sys/class/rtc/rtc0/since_epoch"); err != nil {
		t.Skip("no hardware clock here")
	}
	rtc, err := RTC()
	if err != nil || rtc.Year() < 2000 {
		t.Fatalf("RTC = %v, %v", rtc, err)
	}
}

func TestTIM1BootClock(t *testing.T) {
	a := bootElapsed()
	if a <= 0 || bootID() == "" {
		t.Fatalf("boot elapsed %v, id %q", a, bootID())
	}
	if b := bootElapsed(); b < a {
		t.Fatalf("CLOCK_BOOTTIME went back: %v then %v", a, b)
	}
}

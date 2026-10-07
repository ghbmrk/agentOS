package recovery

import (
	"time"
)

// StaleAge is how old a verified current-key backup may be before the
// only-copy notice returns (BAK-1 ASSUMPTIONS B6 follow-up). Matches the
// monthly digest cadence for an owner who chose none.
const StaleAge = 30 * 24 * time.Hour

// NoticeStale is the status/digest line when the latest verified backup
// under the current recovery key is older than StaleAge.
const NoticeStale = "Your last checked backup is over a month old, so treat this drive as the only recent copy. Back up again on the box's Wi-Fi page."

// CurrentBackupAge is how long since the newest verified backup sealed to
// the drive's current backup key. ok is false when none exists (caller
// keeps the ordinary only-copy notice).
func CurrentBackupAge(b *Box, now time.Time) (age time.Duration, ok bool, err error) {
	l, err := loadLog(b)
	if err != nil {
		return 0, false, err
	}
	cur := currentKey(b)
	if cur == "" {
		return 0, false, nil
	}
	var latest time.Time
	for _, e := range l.Entries {
		if !e.Verified || e.Key != cur {
			continue
		}
		if latest.IsZero() || e.Created.After(latest) {
			latest = e.Created
		}
	}
	if latest.IsZero() {
		return 0, false, nil
	}
	age = now.Sub(latest)
	if age < 0 {
		age = 0
	}
	return age, true, nil
}

// StaleOnlyCopyNotice returns NoticeStale when a current-key verified
// backup exists but is older than StaleAge; otherwise empty. It does not
// replace OnlyCopyNotice when no current backup exists.
func StaleOnlyCopyNotice(b *Box, now time.Time) (string, error) {
	age, ok, err := CurrentBackupAge(b, now)
	if err != nil || !ok {
		return "", err
	}
	if age >= StaleAge {
		return NoticeStale, nil
	}
	return "", nil
}

package meter

import "encoding/json"

// ReportUsage takes the usage the vault process reported for this call
// beside its body (broker/modelroute, egress K9): one provider usage
// object in that provider's own shape, so cached input gets the
// provider's weight, and whether the provider's answer completed. used
// charges it by the same rule as usage read from the body, in its place:
// reported usage only for an answer that completed, by both the report
// and the body; otherwise never less output than the content counted.
func (u *usageWriter) ReportUsage(b []byte, complete bool) {
	var d any
	if len(b) > 4<<10 || json.Unmarshal(b, &d) != nil {
		return
	}
	r := &usage{}
	r.report(d)
	r.done = complete
	u.rep = r
}

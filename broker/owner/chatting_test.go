package owner

import (
	"context"
	"strings"
	"testing"
	"time"
)

// REQ: CH-15, CAP-10

// TestOnlyTaskChatOpensTheChat (security B1 on #2372): a question is
// conversation only while owner task chat reaches the agent. Control
// words, unclear words, settings and question answers need only the
// owner's number, which can be spoofed, and reach no agent, so none of
// them open the chat, locked or unlocked; task chat in an unlocked session
// does, for the window asked.
func TestOnlyTaskChatOpensTheChat(t *testing.T) {
	r := newRig(t, nil)
	r.edit = func(c *Config) {
		c.Answer = func(_ context.Context, msg string) (string, bool) {
			return "Answered.", strings.HasPrefix(msg, "Q100")
		}
	}
	r.ch = r.open()
	for _, spoof := range []string{"HELP", "STATUS", "YES 1", "UNDO 4", "RESUME", "book a table", "Q100 yes"} {
		r.say(spoof)
		if r.ch.Chatting(30 * time.Minute) {
			t.Fatalf("locked %q opened the chat", spoof)
		}
	}
	if !r.ch.Active(30 * time.Minute) {
		t.Fatal("the rig's locked HELP no longer reaches the control handler")
	}
	if len(r.agent.got()) != 0 {
		t.Fatalf("locked texts reached the agent: %q", r.agent.got())
	}
	r.unlock()
	for _, word := range []string{"HELP", "STATUS", "TEXTS 5", "Q100 yes"} {
		r.say(word)
		if r.ch.Chatting(30 * time.Minute) {
			t.Fatalf("unlocked %q opened the chat", word)
		}
	}
	r.say("book a table")
	if len(r.agent.got()) != 1 || !r.ch.Chatting(30*time.Minute) {
		t.Fatalf("task chat: agent got %q, chatting %v", r.agent.got(), r.ch.Chatting(30*time.Minute))
	}
	r.advance(30 * time.Minute)
	if r.ch.Chatting(30 * time.Minute) {
		t.Fatal("the chat stayed open past its window")
	}
}

// TestTaskChatToADownAgentDoesNotOpenTheChat: task chat the agent never
// got is no conversation.
func TestTaskChatToADownAgentDoesNotOpenTheChat(t *testing.T) {
	r := newRig(t, nil)
	r.down = true
	r.ch = r.open()
	r.unlock()
	r.say("book a table")
	if r.ch.Chatting(30 * time.Minute) {
		t.Fatal("task chat with no agent opened the chat")
	}
}

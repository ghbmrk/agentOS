package update

import "testing"

// REQ: OSS-10
func TestOSS10wf1EmptyFollowNameOnlyForImageRoot(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	image := f.rootFile(1)
	ok, err := EmptyFollowNameOK(image, image)
	if err != nil || !ok {
		t.Fatalf("same root: ok=%v err=%v", ok, err)
	}
	fork := forkOf(t, 2, 3)
	ok, err = EmptyFollowNameOK(fork.rootFile(1), image)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("fork root accepted as empty-name project root")
	}
	ok, err = EmptyFollowNameOK(nil, image)
	if err != nil || ok {
		t.Fatalf("nil root: ok=%v err=%v", ok, err)
	}
}

package main

// REQ: CAP-8

import "testing"

// Worker tools are offered only with a registered worker image.
func TestCAP8WorkerToolsNeedARegisteredImage(t *testing.T) {
	imgs := images{"base": "/img"}
	if workerTools(nil, imgs, "", "sleep infinity", 2048) != nil {
		t.Fatal("worker tools offered with no worker image")
	}
	if workerTools(nil, imgs, "missing", "sleep infinity", 2048) != nil {
		t.Fatal("worker tools offered with an unregistered image")
	}
	if workerTools(nil, imgs, "base", "sleep infinity", 2048) == nil {
		t.Fatal("worker tools missing with a registered image")
	}
}

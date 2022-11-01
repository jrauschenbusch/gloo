package main

import (
	"context"
	"fmt"

	"github.com/solo-io/gloo/pkg/utils/probes"
	"github.com/solo-io/gloo/projects/gloo/pkg/setup"
	"github.com/solo-io/go-utils/log"
	"github.com/solo-io/go-utils/stats"
)

func main() {

	// add a race for race detector to pick up:
	// from https://go.dev/doc/articles/race_detector
	c := make(chan bool)
	m := make(map[string]string)
	go func() {
		m["1"] = "a" // First conflicting access.
		c <- true
	}()
	m["2"] = "b" // Second conflicting access.
	<-c
	for k, v := range m {
		fmt.Println(k, v)
	}
	// end race

	ctx := context.Background()
	probes.StartLivenessProbeServer(ctx)
	stats.ConditionallyStartStatsServer()
	if err := setup.Main(ctx); err != nil {
		log.Fatalf("err in main: %v", err.Error())
	}
}

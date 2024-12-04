package shutdown

import (
	"context"
	"fmt"
	"os"
	"os/signal"
)

// OnSignal calls the provided context.CancelFunc when given os.Signal is caught. Example usage:
//
//	ctx, cancel := context.WithCancel(context.Background())
//	go shutdown.OnSignal(os.Interrupt, cancel)
//	g, ctx := errgroup.WithContext(ctx)
//	defer g.Wait()
//	g.Go(...)
func OnSignal(sig os.Signal, cancel context.CancelFunc) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, sig)
	<-ch
	fmt.Fprintf(os.Stderr, "Caught %s, quitting...\n", sig)
	cancel()
}

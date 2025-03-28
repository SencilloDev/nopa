package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/SencilloDev/nopa"
	"github.com/nats-io/jsm.go/natscontext"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nats.go/micro"
)

var agent *nopa.Agent

type Request struct {
	Package string          `json:"package"`
	Input   json.RawMessage `json:"input"`
}

func HandleRequest(r micro.Request) {
	if !json.Valid(r.Data()) {
		r.Error("400", "bad request", []byte("bad request"))
		return
	}

	var req Request
	if err := json.Unmarshal(r.Data(), &req); err != nil {
		r.Error("400", "bad request", []byte("bad request"))
		return
	}

	ctx := context.Background()

	resp, err := agent.Eval(ctx, req.Input, req.Package)
	if err != nil && errors.Is(err, nopa.ErrNotFound) {
		r.Error("404", err.Error(), []byte(err.Error()))
		return
	}
	if err != nil {
		log.Println(err)
		r.Error("500", "internal server error", []byte("uh oh spaghettios"))
		return
	}

	r.Respond(resp)
}

func main() {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	nc, err := natscontext.Connect("")
	if err != nil {
		log.Fatal(err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		log.Fatal(err)
	}

	obj, err := js.ObjectStore(ctx, "bundles")
	if err != nil {
		log.Fatal(err)
	}

	env := map[string]string{
		"token": "1234",
	}

	agent = nopa.NewAgent(nopa.AgentOpts{
		BundleName:  "bundle.tar.gz",
		Env:         env,
		ObjectStore: obj,
		Logger:      logger,
	})

	config := micro.Config{
		Name:        "nopatest",
		Version:     "0.0.1",
		Description: "An example application",
	}

	svc, err := micro.AddService(nc, config)
	if err != nil {
		log.Fatal(err)
	}

	svc.AddEndpoint("test", micro.HandlerFunc(HandleRequest), micro.WithEndpointSubject("test"))
	logger.Info("started service")

	go agent.MustWatchBundleUpdates(ctx)

	sigTerm := make(chan os.Signal, 1)
	signal.Notify(sigTerm, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigTerm
	logger.Info(fmt.Sprintf("received signal: %s", sig))
	svc.Stop()
}

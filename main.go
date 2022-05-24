package main

import (
	"go.uber.org/zap"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/heilerich/webhook-coredns-etcd/solver"
)

func main() {
	logger, _ := zap.NewProduction()
	cmd.RunWebhookServer("k8s.fehe.eu",
		solver.New(logger),
	)
}

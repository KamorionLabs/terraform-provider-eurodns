package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/KamorionLabs/terraform-provider-eurodns/internal/provider"
)

// Set by goreleaser.
var version = "dev"

//go:generate go tool tfplugindocs generate --provider-name eurodns

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/kamorionlabs/eurodns",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err.Error())
	}
}

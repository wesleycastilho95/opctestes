package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/debug"
	"github.com/gopcua/opcua/ua"
)

func main() {

	var (
		endpoint = flag.String("endpoint", "opc.tcp://192.168.0.21:49321", "OPC UA Endpoint URL")
		policy   = flag.String("policy", "None", "Security policy: None, Basic128Rsa15, Basic256, Basic256Sha256. Default: auto")
		mode     = flag.String("mode", "None", "Security mode: None, Sign, SignAndEncrypt. Default: auto")
		certFile = flag.String("cert", "", "Path to cert.pem. Required for security mode/policy != None")
		keyFile  = flag.String("key", "", "Path to private key.pem. Required for security mode/policy != None")
		//nodeID   = flag.String("node", "", "node id to subscribe to")
		//event    = flag.Bool("event", false, "subscribe to node event changes (Default: node value changes)")
		//interval = flag.Duration("interval", opcua.DefaultSubscriptionInterval, "subscription interval")
	)
	flag.BoolVar(&debug.Enable, "debug", false, "enable debug logging")
	flag.Parse()
	log.SetFlags(0)

	//Cria o contexto com um tempo de demonstação de 60 segundos
	d := 60 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	log.Printf("Subscription will stop after %s for demonstration purposes", d)

	// Procura os endpoint ua no endereço

	endpoints, err := opcua.GetEndpoints(ctx, *endpoint)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("\n\n\n--*******************************************************************************************--\n\n\n")

	//printa os endpoints
	for key, v := range endpoints {
		fmt.Printf("Servidor numero:\t%v\n", key)
		fmt.Printf("\tEndpointURL:\t\t%v\n", v.EndpointURL)
		//fmt.Printf("\t%v\n", v.Server)
		//fmt.Printf("\t%v\n", v.ServerCertificate)
		fmt.Printf("\tSecurityMode:\t\t%v\n", v.SecurityMode)
		fmt.Printf("\tSecurityPolicyURI:\t%v\n", v.SecurityPolicyURI)
		//fmt.Printf("\t%v\n", v.UserIdentityTokens)
		fmt.Printf("\tTransportProfileURI:\t%v\n", v.TransportProfileURI)
		fmt.Printf("\tSecurityLevel:\t\t%v\n", v.SecurityLevel)
	}

	fmt.Printf("\n\n\n--**********************************************************************************************--\n\n\n")

	ep := opcua.SelectEndpoint(endpoints, *policy, ua.MessageSecurityModeFromString(*mode))

	if ep == nil {
		log.Fatal("Failed to find suitable endpoint")
	}

	ep.EndpointURL = *endpoint

	fmt.Println("*", ep.SecurityPolicyURI, ep.SecurityMode)

	fmt.Printf("Servidor Selecionado ⬇️\n")
	fmt.Printf("\tEndpointURL:\t\t%v\n", ep.EndpointURL)
	//fmt.Printf("\t%v\n", ep.Server)
	//fmt.Printf("\t%v\n", ep.ServerCertificate)
	fmt.Printf("\tSecurityMode:\t\t%v\n", ep.SecurityMode)
	fmt.Printf("\tSecurityPolicyURI:\t%v\n", ep.SecurityPolicyURI)
	//fmt.Printf("\t%v\n", ep.UserIdentityTokens)
	fmt.Printf("\tTransportProfileURI:\t%v\n", ep.TransportProfileURI)
	fmt.Printf("\tSecurityLevel:\t\t%v\n", ep.SecurityLevel)

	opts := []opcua.Option{
		opcua.SecurityPolicy(*policy),
		opcua.SecurityModeString(*mode),
		opcua.CertificateFile(*certFile),
		opcua.PrivateKeyFile(*keyFile),
		opcua.AuthAnonymous(),
		opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
	}
	//Criação do endpoint opc ua
	c := opcua.NewClient(ep.EndpointURL, opts...)
	if err := c.Connect(ctx); err != nil {
		log.Fatal(err)
	}
	defer c.CloseWithContext(ctx)

}

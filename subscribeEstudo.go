package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/debug"
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
)

func main() {

	var (
		endpoint = flag.String("endpoint", "opc.tcp://192.168.0.21:49321", "OPC UA Endpoint URL")
		policy   = flag.String("policy", "None", "Security policy: None, Basic128Rsa15, Basic256, Basic256Sha256. Default: auto")
		mode     = flag.String("mode", "None", "Security mode: None, Sign, SignAndEncrypt. Default: auto")
		certFile = flag.String("cert", "", "Path to cert.pem. Required for security mode/policy != None")
		keyFile  = flag.String("key", "", "Path to private key.pem. Required for security mode/policy != None")
		nodeID   = flag.String("node", "ns=2;s=Channel1.Device1.Tag1", "node id to subscribe to")
		event    = flag.Bool("event", false, "subscribe to node event changes (Default: node value changes)")
		interval = flag.Duration("interval", 2000*time.Millisecond, "subscription interval")
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

	notifyCh := make(chan *opcua.PublishNotificationData)

	sub, err := c.SubscribeWithContext(ctx, &opcua.SubscriptionParameters{
		Interval: *interval,
	}, notifyCh)
	if err != nil {
		log.Fatal(err)
	}
	defer sub.Cancel(ctx)
	log.Printf("Created subscription with id %v", sub.SubscriptionID)

	id, err := ua.ParseNodeID(*nodeID)
	if err != nil {
		log.Fatal(err)
	}

	var miCreateRequest *ua.MonitoredItemCreateRequest
	var eventFieldNames []string
	if *event {
		miCreateRequest, eventFieldNames = eventRequest(id)
	} else {
		miCreateRequest = valueRequest(id)
	}
	//Parametro que coloca o valor de atualização do tag

	miCreateRequest.RequestedParameters.SamplingInterval = 1000

	fmt.Printf("\n\n\n--**********************************************************************************************--\n\n\n")

	fmt.Printf("\nParamestros do monitoramento ⬇️\n")
	fmt.Printf("\nNames:%v ⬇️\n", eventFieldNames)
	fmt.Printf("\nItemToMonitor:\t\t%v\n", miCreateRequest.ItemToMonitor)
	fmt.Printf("\nMonitoringMode:\t\t%v\n", miCreateRequest.MonitoringMode)
	fmt.Printf("\nRequestedParameters:\t%v\n", miCreateRequest.RequestedParameters)

	res, err := sub.Monitor(ua.TimestampsToReturnBoth, miCreateRequest)
	if err != nil || res.Results[0].StatusCode != ua.StatusOK {
		log.Fatal(err)
	}

	fmt.Printf("\n\n\n--**********************************************************************************************--\n\n\n")

	fmt.Printf("res:%+v\n", res)
	fmt.Printf("res.RespondeHeader:%+v\n", res.ResponseHeader)
	fmt.Printf("res.RespondeHeader[0]:%+v\n", res.Results[0])

	fmt.Printf("\n\n\n--**********************************************************************************************--\n\n\n")

	for {
		select {
		case <-ctx.Done():
			return
		case res := <-notifyCh:
			if res.Error != nil {
				log.Print(res.Error)
				continue
			}

			switch x := res.Value.(type) {
			case *ua.DataChangeNotification:
				for _, item := range x.MonitoredItems {
					data := item.Value.Value.Value()
					log.Printf("MonitoredItem with client handle %v = %v", item.ClientHandle, data)
				}

			case *ua.EventNotificationList:
				for _, item := range x.Events {
					log.Printf("Event for client handle: %v\n", item.ClientHandle)
					for i, field := range item.EventFields {
						log.Printf("%v: %v of Type: %T", eventFieldNames[i], field.Value(), field.Value())
					}
					log.Println()
				}

			default:
				log.Printf("what's this publish result? %T", res.Value)
			}
		}
	}

}

func valueRequest(nodeID *ua.NodeID) *ua.MonitoredItemCreateRequest {
	handle := uint32(42)
	return opcua.NewMonitoredItemCreateRequestWithDefaults(nodeID, ua.AttributeIDValue, handle)
}

func eventRequest(nodeID *ua.NodeID) (*ua.MonitoredItemCreateRequest, []string) {
	fieldNames := []string{"EventId", "EventType", "Severity", "Time", "Message"}
	selects := make([]*ua.SimpleAttributeOperand, len(fieldNames))

	for i, name := range fieldNames {
		selects[i] = &ua.SimpleAttributeOperand{
			TypeDefinitionID: ua.NewNumericNodeID(0, id.BaseEventType),
			BrowsePath:       []*ua.QualifiedName{{NamespaceIndex: 0, Name: name}},
			AttributeID:      ua.AttributeIDValue,
		}
	}

	wheres := &ua.ContentFilter{
		Elements: []*ua.ContentFilterElement{
			{
				FilterOperator: ua.FilterOperatorGreaterThanOrEqual,
				FilterOperands: []*ua.ExtensionObject{
					{
						EncodingMask: 1,
						TypeID: &ua.ExpandedNodeID{
							NodeID: ua.NewNumericNodeID(0, id.SimpleAttributeOperand_Encoding_DefaultBinary),
						},
						Value: ua.SimpleAttributeOperand{
							TypeDefinitionID: ua.NewNumericNodeID(0, id.BaseEventType),
							BrowsePath:       []*ua.QualifiedName{{NamespaceIndex: 0, Name: "Severity"}},
							AttributeID:      ua.AttributeIDValue,
						},
					},
					{
						EncodingMask: 1,
						TypeID: &ua.ExpandedNodeID{
							NodeID: ua.NewNumericNodeID(0, id.LiteralOperand_Encoding_DefaultBinary),
						},
						Value: ua.LiteralOperand{
							Value: ua.MustVariant(uint16(0)),
						},
					},
				},
			},
		},
	}

	filter := ua.EventFilter{
		SelectClauses: selects,
		WhereClause:   wheres,
	}

	filterExtObj := ua.ExtensionObject{
		EncodingMask: ua.ExtensionObjectBinary,
		TypeID: &ua.ExpandedNodeID{
			NodeID: ua.NewNumericNodeID(0, id.EventFilter_Encoding_DefaultBinary),
		},
		Value: filter,
	}

	handle := uint32(42)
	req := &ua.MonitoredItemCreateRequest{
		ItemToMonitor: &ua.ReadValueID{
			NodeID:       nodeID,
			AttributeID:  ua.AttributeIDEventNotifier,
			DataEncoding: &ua.QualifiedName{},
		},
		MonitoringMode: ua.MonitoringModeReporting,
		RequestedParameters: &ua.MonitoringParameters{
			ClientHandle:     handle,
			DiscardOldest:    true,
			Filter:           &filterExtObj,
			QueueSize:        10,
			SamplingInterval: 1.0,
		},
	}

	return req, fieldNames
}

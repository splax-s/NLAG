// Package nlag provides a Go SDK for NLAG tunnel services.
//
// NLAG allows you to expose local services through secure tunnels,
// making them accessible from the internet with custom subdomains,
// authentication, and more.
//
// Quick Start:
//
//	client, err := nlag.NewClient()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	tunnel, err := client.Expose(context.Background(), &nlag.TunnelConfig{
//	    Protocol:  nlag.ProtocolHTTP,
//	    LocalPort: 8080,
//	    Subdomain: "my-app",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	fmt.Println("Tunnel URL:", tunnel.PublicURL())
package nlag

// Version is the SDK version.
const Version = "0.1.0"

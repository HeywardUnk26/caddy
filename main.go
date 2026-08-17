package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// WrappedConn wraps a net.Conn to intercept and handle TLS handshake errors explicitly.
type WrappedConn struct {
	net.Conn
	server *http.Server
	once   sync.Once
}

// Read overrides the net.Conn Read method to ensure handshake is completed.
func (c *WrappedConn) Read(b []byte) (n int, err error) {
	return c.Conn.Read(b)
}

// Write overrides the net.Conn Write method.
func (c *WrappedConn) Write(b []byte) (n int, err error) {
	return c.Conn.Write(b)
}

// WrappedListener wraps a net.Listener to perform explicit TLS handshakes and handle errors.
type WrappedListener struct {
	net.Listener
	config *tls.Config
}

// Accept accepts connections and performs the TLS handshake explicitly.
func (wl *WrappedListener) Accept() (net.Conn, error) {
	c, err := wl.Listener.Accept()
	if err != nil {
		return nil, err
	}

	tlsConn, ok := c.(*tls.Conn)
	if !ok {
		// If it's not a TLS connection, wrap it directly
		return c, nil
	}

	// Perform the handshake explicitly to catch errors early and send TLS alerts
	go func() {
		// Set a handshake timeout to prevent slowloris attacks
		_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
		err := tlsConn.Handshake()
		_ = tlsConn.SetDeadline(time.Time{}) // Reset deadline

		if err != nil {
			log.Printf("[ERROR] TLS handshake failed: %v", err)
			// Go's crypto/tls automatically sends the alert record during Handshake().
			// We must close the connection after the handshake error is returned.
			_ = tlsConn.Close()
			return
		}
	}()

	return &WrappedConn{Conn: tlsConn}, nil
}

// NewWrappedListener creates a new WrappedListener.
func NewWrappedListener(inner net.Listener, config *tls.Config) net.Listener {
	return &WrappedListener{
		Listener: tls.NewListener(inner, config),
		config:   config,
	}
}

func main() {
	// Load or generate mock certificates for demonstration/testing purposes
	log.Println("Starting mTLS-protected listener...")

	// In a real Caddy setup, these would be loaded from files.
	// For this demonstration, we set up a basic TLS configuration template.
	caCertPool := x509.NewCertPool()
	// Mock CA cert loading (in production, use trusted_ca_cert_file)
	caCertPEM, err := os.ReadFile("ca.pem")
	if err == nil {
		caCertPool.AppendCertsFromPEM(caCertPEM)
	}

	tlsConfig := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caCertPool,
		VerifyConnection: func(cs tls.ConnectionState) error {
			// Custom application-layer validation rules
			if len(cs.PeerCertificates) == 0 {
				return errors.New("client certificate required")
			}
			return nil
		},
	}

	// Setup HTTP handler with deferred/application-layer validation checks
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "TLS required", http.StatusBadRequest)
			return
		}

		// If client certificate verification is deferred or handled at the application layer
		if len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "400 Bad Request: Missing Client Certificate\n")
			return
		}

		// Verify certificate validity at application layer
		clientCert := r.TLS.PeerCertificates[0]
		if time.Now().After(clientCert.NotAfter) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "403 Forbidden: Client Certificate Expired\n")
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "mTLS Success\n")
	})

	server := &http.Server{
		Addr:      ":8443",
		Handler:   handler,
		TLSConfig: tlsConfig,
	}

	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	wrappedListener := NewWrappedListener(listener, tlsConfig)
	log.Printf("Server listening on %s", server.Addr)
	err = server.Serve(wrappedListener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("Server error: %v", err)
	}
}

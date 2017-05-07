package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

func runServer(rsaCAPrivateKey *rsa.PrivateKey) {
	// Generate host key for the server
	rsaHostPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	sshHostSigner, err := ssh.NewSignerFromKey(rsaHostPrivateKey)
	if err != nil {
		log.Fatal(err)
	}
	sshHostPubKey, err := ssh.NewPublicKey(&rsaHostPrivateKey.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	// Generate and sign certificate using CA
	sshCert := &ssh.Certificate{
		CertType:        ssh.HostCert,
		Key:             sshHostPubKey,
		ValidPrincipals: []string{"localhost"}, // including "localhost:2022" makes this pass
		ValidAfter:      uint64(time.Now().Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Minute).Unix()),
	}
	sshCASigner, err := ssh.NewSignerFromKey(rsaCAPrivateKey)
	if err != nil {
		log.Fatal(err)
	}
	err = sshCert.SignCert(rand.Reader, sshCASigner)
	if err != nil {
		log.Fatal(err)
	}
	hostKeySigner, err := ssh.NewCertSigner(sshCert, sshHostSigner)
	if err != nil {
		log.Fatal(err)
	}

	// Create and run server
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(hostKeySigner)
	listener, err := net.Listen("tcp", "0.0.0.0:2022")
	if err != nil {
		log.Fatal(err)
	}
	nConn, err := listener.Accept()
	if err != nil {
		log.Fatal(err)
	}

	// Perform handshake
	_, _, _, err = ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Server handshake successful")
}

func runClient(sshCAPublicKey ssh.PublicKey) {
	// Dial server, verifying that the cert is signed with CA public key
	_, err := ssh.Dial("tcp", "localhost:2022", &ssh.ClientConfig{
		User: "foo",
		Auth: []ssh.AuthMethod{ssh.Password("bar")},
		HostKeyCallback: (&ssh.CertChecker{
			IsHostAuthority: func(pk ssh.PublicKey, address string) bool {
				return bytes.Equal(pk.Marshal(), sshCAPublicKey.Marshal())
			},
		}).CheckHostKey,
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Client handshake successful")
}

func main() {
	// Generate CA key pair
	rsaCAPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	sshCAPublicKey, err := ssh.NewPublicKey(&rsaCAPrivateKey.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	// Start server
	go runServer(rsaCAPrivateKey)

	// Wait a little bit to make sure it's up
	time.Sleep(500 * time.Millisecond)

	// Try to connect to it
	runClient(sshCAPublicKey)
}

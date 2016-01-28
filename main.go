// SFTP test server implementation using the Go SSH package.
package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

var debugStream io.Writer

// Based on example server code from golang.org/x/crypto/ssh and server_standalone from github.com/pkg/sftp
func main() {
	var (
		readOnly               bool
		debugStderr            bool
		authUser, authPassword string
		addr                   string
		rootDir                string
	)

	flag.BoolVar(&readOnly, "ro", true, "read-only server")
	flag.BoolVar(&debugStderr, "d", false, "debug to stderr")
	flag.StringVar(&addr, "addr", "0.0.0.0:2022", "address for server to listen on")
	flag.StringVar(&authUser, "usr", "testuser", "user name to require for authentication")
	flag.StringVar(&authPassword, "pwd", "tiger", "password to require for authentication")
	flag.StringVar(&rootDir, "dir", "", "root directory to serve from")
	flag.Parse()

	debugStream = ioutil.Discard
	if debugStderr {
		debugStream = os.Stderr
	}

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			debug("Login: %s", c.User())
			if c.User() == authUser && string(pass) == authPassword {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}

	privateBytes, err := ioutil.ReadFile("id_rsa")
	if err != nil {
		log.Fatal("failed to load private key", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("failed to parse private key", err)
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal("failed to listen for connection", err)
	}
	log.Printf("Listening on %v\n", listener.Addr())

	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept incoming connection: %v\n", err)
			continue
		}

		// Before use, a handshake must be performed on the incoming
		// net.Conn.
		_, chans, reqs, err := ssh.NewServerConn(nConn, config)
		if err != nil {
			log.Printf("failed to handshake: %v\n", err)
			continue
		}
		debug("SSH server established")

		// The incoming Request channel must be serviced.
		go ssh.DiscardRequests(reqs)

		// Service the incoming Channel channel.
		for newChannel := range chans {
			// Channels have a type, depending on the application level
			// protocol intended. In the case of an SFTP session, this is "subsystem"
			// with a payload string of "<length=4>sftp"
			debug("Incoming channel: %s", newChannel.ChannelType())
			if newChannel.ChannelType() != "session" {
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
				debug("Unknown channel type: %s", newChannel.ChannelType())
				continue
			}
			channel, requests, err := newChannel.Accept()
			if err != nil {
				log.Printf("could not accept channel: %v\n", err)
				continue
			}
			debug("Channel accepted")

			// Sessions have out-of-band requests such as "shell",
			// "pty-req" and "env".  Here we handle only the
			// "subsystem" request.
			go func(in <-chan *ssh.Request) {
				for req := range in {
					debug("Request: %v", req.Type)
					ok := false
					switch req.Type {
					case "subsystem":
						debug("Subsystem: %s", req.Payload[4:])
						if string(req.Payload[4:]) == "sftp" {
							ok = true
						}
					}
					debug(" - accepted: %v", ok)
					req.Reply(ok, nil)
				}
			}(requests)

			options := append([]sftp.ServerOption{}, sftp.WithDebug(debugStream))
			options = append(options, sftp.WithRootDir(rootDir))
			if readOnly {
				options = append(options, sftp.ReadOnly())
			}

			server, err := sftp.NewServer(channel, channel, options...)
			if err != nil {
				log.Printf("cannot start server: %v\n", err)
				continue
			}
			if err := server.Serve(); err != nil && err != io.EOF {
				log.Printf("server completed with error: %v\n", err)
				continue
			}
		}
	}
}

func debug(format string, args ...interface{}) {
	fmt.Fprintf(debugStream, format, args...)
	fmt.Fprint(debugStream, "\n")
}

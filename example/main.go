package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dpotapov/winrm-auth-ntlm"
	"github.com/masterzen/winrm"
)

func main() {
	flag.Usage = func() {
		fmt.Printf("Usage:\n\t%s\t[OPTIONS] COMMAND\n", filepath.Base(os.Args[0]))
		fmt.Println("Options:")
		flag.PrintDefaults()
	}
	user := flag.String("user", "Administrator", "username for the WinRM connection")
	pswd := flag.String("pswd", "P@$$w0rd", "password for the WinRM connection")
	host := flag.String("host", "localhost", "WinRM server")
	port := flag.Int("port", 5985, "WinRM port")
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	endpoint := winrm.NewEndpoint(*host, *port, false, false, nil, nil, nil, 0)

	winrm.DefaultParameters.TransportDecorator = func() winrm.Transporter {
		return &winrmntlm.Transport{
			Username: *user,
			Password: *pswd,
		}
	}

	// Note, username/password pair in the NewClientWithParameters call is ignored
	client, err := winrm.NewClientWithParameters(endpoint, "", "", winrm.DefaultParameters)
	if err != nil {
		panic(err)
	}

	_, err = client.Run(flag.Arg(0), os.Stdout, os.Stderr)
	if err != nil {
		panic(err)
	}
}

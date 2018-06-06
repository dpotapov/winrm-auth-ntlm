# winrm-auth-ntlm

NTLM Transporter for the [masterzen's Go WinRM](https://github.com/masterzen/winrm) client.

Comparing to original NTLM implementation, the package allows domain user authentication.

Installation:

```
go get github.com/dpotapov/winrm-auth-ntlm
```

Usage:

```
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
```

Please check the full example in the `example` directory.
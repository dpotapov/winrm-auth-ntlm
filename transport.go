package winrmntlm

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/ThomsonReutersEikon/go-ntlm/ntlm"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/pkg/errors"

	"github.com/masterzen/winrm"
	"github.com/masterzen/winrm/soap"
)

const soapXML = "application/soap+xml"

// Transport implements the winrm.Transporter interface.
type Transport struct {
	Username   string
	Password   string
	HTTPClient *http.Client
	Endpoint   *winrm.Endpoint
}

// Transport applies configuration parameters from the Endpoint to the underlying HTTPClient.
// If the HTTPClient is nil, a new instance of http.Client will be created.
func (t *Transport) Transport(endpoint *winrm.Endpoint) error {
	if t.HTTPClient == nil {
		t.HTTPClient = cleanhttp.DefaultPooledClient()
	}
	if httpTr, ok := t.HTTPClient.Transport.(*http.Transport); ok {
		if httpTr.TLSClientConfig == nil {
			httpTr.TLSClientConfig = &tls.Config{}
		}
		httpTr.TLSClientConfig.InsecureSkipVerify = endpoint.Insecure
		httpTr.TLSClientConfig.ServerName = endpoint.TLSServerName
		httpTr.ResponseHeaderTimeout = endpoint.Timeout
		if len(endpoint.CACert) > 0 {
			certPool := x509.NewCertPool()
			if !certPool.AppendCertsFromPEM(endpoint.CACert) {
				return errors.New("unable to read certificates")
			}
			httpTr.TLSClientConfig.RootCAs = certPool
		}
	} else {
		return errors.New("unable to apply WinRM endpoint parameters to unknown HTTP Transport")
	}

	t.Endpoint = endpoint
	return nil
}

// Post sends a POST request to WinRM server with the provided SOAP payload.
// If the WinRM web service responds with Unauthorized status, the method performs NTLM authentication.
func (t *Transport) Post(client *winrm.Client, request *soap.SoapMessage) (string, error) {
	req, err := t.makeRequest(request.String())
	resp, err := t.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	body, err := t.body(resp)
	if err != nil {
		return "", err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		resp, err = t.authenticate(request.String(), resp.Header)
		if err != nil {
			return "", errors.Wrap(err, "NTLM")
		}
		body, err = t.body(resp)
		if err != nil {
			return "", err
		}
	}

	bodyErrStr := func(body string) string {
		if len(body) > 100 {
			return body[:100] + "..."
		}
		if len(body) == 0 {
			return "<no http content>"
		}
		return body
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("http error %d: %s", resp.StatusCode, bodyErrStr(body))
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, soapXML) {
		return body, fmt.Errorf("incorrect Content-Type \"%s\" (expected %s): %s",
			ct, soapXML, bodyErrStr(body))
	}
	return body, nil
}

// EndpointURL returns a WinRM http(s) URL.
// It does the same job as unexported method url() for the winrm.Endpoint type.
func (t *Transport) EndpointURL() string {
	scheme := "http"
	if t.Endpoint.HTTPS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d/wsman", scheme, t.Endpoint.Host, t.Endpoint.Port)
}

func (t *Transport) makeRequest(payload string) (*http.Request, error) {
	req, err := http.NewRequest("POST", t.EndpointURL(), strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", soapXML+";charset=UTF-8")
	return req, nil
}

// authenticate performs NTLM authentication by exchanging NTLM messages over HTTP transport.
func (t *Transport) authenticate(payload string, hdr http.Header) (*http.Response, error) {
	authMethod, err := t.getAuthMethod(hdr, "Negotiate", "NTLM")
	if err != nil {
		return nil, err
	}

	// initialize ntlm session
	session, err := ntlm.CreateClientSession(ntlm.Version2, ntlm.ConnectionOrientedMode)
	if err != nil {
		return nil, err
	}
	username, domain := t.splitUsername()
	session.SetUserInfo(username, t.Password, domain)
	negotiate := NewNegotiateMessage(domain, "")

	// send ntlm negotiate message
	resp, err := t.postWithAuth("", authMethod, negotiate.Bytes())
	if err != nil {
		return nil, err
	}
	if _, err := t.body(resp); err != nil {
		return nil, err
	}
	challengeBytes, err := t.getAuthData(resp.Header)
	if err != nil {
		return nil, err
	}
	challenge, err := ntlm.ParseChallengeMessage(challengeBytes)
	if err != nil {
		return nil, err
	}
	if err = session.ProcessChallengeMessage(challenge); err != nil {

		return nil, err
	}
	authenticate, err := session.GenerateAuthenticateMessage()
	if err != nil {
		return nil, err
	}

	// send ntlm authenticate message
	return t.postWithAuth(payload, authMethod, authenticate.Bytes())
}

func (t *Transport) getAuthMethod(h http.Header, preferredMethods ...string) (string, error) {
	for _, m := range h["Www-Authenticate"] {
		for _, p := range preferredMethods {
			if m == p {
				return m, nil
			}
		}
	}
	return "", errors.New("server does not support any preferred auth method")
}

func (t *Transport) getAuthData(h http.Header) ([]byte, error) {
	str := h.Get("Www-Authenticate")
	i := strings.Index(str, " ")
	if str == "" || i < 0 {
		return nil, errors.New("server did not reply with auth data")
	}
	return base64.StdEncoding.DecodeString(str[i+1:])
}

func (t *Transport) postWithAuth(payload, authMethod string, token []byte) (*http.Response, error) {
	req, err := t.makeRequest(payload)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", authMethod+" "+base64.StdEncoding.EncodeToString(token))
	resp, err := t.HTTPClient.Do(req)
	return resp, err
}

func (t *Transport) splitUsername() (string, string) {
	parts := strings.SplitN(t.Username, "\\", 2)
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[1], parts[0]
}

// body func reads the response body and return it as a string
func (t *Transport) body(response *http.Response) (string, error) {
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", errors.Wrap(err, "reading http response body")
	}
	return string(body), errors.Wrap(response.Body.Close(), "reading http response body")
}

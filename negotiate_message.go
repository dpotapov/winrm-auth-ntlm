package winrmntlm

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/ThomsonReutersEikon/go-ntlm/ntlm"
)

// NegotiateMessage defines an NTLM Negotiate message that is sent from the client to the server.
// This message allows the client to specify its supported NTLM options to the server.
type NegotiateMessage struct {
	ntlm.NegotiateMessage
}

// NewNegotiateMessage creates a new NegotiateMessage for the NTLMv2 protocol.
// The domain and workstation names, if non-empty, are included into a message to let the server
// to determine whether the client is eligible for local authentication.
func NewNegotiateMessage(domain, workstation string) *NegotiateMessage {
	nm := &NegotiateMessage{
		ntlm.NegotiateMessage{
			Signature:      []byte("NTLMSSP\x00"),
			MessageType:    1,
			NegotiateFlags: 0,
			Version:        &ntlm.VersionStruct{},
			PayloadOffset:  8 + 4 + 4 + 8 + 8 + 8, // size of signature, msg type, flags, etc.
		},
	}
	nm.DomainNameFields, _ = ntlm.CreateStringPayload(domain)
	nm.DomainNameFields.Offset = uint32(nm.PayloadOffset + 0)
	nm.WorkstationFields, _ = ntlm.CreateStringPayload(workstation)
	nm.WorkstationFields.Offset = uint32(nm.PayloadOffset + int(nm.DomainNameFields.Len))

	// the list of flags used by default is from https://github.com/jborean93/ntlm-auth
	flags := nm.NegotiateFlags
	flags = ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO.Set(flags)
	flags = ntlm.NTLMSSP_NEGOTIATE_128.Set(flags)
	flags = ntlm.NTLMSSP_NEGOTIATE_56.Set(flags)
	flags = ntlm.NTLMSSP_NEGOTIATE_UNICODE.Set(flags)
	flags = ntlm.NTLMSSP_NEGOTIATE_VERSION.Set(flags)
	flags = ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH.Set(flags)
	flags = ntlm.NTLMSSP_NEGOTIATE_ALWAYS_SIGN.Set(flags)
	flags = ntlm.NTLMSSP_NEGOTIATE_SIGN.Set(flags)
	flags = ntlm.NTLMSSP_NEGOTIATE_SEAL.Set(flags)
	flags = ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.Set(flags)
	if nm.DomainNameFields.Len != 0 {
		flags = ntlm.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED.Set(flags)
	}
	if nm.WorkstationFields.Len != 0 {
		flags = ntlm.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED.Set(flags)
	}
	nm.NegotiateFlags = flags

	// same behaviour as https://github.com/jborean93/ntlm-auth
	if ntlm.NTLMSSP_NEGOTIATE_VERSION.IsSet(nm.NegotiateFlags) {
		nm.Version.ProductMajorVersion = 6
		nm.Version.ProductMinorVersion = 1
		nm.Version.ProductBuild = 7601
		nm.Version.NTLMRevisionCurrent = 15
	}
	return nm
}

// Bytes converts the NegotiateMessage structure into a slice of bytes.
func (n *NegotiateMessage) Bytes() []byte {
	payloadLen := int(n.DomainNameFields.Len + n.WorkstationFields.Len)

	messageBytes := make([]byte, 0, n.PayloadOffset+payloadLen)
	buffer := bytes.NewBuffer(messageBytes)
	buffer.Write(n.Signature)
	binary.Write(buffer, binary.LittleEndian, n.MessageType)
	binary.Write(buffer, binary.LittleEndian, n.NegotiateFlags)

	buffer.Write(n.DomainNameFields.Bytes())
	buffer.Write(n.WorkstationFields.Bytes())
	buffer.Write(n.Version.Bytes())

	buffer.Write(n.DomainNameFields.Payload)
	buffer.Write(n.WorkstationFields.Payload)

	return buffer.Bytes()
}

func (n *NegotiateMessage) String() string {
	var buffer bytes.Buffer

	buffer.WriteString("Negotiate NTLM Message")
	buffer.WriteString(fmt.Sprintf("\nPayload Offset: %d Length: %d", n.PayloadOffset,
		n.DomainNameFields.Len+n.WorkstationFields.Len))
	buffer.WriteString(fmt.Sprintf("\nFlags %d\n", n.NegotiateFlags))
	buffer.WriteString(ntlm.FlagsToString(n.NegotiateFlags))
	buffer.WriteString(fmt.Sprintf("\nDomain Name: %s", n.DomainNameFields.String()))
	buffer.WriteString(fmt.Sprintf("\nWorkstation Name: %s", n.WorkstationFields.String()))
	buffer.WriteString(fmt.Sprintf("\nVersion: %s\n", n.Version.String()))

	return buffer.String()
}

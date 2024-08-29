package grpccheckerhelper

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"

	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/desc/protoprint"
	"github.com/jhump/protoreflect/dynamic"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

func MetadataFromHeaders(headers []string) metadata.MD {
	md := make(metadata.MD)
	for _, part := range headers {
		if part != "" {
			pieces := strings.SplitN(part, ":", 2)
			if len(pieces) == 1 {
				pieces = append(pieces, "") // if no value was specified, just make it "" (maybe the header value doesn't matter)
			}
			headerName := strings.ToLower(strings.TrimSpace(pieces[0]))
			val := strings.TrimSpace(pieces[1])
			if strings.HasSuffix(headerName, "-bin") {
				if v, err := decode(val); err == nil {
					val = v
				}
			}
			md[headerName] = append(md[headerName], val)
		}
	}
	return md
}

var base64Codecs = []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding}

func decode(val string) (string, error) {
	var firstErr error
	var b []byte
	// we are lenient and can accept any of the flavors of base64 encoding
	for _, d := range base64Codecs {
		var err error
		b, err = d.DecodeString(val)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		return string(b), nil
	}
	return "", firstErr
}

var printer = &protoprint.Printer{
	Compact:                  true,
	OmitComments:             protoprint.CommentsNonDoc,
	SortElements:             true,
	ForceFullyQualifiedNames: true,
}

func GetDescriptorText(dsc desc.Descriptor, _ DescriptorSource) (string, error) {
	txt, err := printer.PrintProtoToString(dsc)
	if err != nil {
		return "", err
	}
	if txt[len(txt)-1] == '\n' {
		txt = txt[:len(txt)-1]
	}
	return txt, nil
}

func fetchAllExtensions(source DescriptorSource, ext *dynamic.ExtensionRegistry, md *desc.MessageDescriptor, alreadyFetched map[string]bool) error {
	msgTypeName := md.GetFullyQualifiedName()
	if alreadyFetched[msgTypeName] {
		return nil
	}
	alreadyFetched[msgTypeName] = true

	if len(md.GetExtensionRanges()) > 0 {
		fds, err := source.AllExtensionsForType(msgTypeName)
		if err != nil {
			return fmt.Errorf("failed to query for extensions of type %s: %v", msgTypeName, err)
		}
		for _, fd := range fds {
			if err := ext.AddExtension(fd); err != nil {
				return fmt.Errorf("could not register extension %s of type %s: %v", fd.GetFullyQualifiedName(), msgTypeName, err)
			}
		}
	}
	for _, fd := range md.GetFields() {
		if fd.GetMessageType() != nil {
			err := fetchAllExtensions(source, ext, fd.GetMessageType(), alreadyFetched)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

type errSignalingCreds struct {
	credentials.TransportCredentials
	writeResult func(res interface{})
}

func (c *errSignalingCreds) ClientHandshake(ctx context.Context, addr string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, auth, err := c.TransportCredentials.ClientHandshake(ctx, addr, rawConn)
	if err != nil {
		c.writeResult(err)
	}
	return conn, auth, err
}

// handleError creates and returns a gRPC error with the appropriate message based on the status code
func handleError(grpcStatusCode codes.Code, errMsg string) error {
	switch grpcStatusCode {
	case codes.Canceled:
		return fmt.Errorf("the operation was cancelled: %v", errMsg)
	case codes.InvalidArgument:
		return fmt.Errorf("invalid argument provided: %v", errMsg)
	case codes.DeadlineExceeded:
		return fmt.Errorf("the operation timed out: %v", errMsg)
	case codes.NotFound:
		return fmt.Errorf("requested resource was not found: %v", errMsg)
	case codes.AlreadyExists:
		return fmt.Errorf("resource already exists: %v", errMsg)
	case codes.PermissionDenied:
		return fmt.Errorf("permission denied: %v", errMsg)
	case codes.ResourceExhausted:
		return fmt.Errorf("resource exhausted: %v", errMsg)
	case codes.FailedPrecondition:
		return fmt.Errorf("failed precondition: %v", errMsg)
	case codes.Aborted:
		return fmt.Errorf("operation aborted: %v", errMsg)
	case codes.OutOfRange:
		return fmt.Errorf("out of range: %v", errMsg)
	case codes.Unimplemented:
		return fmt.Errorf("operation unimplemented: %v", errMsg)
	case codes.Internal:
		return fmt.Errorf("internal error: %v", errMsg)
	case codes.Unavailable:
		return fmt.Errorf("service unavailable: %v", errMsg)
	case codes.DataLoss:
		return fmt.Errorf("data loss: %v", errMsg)
	case codes.Unauthenticated:
		return fmt.Errorf("unauthenticated: %v", errMsg)
	default:
		return fmt.Errorf("unknown error code: %v", errMsg)
	}
}

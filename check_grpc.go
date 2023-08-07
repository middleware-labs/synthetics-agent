package synthetics_agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/gogo/protobuf/jsonpb"
	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/desc/protoparse"
	"github.com/jhump/protoreflect/dynamic"
	"github.com/jhump/protoreflect/dynamic/grpcdynamic"
	"github.com/jhump/protoreflect/grpcreflect"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	reflectpb "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/grpc/status"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

func buildCredentials(skipVerify bool, caCerts, clientCert, clientKey, serverName string) (credentials.TransportCredentials, error) {
	var cfg tls.Config

	if clientCert != "" && clientKey != "" {
		keyPair, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load tls client cert/key pair. error=%v", err)
		}
		cfg.Certificates = []tls.Certificate{keyPair}
	}

	if skipVerify {
		cfg.InsecureSkipVerify = true
	} else if caCerts != "" {
		// override system roots
		rootCAs := x509.NewCertPool()
		pem, err := ioutil.ReadFile(caCerts)
		if err != nil {
			return nil, fmt.Errorf("failed to load root CA certificates from file (%s) error=%v", caCerts, err)
		}
		if !rootCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no root CA certs parsed from file %s", caCerts)
		}
		cfg.RootCAs = rootCAs
	}
	if serverName != "" {
		cfg.ServerName = serverName
	}
	return credentials.NewTLS(&cfg), nil
}

func CheckGrpcRequest(c SyntheticsModelCustom) {
	timers := map[string]float64{
		"duration":            0,
		"duration_connection": 0,
		"duration_resolve":    0,
	}
	assertions := make([]map[string]string, 0)
	_Status := "OK"
	_Message := ""

	attrs := pcommon.NewMap()
	_start := time.Now()
	ctx, _ := context.WithCancel(context.Background())

	opts := make([]grpc.DialOption, 0)

	if c.Request.GRPCPayload.Certificate != "" && c.Request.GRPCPayload.PrivateKey != "" {
		cred, crErr := buildCredentials(c.Request.GRPCPayload.IgnoreServerCertificateError, "", c.Request.GRPCPayload.Certificate, c.Request.GRPCPayload.PrivateKey, "")
		if crErr != nil {
			_Status = "ERROR"
			_Message = fmt.Sprintf("failed to initialize tls credentials. error=%v", crErr)
		}
		opts = append(opts, grpc.WithTransportCredentials(cred))
	} else {
		/*roots, err := x509.SystemCertPool()
		if err != nil {
			log.Printf("root certificates error  %v", roots)
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			RootCAs:            roots,
			InsecureSkipVerify: true,
		})))*/

		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	opts = append(opts,
		grpc.WithCompressor(grpc.NewGZIPCompressor()),
		grpc.WithDecompressor(grpc.NewGZIPDecompressor()),
	)

	dialCtx, _ := context.WithTimeout(ctx, time.Duration(c.Expect.ResponseTimeLessThen)*time.Second)

	isAnyErr := func(err error) bool {
		if err != nil {
			_sts := "ERROR"
			_msg := ""
			if stat, ok := status.FromError(err); ok && stat.Code() == codes.Unimplemented {
				_msg = fmt.Sprintf("error: this server does not implement the : %s", stat.Message())
			} else if stat, ok := status.FromError(err); ok && stat.Code() == codes.DeadlineExceeded {
				_msg = fmt.Sprintf("timeout: health rpc did not complete within %v", time.Duration(c.Expect.ResponseTimeLessThen)*time.Second)
			} else if stat.Code() != codes.OK {
				_msg = fmt.Sprintf("error: rpc failed, status is not OK %+v", err)
			}

			assertions = make([]map[string]string, 0)
			for _, a := range c.Request.Assertions.GRPC.Cases {
				assertions = append(assertions, map[string]string{
					"status": "FAIL",
					"reason": "previous step failed",
					"actual": "N/A",
					"type":   a.Type,
				})
			}

			resultStr, _ := json.Marshal(assertions)
			attrs.PutStr("assertions", string(resultStr))
			FinishCheckRequest(c, _sts, _msg, timers, attrs)
			return true
		}
		return false
	}

	conn, cnErr := grpc.DialContext(dialCtx, c.Endpoint+":"+c.Request.Port, opts...)
	if cnErr != nil {
		_Status = "ERROR"
		_Message = fmt.Sprintf("did not connect: %v", cnErr)
	} else {
		defer conn.Close()

		timers["duration_connection"] = timeInMs(time.Since(_start))

		rpcStart := time.Now()
		var respStr string
		var respHeaders metadata.MD
		var respTrailers metadata.MD
		//c.Request.GRPCPayload.CheckType = "health"

		if c.Request.GRPCPayload.CheckType == "health" {
			rpcCtx, rpcCancel := context.WithTimeout(ctx, time.Duration(c.Expect.ResponseTimeLessThen)*time.Second)
			defer rpcCancel()
			md := metadata.MD{}
			for _, v := range c.Request.GRPCPayload.Metadata {
				md.Set(v.Name, v.Value)
			}

			rpcCtx = metadata.NewOutgoingContext(rpcCtx, md)
			resp, hErr := healthpb.NewHealthClient(conn).Check(rpcCtx, &healthpb.HealthCheckRequest{Service: ""}, grpc.Header(&respHeaders), grpc.Trailer(&respTrailers))
			timers["duration"] = timeInMs(time.Since(rpcStart))
			if isAnyErr(hErr) {
				return
			}
			if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
				_Status = "ERROR"
				_Message = fmt.Sprintf("service unhealthy (responded with %q)", resp.GetStatus().String())
			}
		} else {
			ty := c.Request.GRPCPayload.ServiceDefinition
			_start = time.Now()

			svc, mth := parseSymbol(c.Request.GRPCPayload.MethodSelection) // "helloworld.Greeter/SayHello"

			var fsd *desc.FileDescriptor
			if ty == "reflection" {
				rpcCtx, _ := context.WithTimeout(ctx, time.Duration(c.Expect.ResponseTimeLessThen)*time.Second)
				refClient := grpcreflect.NewClientV1Alpha(rpcCtx, reflectpb.NewServerReflectionClient(conn))
				/*svcs, err := refClient.ListServices()
				for _, svc := range svcs {
					fmt.Printf("Svc: %s\n", svc)
					//list, err:=refClient.FileContainingSymbol(svc)
				}*/
				clientSymbol, cErr := refClient.FileContainingSymbol(svc)
				if cErr != nil {
					_Status = "ERROR"
					_Message = fmt.Sprintf("reflection method not found. %v", cErr)
				} else {
					fsd = clientSymbol
				}
			} else {
				f, _ := os.CreateTemp(os.TempDir(), "proto_file.proto")
				_, _ = f.Write([]byte(c.Request.GRPCPayload.ProtoFileContent))
				_ = f.Close()

				p := protoparse.Parser{
					InferImportPaths:      false,
					IncludeSourceCodeInfo: false,
				}

				fds, err := p.ParseFiles(f.Name())
				if err != nil {
					_Status = "ERROR"
					_Message = fmt.Sprintf("could not parse given files. %v", err)
				}
				if len(fds) == 0 {
					_Status = "ERROR"
					_Message = fmt.Sprintf("no file desc found.")
				}
				if len(fds) > 0 {
					fsd = fds[0]
				}
			}

			for _, fSrv := range fsd.GetServices() {
				fmt.Printf("ServiceName: %s\n", fSrv.GetFullyQualifiedName())
				for _, mtd := range fSrv.GetMethods() {
					fmt.Printf("Method: %s\n", mtd.GetFullyQualifiedName())
				}
			}

			dsc := fsd.FindSymbol(svc)

			if dsc == nil {
				timers["duration"] = timeInMs(time.Since(_start))
				_Status = "ERROR"
				_Message = fmt.Sprintf("service not found %s", svc)
			} else {
				sd, ok := dsc.(*desc.ServiceDescriptor)
				if !ok {
					_Status = "ERROR"
					_Message = fmt.Sprintf("symbol %q is not a service", svc)
				}
				mtd := sd.FindMethodByName(mth)
				if mtd == nil {
					_Status = "ERROR"
					_Message = fmt.Sprintf("service %q does not include a method named %q", svc, mth)
				} else {
					timers["duration_resolve"] = timeInMs(time.Since(rpcStart))

					var ext dynamic.ExtensionRegistry
					msgFactory := dynamic.NewMessageFactoryWithExtensionRegistry(&ext)

					if mtd.IsClientStreaming() || mtd.IsServerStreaming() {
						_Status = "ERROR"
						_Message = fmt.Sprintf("streaming grpc calls are not supported")
					} else {
						rdr := strings.NewReader(c.Request.GRPCPayload.Message)
						var msg json.RawMessage
						deErr := json.NewDecoder(rdr).Decode(&msg)
						if deErr != nil {
							_Status = "ERROR"
							_Message = fmt.Sprintf("json decode failed %v", deErr)
						} else {
							unmarshaler := jsonpb.Unmarshaler{AllowUnknownFields: true}
							req := msgFactory.NewMessage(mtd.GetInputType())

							uErr := unmarshaler.Unmarshal(bytes.NewReader(msg), req)
							if uErr != nil {
								_Status = "ERROR"
								_Message = fmt.Sprintf("unmarshaler.Unmarshal failed %v", uErr)
							} else {
								rpcStart = time.Now()

								stub := grpcdynamic.NewStubWithMessageFactory(conn, msgFactory)
								resp, ivErr := stub.InvokeRpc(ctx, mtd, req, grpc.Trailer(&respTrailers), grpc.Header(&respHeaders))

								if isAnyErr(ivErr) {
									return
								}

								jsm := jsonpb.Marshaler{Indent: "  "}
								_, mErr := jsm.MarshalToString(resp)
								timers["duration"] = timeInMs(time.Since(rpcStart))
								if mErr != nil {
									_Status = "ERROR"
									_Message = fmt.Sprintf("resp msg decode failed %v", mErr)
								}
							}
						}
					}
				}
			}
		}

		for _, assert := range c.Request.Assertions.GRPC.Cases {
			if _Status == "OK" {
				_ck := map[string]string{
					"type":   assert.Type,
					"status": "PASS",
					"reason": "should be " + strings.ReplaceAll(assert.Config.Operator, "_", " ") + " " + fmt.Sprintf("%v", assert.Config.Value),
				}

				switch assert.Type {
				case "response_time":
					_ck["actual"] = fmt.Sprintf("%v", timers["duration"])
					if !assertInt(int64(timers["duration"]), assert) {
						_ck["status"] = "FAIL"
						_Status = "FAIL"
						_Message = "duration didn't matched with condition"
					}
					assertions = append(assertions, _ck)
					break
				case "grpc_response":
					_ck["actual"] = respStr
					if !assertString(respStr, assert) {
						_ck["status"] = "FAIL"
						_Status = "FAIL"
						_Message = "response message didn't matched with condition"
					}
					assertions = append(assertions, _ck)
					break
				case "grpc_metadata":
					_actual := strings.Join(respTrailers.Get(assert.Config.Target), "\n")
					_ck["actual"] = _actual
					if !assertString(_actual, assert) {
						_ck["status"] = "FAIL"
						_Status = "FAIL"
						_Message = "meta data message didn't matched with condition"
					}
					assertions = append(assertions, _ck)
					break
				}
			} else {
				assertions = append(assertions, map[string]string{
					"status": "FAIL",
					"reason": "previous step failed",
					"actual": "N/A",
					"type":   assert.Type,
				})
			}
		}
	}

	resultStr, _ := json.Marshal(assertions)
	attrs.PutStr("assertions", string(resultStr))

	FinishCheckRequest(c, _Status, _Message, timers, attrs)

}
func parseSymbol(svcAndMethod string) (string, string) {
	pos := strings.LastIndex(svcAndMethod, "/")
	if pos < 0 {
		pos = strings.LastIndex(svcAndMethod, ".")
		if pos < 0 {
			return "", ""
		}
	}
	return svcAndMethod[:pos], svcAndMethod[pos+1:]
}

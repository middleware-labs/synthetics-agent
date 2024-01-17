package grpccheckerhelper

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/golang/protobuf/jsonpb" //lint:ignore SA1019 we have to import this because it appears in exported API
	"github.com/golang/protobuf/proto"  //lint:ignore SA1019 we have to import this because it appears in exported API
	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/dynamic"
	"google.golang.org/grpc/status"
)

type RequestParser interface {
	Next(msg proto.Message) error
	NumRequests() int
}

type jsonRequestParser struct {
	dec          *json.Decoder
	unmarshaler  jsonpb.Unmarshaler
	requestCount int
}

func NewJSONRequestParserWithUnmarshaler(in io.Reader, unmarshaler jsonpb.Unmarshaler) RequestParser {
	return &jsonRequestParser{
		dec:         json.NewDecoder(in),
		unmarshaler: unmarshaler,
	}
}

func (f *jsonRequestParser) Next(m proto.Message) error {
	var msg json.RawMessage
	if err := f.dec.Decode(&msg); err != nil {
		return err
	}
	f.requestCount++
	return f.unmarshaler.Unmarshal(bytes.NewReader(msg), m)
}

func (f *jsonRequestParser) NumRequests() int {
	return f.requestCount
}

const (
	textSeparatorChar = '\x1e'
)

type textRequestParser struct {
	r            *bufio.Reader
	err          error
	requestCount int
}

func NewTextRequestParser(in io.Reader) RequestParser {
	return &textRequestParser{r: bufio.NewReader(in)}
}

func (f *textRequestParser) Next(m proto.Message) error {
	if f.err != nil {
		return f.err
	}

	var b []byte
	b, f.err = f.r.ReadBytes(textSeparatorChar)
	if f.err != nil && f.err != io.EOF {
		return f.err
	}
	// remove delimiter
	if len(b) > 0 && b[len(b)-1] == textSeparatorChar {
		b = b[:len(b)-1]
	}

	f.requestCount++

	return proto.UnmarshalText(string(b), m)
}

func (f *textRequestParser) NumRequests() int {
	return f.requestCount
}

type Formatter func(proto.Message) (string, error)

func NewJSONFormatter(emitDefaults bool, resolver jsonpb.AnyResolver) Formatter {
	marshaler := jsonpb.Marshaler{
		EmitDefaults: emitDefaults,
		AnyResolver:  resolver,
	}
	formatter := func(message proto.Message) (string, error) {
		output, err := marshaler.MarshalToString(message)
		if err != nil {
			return "", err
		}
		var buf bytes.Buffer
		if err := json.Indent(&buf, []byte(output), "", "  "); err != nil {
			return "", err
		}
		return buf.String(), nil
	}
	return formatter
}

func NewTextFormatter(includeSeparator bool) Formatter {
	tf := textFormatter{useSeparator: includeSeparator}
	return tf.format
}

type textFormatter struct {
	useSeparator bool
	numFormatted int
}

var protoTextMarshaler = proto.TextMarshaler{ExpandAny: true}

func (tf *textFormatter) format(m proto.Message) (string, error) {
	var buf bytes.Buffer
	if tf.useSeparator && tf.numFormatted > 0 {
		if err := buf.WriteByte(textSeparatorChar); err != nil {
			return "", err
		}
	}

	type indentMarshaler interface {
		MarshalTextIndent() ([]byte, error)
	}

	if indenter, ok := m.(indentMarshaler); ok {
		b, err := indenter.MarshalTextIndent()
		if err != nil {
			return "", err
		}
		if _, err := buf.Write(b); err != nil {
			return "", err
		}
	} else if err := protoTextMarshaler.Marshal(&buf, m); err != nil {
		return "", err
	}

	str := buf.String()
	if len(str) > 0 && str[len(str)-1] == '\n' {
		str = str[:len(str)-1]
	}

	tf.numFormatted++

	return str, nil
}

type Format string

const (
	FormatJSON = Format("json")
	FormatText = Format("text")
)

func AnyResolverFromDescriptorSource(source DescriptorSource) jsonpb.AnyResolver {
	return &anyResolver{source: source}
}

type anyResolver struct {
	source DescriptorSource

	er dynamic.ExtensionRegistry

	mu       sync.RWMutex
	mf       *dynamic.MessageFactory
	resolved map[string]func() proto.Message
}

func (r *anyResolver) Resolve(typeUrl string) (proto.Message, error) {
	mname := typeUrl
	if slash := strings.LastIndex(mname, "/"); slash >= 0 {
		mname = mname[slash+1:]
	}

	r.mu.RLock()
	factory := r.resolved[mname]
	r.mu.RUnlock()

	if factory != nil {
		return factory(), nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	factory = r.resolved[mname]
	if factory != nil {
		return factory(), nil
	}

	d, err := r.source.FindSymbol(mname)
	if err != nil {
		return nil, err
	}
	md, ok := d.(*desc.MessageDescriptor)
	if !ok {
		return nil, fmt.Errorf("unknown message: %s", typeUrl)
	}

	if exts, err := r.source.AllExtensionsForType(mname); err == nil {
		if err := r.er.AddExtension(exts...); err != nil {
			return nil, err
		}
	}

	if r.mf == nil {
		r.mf = dynamic.NewMessageFactoryWithExtensionRegistry(&r.er)
	}

	factory = func() proto.Message {
		return r.mf.NewMessage(md)
	}
	if r.resolved == nil {
		r.resolved = map[string]func() proto.Message{}
	}
	r.resolved[mname] = factory
	return factory(), nil
}

type anyResolverWithFallback struct {
	jsonpb.AnyResolver
}

func (r anyResolverWithFallback) Resolve(typeUrl string) (proto.Message, error) {
	msg, err := r.AnyResolver.Resolve(typeUrl)
	if err == nil {
		return msg, err
	}

	mname := typeUrl
	if slash := strings.LastIndex(mname, "/"); slash >= 0 {
		mname = mname[slash+1:]
	}
	mt := proto.MessageType(mname)
	if mt != nil {
		return reflect.New(mt.Elem()).Interface().(proto.Message), nil
	}

	return &unknownAny{TypeUrl: typeUrl, Error: fmt.Sprintf("%s is not recognized; see @value for raw binary message data", mname)}, nil
}

type unknownAny struct {
	TypeUrl string `json:"@type"`
	Error   string `json:"@error"`
	Value   string `json:"@value"`
}

func (a *unknownAny) MarshalJSONPB(jsm *jsonpb.Marshaler) ([]byte, error) {
	if jsm.Indent != "" {
		return json.MarshalIndent(a, "", jsm.Indent)
	}
	return json.Marshal(a)
}

func (a *unknownAny) Unmarshal(b []byte) error {
	a.Value = base64.StdEncoding.EncodeToString(b)
	return nil
}

func (a *unknownAny) Reset() {
	a.Value = ""
}

func (a *unknownAny) String() string {
	b, err := a.MarshalJSONPB(&jsonpb.Marshaler{})
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err.Error())
	}
	return string(b)
}

func (a *unknownAny) ProtoMessage() {
}

type FormatOptions struct {
	EmitJSONDefaultFields bool
	AllowUnknownFields    bool
	IncludeTextSeparator  bool
}

func RequestParserAndFormatter(format Format, descSource DescriptorSource, in io.Reader, opts FormatOptions) (RequestParser, Formatter, error) {
	switch format {
	case FormatJSON:
		resolver := AnyResolverFromDescriptorSource(descSource)
		unmarshaler := jsonpb.Unmarshaler{AnyResolver: resolver, AllowUnknownFields: opts.AllowUnknownFields}
		return NewJSONRequestParserWithUnmarshaler(in, unmarshaler), NewJSONFormatter(opts.EmitJSONDefaultFields, anyResolverWithFallback{AnyResolver: resolver}), nil
	case FormatText:
		return NewTextRequestParser(in), NewTextFormatter(opts.IncludeTextSeparator), nil
	default:
		return nil, nil, fmt.Errorf("unknown format: %s", format)
	}
}

type DefaultEventHandler struct {
	Out            io.Writer
	Formatter      Formatter
	VerbosityLevel int
	ConnectStart   time.Time
	NumResponses   int
	Status         *status.Status
}

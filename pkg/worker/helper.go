// DO NOT EDIT.. COPY FROM bifrost/app/components/synthetics/helper.go
package worker

import (
	"time"
)

type SyntheticsModel struct {
	Id                int                      `json:"id"`
	AccountId         int                      `json:"account_id"`
	UserId            int                      `json:"user_id"`
	Proto             string                   `json:"proto"`
	SlugName          string                   `json:"slug_name"`
	Endpoint          string                   `json:"endpoint"`
	IntervalSeconds   int                      `json:"interval_seconds"`
	Locations         string                   `json:"locations"`
	Status            string                   `json:"status"`
	Tags              []string                 `json:"tags"`
	Expect            SyntheticsExpectMeta     `json:"expect"`
	Request           SyntheticsRequestOptions `json:"request"`
	CreatedAt         time.Time                `json:"created_at"`
	UpdatedAt         time.Time                `json:"updated_at"`
	Action            string                   `json:"action"`
	AccountKey        string                   `json:"account_key"`
	AccountUID        string                   `json:"account_uid"`
	Details           map[string]interface{}   `json:"details"`
	AdditionalOptions interface{}              `json:"additional_options"`
	CheckTestRequest  CheckTestRequest         `json:"check_test_request"`
	ProjectId         int                      `json:"project_id"`
	ProjectUID        string                   `json:"project_uid"`
	K6ScriptSnippet   string                   `json:"k6_script_snippet"`
}

type CheckTestRequest struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
}

type SyntheticsExpectMeta struct {
	HttpCode             int    `json:"http_status_code,omitempty"`
	ResponseText         string `json:"response_text,omitempty"`
	ResponseTimeLessThen int    `json:"response_time_less_then,omitempty"`

	PacketLossLimit float64 `json:"packet_loss_limit,omitempty"`
	LatencyLimit    float64 `json:"latency_limit,omitempty"`
}

type SyntheticsRequestOptions struct {
	Topic                     string                  `json:"topic" default:"locations"`
	Premise                   []string                `json:"premise"`
	Environment               []interface{}           `json:"environment"`
	TTL                       bool                    `json:"ttl"`
	SslSignedCertificate      bool                    `json:"ssl_signed_certificate"`
	SslRevokedCertificateFail bool                    `json:"ssl_revoked_certificate_fail"`
	SslServerName             string                  `json:"ssl_server_name"`
	SslCertificatePrivateKey  string                  `json:"ssl_certificate_private_key"`
	SslCertificate            string                  `json:"ssl_certificate"`
	SslMinVersion             int                     `json:"ssl_min_version"`
	SslMaxVersion             int                     `json:"ssl_max_version"`
	DNSServer                 string                  `json:"dns_server"`
	ICMPPayload               ICMPPayloadOptions      `json:"icmp_payload"`
	Port                      string                  `json:"port"`
	HTTPMethod                string                  `json:"http_method"`
	HTTPVersion               string                  `json:"http_version"`
	HTTPHeaders               []HTTPHeadersOptions    `json:"http_headers"`
	HTTPPayload               HTTPPayloadOptions      `json:"http_payload"`
	GRPCPayload               GRPCPayloadOptions      `json:"grpc_payload"`
	UDPPayload                UDPPayloadOptions       `json:"udp_payload"`
	WSPayload                 WSPayloadOptions        `json:"ws_payload"`
	SpecifyFrequency          SpecifyFrequencyOptions `json:"specify_frequency"`
	Assertions                AssertionsOptions       `json:"assertions"`
	AlertConditions           AlertConditionsOptions  `json:"alert_conditions"`
	Monitor                   MonitorOptions          `json:"monitor"`
	CurrentAction             string                  `json:"current_action" default:"play"`
	StepTestIndex             int                     `json:"step_test_index"`
	HTTPMultiTest             bool                    `json:"http_multi_test"`
	HTTPMultiSteps            []HTTPMultiStepsOptions `json:"http_multi_steps"`
}

type HTTPMultiStepsOptions struct {
	StepName string               `json:"step_name"`
	Endpoint string               `json:"endpoint"`
	Expect   SyntheticsExpectMeta `json:"expect"`
	Request  struct {
		HTTPMethod  string               `json:"http_method"`
		HTTPVersion string               `json:"http_version"`
		HTTPHeaders []HTTPHeadersOptions `json:"http_headers"`
		HTTPPayload HTTPPayloadOptions   `json:"http_payload"`
	} `json:"request"`
}

type SyntheticsTags struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type HTTPHeadersOptions struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HTTPPayloadOptions struct {
	FollowRedirects              bool   `json:"follow_redirects"`
	IgnoreServerCertificateError bool   `json:"ignore_server_certificate_error"`
	Cookies                      string `json:"cookies"`
	QueryParams                  []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"query_params"`
	RequestBody struct {
		Type    string `json:"type"`
		Content string `json:"content"`
	} `json:"request_body"`
	Privacy struct {
		SaveBodyResponse bool `json:"save_body_response"`
	} `json:"privacy"`
	Proxy struct {
		URL     string `json:"url"`
		Headers []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"headers"`
	} `json:"proxy"`
	Authentication struct {
		ClientCertificate struct {
			Certificate string `json:"certificate"`
			PrivateKey  string `json:"private_key"`
		} `json:"client_certificate"`
		Type  string `json:"type"`
		Basic struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"basic"`
		Digest struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"digest"`
		Ntlm struct {
			Username    string `json:"username"`
			Password    string `json:"password"`
			Domain      string `json:"domain"`
			WorkStation string `json:"work_station"`
		} `json:"ntlm"`
		AwsSignature struct {
			AccessKeyID     string `json:"access_key_id"`
			SecretAccessKey string `json:"secret_access_key"`
			Region          string `json:"region"`
			ServiceName     string `json:"service_name"`
			SessionToken    string `json:"session_token"`
		} `json:"aws_signature"`
		Oauth21 struct {
			CredentialsType        string `json:"credentials_type"`
			TokenAPIAuthentication string `json:"token_api_authentication"`
			AccessTokenURL         string `json:"access_token_url"`
			Username               string `json:"username"`
			Password               string `json:"password"`
			ClientID               string `json:"client_id"`
			ClientSecret           string `json:"client_secret"`
			Audience               string `json:"audience"`
			Resource               string `json:"resource"`
			Scopes                 string `json:"scopes"`
		} `json:"oauth2_1"`
	} `json:"authentication"`
}

type ICMPPayloadOptions struct {
	PingsPerTest int `json:"pings_per_test"`
}

type GRPCPayloadOptions struct {
	CheckType                    string `json:"check_type" default:"behaviour"`
	Service                      string `json:"service"`
	ServiceDefinition            string `json:"service_definition"`
	MethodSelection              string `json:"method_selection"`
	ProtoFileContent             string `json:"proto_file_content"`
	Message                      string `json:"message"`
	IgnoreServerCertificateError bool   `json:"ignore_server_certificate_error"`
	Metadata                     []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"metadata"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

type UDPPayloadOptions struct {
	Message string `json:"message"`
}

type WSPayloadOptions struct {
	Message string `json:"message"`
	Headers []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"headers"`
	Authentication struct {
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"authentication"`
}

type SpecifyFrequencyOptions struct {
	Type             string `json:"type"`
	IntervalType     string `json:"interval_type"`
	SpecifyTimeRange struct {
		IsChecked  bool     `json:"is_checked"`
		StartTime  string   `json:"start_time"`
		EndTime    string   `json:"end_time"`
		Timezone   string   `json:"timezone"`
		DaysOfWeek []string `json:"days_of_week"`
	} `json:"specify_time_range"`
}

type CaseOptions struct {
	Config struct {
		Operator string `json:"operator"`
		Target   string `json:"target"`
		Value    string `json:"value"`
	} `json:"config"`
	Type string `json:"type"`
}

type AssertionsCasesOptions struct {
	Cases []CaseOptions `json:"cases"`
}

type AssertionsOptions struct {
	HTTP      AssertionsCasesOptions `json:"http"`
	TCP       AssertionsCasesOptions `json:"tcp"`
	Ssl       AssertionsCasesOptions `json:"ssl"`
	DNS       AssertionsCasesOptions `json:"dns"`
	WebSocket AssertionsCasesOptions `json:"web_socket"`
	UDP       AssertionsCasesOptions `json:"udp"`
	ICMP      AssertionsCasesOptions `json:"icmp"`
	GRPC      AssertionsCasesOptions `json:"grpc"`
}

type AlertConditionsOptions struct {
	RetryCount           int `json:"retry_count"`
	RetryIntervalSeconds int `json:"retry_interval_seconds"`
}

type MonitorOptions struct {
	Source                  string                   `json:"source"` // slack, email, webhook, etc
	NotifyTo                []interface{}            `json:"notify_to"`
	Renotify                bool                     `json:"renotify"`
	RenotifyIntervalSeconds int                      `json:"renotify_interval_seconds"`
	Priority                string                   `json:"priority"`
	TriggerFailsCase        bool                     `json:"trigger_fails_case"`
	TriggerFailsCaseCount   int                      `json:"trigger_fails_case_count"`
	SelectedSource          string                   `json:"selected_source"`
	NotifyBySource          map[string][]interface{} `json:"notify_by_source"`
	NotifySourceAdditional  map[string]interface{}   `json:"notify_source_additional"`
}

func timeInMs(t time.Duration) float64 {
	return float64(t) / float64(time.Millisecond)
}

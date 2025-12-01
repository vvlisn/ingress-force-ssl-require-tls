package main

import (
	"encoding/json"
	"testing"

	networkingv1 "github.com/kubewarden/k8s-objects/api/networking/v1"
	metav1 "github.com/kubewarden/k8s-objects/apimachinery/pkg/apis/meta/v1"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	kubewarden_testing "github.com/kubewarden/policy-sdk-go/testing"
)

func buildIngressValidationRequest(t *testing.T, ingress *networkingv1.Ingress, settings *Settings) []byte {
	payload, err := kubewarden_testing.BuildValidationRequest(ingress, settings)
	if err != nil {
		t.Fatalf("Unexpected error building validation request: %+v", err)
	}

	return payload
}

func mustUnmarshalResponse(t *testing.T, payload []byte) kubewarden_protocol.ValidationResponse {
	var response kubewarden_protocol.ValidationResponse
	if err := json.Unmarshal(payload, &response); err != nil {
		t.Fatalf("Unexpected error unmarshalling response: %+v", err)
	}

	return response
}

func newBaseIngress() *networkingv1.Ingress {
	return &networkingv1.Ingress{
		Metadata: &metav1.ObjectMeta{
			Name:      "test-ingress",
			Namespace: "default",
			Annotations: map[string]string{
				"nginx.ingress.kubernetes.io/force-ssl-redirect": "true",
			},
		},
		Spec: &networkingv1.IngressSpec{},
	}
}

func TestEmptySettingsLeadsToApproval(t *testing.T) {
	settings := Settings{}
	ingress := newBaseIngress()
	// Disable the validation via settings
	settings.ValidateForceSslRedirect = false

	payload := buildIngressValidationRequest(t, ingress, &settings)

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	response := mustUnmarshalResponse(t, responsePayload)
	if response.Accepted != true {
		t.Errorf("Unexpected rejection: msg %s - code %d", safeMessage(response.Message), safeCode(response.Code))
	}
}

func TestForceSSLRedirectWithoutTLSIsRejected(t *testing.T) {
	settings := Settings{ValidateForceSslRedirect: true}
	ingress := newBaseIngress()
	// No TLS configured

	payload := buildIngressValidationRequest(t, ingress, &settings)

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	response := mustUnmarshalResponse(t, responsePayload)
	if response.Accepted {
		t.Errorf("Expected rejection when force-ssl-redirect is true but no TLS is configured")
	}
}

func TestForceSSLRedirectWithMismatchedHostsIsRejected(t *testing.T) {
	settings := Settings{ValidateForceSslRedirect: true}
	ingress := newBaseIngress()
	ingress.Spec.Rules = []*networkingv1.IngressRule{
		{Host: "example.com"},
	}
	ingress.Spec.TLS = []*networkingv1.IngressTLS{
		{Hosts: []string{"other.com"}},
	}

	payload := buildIngressValidationRequest(t, ingress, &settings)

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	response := mustUnmarshalResponse(t, responsePayload)
	if response.Accepted {
		t.Errorf("Expected rejection when TLS hosts do not match rule hosts")
	}
}

func TestForceSSLRedirectWithMatchingHostsIsAccepted(t *testing.T) {
	settings := Settings{ValidateForceSslRedirect: true}
	ingress := newBaseIngress()
	ingress.Spec.Rules = []*networkingv1.IngressRule{
		{Host: "example.com"},
	}
	ingress.Spec.TLS = []*networkingv1.IngressTLS{
		{Hosts: []string{"example.com"}},
	}

	payload := buildIngressValidationRequest(t, ingress, &settings)

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	response := mustUnmarshalResponse(t, responsePayload)
	if !response.Accepted {
		t.Errorf("Expected approval when TLS hosts match rule hosts")
	}
}

// safeMessage returns the message value or an empty string when nil.
func safeMessage(msg *string) string {
	if msg == nil {
		return ""
	}
	return *msg
}

// safeCode returns the code value or 0 when nil.
func safeCode(code *uint16) uint16 {
	if code == nil {
		return 0
	}
	return *code
}

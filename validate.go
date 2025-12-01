package main

import (
	"encoding/json"
	"fmt"
	"strings"

	onelog "github.com/francoispqt/onelog"
	networkingv1 "github.com/kubewarden/k8s-objects/api/networking/v1"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

const httpBadRequestStatusCode = 400

func validate(payload []byte) ([]byte, error) {
	// Create a ValidationRequest instance from the incoming payload
	validationRequest := kubewarden_protocol.ValidationRequest{}
	err := json.Unmarshal(payload, &validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(httpBadRequestStatusCode))
	}

	// Create a Settings instance from the ValidationRequest object
	settings, err := NewSettingsFromValidationReq(&validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(httpBadRequestStatusCode))
	}

	// Access the **raw** JSON that describes the object
	ingressJSON := validationRequest.Request.Object

	// Try to create an Ingress instance using the RAW JSON we got from the
	// ValidationRequest.
	ingress := &networkingv1.Ingress{}
	if err = json.Unmarshal([]byte(ingressJSON), ingress); err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(
				fmt.Sprintf("Cannot decode Ingress object: %s", err.Error())),
			kubewarden.Code(httpBadRequestStatusCode))
	}

	name := ""
	namespace := ""
	if ingress.Metadata != nil {
		name = ingress.Metadata.Name
		namespace = ingress.Metadata.Namespace
	}

	logger.DebugWithFields("validating ingress object", func(e onelog.Entry) {
		e.String("name", name)
		e.String("namespace", namespace)
	})

	return evaluateIngressRequest(settings, ingress)
}

// evaluateIngressRequest contains the core business logic of the policy.
// It assumes the Ingress object has been successfully decoded.
func evaluateIngressRequest(settings Settings, ingress *networkingv1.Ingress) ([]byte, error) {
	// If this validation is disabled, always accept
	if !settings.ValidateForceSslRedirect {
		return kubewarden.AcceptRequest()
	}

	annotations := map[string]string{}
	if ingress.Metadata != nil && ingress.Metadata.Annotations != nil {
		annotations = ingress.Metadata.Annotations
	}

	forceSsl := isForceSSLRedirectEnabled(annotations)

	// If the annotation is not enabled, nothing to enforce
	if !forceSsl {
		return kubewarden.AcceptRequest()
	}

	if ingress.Spec == nil {
		return kubewarden.RejectRequest(
			kubewarden.Message("force-ssl-redirect is true but Ingress spec is missing"),
			kubewarden.NoCode)
	}

	// Enforce: at least one TLS entry must exist when force-ssl-redirect is enabled
	if len(ingress.Spec.TLS) == 0 {
		return kubewarden.RejectRequest(
			kubewarden.Message("force-ssl-redirect is true but no TLS configuration (spec.tls) is defined"),
			kubewarden.NoCode)
	}

	ruleHosts, ruleErr := collectRuleHosts(ingress)
	if ruleErr != "" {
		return kubewarden.RejectRequest(
			kubewarden.Message(ruleErr),
			kubewarden.NoCode)
	}

	tlsHosts, tlsErr := collectTLSHosts(ingress)
	if tlsErr != "" {
		return kubewarden.RejectRequest(
			kubewarden.Message(tlsErr),
			kubewarden.NoCode)
	}

	if compareErr := compareRuleAndTLSHosts(ruleHosts, tlsHosts); compareErr != "" {
		return kubewarden.RejectRequest(
			kubewarden.Message(compareErr),
			kubewarden.NoCode)
	}

	return kubewarden.AcceptRequest()
}

// collectRuleHosts returns the set of hosts defined in Ingress rules, or an
// error message string when the rules are not acceptable for validation.
func collectRuleHosts(ingress *networkingv1.Ingress) (map[string]struct{}, string) {
	ruleHosts := map[string]struct{}{}

	for _, rule := range ingress.Spec.Rules {
		if rule == nil {
			continue
		}
		if rule.Host == "" {
			return nil, "force-ssl-redirect is true but one or more Ingress rules have an empty host"
		}
		ruleHosts[rule.Host] = struct{}{}
	}

	if len(ruleHosts) == 0 {
		return nil, "force-ssl-redirect is true but Ingress has no rules with host defined"
	}

	return ruleHosts, ""
}

// collectTLSHosts returns the set of hosts defined in the TLS section, or an
// error message string when the TLS configuration is not acceptable.
func collectTLSHosts(ingress *networkingv1.Ingress) (map[string]struct{}, string) {
	tlsHosts := map[string]struct{}{}

	for _, tls := range ingress.Spec.TLS {
		if tls == nil {
			continue
		}
		for _, h := range tls.Hosts {
			if h == "" {
				continue
			}
			tlsHosts[h] = struct{}{}
		}
	}

	if len(tlsHosts) == 0 {
		return nil, "force-ssl-redirect is true but spec.tls[*].hosts is empty"
	}

	return tlsHosts, ""
}

// compareRuleAndTLSHosts ensures the set of rule hosts and TLS hosts match
// one-to-one. It returns an error message when they differ.
func compareRuleAndTLSHosts(ruleHosts, tlsHosts map[string]struct{}) string {
	missingFromTLS := []string{}
	for host := range ruleHosts {
		if _, ok := tlsHosts[host]; !ok {
			missingFromTLS = append(missingFromTLS, host)
		}
	}

	extraInTLS := []string{}
	for host := range tlsHosts {
		if _, ok := ruleHosts[host]; !ok {
			extraInTLS = append(extraInTLS, host)
		}
	}

	if len(missingFromTLS) == 0 && len(extraInTLS) == 0 {
		return ""
	}

	msgParts := []string{
		"TLS hosts must match Ingress rules hosts when force-ssl-redirect is true",
	}

	if len(missingFromTLS) > 0 {
		msgParts = append(
			msgParts,
			fmt.Sprintf(
				"missing TLS entries for hosts: %s",
				strings.Join(missingFromTLS, ","),
			),
		)
	}

	if len(extraInTLS) > 0 {
		msgParts = append(
			msgParts,
			fmt.Sprintf(
				"TLS has extra hosts not present in rules: %s",
				strings.Join(extraInTLS, ","),
			),
		)
	}

	return strings.Join(msgParts, "; ")
}

// isForceSSLRedirectEnabled inspects common annotation keys and returns true
// when force-ssl-redirect is effectively enabled.
func isForceSSLRedirectEnabled(annotations map[string]string) bool {
	if annotations == nil {
		return false
	}

	keys := []string{
		"nginx.ingress.kubernetes.io/force-ssl-redirect",
		"force-ssl-redirect",
	}

	for _, k := range keys {
		if v, ok := annotations[k]; ok {
			if strings.EqualFold(strings.TrimSpace(v), "true") {
				return true
			}
		}
	}

	return false
}

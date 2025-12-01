package main

import (
	"encoding/json"
	"fmt"

	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

// Settings is the structure that describes the policy settings.
//
// When ValidateForceSslRedirect is true, the policy will enforce the
// following rules for Ingress resources:
//   - If TLS is not configured, the annotation force-ssl-redirect cannot be true
//   - If TLS is configured and force-ssl-redirect is true:
//   - TLS.hosts must match rules[*].host one-to-one
//   - There must be at least one TLS entry
//
// The JSON field name uses snake_case to match typical Kubewarden settings
// conventions.
type Settings struct {
	ValidateForceSslRedirect bool `json:"validate_force_ssl_redirect"`
}

func NewSettingsFromValidationReq(validationReq *kubewarden_protocol.ValidationRequest) (Settings, error) {
	settings := Settings{}
	err := json.Unmarshal(validationReq.Settings, &settings)
	return settings, err
}

// Valid is the structure that informs if the policy settings are valid.
// No special checks have to be done for now.
func (s *Settings) Valid() (bool, error) {
	return true, nil
}

func validateSettings(payload []byte) ([]byte, error) {
	logger.Info("validating settings")

	settings := Settings{}
	err := json.Unmarshal(payload, &settings)
	if err != nil {
		return kubewarden.RejectSettings(kubewarden.Message(fmt.Sprintf("Provided settings are not valid: %v", err)))
	}

	valid, err := settings.Valid()
	if err != nil {
		return kubewarden.RejectSettings(kubewarden.Message(fmt.Sprintf("Provided settings are not valid: %v", err)))
	}
	if valid {
		return kubewarden.AcceptSettings()
	}

	logger.Warn("rejecting settings")
	return kubewarden.RejectSettings(kubewarden.Message("Provided settings are not valid"))
}

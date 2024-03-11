package models

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/grafana/grafana-aws-sdk/pkg/awsds"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
)

type Duration struct {
	time.Duration
}
type CloudWatchSettings struct {
	awsds.AWSDatasourceSettings
	Namespace               string   `json:"customMetricsNamespaces"`
	SecureSocksProxyEnabled bool     `json:"enableSecureSocksProxy"` // this can be removed when https://github.com/grafana/grafana/issues/39089 is implemented
	LogsTimeout             Duration `json:"logsTimeout"`

	// GrafanaSettings are fetched from the GrafanaCfg in the context
	GrafanaSettings awsds.AuthSettings `json:"-"`
}

func LoadCloudWatchSettings(ctx context.Context, config backend.DataSourceInstanceSettings) (CloudWatchSettings, error) {
	instance := CloudWatchSettings{}

	if config.JSONData != nil && len(config.JSONData) > 1 {
		if err := json.Unmarshal(config.JSONData, &instance); err != nil {
			return CloudWatchSettings{}, fmt.Errorf("could not unmarshal DatasourceSettings json: %w", err)
		}
	}

	// load the instance using the loader for the wrapped awsds.AWSDatasourceSettings
	if err := instance.Load(config); err != nil {
		return CloudWatchSettings{}, err
	}

	// logs timeout default is 30 minutes, the same as timeout in frontend logs query
	// note: for alerting queries, the context will be cancelled before that unless evaluation_timeout_seconds in defaults.ini is increased (default: 30s)
	if instance.LogsTimeout.Duration == 0 {
		instance.LogsTimeout = Duration{30 * time.Minute}
	}

	instance.GrafanaSettings = *awsds.ReadAuthSettings(ctx)
	if len(instance.GrafanaSettings.AllowedAuthProviders) > 0 {
		authType, err := awsds.ToAuthType(instance.GrafanaSettings.AllowedAuthProviders[0])
		if err != nil {
			logger := backend.Logger.FromContext(ctx)
			logger.Error("Failed to convert auth type", "error", err)
			return CloudWatchSettings{}, err
		}
		instance.AuthType = authType
	}

	return instance, nil
}

func (duration *Duration) UnmarshalJSON(b []byte) error {
	var unmarshalledJson any

	err := json.Unmarshal(b, &unmarshalledJson)
	if err != nil {
		return err
	}

	switch value := unmarshalledJson.(type) {
	case float64:
		*duration = Duration{time.Duration(value)}
	case string:
		dur, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		*duration = Duration{dur}
	default:
		return fmt.Errorf("invalid duration: %#v", unmarshalledJson)
	}

	return nil
}

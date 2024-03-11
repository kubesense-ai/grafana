package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models"
)

type ExternalIdResponse struct {
	ExternalId string `json:"externalId"`
}

func ExternalIdHandler(ctx context.Context, pluginCtx backend.PluginContext, reqCtxFactory models.RequestContextFactoryFunc, parameters url.Values) ([]byte, *models.HttpError) {
	reqCtx, err := reqCtxFactory(ctx, pluginCtx, "us-east-2")
	if err != nil {
		reqCtx.Logger.Error("error in ExternalIdHandler when calling reqCtxFactory", "error", err)
		return nil, models.NewHttpError("error in ExternalIdHandler", http.StatusInternalServerError, err)
	}

	response := ExternalIdResponse{
		ExternalId: reqCtx.Settings.GrafanaSettings.ExternalID,
	}
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		reqCtx.Logger.Error("error in ExternalIdHandler when marshalling response", "error", err)
		return nil, models.NewHttpError("error in ExternalIdHandler", http.StatusInternalServerError, err)
	}

	return jsonResponse, nil
}

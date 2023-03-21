package apiserver

import (
	"github.com/google/wire"
	"github.com/grafana/grafana/pkg/services/k8s/authentication"
	"github.com/grafana/grafana/pkg/services/k8s/authorization"
)

var WireSet = wire.NewSet(
	ProvideService,
	wire.Bind(new(Service), new(*service)),
	wire.Bind(new(RestConfigProvider), new(*service)),
	authentication.ProvideService,
	wire.Bind(new(authentication.K8sAuthnAPI), new(*authentication.K8sAuthnAPIImpl)),
	authorization.ProvideService,
	wire.Bind(new(authorization.K8sAuthzAPI), new(*authorization.K8sAuthzAPIImpl)),
)

/*
Copyright 2023 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ingressnginx

import (
	"fmt"

	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw"
	providerir "github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/provider_intermediate"
	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/providers/common"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

// resourcesToIRConverter implements the ToIR function of i2gw.ResourcesToIRConverter interface.
type resourcesToIRConverter struct {
	featureParsers []i2gw.FeatureParser
	conf           *i2gw.ProviderConf
}

// newResourcesToIRConverter returns an ingress-nginx resourcesToIRConverter instance.
func newResourcesToIRConverter(conf *i2gw.ProviderConf) *resourcesToIRConverter {
	return &resourcesToIRConverter{
		featureParsers: []i2gw.FeatureParser{
			canaryFeature,
			headerModifierFeature,
			regexFeature,
		},
		conf: conf,
	}
}

func (c *resourcesToIRConverter) convert(storage *storage) (providerir.ProviderIR, field.ErrorList) {

	// TODO(liorliberman) temporary until we decide to change ToIR and featureParsers to get a map of [types.NamespacedName]*networkingv1.Ingress instead of a list
	ingressList := storage.Ingresses.List()

	// Check if use-tls-route flag is enabled
	useTLSRoute := false
	if ps := c.conf.ProviderSpecificFlags[Name]; ps != nil {
		flagValue := ps[UseTLSRouteFlag]
		// Accept "true", "1", "yes" as truthy values
		useTLSRoute = flagValue == "true" || flagValue == "1" || flagValue == "yes"
	}

	var pIR providerir.ProviderIR
	var errs field.ErrorList

	if useTLSRoute {
		// Generate TLSRoute for ingresses with TLS configuration
		pIR, errs = c.convertToTLSRoute(ingressList, storage.ServicePorts)
		if len(errs) > 0 {
			return providerir.ProviderIR{}, errs
		}
	} else {
		// Convert plain ingress resources to gateway resources, ignoring all
		// provider-specific features.
		pIR, errs = common.ToIR(ingressList, storage.ServicePorts, i2gw.ProviderImplementationSpecificOptions{
			ToImplementationSpecificHTTPPathTypeMatch: implementationSpecificPathMatch,
		})
		if len(errs) > 0 {
			return providerir.ProviderIR{}, errs
		}

		for _, parseFeatureFunc := range c.featureParsers {
			// Apply the feature parsing function to the gateway resources, one by one.
			parseErrs := parseFeatureFunc(ingressList, storage.ServicePorts, &pIR)
			// Append the parsing errors to the error list.
			errs = append(errs, parseErrs...)
		}
	}

	return pIR, errs
}

func implementationSpecificPathMatch(path *gatewayv1.HTTPPathMatch) {
	// Nginx Ingress Controller treats ImplementationSpecific as Prefix by default,
	// unless regex characters are present (handled by regexFeature).
	// We safely default to Prefix here with a warning.
	notifyImplementationSpecificPath(*path.Value)
	t := gatewayv1.PathMatchPathPrefix
	path.Type = &t
}

func (c *resourcesToIRConverter) convertToTLSRoute(ingresses []networkingv1.Ingress, servicePorts map[types.NamespacedName]map[string]int32) (providerir.ProviderIR, field.ErrorList) {
	var errorList field.ErrorList

	// Initialize empty IR
	ir := providerir.ProviderIR{
		Gateways:           make(map[types.NamespacedName]providerir.GatewayContext),
		HTTPRoutes:         make(map[types.NamespacedName]providerir.HTTPRouteContext),
		Services:           make(map[types.NamespacedName]providerir.ProviderSpecificServiceIR),
		GatewayClasses:     make(map[types.NamespacedName]gatewayv1.GatewayClass),
		TLSRoutes:          make(map[types.NamespacedName]gatewayv1alpha2.TLSRoute),
		TCPRoutes:          make(map[types.NamespacedName]gatewayv1alpha2.TCPRoute),
		UDPRoutes:          make(map[types.NamespacedName]gatewayv1alpha2.UDPRoute),
		GRPCRoutes:         make(map[types.NamespacedName]gatewayv1.GRPCRoute),
		BackendTLSPolicies: make(map[types.NamespacedName]gatewayv1.BackendTLSPolicy),
		ReferenceGrants:    make(map[types.NamespacedName]gatewayv1beta1.ReferenceGrant),
	}

	// Get provider-specific flags
	var gatewayName, gatewaySection string
	if ps := c.conf.ProviderSpecificFlags[Name]; ps != nil {
		gatewayName = ps[TLSGatewayNameFlag]
		gatewaySection = ps[TLSGatewaySectionFlag]
	}

	// Validate: if gateway-section is specified, gateway-name must also be specified
	if gatewaySection != "" && gatewayName == "" {
		return ir, field.ErrorList{
			field.Required(field.NewPath("flags", TLSGatewayNameFlag),
				"--ingress-nginx-tls-gateway-name must be specified when using --ingress-nginx-tls-gateway-section"),
		}
	}

	generateGateway := gatewayName == ""

	// Group ingresses by namespace and ingressClass for gateway generation
	gatewaysByKey := make(map[string]*gatewayv1.Gateway)

	for i, ingress := range ingresses {
		// Validate that ingress has TLS spec
		if len(ingress.Spec.TLS) == 0 {
			errorList = append(errorList, field.Required(
				field.NewPath("spec", "tls").Index(i),
				fmt.Sprintf("Ingress %s/%s has no TLS configuration but use-tls-route flag is enabled", ingress.Namespace, ingress.Name),
			))
			continue
		}

		ingressClass := common.GetIngressClass(ingress)

		// For each TLS entry, create a TLSRoute
		for tlsIdx, tls := range ingress.Spec.TLS {
			// Determine hostnames from TLS hosts
			var hostnames []gatewayv1.Hostname
			for _, host := range tls.Hosts {
				hostnames = append(hostnames, gatewayv1.Hostname(host))
			}

			// If no hosts in TLS, try to get from rules
			if len(hostnames) == 0 {
				for _, rule := range ingress.Spec.Rules {
					if rule.Host != "" {
						hostnames = append(hostnames, gatewayv1.Hostname(rule.Host))
					}
				}
			}

			// Collect backend refs from all rules
			var backendRefs []gatewayv1.BackendRef
			for _, rule := range ingress.Spec.Rules {
				if rule.HTTP == nil {
					continue
				}
				for _, path := range rule.HTTP.Paths {
					backendRef, err := common.ToBackendRef(ingress.Namespace, path.Backend, servicePorts, field.NewPath("spec", "rules"))
					if err != nil {
						errorList = append(errorList, err)
						continue
					}
					backendRefs = append(backendRefs, gatewayv1.BackendRef{
						BackendObjectReference: backendRef.BackendObjectReference,
						Weight:                 backendRef.Weight,
					})
				}
			}

			// Create TLSRoute
			routeName := fmt.Sprintf("%s-tls-%d", ingress.Name, tlsIdx)
			tlsRoute := gatewayv1alpha2.TLSRoute{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "gateway.networking.k8s.io/v1alpha2",
					Kind:       "TLSRoute",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: ingress.Namespace,
				},
				Spec: gatewayv1alpha2.TLSRouteSpec{
					Hostnames: hostnames,
					Rules: []gatewayv1alpha2.TLSRouteRule{
						{
							BackendRefs: backendRefs,
						},
					},
				},
			}

			// Set parent reference
			if generateGateway {
				// Reference the generated gateway
				parentGatewayName := ingressClass
				if parentGatewayName == "" {
					parentGatewayName = "nginx"
				}
				tlsRoute.Spec.ParentRefs = []gatewayv1.ParentReference{
					{
						Name: gatewayv1.ObjectName(parentGatewayName),
					},
				}

				// Create or update Gateway
				gwKey := fmt.Sprintf("%s/%s", ingress.Namespace, parentGatewayName)
				gw := gatewaysByKey[gwKey]
				if gw == nil {
					gw = &gatewayv1.Gateway{
						TypeMeta: metav1.TypeMeta{
							APIVersion: "gateway.networking.k8s.io/v1",
							Kind:       "Gateway",
						},
						ObjectMeta: metav1.ObjectMeta{
							Name:      parentGatewayName,
							Namespace: ingress.Namespace,
						},
						Spec: gatewayv1.GatewaySpec{
							GatewayClassName: gatewayv1.ObjectName(parentGatewayName),
						},
					}
					gatewaysByKey[gwKey] = gw
				}

				// Add TLS passthrough listener for each hostname
				for _, hostname := range hostnames {
					listenerName := fmt.Sprintf("tls-%s", common.NameFromHost(string(hostname)))
					listener := gatewayv1.Listener{
						Name:     gatewayv1.SectionName(listenerName),
						Hostname: &hostname,
						Port:     443,
						Protocol: gatewayv1.TLSProtocolType,
						TLS: &gatewayv1.ListenerTLSConfig{
							Mode: common.PtrTo(gatewayv1.TLSModePassthrough),
						},
					}
					gw.Spec.Listeners = append(gw.Spec.Listeners, listener)
				}
			} else {
				// Reference existing gateway
				parentRef := gatewayv1.ParentReference{
					Name: gatewayv1.ObjectName(gatewayName),
				}
				if gatewaySection != "" {
					parentRef.SectionName = (*gatewayv1.SectionName)(&gatewaySection)
				}
				tlsRoute.Spec.ParentRefs = []gatewayv1.ParentReference{parentRef}
			}

			// Add TLSRoute to IR
			key := types.NamespacedName{Namespace: tlsRoute.Namespace, Name: tlsRoute.Name}
			ir.TLSRoutes[key] = tlsRoute
		}
	}

	// Add generated gateways to IR
	if generateGateway {
		for _, gw := range gatewaysByKey {
			key := types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}
			ir.Gateways[key] = providerir.GatewayContext{Gateway: *gw}
		}
	}

	return ir, errorList
}

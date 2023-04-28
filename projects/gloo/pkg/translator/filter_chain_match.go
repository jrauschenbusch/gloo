package translator

import (
	"fmt"

	core_v3 "github.com/cncf/xds/go/xds/core/v3"
	matcher_v3 "github.com/cncf/xds/go/xds/type/matcher/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	network_inputs_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/matching/common_inputs/network/v3"
	"github.com/golang/protobuf/proto"
	server_name_v3 "github.com/solo-io/gloo/projects/gloo/pkg/api/external/envoy/config/matching/custom_matchers/server_name/v3"
	"github.com/solo-io/gloo/projects/gloo/pkg/utils"
	"golang.org/x/exp/slices"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type ExtendedFilterChain struct {
	*envoy_config_listener_v3.FilterChain
	PassthroughCipherCuites []uint16
}

type comparablePassthroughCipherCuites struct {
	PassthroughCipherCuites []uint16
}

var zero = &comparablePassthroughCipherCuites{}

type comparableCidrRange struct {
	// IPv4 or IPv6 address, e.g. ``192.0.0.0`` or ``2001:db8::``.
	AddressPrefix string
	// Length of prefix, e.g. 0, 32. Defaults to 0 when unset.
	PrefixLen uint32
}

var noIpRanges = comparableCidrRange{
	AddressPrefix: "",
	PrefixLen:     0,
}

type deprecatedCipherMap map[*comparablePassthroughCipherCuites]*envoy_config_listener_v3.FilterChain
type sourceIpCidrMap map[comparableCidrRange]deprecatedCipherMap
type serverNameMap map[string]sourceIpCidrMap

/*
This function is modeled after FilterChainManagerImpl::addFilterChains in envoy
and converts filter chains to the new matcher framework.
*/
func ConvertFilterChain(fcm []ExtendedFilterChain) (*matcher_v3.Matcher, []*envoy_config_listener_v3.FilterChain, error) {
	var ret []*envoy_config_listener_v3.FilterChain
	haveDeperecatedCiphers := false
	for _, fc := range fcm {
		if fc.PassthroughCipherCuites != nil {
			haveDeperecatedCiphers = true
			break
		}
	}
	if !haveDeperecatedCiphers {
		//easy case, NOP
		for _, fc := range fcm {
			ret = append(ret, fc.FilterChain)
		}
		return nil, ret, nil
	}

	// convert existing filter chains to the new matcher framework
	serverNameMap := make(serverNameMap)
	var filterChains []*envoy_config_listener_v3.FilterChain
	for i, fc := range fcm {
		err := addFilterChainToMap(serverNameMap, fc)
		if err != nil {
			return nil, nil, err
		}
		// according to docs, If matcher is specified, all filter_chains  must have a
		// non-empty and unique name field and not specify filter_chain_match
		fc.FilterChainMatch = nil
		fc.Name = fmt.Sprintf("filter_chain_%d", i)
		filterChains = append(filterChains, fc.FilterChain)
	}

	//	we have nice IR, so now we can directly convert it to envoy config
	m := convertIr(serverNameMap)
	return m, filterChains, nil
}

func toTypedExtensionConfig(name string, msg proto.Message) *core_v3.TypedExtensionConfig {
	any, err := utils.MessageToAny(msg)
	if err != nil {
		// this should never happen
		panic(fmt.Errorf("unable to marshal message %v to any %w", msg, err))
	}

	return &core_v3.TypedExtensionConfig{
		Name:        name,
		TypedConfig: any,
	}

}

func convertIr(serverNameMap serverNameMap) *matcher_v3.Matcher {

	matcher := matcher_v3.Matcher{}
	snm := &server_name_v3.ServerNameMatcher{}
	for serverName, sourceIpCidrMap := range serverNameMap {
		// create a server name matcher:
		if serverName == "" {
			matcher.OnNoMatch = sourceCidrMapOnMatch(sourceIpCidrMap)
		} else {
			snm.ServerNameMatchers = append(snm.ServerNameMatchers, &server_name_v3.ServerNameMatcher_ServerNameSetMatcher{
				ServerNames: []string{serverName},
				OnMatch:     sourceCidrMapOnMatch(sourceIpCidrMap),
			})
		}
	}

	matcher.MatcherType = &matcher_v3.Matcher_MatcherTree_{
		MatcherTree: &matcher_v3.Matcher_MatcherTree{
			Input: toTypedExtensionConfig("envoy.matching.inputs.server_name", &network_inputs_v3.ServerNameInput{}),
			TreeType: &matcher_v3.Matcher_MatcherTree_CustomMatch{
				CustomMatch: toTypedExtensionConfig("envoy.matching.custom_matchers.server_name_matcher", snm),
			},
		},
	}
	return &matcher
}

func sourceCidrMapOnMatch(sourceIpCidrMap sourceIpCidrMap) *matcher_v3.Matcher_OnMatch {
	matcher := &matcher_v3.Matcher{}

	onMatch := &matcher_v3.Matcher_OnMatch{
		OnMatch: &matcher_v3.Matcher_OnMatch_Matcher{
			Matcher: matcher,
		},
	}

	ipTrieMatcher := &matcher_v3.IPMatcher{}
	for sourceIpCidr, deprecatedCipherMap := range sourceIpCidrMap {
		if sourceIpCidr == noIpRanges {
			matcher.OnNoMatch = deprecatedCipherOnMatch(deprecatedCipherMap)
		} else {
			ipTrieMatcher.RangeMatchers = append(ipTrieMatcher.RangeMatchers, &matcher_v3.IPMatcher_IPRangeMatcher{
				Ranges: []*core_v3.CidrRange{{
					AddressPrefix: sourceIpCidr.AddressPrefix,
					PrefixLen:     wrapperspb.UInt32(sourceIpCidr.PrefixLen),
				}},
				OnMatch:   deprecatedCipherOnMatch(deprecatedCipherMap),
				Exclusive: true,
			})
		}

	}

	matcher.MatcherType = &matcher_v3.Matcher_MatcherTree_{
		MatcherTree: &matcher_v3.Matcher_MatcherTree{
			Input: toTypedExtensionConfig("envoy.matching.inputs.source_ip", &network_inputs_v3.SourceIPInput{}),
			TreeType: &matcher_v3.Matcher_MatcherTree_CustomMatch{
				CustomMatch: toTypedExtensionConfig("envoy.matching.custom_matchers.trie_matcher", ipTrieMatcher),
			},
		},
	}
	return onMatch
}

func deprecatedCipherOnMatch(deprecatedCipherMap deprecatedCipherMap) *matcher_v3.Matcher_OnMatch {
	panic("implement me")
}

func addFilterChainToMap(serverNameMap serverNameMap, fc ExtendedFilterChain) error {
	serverNames := fc.GetFilterChainMatch().GetServerNames()
	if len(serverNames) == 0 {
		return serverNameMap.addServerNamesToMap("", fc)
	}
	for _, serverName := range serverNames {
		err := serverNameMap.addServerNamesToMap(serverName, fc)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m serverNameMap) addServerNamesToMap(srvname string, fc ExtendedFilterChain) error {
	if m[srvname] == nil {
		m[srvname] = make(sourceIpCidrMap)
	}
	sourceIpRanges := fc.GetFilterChainMatch().GetSourcePrefixRanges()
	if len(sourceIpRanges) == 0 {
		return m[srvname].addSourceIpToMap(noIpRanges, fc)
	}
	for _, ipRange := range sourceIpRanges {
		cirdRange := comparableCidrRange{
			AddressPrefix: ipRange.GetAddressPrefix(),
			PrefixLen:     ipRange.GetPrefixLen().GetValue(),
		}
		err := m[srvname].addSourceIpToMap(cirdRange, fc)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m sourceIpCidrMap) addSourceIpToMap(prefix comparableCidrRange, fc ExtendedFilterChain) error {
	if m[prefix] == nil {
		m[prefix] = make(deprecatedCipherMap)
	}

	return m[prefix].addPassthroughCiphers(fc.PassthroughCipherCuites, fc)
}

func (m deprecatedCipherMap) addPassthroughCiphers(passthroughCipherCuites []uint16, fc ExtendedFilterChain) error {
	// make the cipher suits comparable
	cpcc := &comparablePassthroughCipherCuites{
		PassthroughCipherCuites: passthroughCipherCuites,
	}

	if len(passthroughCipherCuites) == 0 {
		cpcc = zero
	} else {
		// different pointers (even with the same content) are different. so find existing key with
		// the same content and use it if exists
		for k := range m {
			if slices.Equal(k.PassthroughCipherCuites, cpcc.PassthroughCipherCuites) {
				cpcc = k
				break
			}
		}
	}

	if _, ok := m[cpcc]; !ok {
		return fmt.Errorf("multiple filter chains with overlapping matching rules are defined")
	}

	m[cpcc] = fc.FilterChain
	return nil
}

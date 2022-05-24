package solver_test

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"testing"

	"github.com/cert-manager/cert-manager/test/acme/dns"
	"github.com/heilerich/webhook-coredns-etcd/solver"
	"go.uber.org/zap"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

const (
	zone = "suite.zone.test."
)

func TestRunsSuite(t *testing.T) {
	// The manifest path should contain a file named config.json that is a
	// snippet of valid configuration that should be included on the
	// ChallengeRequest passed as part of the test cases.
	//

	// Uncomment the below fixture when implementing your custom DNS provider
	//fixture := dns.NewFixture(&customDNSProviderSolver{},
	//	dns.SetResolvedZone(zone),
	//	dns.SetAllowAmbientCredentials(false),
	//	dns.SetManifestPath("testdata/my-custom-solver"),
	//	dns.SetBinariesPath("_test/kubebuilder/bin"),
	//)

	servers, err := net.LookupIP("coredns")
	if err != nil {
		t.Fatalf("failed to find test DNS server: %v", err)
	}

	if len(servers) != 1 {
		t.Fatalf("expected one address for test DNS server, got %v", servers)
	}

	server := fmt.Sprintf("%v:5354", servers[0].String())

	solverConfig, err := ioutil.ReadFile("testdata/config.json")
	if err != nil {
		log.Fatal(err)
	}

	logger, _ := zap.NewDevelopment()
	solver := solver.New(logger)

	fixture := dns.NewFixture(solver,
		dns.SetResolvedZone(zone),
		dns.SetManifestPath("testdata/k8s-manifests.yaml"),
		dns.SetDNSServer(server),
		dns.SetUseAuthoritative(false),
		dns.SetStrict(true),
		dns.SetConfig(&extapi.JSON{
			Raw: solverConfig,
		}),
	)
	//need to uncomment and  RunConformance delete runBasic and runExtended once https://github.com/cert-manager/cert-manager/pull/4835 is merged
	//fixture.RunConformance(t)
	fixture.RunBasic(t)
	fixture.RunExtended(t)
}

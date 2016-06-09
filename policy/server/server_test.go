package server_test

import (
	"github.com/iovisor/iomodules/policy/fakes"
	"github.com/iovisor/iomodules/policy/models"
	"github.com/iovisor/iomodules/policy/server"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"errors"
)

var _ = Describe("Server", func() {
	var (
		dataplane    *fakes.Dataplane
		db           *fakes.Database
		policyServer *server.PolicyServer
	)

	BeforeEach(func() {
		dataplane = &fakes.Dataplane{}
		db = &fakes.Database{}
		policyServer = &server.PolicyServer{
			Dataplane: dataplane,
			Db:        db,
		}
	})

	Describe("AddEndpoint", func() {
		var endpoint models.EndpointEntry
		BeforeEach(func() {
			endpoint = models.EndpointEntry{
				Id:    "some-id",
				Ip:    "some-ip",
				EpgId: "some-epg",
			}
			db.GetEndpointGroupReturns(models.EndpointGroup{Id: "some-id", Epg: "some-epg", WireId: "some-wire-id"}, nil)
		})
		It("Adds the ip and endpoint group to the database", func() {
			err := policyServer.AddEndpoint(&endpoint)
			Expect(err).NotTo(HaveOccurred())

			Expect(db.AddEndpointCallCount()).To(Equal(1))
			ep := db.AddEndpointArgsForCall(0)
			Expect(ep.Ip).To(Equal(endpoint.Ip))
			Expect(ep.Id).NotTo(Equal(""))
			Expect(dataplane.AddEndpointCallCount()).To(Equal(1))
			ip, epg, wireid := dataplane.AddEndpointArgsForCall(0)
			Expect(ip).To(Equal(endpoint.Ip))
			Expect(wireid).To(Equal("some-wire-id"))
			Expect(epg).To(Equal("some-epg"))
		})

		Context("when adding to the db fails", func() {
			BeforeEach(func() {
				db.AddEndpointReturns(errors.New("potato"))
			})

			It("returns an error", func() {
				err := policyServer.AddEndpoint(&endpoint)
				Expect(err).To(MatchError("add endpoint to Db: potato"))
			})
		})
		Context("when adding to dataplane fails", func() {
			BeforeEach(func() {
				dataplane.AddEndpointReturns(errors.New("potato"))
			})

			It("returns an error", func() {
				err := policyServer.AddEndpoint(&endpoint)
				Expect(err).To(MatchError("add endpoint to dataplane: potato"))
			})
		})
	})
	Describe("Get Endpoint", func() {
		var dbEndpoint models.EndpointEntry

		BeforeEach(func() {
			dbEndpoint = models.EndpointEntry{
				Id:    "some-uuid",
				Ip:    "some-ip",
				EpgId: "some-epg-id",
			}
			db.GetEndpointReturns(dbEndpoint, nil)
		})
		It("Gets an endpoint entry from the database", func() {
			endpoint, err := policyServer.GetEndpoint("some-endpoint-id")
			Expect(err).NotTo(HaveOccurred())
			Expect(db.GetEndpointCallCount()).To(Equal(1))
			Expect(db.GetEndpointArgsForCall(0)).To(Equal("some-endpoint-id"))
			Expect(endpoint).To(Equal(dbEndpoint))
		})
		Context("when getting an endpoint entry fails", func() {
			BeforeEach(func() {
				db.GetEndpointReturns(models.EndpointEntry{}, errors.New("some-potato"))
			})
			It("returns error", func() {
				ep, err := policyServer.GetEndpoint("some-endpoint-id")
				Expect(err).To(MatchError("get endpoint from Db: some-potato"))
				Expect(ep).To(Equal(models.EndpointEntry{}))
			})
		})
	})
	Describe("Endpoints", func() {
		var dbEndpoints []models.EndpointEntry

		BeforeEach(func() {
			dbEndpoints = []models.EndpointEntry{
				{
					Ip:    "some-ip",
					EpgId: "some-epg",
				},
			}
			db.EndpointsReturns(dbEndpoints, nil)
		})
		It("Gets a list of Endpoints from the database", func() {
			endpoints, err := policyServer.Endpoints()
			Expect(err).NotTo(HaveOccurred())
			Expect(db.EndpointsCallCount()).To(Equal(1))
			Expect(endpoints).To(Equal(dbEndpoints))
		})
		Context("when getting the endpoints from the database fails", func() {
			BeforeEach(func() {
				db.EndpointsReturns(nil, errors.New("some-potato"))
			})
			It("returns error", func() {
				_, err := policyServer.Endpoints()
				Expect(err).To(MatchError("get endpoints from Db: some-potato"))
			})
		})
	})

	Describe("AddPolicy", func() {
		var (
			policy models.Policy
			epg    models.EndpointGroup
		)
		BeforeEach(func() {
			policy = models.Policy{
				Id:         "some-id",
				SourceEPG:  "some-id",
				SourcePort: "source-port",
				DestEPG:    "some-id",
				DestPort:   "dest-port",
				Protocol:   "protocol",
				Action:     "action",
			}

			epg = models.EndpointGroup{
				Id:     "some-id",
				WireId: "some-wire-id",
			}
			db.GetEndpointGroupReturns(epg, nil)
		})
		It("add a policy", func() {
			err := policyServer.AddPolicy(&policy)
			Expect(err).NotTo(HaveOccurred())

			Expect(dataplane.AddPolicyCallCount()).To(Equal(1))
			sepgId, sourcePort, depgId, destPort, protocol, action := dataplane.AddPolicyArgsForCall(0)
			Expect(sepgId).To(Equal(epg.WireId))
			Expect(sourcePort).To(Equal(policy.SourcePort))
			Expect(depgId).To(Equal(epg.WireId))
			Expect(destPort).To(Equal(policy.DestPort))
			Expect(action).To(Equal(policy.Action))
			Expect(protocol).To(Equal(policy.Protocol))

			Expect(db.AddPolicyCallCount()).To(Equal(1))
			dbPolicy := db.AddPolicyArgsForCall(0)
			Expect(dbPolicy.Id).NotTo(Equal(""))
		})
		Context("when adding the policy to the dataplane it errors", func() {
			BeforeEach(func() {
				dataplane.AddPolicyReturns(errors.New("some-potato"))
			})
			It("returns error", func() {
				err := policyServer.AddPolicy(&policy)
				Expect(err).To(MatchError("add policy to dataplane: some-potato"))
			})
		})
		Context("when adding the policy to the database fails", func() {
			BeforeEach(func() {
				db.AddPolicyReturns(errors.New("some-potato"))
			})
			It("returns error", func() {
				err := policyServer.AddPolicy(&policy)
				Expect(err).To(MatchError("add policy to Db: some-potato"))
			})
		})
	})
	Describe("Get policies", func() {
		var dbpolicies []models.Policy

		BeforeEach(func() {
			dbpolicies = []models.Policy{
				{
					SourceEPG:  "source-epg",
					SourcePort: "source-port",
					DestEPG:    "dest-epg",
					DestPort:   "dest-port",
					Protocol:   "protocol",
					Action:     "action",
				},
			}
			db.PoliciesReturns(dbpolicies, nil)
		})
		It("Gets a list of policies from the database", func() {
			policies, err := policyServer.Policies()
			Expect(err).NotTo(HaveOccurred())
			Expect(db.PoliciesCallCount()).To(Equal(1))
			Expect(policies).To(Equal(dbpolicies))
		})
		Context("when getting the policies from the db fails", func() {
			BeforeEach(func() {
				db.PoliciesReturns(nil, errors.New("some-potato"))
			})
			It("returns an error", func() {
				_, err := policyServer.Policies()
				Expect(err).To(MatchError("get policies from Db: some-potato"))
			})
		})
	})
	Describe("Delete Endpoint", func() {
		BeforeEach(func() {
			db.GetEndpointReturns(models.EndpointEntry{Id: "some-id", Ip: "some-ip", EpgId: "some-epg"}, nil)
		})
		It("deletes an endpoint from the dataplane", func() {
			err := policyServer.DeleteEndpoint("some-ep-id")
			Expect(err).NotTo(HaveOccurred())
			Expect(dataplane.DeleteEndpointCallCount()).To(Equal(1))
			Expect(dataplane.DeleteEndpointArgsForCall(0)).To(Equal("some-ip"))
			Expect(db.DeleteEndpointCallCount()).To(Equal(1))
			Expect(db.DeleteEndpointArgsForCall(0)).To(Equal("some-ep-id"))
		})
		Context("when deleting the endpoint from the dataplane fails", func() {
			BeforeEach(func() {
				dataplane.DeleteEndpointReturns(errors.New("some-potato"))
			})
			It("returns an error", func() {
				err := policyServer.DeleteEndpoint("some-ep-id")
				Expect(err).To(MatchError("delete endpoint from dataplane: some-potato"))
			})
		})
		Context("when deleting the endpoint from the db fails", func() {
			BeforeEach(func() {
				db.DeleteEndpointReturns(errors.New("some-potato"))
			})
			It("returns an error", func() {
				err := policyServer.DeleteEndpoint("some-ep-id")
				Expect(err).To(MatchError("delete endpoint from Db: some-potato"))
			})
		})
	})
	Describe("Delete a Policy", func() {
		var policy models.Policy
		BeforeEach(func() {
			policy = models.Policy{
				SourceEPG:  "some-wire-id",
				SourcePort: "source-port",
				DestEPG:    "some-wire-id",
				DestPort:   "dest-port",
				Protocol:   "protocol",
				Action:     "action",
			}
			db.GetEndpointGroupReturns(models.EndpointGroup{WireId: "some-wire-id", Id: "some-id"}, nil)
			db.GetPolicyReturns(policy, nil)
		})
		It("deletes a policy from the policy server", func() {
			err := policyServer.DeletePolicy("some-policy-id")
			Expect(err).NotTo(HaveOccurred())
			Expect(dataplane.DeletePolicyCallCount()).To(Equal(1))
			sepgId, sourcePort, depgId, destPort, protocol := dataplane.DeletePolicyArgsForCall(0)
			Expect(sepgId).To(Equal(policy.SourceEPG))
			Expect(sourcePort).To(Equal(policy.SourcePort))
			Expect(depgId).To(Equal(policy.DestEPG))
			Expect(destPort).To(Equal(policy.DestPort))
			Expect(protocol).To(Equal(policy.Protocol))
			Expect(db.DeletePolicyCallCount()).To(Equal(1))
			Expect(db.DeletePolicyArgsForCall(0)).To(Equal("some-policy-id"))
		})
		Context("when deleting the policy from the dataplane fails", func() {
			BeforeEach(func() {
				dataplane.DeletePolicyReturns(errors.New("some-potato"))
			})
			It("returns an error", func() {
				err := policyServer.DeletePolicy("some-policy-id")
				Expect(err).To(MatchError("delete policy from dataplane: some-potato"))
			})
		})
		Context("when delete the policy from the db fails", func() {
			BeforeEach(func() {
				db.DeletePolicyReturns(errors.New("some-potato"))
			})
			It("returns an error", func() {
				err := policyServer.DeletePolicy("some-policy-id")
				Expect(err).To(MatchError("delete policy from Db: some-potato"))
			})
		})
	})
	Describe("Get a Policy", func() {
		var policy models.Policy
		BeforeEach(func() {
			policy = models.Policy{
				SourceEPG:  "source-epg",
				SourcePort: "source-port",
				DestEPG:    "dest-epg",
				DestPort:   "dest-port",
				Protocol:   "protocol",
				Action:     "action",
			}
			db.GetPolicyReturns(policy, nil)
		})
		It("gets a policy from the policy server", func() {
			p, err := policyServer.GetPolicy("some-policy-id")
			Expect(db.GetPolicyCallCount()).To(Equal(1))
			Expect(db.GetPolicyArgsForCall(0)).To(Equal("some-policy-id"))
			Expect(p).To(Equal(policy))
			Expect(err).NotTo(HaveOccurred())
		})
		Context("when getting a policy entry from the db fails", func() {
			BeforeEach(func() {
				db.GetPolicyReturns(models.Policy{}, errors.New("some-potato"))
			})
			It("returns an error", func() {
				p, err := policyServer.GetPolicy("some-policy-id")
				Expect(err).To(MatchError("get policy from Db: some-potato"))
				Expect(p).To(Equal(models.Policy{}))
			})
		})
	})
	Describe("Get an EndpointGroup", func() {
		var epg models.EndpointGroup
		BeforeEach(func() {
			epg = models.EndpointGroup{
				Id:     "some-id",
				WireId: "some-wire-id",
			}
			db.GetEndpointGroupReturns(epg, nil)
		})
		It("gets an endpoint group from the server", func() {
			g, err := policyServer.GetEndpointGroup("some-id")
			Expect(db.GetEndpointGroupCallCount()).To(Equal(1))
			Expect(db.GetEndpointGroupArgsForCall(0)).To(Equal("some-id"))
			Expect(g).To(Equal(epg))
			Expect(err).NotTo(HaveOccurred())
		})
		Context("when getting an endpoint group entry from the db fails", func() {
			BeforeEach(func() {
				db.GetEndpointGroupReturns(models.EndpointGroup{}, errors.New("some-potato"))
			})
			It("returns an error", func() {
				g, err := policyServer.GetEndpointGroup("some-epg-id")
				Expect(err).To(MatchError("get epg from Db: some-potato"))
				Expect(g).To(Equal(models.EndpointGroup{}))
			})
		})
	})
	Describe("Delete an EndpointGroup", func() {
		BeforeEach(func() {
			db.GetEndpointGroupReturns(models.EndpointGroup{Id: "some-epg-id", WireId: "some-id"}, nil)
		})
		It("deletes an endpoint group from the dataplane", func() {
			err := policyServer.DeleteEndpointGroup("some-epg-id")
			Expect(err).NotTo(HaveOccurred())
			Expect(db.DeleteEndpointGroupCallCount()).To(Equal(1))
			Expect(db.DeleteEndpointGroupArgsForCall(0)).To(Equal("some-epg-id"))
		})
	})
	Describe("Add EndpointGroup", func() {
		var (
			epg models.EndpointGroup
		)
		BeforeEach(func() {
			epg = models.EndpointGroup{
				Id:     "some-id",
				WireId: "some-wire-id",
			}
			db.GetEndpointGroupReturns(epg, nil)
		})
		It("adds an epg", func() {
			err := policyServer.AddEndpointGroup(&epg)
			Expect(err).NotTo(HaveOccurred())
			Expect(db.AddEndpointGroupCallCount()).To(Equal(1))
			dbEpg := db.AddEndpointGroupArgsForCall(0)
			Expect(dbEpg.Id).NotTo(Equal(""))
		})
		Context("when adding the endpoint group to the database fails", func() {
			BeforeEach(func() {
				db.AddEndpointGroupReturns(errors.New("some-potato"))
			})
			It("returns error", func() {
				err := policyServer.AddEndpointGroup(&epg)
				Expect(err).To(MatchError("add epg to Db: some-potato"))
			})
		})
	})
	Describe("Endpoint groups", func() {
		var dbepgs []models.EndpointGroup
		BeforeEach(func() {
			dbepgs = []models.EndpointGroup{
				{
					Id:     "some-id",
					WireId: "some-wire-id",
				},
			}
			db.EndpointGroupsReturns(dbepgs, nil)
		})
		It("Gets a list of endpoint groups from the database", func() {
			epgs, err := policyServer.EndpointGroups()
			Expect(err).NotTo(HaveOccurred())
			Expect(db.EndpointGroupsCallCount()).To(Equal(1))
			Expect(epgs).To(Equal(dbepgs))
		})
		Context("when getting the endpoint groups from the db fails", func() {
			BeforeEach(func() {
				db.EndpointGroupsReturns(nil, errors.New("some-potato"))
			})
			It("returns an error", func() {
				_, err := policyServer.EndpointGroups()
				Expect(err).To(MatchError("get epgs from Db: some-potato"))
			})
		})
	})
})

package server_test

import (
	"github.com/iomodules/policy/fakes"
	"github.com/iomodules/policy/models"
	"github.com/iomodules/policy/server"

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
				WireId: "some-wire-id",
				Id:     "some-id",
				Ip:     "some-ip",
				Epg:    "some-epg",
			}
		})
		It("Adds the ip and endpoint group to the database", func() {
			err := policyServer.AddEndpoint(endpoint)
			Expect(err).NotTo(HaveOccurred())

			Expect(db.AddEndpointCallCount()).To(Equal(1))
			ep := db.AddEndpointArgsForCall(0)
			Expect(ep).To(Equal(endpoint))

			Expect(dataplane.AddEndpointCallCount()).To(Equal(1))
		})

		Context("when adding to the db fails", func() {
			BeforeEach(func() {
				db.AddEndpointReturns(errors.New("potato"))
			})

			It("returns an error", func() {
				err := policyServer.AddEndpoint(endpoint)
				Expect(err).To(MatchError("add endpoint to Db: potato"))
			})
		})
		Context("when adding to dataplane fails", func() {
			BeforeEach(func() {
				dataplane.AddEndpointReturns(errors.New("potato"))
			})

			It("returns an error", func() {
				err := policyServer.AddEndpoint(endpoint)
				Expect(err).To(MatchError("add endpoint to dataplane: potato"))
			})
		})
	})
	Describe("Get Endpoint", func() {
		var dbEndpoint models.EndpointEntry

		BeforeEach(func() {
			dbEndpoint = models.EndpointEntry{
				WireId: "some-wire-id",
				Id:     "some-uuid",
				Ip:     "some-ip",
				Epg:    "some-epg",
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
					Ip:  "some-ip",
					Epg: "some-epg",
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
			policy   models.Policy
			endpoint models.EndpointEntry
		)
		BeforeEach(func() {
			policy = models.Policy{
				SourceEPG:  "some-wire-id",
				SourcePort: "source-port",
				DestEPG:    "some-wire-id",
				DestPort:   "dest-port",
				Protocol:   "protocol",
				Action:     "action",
			}

			endpoint = models.EndpointEntry{
				Ip:     "some-ip",
				Epg:    "some-epg",
				WireId: "some-wire-id",
			}
			db.GetEndpointReturns(endpoint, nil)
		})
		It("add a policy", func() {
			err := policyServer.AddPolicy(policy)
			Expect(err).NotTo(HaveOccurred())

			Expect(dataplane.AddPolicyCallCount()).To(Equal(1))
			sepgId, sourcePort, depgId, destPort, protocol, action := dataplane.AddPolicyArgsForCall(0)
			Expect(sepgId).To(Equal(policy.SourceEPG))
			Expect(sourcePort).To(Equal(policy.SourcePort))
			Expect(depgId).To(Equal(policy.DestEPG))
			Expect(destPort).To(Equal(policy.DestPort))
			Expect(action).To(Equal(policy.Action))
			Expect(protocol).To(Equal(policy.Protocol))

			Expect(db.AddPolicyCallCount()).To(Equal(1))
			dbPolicy := db.AddPolicyArgsForCall(0)
			Expect(dbPolicy).To(Equal(policy))
		})
		Context("when adding the policy to the dataplane it errors", func() {
			BeforeEach(func() {
				dataplane.AddPolicyReturns(errors.New("some-potato"))
			})
			It("returns error", func() {
				err := policyServer.AddPolicy(policy)
				Expect(err).To(MatchError("add policy to dataplane: some-potato"))
			})
		})
		Context("when adding the policy to the database fails", func() {
			BeforeEach(func() {
				db.AddPolicyReturns(errors.New("some-potato"))
			})
			It("returns error", func() {
				err := policyServer.AddPolicy(policy)
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
			db.GetEndpointReturns(models.EndpointEntry{Id: "some-id", Ip: "some-ip", Epg: "some-epg"}, nil)
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
			db.GetEndpointReturns(models.EndpointEntry{WireId: "some-wire-id", Id: "some-id", Ip: "some-ip", Epg: "some-epg"}, nil)
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
})

package client_test

import (
	"net/http"

	. "github.com/iovisor/iomodules/policy/client"
	"github.com/iovisor/iomodules/policy/models"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
)

var _ = Describe("Client", func() {
	var (
		fakeserver *ghttp.Server
		p          PolicyClient
	)
	BeforeEach(func() {
		fakeserver = ghttp.NewServer()
		p = NewClient(fakeserver.URL())
	})
	Describe("Endpoint APIs", func() {
		var endpoint models.EndpointEntry
		BeforeEach(func() {
			endpoint = models.EndpointEntry{
				Ip:    "some-ip",
				EpgId: "some-id",
			}
		})
		Describe("Add Endpoint", func() {
			It("Adds an endpoint to the server", func() {
				statusCode := http.StatusOK
				Expect(p).NotTo(BeNil())
				fakeserver.AppendHandlers(ghttp.CombineHandlers(
					ghttp.VerifyRequest("POST", "/endpoint/"),
					ghttp.RespondWithJSONEncodedPtr(&statusCode, &endpoint),
				))
				err := p.AddEndpoint(&endpoint)
				Expect(err).NotTo(HaveOccurred())
			})
		})
		Describe("Delete Endpoint", func() {
			It("Deletes an endpint from the server", func() {
				someId := "some-id"
				statusCode := http.StatusOK
				fakeserver.AppendHandlers(ghttp.CombineHandlers(
					ghttp.VerifyRequest("DELETE", "/endpoint/"+someId),
					ghttp.RespondWith(statusCode, ""),
				))
				err := p.DeleteEndpoint(someId)
				Expect(err).NotTo(HaveOccurred())
			})
		})
		Describe("Get Endpoint", func() {
			It("Gets an endpoint from the server", func() {
				someId := "some-id"
				statusCode := http.StatusOK
				fakeserver.AppendHandlers(ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/endpoint/"+someId),
					ghttp.RespondWithJSONEncodedPtr(&statusCode, &endpoint),
				))
				ep, err := p.GetEndpoint(someId)
				Expect(err).NotTo(HaveOccurred())
				Expect(ep).To(Equal(endpoint))
			})
		})
		Describe("Get Endpoint List", func() {
			var eplist []models.EndpointEntry
			BeforeEach(func() {
				eplist = []models.EndpointEntry{
					{
						Ip:    "some-ip",
						EpgId: "some-id",
					},
				}
			})
			It("Gets endpoint list from the server", func() {
				statusCode := http.StatusOK
				fakeserver.AppendHandlers(ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/endpoint/"),
					ghttp.RespondWithJSONEncodedPtr(&statusCode, &eplist),
				))
				epl, err := p.Endpoints()
				Expect(err).NotTo(HaveOccurred())
				Expect(epl).To(Equal(eplist))
			})
		})
	})
	Describe("Policy APIs", func() {
		var policy models.Policy
		BeforeEach(func() {
			policy = models.Policy{
				SourceEPG:  "some-epg",
				SourcePort: "some-id",
				DestEPG:    "some-epg",
				DestPort:   "some-port",
				Protocol:   "some-protocol",
				Action:     "some-action",
			}
		})
		Describe("Add Policy", func() {
			It("Adds a policy to the server", func() {
				statusCode := http.StatusOK
				Expect(p).NotTo(BeNil())
				fakeserver.AppendHandlers(ghttp.CombineHandlers(
					ghttp.VerifyRequest("POST", "/policy/"),
					ghttp.RespondWithJSONEncodedPtr(&statusCode, &policy),
				))
				err := p.AddPolicy(policy)
				Expect(err).NotTo(HaveOccurred())
			})
		})
		Describe("Delete Policy", func() {
			It("Deletes a policy from the server", func() {
				someId := "some-id"
				statusCode := http.StatusOK
				fakeserver.AppendHandlers(ghttp.CombineHandlers(
					ghttp.VerifyRequest("DELETE", "/policy/"+someId),
					ghttp.RespondWith(statusCode, ""),
				))
				err := p.DeletePolicy(someId)
				Expect(err).NotTo(HaveOccurred())
			})
		})
		Describe("Get Policy", func() {
			It("Get a policy from the server", func() {
				someId := "some-id"
				statusCode := http.StatusOK
				fakeserver.AppendHandlers(ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/policy/"+someId),
					ghttp.RespondWithJSONEncodedPtr(&statusCode, &policy),
				))
				p, err := p.GetPolicy(someId)
				Expect(err).NotTo(HaveOccurred())
				Expect(p).To(Equal(policy))
			})
		})
		Describe("Get Policy Group List", func() {
			var policylist []models.Policy
			BeforeEach(func() {
				policylist = []models.Policy{
					{
						SourceEPG:  "some-epg",
						SourcePort: "some-id",
						DestEPG:    "some-epg",
						DestPort:   "some-port",
						Protocol:   "some-protocol",
						Action:     "some-action",
					},
				}
			})
			It("Gets policy list from the server", func() {
				statusCode := http.StatusOK
				fakeserver.AppendHandlers(ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/policies/"),
					ghttp.RespondWithJSONEncodedPtr(&statusCode, &policylist),
				))
				policyl, err := p.Policies()
				Expect(err).NotTo(HaveOccurred())
				Expect(policyl).To(Equal(policylist))
			})
		})

	})
	Describe("Endpoint Group APIs", func() {
		var epg models.EndpointGroup
		BeforeEach(func() {
			epg = models.EndpointGroup{
				Epg:    "some-epg",
				WireId: "some-wire-id",
			}
		})
		Describe("Add Endpoint Group", func() {
			It("Adds endpoint group to the server", func() {
				statusCode := http.StatusOK
				Expect(p).NotTo(BeNil())
				fakeserver.AppendHandlers(ghttp.CombineHandlers(
					ghttp.VerifyRequest("POST", "/epg/"),
					ghttp.RespondWithJSONEncodedPtr(&statusCode, &epg),
				))
				err := p.AddEndpointGroup(epg)
				Expect(err).NotTo(HaveOccurred())
			})
		})
		Describe("Delete Endpoint Group", func() {
			It("Deletes an endpoint group from the server", func() {
				someId := "some-id"
				statusCode := http.StatusOK
				fakeserver.AppendHandlers(ghttp.CombineHandlers(
					ghttp.VerifyRequest("DELETE", "/epg/"+someId),
					ghttp.RespondWith(statusCode, ""),
				))
				err := p.DeleteEndpointGroup(someId)
				Expect(err).NotTo(HaveOccurred())
			})
		})
		Describe("Get Endpoint Group", func() {
			It("Get a epg from the server", func() {
				someId := "some-id"
				statusCode := http.StatusOK
				fakeserver.AppendHandlers(ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/epg/"+someId),
					ghttp.RespondWithJSONEncodedPtr(&statusCode, &epg),
				))
				epgrp, err := p.GetEndpointGroup(someId)
				Expect(err).NotTo(HaveOccurred())
				Expect(epgrp).To(Equal(epg))
			})
		})
		Describe("Get Endpoint Group List", func() {
			var epglist []models.EndpointGroup
			BeforeEach(func() {
				epglist = []models.EndpointGroup{
					{
						Epg:    "some-epg",
						WireId: "some-wire-id",
					},
				}
			})
			It("Gets an epg list from the server", func() {
				statusCode := http.StatusOK
				fakeserver.AppendHandlers(ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/epg/"),
					ghttp.RespondWithJSONEncodedPtr(&statusCode, &epglist),
				))
				epgl, err := p.EndpointGroups()
				Expect(err).NotTo(HaveOccurred())
				Expect(epgl).To(Equal(epglist))
			})
		})
	})
})

package database_test

import (
	"github.com/iovisor/iomodules/policy/database"
	"github.com/iovisor/iomodules/policy/models"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Database", func() {
	var db database.Database
	BeforeEach(func() {
		var err error
		db, err = database.Init("test-db")
		Expect(err).NotTo(HaveOccurred())
	})
	Describe("Endpoints", func() {
		var endpoint = models.EndpointEntry{
			Id:  "some-uuid",
			Ip:  "some-ip",
			Epg: "some-epg"}
		BeforeEach(func() {
			err := db.AddEndpoint(endpoint)
			Expect(err).NotTo(HaveOccurred())
		})
		It("Gets endpoints from the database", func() {
			eps, err := db.Endpoints()
			Expect(err).NotTo(HaveOccurred())
			Expect(eps[0]).To(Equal(endpoint))
		})
	})
	Describe("Delete Endpoint", func() {
		BeforeEach(func() {
			endpoints := []models.EndpointEntry{
				{Id: "some-uuid1"},
				{Id: "some-uuid2"},
				{Id: "some-uuid3"},
			}
			for _, e := range endpoints {
				Expect(db.AddEndpoint(e)).To(Succeed())
			}
		})
		It("Deletes an endpoint from the database", func() {
			Expect(db.DeleteEndpoint("some-uuid1")).To(Succeed())
			Expect(db.Endpoints()).To(ConsistOf(
				[]models.EndpointEntry{
					{Id: "some-uuid2"},
					{Id: "some-uuid3"},
				}))
		})
	})
	Describe("Policies", func() {
		policy := models.Policy{
			SourceEPG:  "some-epg",
			SourcePort: "some-port",
			DestEPG:    "some-epg",
			DestPort:   "some-port",
			Protocol:   "some-protocol",
			Action:     "some-action",
		}
		BeforeEach(func() {
			err := db.AddPolicy(policy)
			Expect(err).NotTo(HaveOccurred())
		})
		It("Gets policies from the database", func() {
			policies, err := db.Policies()
			Expect(err).NotTo(HaveOccurred())
			Expect(policies[0]).To(Equal(policy))
		})
	})
	Describe("Delete Policy", func() {
		BeforeEach(func() {
			policies := []models.Policy{
				{Id: "some-uuid1"},
				{Id: "some-uuid2"},
				{Id: "some-uuid3"},
			}
			for _, p := range policies {
				Expect(db.AddPolicy(p)).To(Succeed())
			}
		})
		It("Deletes a policy entry from the database", func() {
			Expect(db.DeletePolicy("some-uuid1")).To(Succeed())
			Expect(db.Policies()).To(ConsistOf(
				[]models.Policy{
					{Id: "some-uuid2"},
					{Id: "some-uuid3"},
				}))
		})
	})
	Describe("Get Policy", func() {
		BeforeEach(func() {
			policies := []models.Policy{
				{Id: "some-uuid1"},
				{Id: "some-uuid2"},
				{Id: "some-uuid3"},
			}
			for _, p := range policies {
				Expect(db.AddPolicy(p)).To(Succeed())
			}
		})
		It("Gets a policy entry from the database", func() {
			p, err := db.GetPolicy("some-uuid1")
			Expect(err).NotTo(HaveOccurred())
			Expect(p).To(Equal(models.Policy{Id: "some-uuid1"}))
		})
	})
	Describe("Get Endpoint", func() {
		BeforeEach(func() {
			endpoints := []models.EndpointEntry{
				{Id: "some-uuid1"},
				{Id: "some-uuid2"},
				{Id: "some-uuid3"},
			}
			for _, p := range endpoints {
				Expect(db.AddEndpoint(p)).To(Succeed())
			}
		})
		It("Gets an endpoint entry from the database", func() {
			e, err := db.GetEndpoint("some-uuid1")
			Expect(err).NotTo(HaveOccurred())
			Expect(e).To(Equal(models.EndpointEntry{Id: "some-uuid1"}))
		})
	})
	Describe("Get Endpoint by name", func() {
		BeforeEach(func() {
			endpoints := []models.EndpointEntry{
				{Id: "some-uuid1",
					Epg: "db"},
				{Id: "some-uuid2",
					Epg: "app"},
				{Id: "some-uuid3",
					Epg: "web"},
			}
			for _, p := range endpoints {
				Expect(db.AddEndpoint(p)).To(Succeed())
			}
		})
		It("Gets an endpoint entry from the database", func() {
			e, err := db.GetEndpointByName("app")
			Expect(err).NotTo(HaveOccurred())
			Expect(e).To(Equal(models.EndpointEntry{Id: "some-uuid2", Epg: "app"}))

		})
	})
})

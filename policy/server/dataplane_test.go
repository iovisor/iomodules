package server_test

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/iovisor/iomodules/policy/models"
	. "github.com/iovisor/iomodules/policy/server"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
)

var _ = Describe("Dataplane", func() {
	var (
		dataplane  *Dataplane
		fakeserver *ghttp.Server
		module     models.ModuleEntry
	)
	BeforeEach(func() {
		fakeserver = ghttp.NewServer()
		dataplane = NewDataplane()
		Expect(dataplane).NotTo(BeNil())
		module = models.ModuleEntry{
			Id: "some-module-id",
		}
	})
	Describe("Init Dataplane", func() {
		var statusCode int
		It("Instantiates a dataplane object", func() {
			statusCode := http.StatusOK
			fakeserver.AppendHandlers(ghttp.CombineHandlers(
				ghttp.VerifyRequest("POST", "/modules/"),
				ghttp.RespondWithJSONEncodedPtr(&statusCode, &module),
			))
			err := dataplane.Init(fakeserver.URL())
			Expect(err).NotTo(HaveOccurred())
			Expect(dataplane.Id()).To(Equal("some-module-id"))
		})
		Context("When the post to server fails", func() {
			BeforeEach(func() {
				statusCode = http.StatusInternalServerError
				fakeserver.AppendHandlers(ghttp.CombineHandlers(
					ghttp.VerifyRequest("POST", "/modules/"),
					ghttp.RespondWithJSONEncodedPtr(&statusCode, &models.ModuleEntry{}),
				))
			})
			It("Returns an error", func() {
				err := dataplane.Init(fakeserver.URL())
				Expect(err).To(HaveOccurred())
				ret := errors.New("module server returned: " + fmt.Sprintf("%d", statusCode) + " " + http.StatusText(statusCode))
				Expect(err).To(Equal(ret))
			})
		})
	})
	Describe("Policy APIs", func() {
		var entry models.TableEntry
		var statusCode int
		BeforeEach(func() {
			statusCode = http.StatusOK
			fakeserver.AppendHandlers(ghttp.CombineHandlers(
				ghttp.VerifyRequest("POST", "/modules/"),
				ghttp.RespondWithJSONEncodedPtr(&statusCode, &module),
			))
			err := dataplane.Init(fakeserver.URL())
			Expect(err).NotTo(HaveOccurred())
			Expect(dataplane.Id()).To(Equal("some-module-id"))
		})
		It("Adds a policy to the server", func() {
			entry = models.TableEntry{
				Key:   fmt.Sprintf("{ %s %s %s %s %s [ 0 0 0 ]}", "200", "200", "0", "0", "20"),
				Value: "0",
			}
			fakeserver.AppendHandlers(ghttp.CombineHandlers(
				ghttp.VerifyRequest("POST", "/modules/"+dataplane.Id()+"/tables/rules/entries/"),
				ghttp.VerifyJSONRepresenting(&entry),
				ghttp.RespondWithJSONEncodedPtr(&statusCode, &entry),
			))
			err := dataplane.AddPolicy("200", "", "200", "", "20", "allow")
			Expect(err).NotTo(HaveOccurred())
		})
		Context("when adding a policy to the server fails", func() {
			BeforeEach(func() {
				statusCode = http.StatusInternalServerError
				fakeserver.AppendHandlers(ghttp.CombineHandlers(
					ghttp.VerifyRequest("POST", "/modules/"+dataplane.Id()+"/tables/rules/entries/"),
					ghttp.RespondWithJSONEncodedPtr(&statusCode, models.TableEntry{}),
				))
			})
			It("Returns an error", func() {
				err := dataplane.AddPolicy("200", "", "200", "", "20", "allow")
				Expect(err).To(HaveOccurred())
			})
		})
		It("Deletes a policy from the server", func() {
			fakeserver.AppendHandlers(ghttp.CombineHandlers(
				ghttp.VerifyRequest("DELETE", "/modules/"+dataplane.Id()+"/tables/rules/entries/"+entry.Key),
				ghttp.RespondWith(http.StatusOK, ""),
			))
			err := dataplane.DeletePolicy("200", "0", "200", "0", "20")
			Expect(err).NotTo(HaveOccurred())
		})
		Context("when delete a policy from the server fails", func() {
			BeforeEach(func() {
				statusCode = http.StatusInternalServerError
				fakeserver.AppendHandlers(ghttp.CombineHandlers(
					ghttp.VerifyRequest("DELETE", "/modules/"+dataplane.Id()+"/tables/rules/entries/"+entry.Key),
					ghttp.RespondWith(statusCode, ""),
				))
			})
			It("Returns an error", func() {
				err := dataplane.DeletePolicy("200", "0", "200", "0", "20")
				Expect(err).To(HaveOccurred())
			})
		})
	})
	Describe("Endpoint APIs", func() {
		var (
			entry      models.TableEntry
			ipStr      string
			wireid     string
			ipKey      string
			epg        string
			ip         net.IP
			statusCode int
		)
		BeforeEach(func() {
			ipStr = "10.1.1.1"
			epg = "some-epg"
			ip = net.ParseIP(ipStr)
			ipKey = fmt.Sprintf("%d", binary.BigEndian.Uint32(ip.To4()))
			wireid = "300"
			entry = models.TableEntry{
				Key:   ipKey,
				Value: wireid,
			}
			statusCode = http.StatusOK
			fakeserver.AppendHandlers(ghttp.CombineHandlers(
				ghttp.VerifyRequest("POST", "/modules/"),
				ghttp.RespondWithJSONEncodedPtr(&statusCode, &module),
			))
			err := dataplane.Init(fakeserver.URL())
			Expect(err).NotTo(HaveOccurred())
			Expect(dataplane.Id()).To(Equal("some-module-id"))
		})
		It("Adds an endpoint to the server", func() {
			fakeserver.AppendHandlers(ghttp.CombineHandlers(
				ghttp.VerifyRequest("POST", "/modules/"+dataplane.Id()+"/tables/endpoints/entries/"),
				ghttp.VerifyJSONRepresenting(&entry),
				ghttp.RespondWithJSONEncodedPtr(&statusCode, &entry),
			))
			err := dataplane.AddEndpoint(ipStr, epg, wireid)
			Expect(err).NotTo(HaveOccurred())
		})
		Context("when add an endpoint from the server fails", func() {
			BeforeEach(func() {
				statusCode = http.StatusInternalServerError
				fakeserver.AppendHandlers(ghttp.CombineHandlers(
					ghttp.VerifyRequest("POST", "/modules/"+dataplane.Id()+"/tables/endpoints/entries/"),
					ghttp.RespondWith(statusCode, ""),
				))
			})
			It("Returns an error", func() {
				err := dataplane.AddEndpoint(ipStr, epg, wireid)
				Expect(err).To(HaveOccurred())
			})
		})
		It("Deletes an endpoint from the server", func() {
			fakeserver.AppendHandlers(ghttp.CombineHandlers(
				ghttp.VerifyRequest("DELETE", "/modules/"+dataplane.Id()+"/tables/endpoints/entries/"+entry.Key),
				ghttp.RespondWith(http.StatusOK, ""),
			))
			err := dataplane.DeleteEndpoint(ipStr)
			Expect(err).NotTo(HaveOccurred())
		})
		Context("when deleting an endpoint from the server fails", func() {
			BeforeEach(func() {
				statusCode = http.StatusInternalServerError
				fakeserver.AppendHandlers(ghttp.CombineHandlers(
					ghttp.VerifyRequest("DELETE", "/modules/"+dataplane.Id()+"/tables/endpoints/entries/"+entry.Key),
					ghttp.RespondWith(statusCode, ""),
				))
			})
			It("Returns an error", func() {
				err := dataplane.DeleteEndpoint(ipStr)
				Expect(err).To(HaveOccurred())
			})
		})
	})
})

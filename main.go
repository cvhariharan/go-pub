package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/gob"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/go-resty/resty/v2"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

var actorObj *Actor
var finger *WebFingerResp

type Actor struct {
	Context           []string  `json:"@context"`
	ID                string    `json:"id"`
	Type              string    `json:"type"`
	PreferredUsername string    `json:"preferredUsername"`
	Inbox             string    `json:"inbox"`
	Followers         string    `json:"followers"`
	PubKey            PublicKey `json:"PublicKey"`
}

type PublicKey struct {
	ID        string `json:"id"`
	Owner     string `json:"owner"`
	PubKeyPem string `json:"publicKeyPem"`
}

type WebFingerResp struct {
	Subject string `json:"subject"`
	Links   []Link `json:"links"`
}

type Link struct {
	Rel  string `json:"rel"`
	Type string `json:"type"`
	Href string `json:"href"`
}

// TODO - Create RSA keys and store them
func createActor(c echo.Context) error {
	reader := rand.Reader
	bitSize := 2048

	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		log.Println(err)
		return err
	}
	encoder := gob.NewEncoder(outFile)
	err = encoder.Encode(key.)

	if actorObj == nil {
		// Create actor
		actorObj = &Actor{
			Context: []string{
				"https://www.w3.org/ns/activitystreams",
				"https://w3id.org/security/v1",
			},
			ID:                "https://" + c.Request().Host + "/u/test",
			Type:              "Person",
			PreferredUsername: "test",
			Inbox:             "https://" + c.Request().Host + "/test/inbox",
			Followers:         "https://" + c.Request().Host + "/test/followers",
			PubKey: PublicKey{
				ID:        "https://" + c.Request().Host + "/u/test#main-key",
				Owner:     "https://" + c.Request().Host + "/u/test",
				PubKeyPem: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzQc0MZF/+hjCJlNKPhi\nlVte7aC52w1lSxD7joLYq8Iz5YL3KVnbFPKnPZzMQiTOd7IN1wvxmPvKgRNUwgJJ\ncO4vEEVJt+Tayut1JVdmVTVTD2izIQYl12BuwnPBvgJx4Mhx7h9TMy+5X0wKm/aj\naQjE/Hn7t3v5/PFxvRNol7xknB4KQIY2BnFQIsqsmwDNgDpcV+0hps4J95jNyldm\nQlUbPC6JKocomMAMf2EoPvtQVeiQaoy82JnkrMkYjOxI0CiAgakvheX2octEjbf2\nIpUIfNRZvoJF646q72Z/C1pJ5GZoLqVACIpoV/fWEt5z6ICOisy7EOmt6NAh8WHl\nhwIDAQAB\n-----END PUBLIC KEY-----\n",
			},
		}

		// Create webfinger
		finger = &WebFingerResp{
			Subject: "acct:test@" + c.Request().Host,
			Links: []Link{
				Link{
					Rel:  "self",
					Type: "application/activity+json",
					Href: "https://" + c.Request().Host + "/u/test",
				},
			},
		}
	}
	return nil
}

func actor(c echo.Context) error {
	if actorObj == nil {
		return c.JSON(http.StatusNotFound, `{"error": "Actor not found"}`)
	}
	log.Println(actorObj)
	return c.JSON(http.StatusOK, actorObj)
}

func webfinger(c echo.Context) error {
	if finger == nil {
		return c.JSON(http.StatusNotFound, `{"error": "Webfinger not found"}`)
	}
	log.Println(finger)
	return c.JSON(http.StatusOK, finger)
}

// TODO - Add func to sign and send messages to an inbox address

// TODO - Add func to accept a follow request

func inbox(c echo.Context) error {
	log.Println("Inbox accessed")
	var req map[string]interface{}
	reqBytes, err := ioutil.ReadAll(c.Request().Body)
	if err != nil {
		log.Println(err)
		return err
	}
	err = json.Unmarshal(reqBytes, &req)
	if err != nil {
		log.Println(err)
		return err
	}
	// Handle follow requests, this does not work without the signature
	if req["type"] != nil {
		if req["type"].(string) == "Follow" {
			followee := req["actor"].(string)
			req["actor"] = "https://" + c.Request().Host + "/u/test"
			req["id"] = "https://" + c.Request().Host + "/u/test"
			req["type"] = "Accept"
			req["object"] = followee
			r := resty.New()
			actorResp, err := r.R().Get(followee + ".json")
			if err != nil {
				log.Println(err)
				return err
			}
			log.Println("Actor resp: ", actorResp.Status())

			actorMap := make(map[string]interface{})
			err = json.Unmarshal(actorResp.Body(), &actorMap)
			if err != nil {
				log.Println(err)
				return err
			}

			inboxUrl := actorMap["inbox"].(string)
			inboxResp, err := r.R().SetBody(req).Post(inboxUrl)
			if err != nil {
				log.Println(err)
				return err
			}
			log.Println("Inbox resp: ", inboxResp.Status())
			log.Println(req)
		}
	}
	// log.Println(req)
	return nil
}

func main() {
	e := echo.New()
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete},
	}))
	e.GET("/.well-known/webfinger", webfinger)
	e.GET("/u/test", actor)
	e.POST("/test/inbox", inbox)
	e.POST("/u/actor", createActor)
	e.Logger.Fatal(e.Start(":8080"))
}

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

var actorObj *Actor
var finger *WebFingerResp

// createKeys returns (publickey, privatekey)
func createKeys() (rsa.PublicKey, *rsa.PrivateKey) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	pubKey := privKey.PublicKey

	return pubKey, privKey
}

func stringifyPrivateKey(privKey *rsa.PrivateKey) string {
	// Encode to string
	privatePemData := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKey),
		},
	)

	return string(privatePemData)
}

func jsonEscapePublicKey(pubKey rsa.PublicKey) string {
	// Encode to string
	publicPemData := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(&pubKey),
		},
	)
	return string(publicPemData)
}

func createActor(c echo.Context) error {
	publicKey, privateKey := createKeys()

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
				PubKeyPem: jsonEscapePublicKey(publicKey),
			},
			PrivateKey: privateKey,
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
func sendMessage(c echo.Context, actorObj *Actor, message map[string]interface{}, inbox, fromDomain string) error {
	u, err := url.Parse(inbox)
	if err != nil {
		log.Println(err)
		return err
	}
	toDomain := u.Host
	log.Println("Sending to domain: ", toDomain)

	t := time.Now().UTC().String()
	log.Println("Time: ", t)
	toSign := "(request-target): post " + u.Path + "\nhost: " + toDomain + "\ndate: " + t
	hasher := sha1.New()
	hasher.Write([]byte(toSign))
	sha := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
	log.Println(sha)
	return nil
}

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

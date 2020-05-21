package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/guid"
	"github.com/cvhariharan/ActivityPub/models"
	"github.com/go-resty/resty/v2"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/spacemonkeygo/httpsig"
)

var actorObj *models.Actor
var finger *models.WebFingerResp

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
	log.Println("Private Key: ", stringifyPrivateKey(privateKey))
	if actorObj == nil {
		// Create actor
		actorObj = &models.Actor{
			Context: []string{
				"https://www.w3.org/ns/activitystreams",
				"https://w3id.org/security/v1",
			},
			ID:                "https://" + c.Request().Host + "/u/test",
			Type:              "Person",
			PreferredUsername: "test",
			Inbox:             "https://" + c.Request().Host + "/test/inbox",
			Followers:         "https://" + c.Request().Host + "/test/followers",
			PubKey: models.PublicKey{
				ID:        "https://" + c.Request().Host + "/u/test#main-key",
				Owner:     "https://" + c.Request().Host + "/u/test",
				PubKeyPem: jsonEscapePublicKey(publicKey),
			},
			PrivateKey: privateKey,
		}

		// Create webfinger
		finger = &models.WebFingerResp{
			Subject: "acct:test@" + c.Request().Host,
			Links: []models.Link{
				models.Link{
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
func sendMessage(c echo.Context, actorObj models.Actor, message map[string]interface{}, inbox, fromDomain string) error {
	u, err := url.Parse(inbox)
	if err != nil {
		log.Println(err)
		return err
	}
	toDomain := u.Host
	log.Println("Sending to domain: ", toDomain)

	t := time.Now().UTC().Format(time.RFC1123)
	t = strings.Replace(t, "UTC", "GMT", -1)
	log.Println("Time: ", t)
	toSign := "(request-target): post " + u.Path + "\nhost: " + fromDomain + "\ndate: " + t
	signer := httpsig.NewSigner(actorObj.PubKey.ID, actorObj.PrivateKey, httpsig.RSASHA256, []string{"(request-target)", "host", "date"})
	log.Println("TO SIGN: ", toSign)
	h := sha256.New()
	h.Write([]byte(toSign))
	log.Println("SHA256 hash: ", string(h.Sum(nil)))

	requestBody, err := json.Marshal(message)
	if err != nil {
		log.Println(err)
		return err
	}
	r, err := http.NewRequest("POST", inbox, bytes.NewBuffer(requestBody))
	if err != nil {
		log.Println(err)
	}

	r.Header.Add("Content-Type", "application/activity+json")
	err = signer.Sign(r)
	if err != nil {
		log.Println(err)
		return err
	}
	sigHeader := r.Header.Get("Authorization")
	sigHeader = strings.ReplaceAll(sigHeader, "Signature", "")
	sigHeader = strings.TrimLeft(sigHeader, " ")
	log.Println("Signature NEW: ", sigHeader)
	r.Header.Set("Signature", sigHeader)
	r.Header.Del("Authorization")

	response, err := http.DefaultClient.Do(r)
	if err != nil {
		log.Println(err)
		return err
	}
	log.Println(r.Header)
	resp, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
		return err
	}
	log.Println("Send message response status: ", response.StatusCode)
	log.Println("Send message response message: ", string(resp))
	return nil
}

func sendAccept(c echo.Context, actorObj models.Actor, object interface{}, inbox, fromDomain string) error {
	id := guid.NewString()
	urlId := "https://" + fromDomain + "/" + id
	message := make(map[string]interface{})

	message["@context"] = "https://www.w3.org/ns/activitystreams"
	message["id"] = urlId
	message["type"] = "Accept"
	message["actor"] = actorObj.ID
	message["object"] = object

	return sendMessage(c, actorObj, message, inbox, fromDomain)
}

func sendNote(c echo.Context, actorObj models.Actor, note string, inbox, fromDomain string) error {
	messageId := guid.NewString()
	createId := guid.NewString()
	createUrl := "https://" + fromDomain + "/" + createId
	messageUrl := "https://" + fromDomain + "/" + messageId

	message := make(map[string]interface{})
	object := make(map[string]interface{})

	object["id"] = messageUrl
	object["type"] = "Note"
	object["published"] = time.Now().UTC().Format(time.RFC1123)
	object["attributedTo"] = actorObj.ID
	object["content"] = note
	object["to"] = []string{inbox}

	message["@context"] = "https://www.w3.org/ns/activitystreams"
	message["id"] = createUrl
	message["type"] = "Create"
	message["actor"] = actorObj.ID
	message["to"] = []string{inbox}
	message["object"] = object

	return sendMessage(c, actorObj, message, inbox, fromDomain)
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
			r := resty.New()
			actorResp, err := r.R().Get(req["actor"].(string) + ".json")
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
			err = sendAccept(c, *actorObj, req["actor"], inboxUrl, c.Request().Host)
			if err != nil {
				log.Println(err)
				return err
			}

			// Send a test note to the followee
			err = sendNote(c, *actorObj, "This is a test message", inboxUrl, c.Request().Host)
			if err != nil {
				log.Println(err)
				return err
			}
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

package models

import "crypto/rsa"

type Actor struct {
	Context           []string        `json:"@context"`
	ID                string          `json:"id"`
	Type              string          `json:"type"`
	PreferredUsername string          `json:"preferredUsername"`
	Inbox             string          `json:"inbox"`
	Followers         string          `json:"followers"`
	PubKey            PublicKey       `json:"publicKey"`
	PrivateKey        *rsa.PrivateKey `json:"-"`
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

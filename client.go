package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/codeallthethingz/secrets/model"
)

// SecretsClient for accessing the secrets server.
type SecretsClient struct {
	URL  string
	Auth string
}

// NewSecretsClient construct a secrets client.
func NewSecretsClient(url string, auth string) *SecretsClient {
	return &SecretsClient{
		URL:  url,
		Auth: auth,
	}
}

// Get Go to the server and retrieve a secret
func (s *SecretsClient) Get(name string) (*model.Secret, error) {
	secretRequest, err := json.Marshal(&model.Secret{
		Name: name,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", s.URL, bytes.NewBuffer(secretRequest))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", s.Auth)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Got non-200 response: %d, body: %s", resp.StatusCode, string(body))
	}
	var responseSecret model.Secret
	err = json.Unmarshal(body, &responseSecret)
	if err != nil {
		return nil, err
	}
	return &responseSecret, nil
}

package service

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/codeallthethingz/secrets/model"
)

var secretsLookup map[string]*model.Secret

//SecretHandler returns a secret if you're authorized
func SecretHandler(w http.ResponseWriter, r *http.Request) {
	wd, _ := os.Getwd()
	fmt.Println("CWD: " + wd)
	if secretsLookup == nil {
		err := loadSecrets()
		if err != nil {
			sendError(w, "could not load secrets from file: "+err.Error(), 500)
			return
		}
	}
	auth := r.Header.Get("Authorization")
	serviceName, err := getSecretName(r)
	if err != nil {
		sendError(w, "must send secret name {name: \"mysecret\"}", 400)
		return
	}
	if secret, ok := secretsLookup[serviceName+"_"+auth]; ok {
		data, err := json.Marshal(secret)
		if err != nil {
			sendError(w, "could not unmarshal secret: "+err.Error(), 500)
			return
		}
		w.Write(data)
	} else {
		sendError(w, "secret not found", 404)
		return
	}
}
func getSecretName(r *http.Request) (string, error) {
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return "", err
	}
	var secret model.Secret
	err = json.Unmarshal(body, &secret)
	if err != nil {
		return "", err
	}
	return secret.Name, nil
}

func sendError(w http.ResponseWriter, message string, status int) {
	w.WriteHeader(status)
	w.Write([]byte(message))
}

func loadSecrets() error {
	passphrase := os.Getenv("PASSPHRASE")
	file := os.Getenv("SECRET_FILE")
	secretsFile, err := model.LoadOrCreateSecretsFile(file, passphrase)
	if err != nil {
		return err
	}
	processSecretsFile(secretsFile)
	return nil
}

func processSecretsFile(secretsFile *model.SecretsFile) {
	secretsLookupTemp := map[string]*model.Secret{}
	for _, service := range secretsFile.Services {
		serviceName := service.Name
		serviceSecret := string(service.Secret)
		for _, secret := range secretsFile.Secrets {
			for _, access := range secret.Access {
				if access == serviceName {
					secretsLookupTemp[fmt.Sprintf("%s_%s", secret.Name, serviceSecret)] = &model.Secret{
						Name:   secret.Name,
						Secret: secret.Secret,
					}
				}
			}
		}
	}
	secretsLookup = secretsLookupTemp
}

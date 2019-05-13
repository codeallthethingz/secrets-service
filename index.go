package service

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"log"

	"github.com/codeallthethingz/secrets/model"
)

var secretsLookup map[string]*model.Secret

//SecretHandler returns a secret if you're authorized
func SecretHandler(w http.ResponseWriter, r *http.Request) {
	if secretsLookup == nil {
		err := loadSecrets()
		if err != nil {
			sendError(w, "could not load secrets from file: "+err.Error(), err, 500)
			return
		}
	}
	auth := r.Header.Get("Authorization")
	secretName, err := getSecretName(r)
	if err != nil {
		sendError(w, "must send secret name {name: \"mysecret\"}", err, 400)
		return
	}
	lastFourDigits := string(auth[len(auth)-4:])
	log.Printf("accessing secret: ****%s: %s\n", lastFourDigits, secretName)
	if secret, ok := secretsLookup[secretName+"_"+auth]; ok {
		data, err := json.Marshal(secret)
		if err != nil {
			sendError(w, "could not unmarshal secret: "+err.Error(), err, 500)
			return
		}
		w.Write(data)
	} else {
		sendError(w, "secret not found", fmt.Errorf("not found in lookup"), 404)
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

// sendError responds with a string and an error code
func sendError(w http.ResponseWriter, message string, err error, status int) {
	log.Println(err)
	w.WriteHeader(status)
	w.Write([]byte(message))
}

func loadSecrets() error {
	wd, _ := os.Getwd()
	passphrase := os.Getenv("PASSPHRASE")
	file := os.Getenv("SECRET_FILE")
	log.Println("Loading secrets from: " + wd + "/" + file)
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

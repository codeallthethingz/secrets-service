package service

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/codeallthethingz/secrets/model"
	"github.com/stretchr/testify/require"
)

func TestGetSecret(t *testing.T) {
	dir := setup()
	defer teardown(dir)
	file := dir + "/secrets.test.json"
	os.Setenv("SECRET_FILE", file)
	os.Setenv("PASSPHRASE", "sillypassphrase")
	testServer := httptest.NewServer(
		http.HandlerFunc(SecretHandler),
	)
	defer testServer.Close()

	secretsFile, err := model.LoadOrCreateSecretsFile(file, "sillypassphrase")
	if err != nil {
		panic(err)
	}
	secretsFile.Secrets = append(secretsFile.Secrets, &model.Secret{
		Name:   "secretname",
		Secret: []byte("secretvalue"),
		Access: []string{"rpm.org"},
	})
	secretsFile.Services = append(secretsFile.Services, &model.Service{
		Name:   "rpm.org",
		Secret: []byte("authcode"),
	})
	secretsFile.Save("sillypassphrase")
	secretsClient := NewSecretsClient(testServer.URL, "authcode")
	secret, err := secretsClient.Get("secretname")
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, "secretvalue", string(secret.Secret))
}

func teardown(dir string) {
	os.RemoveAll(dir)
}

func setup() string {
	dir, err := ioutil.TempDir("", "prefix")
	if err != nil {
		panic(err)
	}
	return dir
}

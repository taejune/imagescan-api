package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"github.com/genuinetools/reg/clair"
	"go.uber.org/zap"
)

type reporter struct {
	addr   string
	client *http.Client
	logger *zap.SugaredLogger
}

func NewReporter(url string, transport *http.Transport, logger *zap.SugaredLogger) *reporter {

	if url == "" || transport == nil || logger == nil {
		log.Fatal("Cannot create reporter")
		return nil
	}

	return &reporter{
		addr: url,
		client: &http.Client{
			Transport: transport,
		},
		logger: logger,
	}
}

func (c *reporter) SendReport(image string, vuls []clair.Vulnerability) error {

	index := "imgscantest"
	doc := url.QueryEscape(image)
	endpoint := fmt.Sprintf("%s/%s/_doc/%s", c.addr, index, doc)

	dat, err := json.Marshal(vuls)
	if err != nil {
		return err
	}

	c.logger.Info("POST vulnerability report", zap.String("url", endpoint))
	response, err := c.client.Post(endpoint, "application/json", bytes.NewReader(dat))
	if err != nil {
		fmt.Println(err)
		return err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer response.Body.Close()

	c.logger.Info("POST vulerability report response", zap.Int("statusCode", response.StatusCode), zap.String("body", string(body)))
	if response.StatusCode >= 400 && response.StatusCode < 600 {
		return fmt.Errorf(fmt.Sprintf("ES server respond with %d(%s)\n", response.StatusCode, body))
	}

	return nil
}

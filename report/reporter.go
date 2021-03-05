package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/genuinetools/reg/clair"
)

type reporter struct {
	addr   string
	client *http.Client
}

func NewReporter(url string, transport *http.Transport) *reporter {

	return &reporter{
		addr: url,
		client: &http.Client{
			Transport: transport,
		},
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

	if response.StatusCode >= 400 && response.StatusCode < 600 {
		return fmt.Errorf(fmt.Sprintf("ES server respond with %d(%s)\n", response.StatusCode, body))
	}

	return nil
}

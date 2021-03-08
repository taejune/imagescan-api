package store

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

type Store struct {
	addr   string
	client *http.Client
	logger *zap.SugaredLogger
}

func NewStore(url string, transport *http.Transport, logger *zap.SugaredLogger) *Store {

	if url == "" || transport == nil || logger == nil {
		log.Fatal("Cannot create Store")
		return nil
	}

	return &Store{
		addr: url,
		client: &http.Client{
			Transport: transport,
		},
		logger: logger,
	}
}

func (s *Store) Get(image string) error {

	index := "imgscantest"
	doc := url.QueryEscape(image)
	endpoint := fmt.Sprintf("%s/%s/_doc/%s", s.addr, index, doc)

	s.logger.Info("GET vulnerability report", zap.String("url", endpoint))

	// FIXME: Change to use transport.RoundTrip()
	response, err := s.client.Get(endpoint)
	if err != nil {
		s.logger.Error(err)
		return err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		s.logger.Error(err)
		return err
	}
	defer response.Body.Close()

	if response.StatusCode >= 400 && response.StatusCode < 600 {
		s.logger.Error("Failed to get report" + err.Error())
		return fmt.Errorf(fmt.Sprintf("ES server respond with %d(%s)\n", response.StatusCode, body))
	}

	s.logger.Info("GET report success", zap.Int("statusCode", response.StatusCode), zap.String("body", string(body)))
	return nil
}

func (s *Store) Save(image string, vuls []clair.Vulnerability) error {

	index := "imgscantest"
	doc := url.QueryEscape(image)
	endpoint := fmt.Sprintf("%s/%s/_doc/%s", s.addr, index, doc)

	dat, err := json.Marshal(vuls)
	if err != nil {
		s.logger.Error(err)
		return err
	}

	s.logger.Info("POST vulnerability report", zap.String("url", endpoint), zap.String("body", string(dat)))
	// FIXME: Change to use transport.RoundTrip()
	response, err := s.client.Post(endpoint, "application/json", bytes.NewReader(dat))
	if err != nil {
		s.logger.Error(err)
		return err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		s.logger.Error(err)
		return err
	}
	defer response.Body.Close()

	if response.StatusCode >= 300 {
		s.logger.Error(err.Error())
		return fmt.Errorf(fmt.Sprintf("ES server respond with %d(%s)\n", response.StatusCode, body))
	}

	s.logger.Info("Sending report success", zap.Int("statusCode", response.StatusCode), zap.String("body", string(body)))
	return nil
}

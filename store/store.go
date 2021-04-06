package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

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
		logger: logger.Named("store"),
	}
}

type esResponse struct {
	Index   string                 `json:"_index"`
	Id      string                 `json:"_id"`
	Version int                    `json:"_ind_versionex"`
	Score   int                    `json:"_score"`
	Type    string                 `json:"_type"`
	Found   bool                   `json:"found"`
	Source  map[string]interface{} `json:"_source"`
}

func (s *Store) Exist(digest string) (bool, error) {
	index := "imgscantest"
	doc := url.PathEscape(digest)
	endpoint := fmt.Sprintf("%s/%s/_doc/%s", s.addr, index, doc)

	s.logger.Infow("get", "url", endpoint)

	response, err := s.client.Get(endpoint)
	if err != nil {
		s.logger.Error(err)
		return false, err
	}
	if response.StatusCode >= 300 {
		s.logger.Errorw("error response from server", "url", endpoint, "status", response.StatusCode)
		return false, err
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		s.logger.Error(err)
		return false, err
	}
	defer response.Body.Close()
	var dat esResponse
	err = json.Unmarshal(body, &dat)
	if err != nil {
		s.logger.Error(err)
		return false, err
	}

	return dat.Found, nil
}

func (s *Store) Get(digest string) (map[string]interface{}, error) {
	index := "imgscantest"
	doc := url.PathEscape(digest)
	endpoint := fmt.Sprintf("%s/%s/_doc/%s", s.addr, index, doc)

	s.logger.Infow("get", "url", endpoint)

	response, err := s.client.Get(endpoint)
	if err != nil {
		s.logger.Error(err)
		return nil, err
	}
	if response.StatusCode >= 300 {
		s.logger.Errorw("error response from server", "url", endpoint, "status", response.StatusCode)
		return nil, err
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		s.logger.Error(err)
		return nil, err
	}
	defer response.Body.Close()

	var dat esResponse
	err = json.Unmarshal(body, &dat)
	if err != nil {
		s.logger.Error(err)
		return nil, err
	}

	return dat.Source, nil
}

func (s *Store) Save(digest string, data []byte) error {
	index := "imgscantest"
	doc := url.PathEscape(digest)
	endpoint := fmt.Sprintf("%s/%s/_doc/%s", s.addr, index, doc)

	s.logger.Infow("post", "url", endpoint)

	response, err := s.client.Post(endpoint, "application/json", bytes.NewReader(data))
	if err != nil {
		s.logger.Errorw("failed to post request", "url", endpoint, "msg", err)
		return err
	}
	if response.StatusCode >= 300 {
		s.logger.Errorw("error response from server", "url", endpoint, "status", response.StatusCode)
		return err
	}
	_, err = ioutil.ReadAll(response.Body)
	if err != nil {
		s.logger.Errorw("failed to read response body", "error", err)
		return err
	}
	defer response.Body.Close()

	return nil
}

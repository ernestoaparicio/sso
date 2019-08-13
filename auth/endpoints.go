package auth

import (
	"context"
	"encoding/json"
	"github.com/go-kit/kit/endpoint"
	httptransport "github.com/go-kit/kit/transport/http"
	"net/http"
	"net/url"
	"strings"
)

type Endpoints struct {
	AuthenticateEndpoint endpoint.Endpoint
}

func MakeServerEndpoints(s Service) Endpoints {
	return Endpoints{AuthenticateEndpoint: MakeAuthenticateEndpoint(s)}
}

func MakeClientEndpoints(instance string) (Endpoints, error) {
	if !strings.HasPrefix(instance, "http") {
		instance = "http://" + instance
	}
	tgt, err := url.Parse(instance)
	if err != nil {
		return Endpoints{}, err
	}
	tgt.Path = ""

	options := []httptransport.ClientOption{}

	return Endpoints{
		AuthenticateEndpoint: httptransport.NewClient("POST", tgt, encodeAuthenticateRequest, decodeAuthenticateResponse, options...).Endpoint(),
	}, nil
}

func MakeAuthenticateEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(authenticateRequest)
		token, err := s.Authenticate(ctx, req.User)
		return authenticateResponse{
			AuthToken: token,
			Err:       err,
		}, nil
	}

}

type authenticateRequest struct {
	User User
}

type authenticateResponse struct {
	AuthToken Token `json:"authtoken"`
	Err       error `json:"err,omitempty"`
}

func encodeAuthenticateRequest(ctx context.Context, req *http.Request, request interface{}) error {
	req.URL.Path = "/authenticate/"
	return encodeRequest(ctx, req, request)
}

func decodeAuthenticateResponse(_ context.Context, resp *http.Response) (interface{}, error) {
	var response authenticateResponse
	err := json.NewDecoder(resp.Body).Decode(&response)
	return response, err
}

func (e Endpoints) Authenticate(ctx context.Context, u User) error {
	request := authenticateRequest{User: u}
	response, err := e.AuthenticateEndpoint(ctx, request)
	if err != nil {
		return err
	}
	resp := response.(authenticateResponse)
	return resp.Err
}

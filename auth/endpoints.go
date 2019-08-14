package auth

import (
	"context"
	"github.com/go-kit/kit/endpoint"
)

type Endpoints struct {
	AuthenticateEndpoint endpoint.Endpoint
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

func MakeServerEndpoints(s Service) Endpoints {
	return Endpoints{AuthenticateEndpoint: MakeAuthenticateEndpoint(s)}
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

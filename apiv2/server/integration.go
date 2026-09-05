package apiv2

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"
	"gorm.io/gorm"

	e "github.com/TUM-Dev/gocast/apiv2/errors"
	protobuf "github.com/TUM-Dev/gocast/apiv2/protobuf/server"
)

func (a *API) GetIntegration(ctx context.Context, _ *emptypb.Empty) (*protobuf.GetIntegrationResponse, error) {
	integration, err := a.getCurrentIntegration(ctx)
	if err != nil {
		return nil, err
	}
	return &protobuf.GetIntegrationResponse{
		Id:        uint32(integration.ID),
		Name:      integration.Name,
		ReturnUrl: integration.ReturnURL,
	}, nil
}

func (a *API) RedeemIntegrationAuthorization(ctx context.Context, req *protobuf.RedeemIntegrationAuthorizationRequest) (*protobuf.RedeemIntegrationAuthorizationResponse, error) {
	codeHash, codeOK := authorizationValueHash(req.GetCode())
	stateHash, stateOK := authorizationValueHash(req.GetState())
	if !codeOK || !stateOK {
		return nil, e.WithStatus(http.StatusBadRequest, errors.New("code and state must encode 32 bytes as unpadded base64url"))
	}
	integration, err := a.getCurrentIntegration(ctx)
	if err != nil {
		return nil, err
	}
	grantID, courseID, err := a.dao.IntegrationGrantDao.RedeemIntegrationAuthorizationCode(ctx, integration.ID, codeHash, stateHash, time.Now())
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, e.WithStatus(http.StatusNotFound, errors.New("authorization not found"))
	}
	if err != nil {
		a.log.Error("integration authorization redemption failed", "err", err)
		return nil, e.WithStatus(http.StatusInternalServerError, errors.New("could not redeem authorization"))
	}
	return &protobuf.RedeemIntegrationAuthorizationResponse{GrantId: uint32(grantID), CourseId: uint32(courseID)}, nil
}

func (a *API) GetIntegrationGrant(ctx context.Context, req *protobuf.GetIntegrationGrantRequest) (*protobuf.GetIntegrationGrantResponse, error) {
	if req.GetGrantId() == 0 {
		return nil, e.WithStatus(http.StatusBadRequest, errors.New("grant_id must be positive"))
	}
	integration, err := a.getCurrentIntegration(ctx)
	if err != nil {
		return nil, err
	}
	course, err := a.dao.IntegrationGrantDao.GetIntegrationGrantCourse(ctx, uint(req.GetGrantId()), integration.ID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, e.WithStatus(http.StatusNotFound, errors.New("grant not found"))
	}
	if err != nil {
		a.log.Error("integration grant lookup failed", "err", err)
		return nil, e.WithStatus(http.StatusInternalServerError, errors.New("could not read integration grant"))
	}
	return &protobuf.GetIntegrationGrantResponse{
		CourseId: uint32(course.ID), Name: course.Name, Slug: course.Slug, Visibility: course.Visibility,
	}, nil
}

func authorizationValueHash(value string) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != sha256.Size || base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, false
	}
	hash := sha256.Sum256(raw)
	return hash[:], true
}

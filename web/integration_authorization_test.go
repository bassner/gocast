package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"gorm.io/gorm"

	"github.com/TUM-Dev/gocast/dao"
	"github.com/TUM-Dev/gocast/mock_dao"
	"github.com/TUM-Dev/gocast/model"
	"github.com/TUM-Dev/gocast/tools"
)

type authorizationTemplateCapture struct {
	authorization *integrationAuthorizationData
	admin         *AdminPageData
	error         *tools.ErrorPageData
}

func (c *authorizationTemplateCapture) ExecuteTemplate(_ io.Writer, name string, data interface{}) error {
	switch name {
	case "integration-authorization.gohtml":
		value := data.(integrationAuthorizationData)
		c.authorization = &value
	case "admin.gohtml":
		value := data.(AdminPageData)
		c.admin = &value
	case "error.gohtml":
		value := data.(tools.ErrorPageData)
		c.error = &value
	}
	return nil
}

func authorizationState(fill byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func serveAuthorization(t *testing.T, integrationGrantDao dao.IntegrationGrantDao, user *model.User, method, target string, form url.Values) (*httptest.ResponseRecorder, *authorizationTemplateCapture) {
	t.Helper()
	capture := &authorizationTemplateCapture{}
	previousTemplateExecutor := templateExecutor
	templateExecutor = capture
	t.Cleanup(func() { templateExecutor = previousTemplateExecutor })
	tools.SetTemplateExecutor(capture)
	router := gin.New()
	router.Use(func(c *gin.Context) { c.Set("TUMLiveContext", tools.TUMLiveContext{User: user}) })
	loggedIn := router.Group("/")
	loggedIn.Use(tools.LoggedIn)
	routes := mainRoutes{DaoWrapper: dao.DaoWrapper{IntegrationGrantDao: integrationGrantDao}}
	loggedIn.GET("/integration/authorize/:id", routes.integrationAuthorizationPage)
	loggedIn.POST("/integration/authorize/:id", routes.authorizeIntegration)
	loggedIn.POST("/admin/course/:courseID/integrations/:grantID/revoke", routes.revokeCourseIntegration)
	var body io.Reader
	if form != nil {
		body = bytes.NewBufferString(form.Encode())
	}
	request := httptest.NewRequest(method, target, body)
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder, capture
}

func TestIntegrationAuthorizationPage(t *testing.T) {
	ctrl := gomock.NewController(t)
	integrationGrantDao := mock_dao.NewMockIntegrationGrantDao(ctrl)
	integration := model.Integration{ID: 7, Name: "Course portal"}
	courses := []model.Course{{Model: gorm.Model{ID: 11}, Name: "Example course"}}
	integrationGrantDao.EXPECT().GetIntegrationByID(gomock.Any(), uint(7)).Return(integration, nil)
	integrationGrantDao.EXPECT().GetAuthorizableCourses(gomock.Any(), uint(1)).Return(courses, nil)
	user := &model.User{Model: gorm.Model{ID: 1}, Role: model.LecturerType}
	state := authorizationState(1)

	recorder, capture := serveAuthorization(t, integrationGrantDao, user, http.MethodGet, "/integration/authorize/7?state="+state, nil)

	assert.Equal(t, http.StatusOK, recorder.Code)
	require.NotNil(t, capture.authorization)
	assert.Equal(t, integration, capture.authorization.Integration)
	assert.Equal(t, courses, capture.authorization.Courses)
	assert.Equal(t, state, capture.authorization.State)
}

func TestIntegrationAuthorizationApprovesOnlyOwnerOrDelegate(t *testing.T) {
	state := authorizationState(3)
	course := model.Course{
		UserID: 1,
		Admins: []model.User{{Model: gorm.Model{ID: 2}}},
	}
	for _, test := range []struct {
		name    string
		userID  uint
		role    uint
		allowed bool
	}{
		{name: "owner", userID: 1, role: model.LecturerType, allowed: true},
		{name: "delegate", userID: 2, role: model.LecturerType, allowed: true},
		{name: "outsider", userID: 3, role: model.LecturerType},
		{name: "instance admin without course grant", userID: 4, role: model.AdminType},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			integrationGrantDao := mock_dao.NewMockIntegrationGrantDao(ctrl)
			integration := model.Integration{ID: 7, ReturnURL: "https://client.example/callback?existing=1"}
			integrationGrantDao.EXPECT().GetIntegrationByID(gomock.Any(), uint(7)).Return(integration, nil)
			integrationGrantDao.EXPECT().GetCourseForAuthorization(gomock.Any(), uint(11)).Return(course, nil)
			var codeHash, stateHash []byte
			var expiresAt time.Time
			if test.allowed {
				integrationGrantDao.EXPECT().ApproveIntegrationCourse(gomock.Any(), uint(7), uint(11), gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, _, _ uint, gotCodeHash, gotStateHash []byte, gotExpiresAt time.Time) (uint, error) {
						codeHash = bytes.Clone(gotCodeHash)
						stateHash = bytes.Clone(gotStateHash)
						expiresAt = gotExpiresAt
						return 19, nil
					})
			}
			user := &model.User{Model: gorm.Model{ID: test.userID}, Role: test.role}
			form := url.Values{"state": {state}, "decision": {"approve"}, "course_id": {"11"}}

			recorder, capture := serveAuthorization(t, integrationGrantDao, user, http.MethodPost, "/integration/authorize/7", form)

			if !test.allowed {
				assert.Equal(t, http.StatusForbidden, recorder.Code)
				require.NotNil(t, capture.error)
				return
			}
			assert.Equal(t, http.StatusFound, recorder.Code)
			location, err := url.Parse(recorder.Header().Get("Location"))
			require.NoError(t, err)
			code, err := base64.RawURLEncoding.DecodeString(location.Query().Get("code"))
			require.NoError(t, err)
			wantCodeHash := sha256.Sum256(code)
			wantStateHash := sha256.Sum256(bytes.Repeat([]byte{3}, 32))
			assert.Len(t, code, 32)
			assert.Equal(t, wantCodeHash[:], codeHash)
			assert.Equal(t, wantStateHash[:], stateHash)
			assert.WithinDuration(t, time.Now().Add(integrationCodeLifetime), expiresAt, 2*time.Second)
			assert.Equal(t, state, location.Query().Get("state"))
			assert.Equal(t, "1", location.Query().Get("existing"))
		})
	}
}

func TestIntegrationAuthorizationRejectsInvalidStateBeforeWrites(t *testing.T) {
	ctrl := gomock.NewController(t)
	user := &model.User{Model: gorm.Model{ID: 1}, Role: model.LecturerType}
	recorder, capture := serveAuthorization(t, mock_dao.NewMockIntegrationGrantDao(ctrl), user, http.MethodPost, "/integration/authorize/7", url.Values{
		"state": {"short"}, "decision": {"approve"}, "course_id": {"11"},
	})

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	require.NotNil(t, capture.error)
}

func TestIntegrationAuthorizationCancelDoesNotPersist(t *testing.T) {
	ctrl := gomock.NewController(t)
	integrationGrantDao := mock_dao.NewMockIntegrationGrantDao(ctrl)
	integrationGrantDao.EXPECT().GetIntegrationByID(gomock.Any(), uint(7)).Return(model.Integration{
		ID: 7, ReturnURL: "https://client.example/callback",
	}, nil)
	state := authorizationState(6)
	user := &model.User{Model: gorm.Model{ID: 1}}

	recorder, _ := serveAuthorization(t, integrationGrantDao, user, http.MethodPost, "/integration/authorize/7", url.Values{
		"state": {state}, "decision": {"cancel"},
	})

	assert.Equal(t, http.StatusFound, recorder.Code)
	location, err := url.Parse(recorder.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "access_denied", location.Query().Get("error"))
	assert.Equal(t, state, location.Query().Get("state"))
	assert.Empty(t, location.Query().Get("code"))
}

func TestCourseIntegrationRevocationRechecksCourseAuthority(t *testing.T) {
	course := model.Course{UserID: 1, Admins: []model.User{{Model: gorm.Model{ID: 2}}}}
	for _, test := range []struct {
		name    string
		userID  uint
		role    uint
		allowed bool
	}{
		{"owner", 1, model.LecturerType, true},
		{"delegate", 2, model.LecturerType, true},
		{"outsider", 3, model.LecturerType, false},
		{"instance admin without course grant", 4, model.AdminType, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			integrationGrantDao := mock_dao.NewMockIntegrationGrantDao(ctrl)
			integrationGrantDao.EXPECT().GetCourseForAuthorization(gomock.Any(), uint(11)).Return(course, nil)
			if test.allowed {
				integrationGrantDao.EXPECT().RevokeIntegrationGrant(gomock.Any(), uint(23), uint(11)).Return(nil)
			}
			user := &model.User{Model: gorm.Model{ID: test.userID}, Role: test.role}

			recorder, _ := serveAuthorization(t, integrationGrantDao, user, http.MethodPost, "/admin/course/11/integrations/23/revoke", nil)

			if test.allowed {
				assert.Equal(t, http.StatusFound, recorder.Code)
			} else {
				assert.Equal(t, http.StatusForbidden, recorder.Code)
			}
		})
	}
}

func TestIntegrationAuthorizationReportsDaoErrors(t *testing.T) {
	t.Run("approval", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		integrationGrantDao := mock_dao.NewMockIntegrationGrantDao(ctrl)
		integrationGrantDao.EXPECT().GetIntegrationByID(gomock.Any(), uint(7)).Return(model.Integration{ID: 7}, nil)
		integrationGrantDao.EXPECT().GetCourseForAuthorization(gomock.Any(), uint(11)).Return(model.Course{UserID: 1}, nil)
		integrationGrantDao.EXPECT().ApproveIntegrationCourse(gomock.Any(), uint(7), uint(11), gomock.Any(), gomock.Any(), gomock.Any()).Return(uint(0), errors.New("write failed"))
		user := &model.User{Model: gorm.Model{ID: 1}}

		recorder, capture := serveAuthorization(t, integrationGrantDao, user, http.MethodPost, "/integration/authorize/7", url.Values{
			"state": {authorizationState(10)}, "decision": {"approve"}, "course_id": {"11"},
		})

		assert.Equal(t, http.StatusInternalServerError, recorder.Code)
		require.NotNil(t, capture.error)
	})

	t.Run("revocation not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		integrationGrantDao := mock_dao.NewMockIntegrationGrantDao(ctrl)
		integrationGrantDao.EXPECT().GetCourseForAuthorization(gomock.Any(), uint(11)).Return(model.Course{UserID: 1}, nil)
		integrationGrantDao.EXPECT().RevokeIntegrationGrant(gomock.Any(), uint(23), uint(11)).Return(gorm.ErrRecordNotFound)
		user := &model.User{Model: gorm.Model{ID: 1}}

		recorder, capture := serveAuthorization(t, integrationGrantDao, user, http.MethodPost, "/admin/course/11/integrations/23/revoke", nil)

		assert.Equal(t, http.StatusNotFound, recorder.Code)
		require.NotNil(t, capture.error)
	})
}

func TestCourseIntegrationListFailureStaysVisible(t *testing.T) {
	ctrl := gomock.NewController(t)
	course := &model.Course{Model: gorm.Model{ID: 11}, UserID: 1}
	user := &model.User{Model: gorm.Model{ID: 1}, Role: model.LecturerType}
	coursesDao := mock_dao.NewMockCoursesDao(ctrl)
	coursesDao.EXPECT().GetInvitedUsersForCourse(course).Return(nil)
	coursesDao.EXPECT().GetAdministeredCoursesByUserId(gomock.Any(), uint(1), "", 0).Return([]model.Course{*course}, nil)
	coursesDao.EXPECT().GetAvailableSemesters(gomock.Any(), true).Return(nil)
	lectureHallsDao := mock_dao.NewMockLectureHallsDao(ctrl)
	lectureHallsDao.EXPECT().GetAllLectureHalls().Return(nil)
	integrationGrantDao := mock_dao.NewMockIntegrationGrantDao(ctrl)
	integrationGrantDao.EXPECT().GetCourseForAuthorization(gomock.Any(), uint(11)).Return(*course, nil)
	integrationGrantDao.EXPECT().GetCourseIntegrationGrants(gomock.Any(), uint(11)).Return(nil, errors.New("read failed"))
	capture := &authorizationTemplateCapture{}
	previousTemplateExecutor := templateExecutor
	templateExecutor = capture
	t.Cleanup(func() { templateExecutor = previousTemplateExecutor })
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/admin/course/11", nil)
	c.Set("TUMLiveContext", tools.TUMLiveContext{User: user, Course: course})
	routes := mainRoutes{DaoWrapper: dao.DaoWrapper{
		CoursesDao: coursesDao, LectureHallsDao: lectureHallsDao, IntegrationGrantDao: integrationGrantDao,
	}}

	routes.EditCoursePage(c)

	require.NotNil(t, capture.admin)
	data := capture.admin.EditCourseData.CourseIntegrations
	assert.True(t, data.CanManage)
	assert.NotEmpty(t, data.Error)
}

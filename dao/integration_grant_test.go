package dao

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"github.com/TUM-Dev/gocast/model"
)

func TestRedeemIntegrationAuthorizationCodeIsAtomicAndRequiresLiveGrant(t *testing.T) {
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN is not set")
	}
	prefix := fmt.Sprintf("g04_%d_", time.Now().UnixNano())
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{NamingStrategy: schema.NamingStrategy{TablePrefix: prefix}})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&model.Integration{}, &model.IntegrationGrant{}, &model.IntegrationAuthorizationCode{}))
	t.Cleanup(func() {
		_ = db.Migrator().DropTable(&model.IntegrationAuthorizationCode{}, &model.IntegrationGrant{}, &model.Integration{})
	})
	require.NoError(t, db.Create(&model.Integration{ID: 7, Name: "Test integration", ReturnURL: "https://example.invalid/callback"}).Error)
	redeemer := integrationGrantDao{db: db}
	now := time.Now()
	seed := func(code byte, revoked bool) ([]byte, []byte) {
		grant := model.IntegrationGrant{IntegrationID: 7, CourseID: 456, CreatedAt: now}
		if revoked {
			grant.RevokedAt = &now
		}
		require.NoError(t, db.Create(&grant).Error)
		codeHash, stateHash := bytes.Repeat([]byte{code}, 32), bytes.Repeat([]byte{9}, 32)
		require.NoError(t, db.Create(&model.IntegrationAuthorizationCode{
			CodeHash: codeHash, StateHash: stateHash, IntegrationID: 7,
			GrantID: grant.ID, ExpiresAt: now.Add(time.Minute),
		}).Error)
		return codeHash, stateHash
	}

	codeHash, stateHash := seed(1, false)
	_, _, err = redeemer.RedeemIntegrationAuthorizationCode(context.Background(), 7, codeHash, bytes.Repeat([]byte{8}, 32), now)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)
	grantID, courseID, err := redeemer.RedeemIntegrationAuthorizationCode(context.Background(), 7, codeHash, stateHash, now)
	require.NoError(t, err)
	require.NotZero(t, grantID)
	require.Equal(t, uint(456), courseID)
	_, _, err = redeemer.RedeemIntegrationAuthorizationCode(context.Background(), 7, codeHash, stateHash, now)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)

	revokedCode, revokedState := seed(2, true)
	_, _, err = redeemer.RedeemIntegrationAuthorizationCode(context.Background(), 7, revokedCode, revokedState, now)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)

	concurrentCode, concurrentState := seed(3, false)
	start, results := make(chan struct{}), make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, _, redeemErr := redeemer.RedeemIntegrationAuthorizationCode(context.Background(), 7, concurrentCode, concurrentState, now)
			results <- redeemErr
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	var successes, missing int
	for result := range results {
		if result == nil {
			successes++
		} else if errors.Is(result, gorm.ErrRecordNotFound) {
			missing++
		}
	}
	require.Equal(t, 1, successes)
	require.Equal(t, 1, missing)
}

package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestJWTCreateAndValidate_Success(t *testing.T) {
	userID := uuid.New()
	secret := "my_secret_key"
	expiresIn := time.Minute * 5

	// Create JWT
	token, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("failed to create JWT: %v", err)
	}

	// Validate JWT
	parsedID, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("failed to validate JWT: %v", err)
	}

	if parsedID != userID {
		t.Errorf("expected userID %v, got %v", userID, parsedID)
	}
}

func TestJWT_ExpiredToken(t *testing.T) {
	userID := uuid.New()
	secret := "my_secret_key"

	// Create JWT with expiration in the past
	token, err := MakeJWT(userID, secret, -time.Minute)
	if err != nil {
		t.Fatalf("failed to create JWT: %v", err)
	}

	// Validate JWT - should fail
	_, err = ValidateJWT(token, secret)
	if err == nil {
		t.Error("expected error for expired token, got nil")
	}
}

func TestJWT_InvalidSignature(t *testing.T) {
	userID := uuid.New()
	secret := "correct_secret"
	wrongSecret := "wrong_secret"

	// Create JWT with correct secret
	token, err := MakeJWT(userID, secret, time.Minute*5)
	if err != nil {
		t.Fatalf("failed to create JWT: %v", err)
	}

	// Validate JWT with wrong secret - should fail
	_, err = ValidateJWT(token, wrongSecret)
	if err == nil {
		t.Error("expected error for token with invalid signature, got nil")
	}
}

func TestGetBearerToken(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    string
		wantErr bool
	}{
		{
			name:    "valid token",
			headers: http.Header{"Authorization": []string{"Bearer abc123"}},
			want:    "abc123",
			wantErr: false,
		},
		{
			name:    "missing header",
			headers: http.Header{},
			wantErr: true,
		},
		{
			name:    "wrong prefix",
			headers: http.Header{"Authorization": []string{"Token abc123"}},
			wantErr: true,
		},
		{
			name:    "empty token",
			headers: http.Header{"Authorization": []string{"Bearer "}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetBearerToken(tt.headers)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got = %q, want %q", got, tt.want)
			}
		})
	}
}

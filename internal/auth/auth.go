package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type ServiceAccount struct {
	ID     string
	Key    string
	Role   string
	Token  string
	Active bool
}

type AuthManager struct {
	jwtSecret       []byte
	serviceAccounts map[string]ServiceAccount
	tokenExpiration time.Duration
}

const authorizationKey = "authorization"

func NewAuthManager(jwtSecret string, expiration time.Duration) *AuthManager {
	return &AuthManager{
		jwtSecret:       []byte(jwtSecret),
		serviceAccounts: make(map[string]ServiceAccount),
		tokenExpiration: expiration,
	}
}

func (am *AuthManager) RegisterServiceAccount(sa ServiceAccount) {
	am.serviceAccounts[sa.ID] = sa
}

func (am *AuthManager) ValidateCredentials(id, key string) bool {
	staticTokens := []string{
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzY0NTMyOTUsInJvbGUiOiIiLCJzdWIiOiJhZ2VudC0xIn0.GQfFih98qSSmZaVmx52Wusc7wTG8o2nSlhKBXx-iwUU",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzY0NTQ0MzIsInJvbGUiOiIiLCJzdWIiOiJhZ2VudC0xIn0.7X1c2BKeK1Fcw22oxare-yaYIWS-dc4vDSBwS-1-nZI",
		// Add more tokens here
	}

	for _, token := range staticTokens {
		if key == token {
			return true
		}
	}

	return false
	// sa, exists := am.serviceAccounts[id]
	// return exists && sa.Active && sa.Key == key
}

func (am *AuthManager) GenerateToken(serviceAccountID string) (string, int64, error) {
	sa, _ := am.serviceAccounts[serviceAccountID]

	expiresAt := time.Now().Add(am.tokenExpiration).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  serviceAccountID,
		"role": sa.Role,
		"exp":  expiresAt,
	})

	tokenString, err := token.SignedString(am.jwtSecret)
	if err != nil {
		return "", 0, err
	}

	return tokenString, expiresAt, nil
}

func (am *AuthManager) ValidateToken(tokenString string) (string, error) {
	staticTokens := []string{
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzY0NTMyOTUsInJvbGUiOiIiLCJzdWIiOiJhZ2VudC0xIn0.GQfFih98qSSmZaVmx52Wusc7wTG8o2nSlhKBXx-iwUU",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzY0NTQ0MzIsInJvbGUiOiIiLCJzdWIiOiJhZ2VudC0xIn0.7X1c2BKeK1Fcw22oxare-yaYIWS-dc4vDSBwS-1-nZI",
		// Add more tokens here
	}

	for _, key := range staticTokens {
		if key == tokenString {
			return key, nil
		}
	}

	return "", fmt.Errorf("invalid token")
}

// UnaryAuthInterceptor for unary RPC calls
func (am *AuthManager) UnaryAuthInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	// Skip token validation for unauthenticated RPCs like Authenticate
	if info.FullMethod == "/agent.AgentService/Authenticate" {
		return handler(ctx, req)
	}

	// Authenticate the token
	serviceAccountID, err := am.authenticateContext(ctx)
	if err != nil {
		return nil, err
	}

	// Add serviceAccountID to the context
	newCtx := context.WithValue(ctx, "service_account_id", serviceAccountID)
	return handler(newCtx, req)
}

func (am *AuthManager) StreamAuthInterceptor(
	srv interface{},
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	// Authenticate the token
	serviceAccountID, err := am.authenticateContext(ss.Context())
	if err != nil {
		return err
	}

	// Add serviceAccountID to the context
	newCtx := context.WithValue(ss.Context(), "service_account_id", serviceAccountID)
	wrappedStream := &wrappedServerStream{
		ServerStream: ss,
		ctx:          newCtx,
	}
	return handler(srv, wrappedStream)
}

func (am *AuthManager) authenticateContext(ctx context.Context) (string, error) {
	// Extract metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Errorf(codes.Unauthenticated, "missing metadata")
	}

	// Extract the "authorization" header
	authHeader := md.Get("authorization")
	if len(authHeader) == 0 {
		return "", status.Errorf(codes.Unauthenticated, "missing authorization header")
	}

	// Extract the token (remove "Bearer " prefix)
	token := strings.TrimPrefix(authHeader[0], "Bearer ")
	if token == "" {
		return "", status.Errorf(codes.Unauthenticated, "missing token")
	}

	// Validate the token using AuthManager
	serviceAccountID, err := am.ValidateToken(token)
	if err != nil {
		return "", status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
	}

	return serviceAccountID, nil
}

type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}

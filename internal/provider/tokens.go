package provider

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// refreshMargin renews a token this long before it expires.
const refreshMargin = 2 * time.Minute

// defaultTokenLifetime is used when a token carries no readable exp claim.
const defaultTokenLifetime = 5 * time.Minute

type fetchFunc func(ctx context.Context) (token string, expiry time.Time, err error)

// cachingTokenSource implements eurodns.TokenSource and refetches the token
// shortly before it expires.
type cachingTokenSource struct {
	fetch  fetchFunc
	now    func() time.Time
	mu     sync.Mutex
	token  string
	expiry time.Time
}

func newCachingTokenSource(f fetchFunc) *cachingTokenSource {
	return &cachingTokenSource{fetch: f, now: time.Now}
}

func (c *cachingTokenSource) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && c.now().Add(refreshMargin).Before(c.expiry) {
		return c.token, nil
	}
	tok, exp, err := c.fetch(ctx)
	if err != nil {
		return "", err
	}
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return "", errors.New("empty token")
	}
	if exp.IsZero() {
		exp = jwtExpiry(tok)
	}
	if exp.IsZero() {
		exp = c.now().Add(defaultTokenLifetime)
	}
	c.token, c.expiry = tok, exp
	return tok, nil
}

// jwtExpiry reads the exp claim without verifying the signature (the gate
// verifies it); zero if the token is not a readable JWT.
func jwtExpiry(tok string) time.Time {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}
	}
	var claims struct {
		Exp json.Number `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}
	}
	sec, err := claims.Exp.Int64()
	if err != nil || sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}

type staticTokenSource string

func (s staticTokenSource) Token(context.Context) (string, error) { return string(s), nil }

func fileTokenFetch(path string) fetchFunc {
	return func(context.Context) (string, time.Time, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("read token file: %w", err)
		}
		return string(b), time.Time{}, nil
	}
}

func commandTokenFetch(argv []string) fetchFunc {
	return func(ctx context.Context) (string, time.Time, error) {
		var stdout, stderr bytes.Buffer
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			return "", time.Time{}, fmt.Errorf("token command %q: %w: %s", argv[0], err, strings.TrimSpace(stderr.String()))
		}
		return stdout.String(), time.Time{}, nil
	}
}

type awsWebIdentityConfig struct {
	Audience         string
	SigningAlgorithm string
	Region           string
	DurationSeconds  int32
}

// stsTokenAPI is the subset of the STS client used, for tests.
type stsTokenAPI interface {
	GetWebIdentityToken(ctx context.Context, in *sts.GetWebIdentityTokenInput, opts ...func(*sts.Options)) (*sts.GetWebIdentityTokenOutput, error)
}

// awsWebIdentityFetch obtains a JWT signed by AWS STS (IAM outbound identity
// federation) for the current AWS principal.
func awsWebIdentityFetch(cfg awsWebIdentityConfig, newClient func(ctx context.Context) (stsTokenAPI, error)) fetchFunc {
	var (
		once      sync.Once
		client    stsTokenAPI
		clientErr error
	)
	return func(ctx context.Context) (string, time.Time, error) {
		once.Do(func() { client, clientErr = newClient(ctx) })
		if clientErr != nil {
			return "", time.Time{}, clientErr
		}
		in := &sts.GetWebIdentityTokenInput{
			Audience:         []string{cfg.Audience},
			SigningAlgorithm: aws.String(cfg.SigningAlgorithm),
		}
		if cfg.DurationSeconds > 0 {
			in.DurationSeconds = aws.Int32(cfg.DurationSeconds)
		}
		out, err := client.GetWebIdentityToken(ctx, in)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("sts:GetWebIdentityToken: %w", err)
		}
		if out.WebIdentityToken == nil {
			return "", time.Time{}, errors.New("sts:GetWebIdentityToken returned no token")
		}
		var exp time.Time
		if out.Expiration != nil {
			exp = *out.Expiration
		}
		return *out.WebIdentityToken, exp, nil
	}
}

func defaultSTSClient(region string) func(ctx context.Context) (stsTokenAPI, error) {
	return func(ctx context.Context) (stsTokenAPI, error) {
		var opts []func(*awsconfig.LoadOptions) error
		if region != "" {
			opts = append(opts, awsconfig.WithRegion(region))
		}
		cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return nil, fmt.Errorf("load AWS configuration: %w", err)
		}
		if cfg.Region == "" {
			cfg.Region = "us-east-1"
		}
		return sts.NewFromConfig(cfg), nil
	}
}

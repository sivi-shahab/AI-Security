package events

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"
)

// KafkaOpts is the broker connection every service uses (ticket 41, spec §10.1): TLS, and a SASL identity the
// broker ACLs (ApplyACLs) recognise. A plaintext connection is refused unless KAFKA_PLAINTEXT=true, which only a
// local or CI broker may set.
//
// Env (read through getenv): KAFKA_BROKERS (comma-separated), KAFKA_CA_FILE (PEM; empty = system roots),
// KAFKA_CERT_FILE + KAFKA_KEY_FILE (mTLS client certificate, instead of or besides SASL), KAFKA_SASL_USER +
// KAFKA_SASL_PASSWORD_FILE, KAFKA_SASL_MECHANISM (SCRAM-SHA-512, the default, or PLAIN), KAFKA_PLAINTEXT.
func KafkaOpts(getenv func(string) string) ([]kgo.Opt, error) {
	opts := []kgo.Opt{kgo.SeedBrokers(strings.Split(getenv("KAFKA_BROKERS"), ",")...)}
	plaintext := getenv("KAFKA_PLAINTEXT") == "true"
	if !plaintext {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if f := getenv("KAFKA_CA_FILE"); f != "" {
			pem, err := os.ReadFile(f)
			if err != nil {
				return nil, fmt.Errorf("KAFKA_CA_FILE: %w", err)
			}
			cfg.RootCAs = x509.NewCertPool()
			if !cfg.RootCAs.AppendCertsFromPEM(pem) {
				return nil, errors.New("KAFKA_CA_FILE: no certificate")
			}
		}
		if cert, key := getenv("KAFKA_CERT_FILE"), getenv("KAFKA_KEY_FILE"); cert != "" || key != "" {
			pair, err := tls.LoadX509KeyPair(cert, key)
			if err != nil {
				return nil, fmt.Errorf("KAFKA_CERT_FILE/KAFKA_KEY_FILE: %w", err)
			}
			cfg.Certificates = []tls.Certificate{pair}
		}
		opts = append(opts, kgo.DialTLSConfig(cfg))
	}
	user := getenv("KAFKA_SASL_USER")
	if user == "" {
		if !plaintext && getenv("KAFKA_CERT_FILE") == "" {
			return nil, errors.New("kafka: no client identity (KAFKA_SASL_USER or KAFKA_CERT_FILE)")
		}
		return opts, nil
	}
	pw, err := os.ReadFile(getenv("KAFKA_SASL_PASSWORD_FILE"))
	if err != nil {
		return nil, fmt.Errorf("KAFKA_SASL_PASSWORD_FILE: %w", err)
	}
	m, err := Mechanism(getenv("KAFKA_SASL_MECHANISM"), user, strings.TrimSpace(string(pw)))
	if err != nil {
		return nil, err
	}
	return append(opts, kgo.SASL(m)), nil
}

// Mechanism is a SASL mechanism by name: SCRAM-SHA-512 (default) or PLAIN.
func Mechanism(name, user, pass string) (sasl.Mechanism, error) {
	switch name {
	case "", "SCRAM-SHA-512":
		return scram.Auth{User: user, Pass: pass}.AsSha512Mechanism(), nil
	case "PLAIN":
		return plain.Auth{User: user, Pass: pass}.AsMechanism(), nil
	}
	return nil, fmt.Errorf("KAFKA_SASL_MECHANISM %q: SCRAM-SHA-512 or PLAIN", name)
}

// Grant is what one service account (the SASL user, or the mTLS certificate's principal) may do on the bus.
type Grant struct {
	Principal string   // e.g. "User:ai-gateway"
	Produce   []string // topics
	Consume   []string // topics
	Groups    []string // consumer groups
}

// ApplyACLs creates the allow ACLs for grants through an admin (super user) client. Idempotent: Kafka keeps one
// copy of an ACL created twice. With an authorizer and no allow.everyone.if.no.acl.found, anything not granted
// here is refused, so only the PEPs can produce decision events.
func ApplyACLs(ctx context.Context, admin *kgo.Client, grants []Grant) error {
	adm := kadm.NewClient(admin)
	for _, g := range grants {
		var bs []*kadm.ACLBuilder
		if len(g.Produce) > 0 {
			bs = append(bs, kadm.NewACLs().Allow(g.Principal).Topics(g.Produce...).Operations(kadm.OpWrite, kadm.OpDescribe).ResourcePatternType(kadm.ACLPatternLiteral))
		}
		if len(g.Consume) > 0 {
			bs = append(bs, kadm.NewACLs().Allow(g.Principal).Topics(g.Consume...).Operations(kadm.OpRead, kadm.OpDescribe).ResourcePatternType(kadm.ACLPatternLiteral))
		}
		if len(g.Groups) > 0 {
			bs = append(bs, kadm.NewACLs().Allow(g.Principal).Groups(g.Groups...).Operations(kadm.OpRead).ResourcePatternType(kadm.ACLPatternLiteral))
		}
		for _, b := range bs {
			res, err := adm.CreateACLs(ctx, b)
			if err != nil {
				return err
			}
			for _, r := range res {
				if r.Err != nil {
					return fmt.Errorf("acl %s: %w", g.Principal, r.Err)
				}
			}
		}
	}
	return nil
}

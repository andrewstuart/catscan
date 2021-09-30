package scan

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// A KubeSecretScanner can scan kubernetes secrets from inside the cluster.
type KubeSecretScanner struct {
	KubeConfig *rest.Config
	// Any extra ways of extracting data from secrets files
	Extra []func(v1.Secret) ([]*x509.Certificate, error)
}

var _ Scanner = (*KubeSecretScanner)(nil)

// Scan implements Scanner :sob:
func (s *KubeSecretScanner) Scan(context.Context) (Certer, error) {
	return s, nil
}

// SecretDataError describes secrets that were invalid, and the secret key.
type SecretDataError struct {
	Namespace, SecretName, Path string
	Cause                       error
}

func (k *SecretDataError) Error() string {
	return fmt.Sprintf(
		"error decoding data from key %q in secret \"%s/%s\": %s",
		k.Path,
		k.Namespace,
		k.SecretName,
		k.Cause,
	)
}

// Read implements Certer
func (s *KubeSecretScanner) Read(ctx context.Context, certs chan<- *x509.Certificate, errs chan<- error) {
	if s.KubeConfig == nil {
		var err error
		s.KubeConfig, err = rest.InClusterConfig()
		if err != nil {
			errs <- err
			return
		}
	}

	cs, err := kubernetes.NewForConfig(s.KubeConfig)
	if err != nil {
		errs <- err
		return
	}

	ns, err := cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		errs <- err
		return
	}

	for _, n := range ns.Items {
		ss, err := cs.CoreV1().Secrets(n.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			errs <- errors.Wrap(err, "error getting secrets")
			continue
		}

		for _, secret := range ss.Items {
			if len(s.Extra) > 0 {
				for i, ef := range s.Extra {
					cs, err := ef(secret)
					if err != nil {
						errs <- &SecretDataError{
							Namespace:  secret.Namespace,
							SecretName: secret.Name,
							Path:       "appsecrets",
							Cause:      errors.Wrapf(err, "error from Extra func %d", i),
						}
					}
					for _, cert := range cs {
						certs <- cert
					}
				}
			}

			if len(secret.Data["tls.crt"]) == 0 {
				continue
			}

			b, _ := pem.Decode(secret.Data["tls.crt"])
			if b == nil {
				errs <- &SecretDataError{
					Namespace:  secret.Namespace,
					SecretName: secret.Name,
					Path:       "tls.crt",
					Cause:      fmt.Errorf("no cert bytes"),
				}
				continue
			}

			c, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				errs <- &SecretDataError{
					Namespace:  secret.Namespace,
					SecretName: secret.Name,
					Path:       "tls.crt",
					Cause:      errors.Wrap(err, "error parsing"),
				}
				continue
			}
			certs <- c
		}
	}
}

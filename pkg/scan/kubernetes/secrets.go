package kubernetes

import (
	"crypto/x509"
	"log"

	"astuart.co/catscan/pkg/scan"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type SecretScanner struct {
}

func (s SecretScanner) Scan() scan.Certer {
	return s
}

func (s SecretScanner) Read(certs chan<- *x509.Certificate, errs chan<- error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal(err)
	}

	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatal(err)
	}

	ns, err := cs.CoreV1().Namespaces().List(v1.ListOptions{})
	if err != nil {
		log.Fatal(err)
	}

	for _, n := range ns.Items {
		ss, err := cs.CoreV1().Secrets(n.Name).List(v1.ListOptions{})
		if err != nil {
			log.Println(err)
			continue
		}

		for _, secret := range ss.Items {
			c, err := x509.ParseCertificate(secret.Data["tls.crt"])
			if err != nil {
				errs <- err
				continue
			}
			certs <- c
		}
	}
}

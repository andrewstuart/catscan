package main

import (
	"crypto/x509"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"astuart.co/catscan/pkg/scan"
	"astuart.co/catscan/pkg/validate"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
)

func main() {
	d := scan.KubeSecretScanner{
		KubeConfig: &rest.Config{
			BearerToken: os.Getenv("TOKEN"),
			Host:        os.Getenv("SERVER"),
		},
		Extra: []func(corev1.Secret) ([]*x509.Certificate, error){},
	}

	c, err := d.Scan()
	if err != nil {
		log.Fatal(err)
	}

	certs, errs := make(chan *x509.Certificate), make(chan error)

	sigs := make(chan os.Signal)
	go signal.Notify(sigs, syscall.SIGTERM, os.Interrupt)

	go func() {
		defer close(certs)
		defer close(errs)
		tkr := time.NewTicker(time.Minute)
		for {
			select {
			case sig := <-sigs:
				log.Println("got ", sig)
				return
			case <-tkr.C:
				c.Read(certs, errs)
			}
		}
	}()

	v := validate.MultiValidator{
		validate.MinKeyStrength(2048),
		validate.ValidAt(time.Now()),
	}

	for {
		select {
		case c, ok := <-certs:
			if !ok {
				logrus.Info("certs closed")
				return
			}
			log.Println(c.Subject)
			err := v.Validate(c)
			if err != nil {
				log.Println(err)
			}
		case <-sigs:
			logrus.Info("shutdown signaled")
			return
		case err, ok := <-errs:
			if !ok {
				logrus.Info("errs closed")
				return
			}
			logrus.WithError(err).Error("encounted error scanning")
		}
	}
}

package main

import (
	"context"
	"crypto/x509"
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

var ctx, cancel = context.WithCancel(context.Background())

func init() {
	go func() {
		ch := make(chan os.Signal, 2)
		signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
		i := 0
		for range ch {
			i++
			if i > 1 {
				os.Exit(1)
			}
			cancel()
		}
	}()

}

func main() {
	d := scan.MultiScanner{
		Scanners: []scan.Scanner{
			&scan.KubeSecretScanner{
				KubeConfig: &rest.Config{
					Host: "http://localhost:8001",
					// BearerToken: os.Getenv("TOKEN"),
					// Host:        os.Getenv("SERVER"),
				},
				Extra: []func(corev1.Secret) ([]*x509.Certificate, error){},
				// }, &scan.AXFRScanner{
				// 	DNSServer:   "192.168.16.5:53",
				// 	Domain:      "astuart.co",
				// 	Ports:       []int16{443},
				// 	Concurrency: 30,
			}},
		Concurrency: 2,
	}

	c, err := d.Scan(ctx)
	if err != nil {
		logrus.Fatal(err)
	}

	certs, errs := make(chan *x509.Certificate), make(chan error)

	go func() {
		defer close(certs)
		defer close(errs)
		tkr := time.NewTicker(time.Minute)
		c.Read(ctx, certs, errs)
		for {
			select {
			case <-ctx.Done():
				return
			case <-tkr.C:
				c.Read(ctx, certs, errs)
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
			err := v.Validate(c)
			if err != nil {
				logrus.WithField("certNames", c.DNSNames).WithError(err).Error("invalid cert encountered")
			}
		case <-ctx.Done():
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

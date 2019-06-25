package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	MQTT "github.com/eclipse/paho.mqtt.golang"
)

// Config holds all the AQS IoT properties
type Config struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	CaCert     string `json:"caCert"`
	ClientCert string `json:"clientCert"`
	PrivateKey string `json:"privateKey"`
}

func getSettingsFromFile(p string, opts *MQTT.ClientOptions) error {
	var conf, err = readFromConfigFile(p)
	if err != nil {
		return err
	}

	var tlsConfig, err2 = makeTLSConfig(conf.CaCert, conf.ClientCert, conf.PrivateKey)
	if err2 != nil {
		return err2
	}

	opts.SetTLSConfig(tlsConfig)

	var brokerURI = fmt.Sprintf("ssl://%s:%d", conf.Host, conf.Port)
	opts.AddBroker(brokerURI)

	return nil
}

func readFromConfigFile(path string) (Config, error) {
	var ret = Config{}

	var b, err = ioutil.ReadFile(path)
	if err != nil {
		return ret, err
	}

	err = json.Unmarshal(b, &ret)
	if err != nil {
		return ret, err
	}

	return ret, nil
}

func makeTLSConfig(cafile, cert, key string) (*tls.Config, error) {
	var TLSConfig = &tls.Config{InsecureSkipVerify: false}

	var certPool *x509.CertPool
	var err error
	var tlsCert tls.Certificate

	certPool, err = getCertPool(cafile)
	if err != nil {
		return nil, err
	}

	TLSConfig.RootCAs = certPool

	certPool, err = getCertPool(cert)
	if err != nil {
		return nil, err
	}

	TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
	TLSConfig.ClientCAs = certPool

	tlsCert, err = tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}

	TLSConfig.Certificates = []tls.Certificate{tlsCert}

	return TLSConfig, nil
}

func getCertPool(pemPath string) (*x509.CertPool, error) {
	var pemData, err = ioutil.ReadFile(pemPath)
	if err != nil {
		return nil, err
	}

	var certs = x509.NewCertPool()
	certs.AppendCertsFromPEM(pemData)

	return certs, nil
}

// ArgOption holds command line arguments
type ArgOption struct {
	Conf     string
	ClientID string
}

// NewOption creates new AWS IoT options (from a configuration file)
func NewOption(args *ArgOption) (*MQTT.ClientOptions, error) {
	var opts *MQTT.ClientOptions = MQTT.NewClientOptions()

	err := getSettingsFromFile(args.Conf, opts)
	if err != nil {
		return nil, err
	}

	opts.SetClientID(args.ClientID)
	opts.SetAutoReconnect(true)

	return opts, nil
}

//define a function for the default message handler
var f MQTT.MessageHandler = func(client MQTT.Client, msg MQTT.Message) {
	fmt.Printf("TOPIC: %s\n", msg.Topic())
	fmt.Printf("MSG: %s\n", msg.Payload())
}

var args ArgOption

func main() {
	flag.StringVar(&args.Conf, "conf", "", "Config file JSON path and name for accessing to AWS IoT endpoint")
	flag.StringVar(&args.ClientID, "client-id", "", "client id to connect with")
	flag.Parse()

	opts, err := NewOption(&args)
	if err != nil {
		panic(err)
	}

	opts.SetDefaultPublishHandler(f)

	//create and start a client using the above ClientOptions
	c := MQTT.NewClient(opts)
	if token := c.Connect(); token.Wait() && token.Error() != nil {
		panic(token.Error())
	}

	//subscribe to the topic /go-mqtt/sample and request messages to be delivered
	//at a maximum qos of zero, wait for the receipt to confirm the subscription
	if token := c.Subscribe("go-mqtt/sample", 0, nil); token.Wait() && token.Error() != nil {
		fmt.Println(token.Error())
		os.Exit(1)
	}

	//Publish 5 messages to /go-mqtt/sample at qos 1 and wait for the receipt
	//from the server after sending each message
	for i := 0; i < 5; i++ {
		text := fmt.Sprintf("this is msg #%d!", i)
		token := c.Publish("go-mqtt/sample", 0, false, text)
		token.Wait()
	}

	time.Sleep(3 * time.Second)

	//unsubscribe from /go-mqtt/sample
	if token := c.Unsubscribe("go-mqtt/sample"); token.Wait() && token.Error() != nil {
		fmt.Println(token.Error())
		os.Exit(1)
	}

	c.Disconnect(250)
}

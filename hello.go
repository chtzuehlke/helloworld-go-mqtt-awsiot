package main

import (
	"fmt"
	"os"
	"time"

	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"

	MQTT "github.com/eclipse/paho.mqtt.golang"

	"flag"
)

///

type Config struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	CaCert     string `json:"caCert"`
	ClientCert string `json:"clientCert"`
	PrivateKey string `json:"privateKey"`
}

func getSettingsFromFile(p string, opts *MQTT.ClientOptions) error {
	var (
		conf Config
		err  error
	)

	// Read condig json file
	conf, err = readFromConfigFile(p)
	if err != nil {
		//log.SetOutput(os.Stderr)
		//log.Error(err)
		return err
	}

	// Make TLS configulation
	var (
		tlsConfig *tls.Config
		ok        bool
	)
	tlsConfig, ok, err = makeTlsConfig(conf.CaCert, conf.ClientCert, conf.PrivateKey)
	if err != nil {
		return err
	}
	if ok {
		opts.SetTLSConfig(tlsConfig)
	}

	// Add Broker
	var brokerUri = /* string */ fmt.Sprintf("ssl://%s:%d", conf.Host, conf.Port)
	opts.AddBroker(brokerUri)

	return nil
}

func readFromConfigFile(path string) (Config, error) {
	var ret = /* Config */ Config{}

	var (
		b   []byte
		err error
	)

	b, err = ioutil.ReadFile(path)
	if err != nil {
		return ret, err
	}

	err = json.Unmarshal(b, &ret)
	if err != nil {
		return ret, err
	}

	return ret, nil
}

func makeTlsConfig(cafile, cert, key string) (*tls.Config, bool, error) {
	var TLSConfig = /* *tls.Config */ &tls.Config{InsecureSkipVerify: false}
	var ok bool

	var certPool *x509.CertPool
	var err error
	var tlsCert tls.Certificate
	if cafile != "" {
		certPool, err = getCertPool(cafile)
		if err != nil {
			return nil, false, err
		}
		TLSConfig.RootCAs = certPool
		ok = true
	}
	if cert != "" {
		certPool, err = getCertPool(cert)
		if err != nil {
			return nil, false, err
		}
		TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
		TLSConfig.ClientCAs = certPool
		ok = true

	}
	if key != "" {
		if cert == "" {
			return nil, false, fmt.Errorf("key specified but cert is not specified")
		}
		tlsCert, err = tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, false, err
		}
		TLSConfig.Certificates = []tls.Certificate{tlsCert}
		ok = true
	}
	return TLSConfig, ok, nil
}

func getCertPool(pemPath string) (*x509.CertPool, error) {
	var certs = /* *x509.CertPool */ x509.NewCertPool()
	var pemData []byte
	var err error

	pemData, err = ioutil.ReadFile(pemPath)
	if err != nil {
		return nil, err
	}
	certs.AppendCertsFromPEM(pemData)
	return certs, nil
}

type ArgOption struct {
	PubTopic string
	SubTopic string
	Qos      int
	Conf     string
	ClientId string
	Host     string
	Port     int
	Cacert   string
	Cert     string
	Key      string
}

func NewOption(args *ArgOption) (*MQTT.ClientOptions, error) {
	var opts *MQTT.ClientOptions = MQTT.NewClientOptions()

	var host string = args.Host

	if host == "" {
		err := getSettingsFromFile(args.Conf, opts)
		if err != nil {
			//log.SetOutput(os.Stderr)
			//log.Error(err)
			return nil, err
		}
	}

	var clientId string = args.ClientId
	//if clientId == "" {
	//	clientId = getRandomClientId()
	//}
	opts.SetClientID(clientId)
	opts.SetAutoReconnect(true)
	return opts, nil
}

///

//define a function for the default message handler
var f MQTT.MessageHandler = func(client MQTT.Client, msg MQTT.Message) {
	fmt.Printf("TOPIC: %s\n", msg.Topic())
	fmt.Printf("MSG: %s\n", msg.Payload())
}

var args ArgOption

func main() {

	///

	flag.StringVar(&args.PubTopic, "pub-topic", "", "Topic name to publish")
	flag.StringVar(&args.SubTopic, "sub-topic", "", "Topic name to subscribe")
	flag.IntVar(&args.Qos, "qos", 0, "QoS of the topic communication.")
	flag.StringVar(&args.Conf, "conf", "", "Config file JSON path and name for accessing to AWS IoT endpoint")
	flag.StringVar(&args.ClientId, "client-id", "", "client id to connect with")
	flag.Parse()

	opts, err := NewOption(&args)
	if err != nil {
		//log.SetOutput(os.Stderr)
		//log.Error(err)
		fmt.Fprintf(os.Stderr, "Error on making client options: %s", err)
		os.Exit(2)
	}

	///

	//create a ClientOptions struct setting the broker address, clientid, turn
	//off trace output and set the default message handler
	//x opts := MQTT.NewClientOptions().AddBroker("tcp://iot.eclipse.org:1883")
	//x opts.SetClientID("go-simple")
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

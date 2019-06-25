# helloworld-go-mqtt-awsiot

## Steps

0. install golang

1. create thing, cert & policy in AWS IoT and download certificate and private key

2. create config file (conf.json)

    ```
    {
        "host": "YOUR-AWS-IOT-ENDPOINT-HERE-ats.iot.eu-west-1.amazonaws.com",
        "port": 8883,
        "caCert": "AmazonRootCA1.pem",
        "clientCert": "YOUR-CERT-HERE-certificate.pem.crt",
        "privateKey": "YOUR-PRIVATE-KEY-HERE-e7c08dd12d-private.pem.key"
    }
    ```

3. build

    ```
    go build
    ```

4. run (you might want to create test subscription to "go-mqtt/sample" in the AWS IoT web console)

    ```
    ./hello -conf conf.json -client-id testclient
    ```

## Sources partially "borrowed" from here

- https://www.eclipse.org/paho/clients/golang/
- https://github.com/manamanmana/aws-mqtt-chat-example/
- https://github.com/golang/go/wiki/Modules

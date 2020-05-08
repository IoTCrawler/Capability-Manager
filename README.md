# License

Capability Manager Project source code files are made avaialable under the Apache License, Version 2.0 (Apache-2.0), located into the LICENSE file.

# Introduction

This project is a WEB SERVICE for Capability Manager  (CM-WBS) that allows a POST request and return a Capability token.

This project contains:

- Source files & folders.

    - API-CM.py: Run the component.
    - config.cfg file: Contain the configuration of the component.

- Folder to ssl.

    - certs folder: Contains the certificates needed to ssl.

- Files & folder to generate the Capability Token.
    - CapabilityGenerator.jar: Java aplication (validate Capability Token process). 
    - config folder: Contain the certificate paths.
    - local_dependencies folder: To allow run the java process (CapabilityGenerator.jar).

- Files to deploy.

    - Dockerfile file: Contain the actions and commands to create the Docker image needed to run the component.
    - build.sh file: To create the component Docker image using Dockerfile.
    - docker-compose.yml file: To deploy the component container.

# Configuration config.cfg file

Before launching the CM-WBS, it's necessary to review the config.cfg file:

```sh
cd projectPath / Py_CapabilityManagerWebService
vi config.cfg
```

- Params to CM-WBS's endpoint.

    - host: No change admittable (always 0.0.0.0)
    - port: If change this param, it's necessary to review Dockerfile and docker-compose.yml files. By default 3030.

- Params to the keyrock's endpoint (authentication).

    - keyrock_protocol=Keyrock protocol. Admitted values: "http","https"
    - keyrock_host=Keyrock host.
    - keyrock_port=Keyrock port.

- Params to log KPIs info

    - logginKPI=Admitted values: "Y","N"

# Configuration docker-compose.yml file

We need to define the PDP endpoint, review PDP_URL environment variable.

# Prerequisites

To run this project is neccessary to install the docker-compose tool.

https://docs.docker.com/compose/install/

Launch then next components:

- PDP component running. 
- Keyrock component running. 

# Installation / Execution.

After the review of config.cfg file and docker-compose finle, we are going to obtain then Docker image. To do this, you have to build a local one, thus:

```sh
cd projectPath / Py_CapabilityManagerWebService
./build.sh
```

The build.sh file contains docker build -t iotcrawler/capability-manager ./ command.

Finally, to launch the connector image, we use the next command:

```sh
cd projectPath / Py_CapabilityManagerWebService
docker-compose up -d
```

# Monitoring.

- To test if the container is running:

```sh
docker ps -as
```

The system must return that the status of the Capability Manager WEB SERVICE container is up.

- To show the CM-WBS container logs.

```sh
docker-compose logs apicapabilitymanager
```

# CM-WBS functionality.

CM-WBS is waiting a POST request with an specific format data body.

```sh
curl -X POST \
  https://<CM-WBS_host>:<CM-WBS_port> \
  -H 'Content-Type: application/json' \
  -d '{"token": "f587e811-17e2-4c39-afe8-fd621d45f1e1","de": "216.57.210.163","ac": "GET","re": "/ngsi-ld/v1/entities/?type=http://example.org/room/Room"}'
```

- token: Keyrock token obtained when the user is authenticated.
- de: IP of the device.
- ac: Action (POST, GET, DELETE, ...).
- re: Resource.

To create a Capability Token CM-WBS follow the next steps:

1. Send request to Keyrock API to validate and obtain Keyrock Token info.

2. Try to create a Capability token accessing to PDP component to verify the user has autorisation.











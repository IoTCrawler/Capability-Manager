from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import http.client
import logging
import sys
import json
import configparser
from subprocess import Popen, PIPE
import html

#Obtain configuracion from config.cfg file.
cfg = configparser.ConfigParser()  
cfg.read(["./config.cfg"])  
host = cfg.get("GENERAL", "host")
port = int(cfg.get("GENERAL", "port"))

keyrock_protocol = cfg.get("GENERAL", "keyrock_protocol")
keyrock_host = cfg.get("GENERAL", "keyrock_host")
keyrock_port = cfg.get("GENERAL", "keyrock_port")

gcontext = ssl.SSLContext()

def getstatusoutput(command):
    process = Popen(command, stdout=PIPE,stderr=PIPE)
    out, err = process.communicate()

    #print("out")
    #print(out)
    #print("err")
    #print(err)

    return (process.returncode, out)

def obtainRequestHeaders(RequestHeaders):

    headers = dict()

    content_length = 0

    try:
        # We get the headers
        
        #logging.info (" ********* HEADERS BEFORE obtainRequestHeaders ********* ")
        #logging.info (RequestHeaders)
        
        for key in RequestHeaders:
            #logging.info("Procesando: " + str(key) + ":" + str(RequestHeaders[key]))

            value_index=-1

            try:
                #To find only admittable headers from request previously configured in config.cfg file.
                value_index = apiHeaders.index(key.lower())

            except:
                value_index = -1

            #If the header key was found, it will be considered after.
            if (value_index > -1 ):

                #logging.info("Incluido: " + str(key) + ":" + str(RequestHeaders[key]))

                headers[key] = RequestHeaders[key]

            if(key.upper()=="Content-Length".upper()):
                content_length = int(RequestHeaders[key])

    except Exception as e:
        logging.info(e)

        headers["Error"] = str(e)

    #logging.info (" ********* HEADERS AFTER obtainRequestHeaders ********* ")
    #logging.info (headers)

    return headers, content_length

def generateToken(subject, action, device, resource):

    #validation = False

    outTypeProcessed = ""

    cmToken=""

    try:

        #logging.info("subject: " +str(subject))
        #logging.info("action: " +str(action))
        #logging.info("device: " +str(device))
        #logging.info("resource: " +str(resource))


        #Validating token : 
        #Observation: str(resource).replace("&",";") --> for PDP error: "The reference to entity "***" must end with the ';' delimiter.""
        codeType, outType = getstatusoutput(["java","-jar","CapabilityGenerator.jar",
            str(subject),
            str(action),
            str(device),
            str(resource).replace("&",";")
            ])
        
        #logging.info("subject: " +str(subject))
        #logging.info("action: " +str(action))
        #logging.info("device: " +str(device))
        #logging.info("resource: " +str(resource))

        #logging.info("GENERATE CAPABILITY TOKEN - Response:\n" + str(outType))

        outTypeProcessed = json.loads(outType.decode('utf8').replace("'", '"').replace("*****generateSignature: \n","").replace("\n", ""))
        #outTypeProcessed = outType.decode('utf8').replace("'", '"').replace("CODE: ","")

        #logging.info("generateToken - outTypeProcessed: " + str(outTypeProcessed))

        #logging.info("outTypeProcessed")
        #logging.info(outTypeProcessed)
        #logging.info(type(outTypeProcessed))

        if(outTypeProcessed["code"]=="ok"):
            cmToken = outTypeProcessed["capabilityToken"]
        else:
            cmToken = {"error": "error"}

    except Exception as e:
        logging.info(e)

#    logging.info ("validationToken - Result: " + str(validation) + " - Code: " + str(outTypeProcessed))

    return cmToken


def loggingRequest(req):
    logging.info("")
    #logging.info (" ********* PEP-REQUEST ********* ")
    #logging.info(req.address_string())
    #logging.info(req.date_time_string())
    #logging.info(req.path)
    #logging.info(req.protocol_version)
    #logging.info(req.raw_requestline)
    logging.info(" ******* NEW CAPABILITY TOKEN - Request : " + req.address_string() + " - " + str(req.raw_requestline) + " ******* ")  

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_HandleError(self,method):
        self.send_response(500)
        self.end_headers() 
        data = json.dumps("Internal server error").encode()

        self.wfile.write(data)

        self.close_connection
    
    def do_POST(self):
        try:

            #loggingRequest(self)

            logging.info("******* NEW CAPABILITY TOKEN REQUEST : " + self.address_string() + " *******")  

            headers,content_length = obtainRequestHeaders(self.headers)

            try:
                #To find only admittable headers from request previously configured in config.cfg file.
                value_index = apiHeaders.index("Error")
            except:
                value_index = -1

            if (value_index != -1):
                logging.info("Error: " + str(headers["Error"]))
                SimpleHTTPRequestHandler.do_HandleError(self,"POST")
                    
            else:

                #logging.info (" ********* OBTAIN BODY ********* ")
                # We get the body
                if (content_length>0):
                    #logging.info ("-------- self.rfile.read(content_length) -------")
                    post_body   = self.rfile.read(content_length)
                else:
                    #logging.info ("-------- Lanzo self.rfile.read() -------")
                    post_body   = self.rfile.read()

                #logging.info(post_body)

                #Convert from byte to JSON (dict)
                bodyJSON = json.loads(post_body.decode('utf8').replace("'", '"'))

                token = bodyJSON["token"]
                deValue = bodyJSON["de"]
                acValue = bodyJSON["ac"]
                reValue = bodyJSON["re"]
                
                logging.info("Step 1) Obtaining Keyrock Token info ...")

                headers = {"X-Auth-token": token, 
                        "X-Subject-token": token}

                if(keyrock_protocol.upper()=="http".upper()):
                    conn = http.client.HTTPConnection(keyrock_host,keyrock_port)
                else:
                    #conn = http.client.HTTPSConnection(keyrock_host,keyrock_port,
                    #                                key_file="./certs/idm-2018-key.pem",
                    #                                cert_file="./certs/idm-2018-cert.pem",
                    #                                context=gcontext)
                    conn = http.client.HTTPSConnection(keyrock_host,keyrock_port,
                                                context=gcontext)

                conn.request("GET", "/v1/auth/tokens", None, headers)
                response = conn.getresponse()

                status = response.status
                reason = response.reason
                data = response.read()
                conn.close()

                if(status==200):

                    bodyJSON = json.loads(data.decode('utf8').replace("'", '"'))

                    logging.info("Keyrock Token info response : " + str(bodyJSON))

                    validToken = bodyJSON["valid"]

                    userEnabled = bodyJSON["User"]["enabled"]

                    if (validToken == False or userEnabled == False):
                        logging.info("Obtaining Keyrock Token info response : Error.")
                        
                        #self.send_response(500)
                        #self.end_headers()
                        #
                        #if(validToken == False):
                        #    self.wfile.write(json.dumps("Invalid token.").encode())
                        #else
                        #    self.wfile.write(json.dumps("User disabled.").encode())

                        self.send_response(401)
                        self.end_headers()
                        
                        message = {"error": { "message": "Invalid email or password", "code": 401, "title": "Unauthorized" } }

                        if(validToken == False):
                            message["error"]["message"] =  "Invalid token."
                        
                        logging.info(str(message))

                        self.wfile.write(json.dumps(message).encode())

                    else:

                        suValue = bodyJSON["User"]["username"]

                        logging.info("Step 2) Generating capability token to:\n" +
                        "{\n" + 
                        "\t\tsu: " + suValue + ",\n" +
                        "\t\tde: " + deValue + ",\n" +
                        "\t\tac: " + acValue + ",\n" +
                        "\t\tre: " + reValue + "\n" +
                        "}")

                        cmToken = generateToken(suValue, acValue, deValue, reValue)

                        # We send back the response to the client
                        if 'error' not in cmToken:
                            logging.info("Generating capability token response : NEW CAPABILITY TOKEN : " + str(cmToken))
                            self.send_response(200)
                            self.end_headers()
                            self.wfile.write(json.dumps(cmToken).encode())
                        else:
                            logging.info("Generating capability token response : Error.")
                            self.send_response(500)
                            self.end_headers()
                            self.wfile.write(json.dumps("Can't generate capability token").encode())

                    self.close_connection
                else:
                    logging.info("Obtaining Keyrock Token info response : Error.")
                    logging.info(json.loads(data.decode('utf8').replace("'", '"')))

                    #self.send_response(500)
                    self.send_response(status)
                    self.end_headers()
                    #self.wfile.write(json.dumps("Keyrock Token info response : Token info not found.").encode())
                    self.wfile.write(data)
                    self.close_connection
                
        except Exception as e:
            logging.info(str(e))
            
            SimpleHTTPRequestHandler.do_HandleError(self,"POST")

logPath="./"
fileName="out"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s",
    handlers=[
        logging.FileHandler("{0}/{1}.log".format(logPath, fileName)),
        logging.StreamHandler(sys.stdout)
    ])

httpd = HTTPServer( (host, port), SimpleHTTPRequestHandler )

httpd.socket = ssl.wrap_socket (httpd.socket,
        keyfile="certs/server-priv-rsa.pem",
        certfile='certs/server-public-cert.pem',
        server_side = True)

httpd.serve_forever()
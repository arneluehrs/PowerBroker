#!/usr/bin/env python
gVers = "4.2.4"
'''
 BeyondTrust PBPS API Client

 Copyright 2016-2017 BeyondTrust Software

To get more help, run "--help", then run "-t help" and then "-t <type> -a help"
 Each type has its own printable help module, so feel free to add there!

Programmer's information at the bottom.
'''

# Customer can change items here:
#
# Global variables OK for customer to set. These will be pulled in if the corresponding CLI options are not passed
gPBPSHost = "retina2"
gPBPSUser = "apiadmin"
gPBPSKey = "D98C2323-3E87-4855-AC0A-B732D57E006A"
gWorkgroup = "BEYONDTRUST"
gEmail = "labpasswords@totalnetsolutions.net"

#############################################################################################################################
# Less-frequently-changed globals (every class has a set of defaults that pull from here)
gAttributeType = "Business Unit"
gNewPassword = "P@s5w0rd!"
gPrivateKey = ""
gPublicKey = ""
gPassphrase = ""
gIpAddress = "1.1.1.1"
gMacAddress = "AB:AD:1D:EA"
gPasswordRuleId = 1
gDssKeyRuleId = 0
gReleaseDuration = 120
gMaxReleaseDuration = 1440
gIsaReleaseDuration =120
gApiEnabled = True
gPasswordFallbackFlag = True
gLoginAccountFlag = False
gChangeServicesFlag = False
gRestartServicesFlag = False
gAutoManagementFlag = True
gDSSAutoManagementFlag = False
gFunctionalAccountId= 1
gElevationCommand = None
gCheckPasswordFlag = True
gChangePasswordAfterAnyReleaseFlag = True
gResetPasswordOnMismatchFlag = True
gChangeFrequencyType = "xdays"
gChangeFrequencyDays = 7
gChangeTime = "23:30"
gUpdateOnSystem = False
gCredentialReason = "PBPS Python API CLI Tool."
gCredentialDuration = 1
gRequestType="password"
gAccessType="View"
gConflictOption="reuse"
gRequestBackOffTime= 5  # If a request isn't approved, backoff for this number of seconds,
gMaxretries = 24        #  a maximum of this number of times.
logsep = "\t"  #the seperator character for input and output

#############################################################################################################################
#############################################################################################################################
#############################################################################################################################
#############################################################################################################################
#
#
#
#  END OF USER CONFIGURATION!!!!
#
#
#############################################################################################################################
#############################################################################################################################
#############################################################################################################################
#############################################################################################################################
# Global variables
gExamples='''
All options have no order dependencies.
All examples assume you have changed the global variables on lines 14-19 for your environment.

Getting Help:

Get a list of supported types:
    ./pbpsapi.py -t help

Get a list of actions for a specific type:
    ./pbpsapi.py -t ma -a help

Get a list of required options for a specific action:
    ./pbpsapi.py -t ma -a create --show

Account Commands:
List all managed accounts you have rights to check out:
    ./pbpsapi.py -t ma -a list

Check out a password (the password will be printed raw, suitable for use in scripts as a return value):
    ./pbpsapi.py -t pw -a request --system centos6-1 --account root --reason "Breaking Glass" --duration 60

Set a password on a managed account (blank values will prompt if interactive):
    ./pbpsapi.py -t pw -a set --account 133 --newpassword P@ssw0rd
    Please enter the publickey:
    Please enter the privatekey:
    Please enter the passphrase:
    Please enter the Update On System?: n
    Successfully set new credentials for btadmin@None


System(Asset) Commands:
List all Workgroups and IDs (workgroup name/ID is required for asset creation and search):
    ./pbpsapi.py -t wg -a list

Create a new Managed System (and the related underlying asset, if it does not exist), with coded defaults:
    ./pbpsapi.py -t ms -a create --system "linux1.bttest.corp" --workgroup BEYONDTRUST --defaults


Searching for a particular asset?  the --searchdata field can search the line, or a particular field.
This will return only assets in workgroup 2 who have an UNKNOWN AssetType:
    ./pbpsapi.py -t asset -a list --workgroup 2 --searchdata UNKNOWN --searchfield AssetType

This will print only systems with "linux" anywhere in the result line:
    ./pbpsapi.py -t asset -a list --workgroup BEYONDTRUST --searchdata linux

Examples of the --multiple flag:
All items above support the "--multiple" flag to read a file and do the same operation... a lot:
    ./pbpsapi.py -t pw -a request --multiple --file ./examples/mass-checkout.txt

Or use a single spreadsheet to create assets, then add attributes to them (note use of the same file):
    ./pbpsapi.py -t asset -a create --multiple --file ./examples/firewall-systems.txt
    ./pbpsapi.py -t attribute -a addToAsset --multiple --file ./examples/firewall-systems.txt

List all accounts with "mass" in the name, and then delete them (in a pipeline)
    ./pbpsapi.py -t ma -a list --searchdata mass | ./pbpsapi.py -t ma -a delete --multiple

You can also pipeline things like a managed account list to a password checkout:
    ./pbpsapi.py -t ma -a list --searchdata root | ./pbpsapi.py -t pw -a request --multiple -D

Or delete every system from a lab DNS domain:
    /pbpsapi.py -t asset -a list  --searchdata labdomain.com --workgroup 2 | ./pbpsapi.py  \\
         -t asset -a delete --multiple --workgroup 2


'''

#from __future__ import generators
import os, sys, re, warnings, operator, datetime, socket, io
try:
    import requests
except ImportError:
    print("ERROR: You need to install the python requests library to use this tool!")
    print("ERROR: You can get it with either: ")
    print("ERROR:   yum -y install python35-pip; pip install requests")
    print("ERROR:   yum -y install python-requests")
    print("ERROR: or your specific OS's package management system.")
    sys.exit(2)

# because Python 2.x uses "socket.error" and Python 3.x uses BrokenPipeError
# We have to variablize the expected error states so that we can properly
# catch pipe breaks in the print code throughout the script.
# in other words, if we drop python 2.x support, remove this code, 
# then do :%s/brokenpipeerror/BrokenPipeError/g
import socket
try:
    brokenpipeerror = BrokenPipeError
except NameError:
    brokenpipeerror = IOError

gInteractive=True
if not (sys.stdout.isatty() and sys.stdin.isatty()):
    #Are in some kind of pipeline, so disabling interactive input.
    gInteractive=False

from collections import defaultdict
from optparse import (OptionParser,BadOptionError,AmbiguousOptionError,OptionGroup)

# BeyondTrust use so many self-signed certificates, these warnings should be hidden
# especially in scripts where the only output should be the actual password.
requests.packages.urllib3.disable_warnings()
try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    from requests.packages.urllib3.exceptions import SubjectAltNameWarning
    from requests.packages.urllib3.exceptions import SecurityWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    requests.packages.urllib3.disable_warnings(SubjectAltNameWarning)
    requests.packages.urllib3.disable_warnings(SecurityWarning)
except ImportError:
    if gInteractive:
        print("WARNING: Your version of requests includes an older urllib3. If you are using '-i' you will still get warnings. (This will not print in scripts.)")
# some additional globals, so we can use them across other classes
wg = None
attType = None
manaccount= None
mansystem = None
myasset = None
myrequest = None
searchdatare = None

def do(objtype, **kwargs):
    printdebug(objtype.name, "dispatching action: " + str(kwargs["act"]))
    printdebug(objtype.name, "passing arguments: " + str(kwargs))
    action=kwargs["act"]
    printdebug(objtype.name, "running self.actions[" + action + "], which is: " + str(objtype.actions[action]))
    #printdebug(self.name, "type is " + self)
    #run=self.actions[action].__get__(self.actions[action], type(self.actions[action]))
    #run=getattr(self.actions[action], action)(kwargs)
    return objtype.actions[action]()
    #self.actions[action]()
    #run(kwarg)

class PbpsObject(object):
    def __init__(self, name):
        self.name=str(name)  #might be passed an int or ID, so make sure to stringify it.
        global wg
        printdebug(self.name + ":init", "initializing object from class " + self.name);
        self.id=None
        self.baseurl="https://" + options.host + "/BeyondTrust/api/public/v3"
        self.headers= gAuth["headers"]
        self.cookies=gAuth["cookies"]
        self.data={}  # data that will be sent after the "?" in the URI
        self.reqdata={}  # data used internally to build the URI and check self.checkRequirements
        self.verify=options.verify
        self.result=False
        self.printheader=True
        self.help=""
        self.defaults={}  # in case "-D" for defaults is passed, what are those default values? set per-class
        self.fields=[]
        self.actions={
                "json": self.json,
                "list": self.list,
                "signAppin": self.signAppin,
                "signAppout": self.signAppout,
                "header": self.header,
                }
        self.responses={
                200 : {
                    'result' : True,
                    'description' : "Request Successful.",
                    'data' : True,
                    },
                201 : {
                    'result' : True,
                    'description' : "Request Successful - Response in body.",
                    'data' : True,
                    },
                204 : {
                    'result' : True,
                    'description' : "Request Successful. No content in body.",
                    'data' : False,
                    },
                400 : {
                    'result' : False,
                    'description' : "The Import file was not found in the body of the request.",
                    'data' : True,
                    },
                401 : {
                    'result' : False,
                    'description' : "User is not authenticated. The request headers were not set properly, the server could not verify the validity f the request, or the user session has expired.",
                    'data' : False,
                    },
                403 : {
                    'result' : False,
                    'description' : "Access forbidden. User does not have permissions to this collection (or license is expired).",
                    'data' : True,
                    },
                4031 : {
                    'result' : False,
                    'description' : "User does not have permission for this request.",
                    'data' : False,
                    },
                4032 : {
                    'result' : False,
                    'description' : "Requestor Only API or account - only Requestors can access this API or account.",
                    'data' : False,
                    },
                4033 : {
                    'result' : False,
                    'description' : "Approver Only API or account - only Approvers can access this API or account.",
                    'data' : False,
                    },
                4034 : {
                    'result' : None,   #returning none here, so we can "wait and retry" on NoneType, vs. False, but None will still evaluate False in __bool__
                    'description' : "Request not yet approved.",
                    'data' : False,
                    },
                4035 : {
                    'result' : False,
                    'description' : "Not enough approvers configured to approve a request.",
                    'data' :False,
                    },
                404 : {
                    'result' : False,
                    'description' : "Object not found where expected. Reason in response body.",
                    'data' : True,
                    },
                405 : {
                    'result' : False,
                    'description' : "Method not allowed",
                    'data' : False,
                    },
                409 : {
                    'result' : False,
                    'description' : "Conflicting request exists. Another user has already requrested a password for the account within the requested window.",
                    'data' : False,
                    },
                410 : {
                    'result' : False,
                    'description' : "API version has been disabled",
                    'data' : False,
                    },
                415 : {
                    'result' : False,
                    'description' : "Unsupported Media Type.",
                    'data' : False,
                    },
                500 : {
                    'result' : False,
                    'description' : "Server error has occurred. Please contact BeyondTrust.",
                    'data' : False,
                    },
                }
        #self.signAppin()
        #if self.result:
        #    self.cookies=self.r.cookies
        #    printdebug(self.name, "able to save cookies from response")


    def json(self):
        try:
            if self.r.json():
                pass
        except AttributeError:
            self.signAppin()
        self.doprint(doprint=True)
        return self.r.json()

    def header(self):
        print(logsep.join(self.fields))
        sys.exit(0)

    def list(self):
        return self.actions
    def auth(self):
        return gAuth["auth"]
    def cookies(self):
        return gAuth["cookies"]
    def headers(self):
        return gAuth["headers"]

    def callPbps(self, verb, stub, **kwargs):
        if not gAuth["auth"]:
            printinfo(self.name + ":callPbps", "Not logged in, doing so now.")
            result = self.signAppin()
            if not result:
                printerror(self.name + ":callPbps", "Failed to log in, bailing.")
                self.result=False
                return False
        #if options.show and stub != "/Auth/SignAppin":
        if options.show:
            printdebug(self.name + ":requirements", "End of required arguments.")
            #sys.exit(2)
            self.result=False
            return False
        url=self.baseurl + stub
        if not url.find("?") > 0 and not url.endswith("\/") and not verb == "POST":
            url = url + "/"
            printdebug(self.name + ":callPbps", "Adding '/' to end of url to avoid IIS file vs API problems.")
        printinfo(self.name + ":callPbps", "Attempting to " + verb + " " +url + " at time: " + str(now.datetime.now()))
        # ugh, some things do NOT want to come in on the command line, like ssh private keys.  So let's DWIM... if they pass a file
        # figure it out in the data, and read that file in *here* in the bowells of the script.
        for key in self.data:
            printdebug(self.name + ":callPbps", "figuring out if {0} is a file.".format(self.data[key]))
            if type(self.data[key]) is str:
                if os.path.exists(self.data[key]):
                    try:
                        with open(self.data[key], 'r') as fp:
                            self.data[key]=fp.read()
                            printinfo(self.name + ":callPbps", "Reading in file {0}".format(self.data[key]))
                    except IOError:
                        printdebug(self.name + ":callPbps", "{0} is not a file.".format(self.data[key]))
                else:
                    printdebug(self.name + ":callPbps", "Path: '{0}' does not exist.".format(self.data[key]))
            else:
                printdebug(self.name + ":callPbps", "'{0}' is not even a string, it's: {1}".format(self.data[key], type(self.data[key])))
        if options.prototype:
            print("->{1}{0}'{2}'".format(logsep, verb, url))
            cleanHeaders={'Authorization':'PS-Auth key=<REDACTED>; runas=' + options.user + ';' }
            print("->{0}Headers:{0}'{1}'".format(logsep, cleanHeaders))
            print("->{0}Cookie:{0}'<hidden>'".format(logsep))
        printdebug(self.name + ":callPbps", "Using headers: " + str(self.headers) + ", and verify: " + str(self.verify) + ", and cookie: " + str(gAuth["cookies"]))
        try:
            if verb == "POST":
                if not self.data:
                    self.data = kwargs.get("data", {})
                if not kwargs.get("files", False):
                    if options.prototype:
                        print("->{0}Data:{0}'{1}'".format(logsep, self.data))
                    printinfo(self.name + ":callPbps", "Using files-free POST with data='{0}'".format(self.data))
                    self.r = requests.post(url, headers=self.headers, verify=self.verify, cookies=gAuth["cookies"], data=self.data)
                else:
                    if options.prototype:
                        print("->{0}Data:{0}'{1}'".format(logsep, self.data))
                        print("->{0}Files::{0}'{1}'".format(logsep, kwargs["files"]))
                    printinfo(self.name + ":callPbps", "using files-based POST with data = '" + str(self.data) + ", and file: " + kwargs["files"])
                    self.r = requests.post(url, headers=self.headers, verify=self.verify, cookies=gAuth["cookies"], data=self.data, files=kwargs["files"])
            elif verb == "PUT":
                if not self.data:
                    self.data= kwargs.get("data", {})
                printinfo(self.name + ":callPbps", "PUT with data: " + str(self.data))
                if options.prototype:
                    print("->{0}Data:{0}'{1}'".format(logsep, self.data))
                self.r = requests.put(url, headers=self.headers, verify=self.verify, cookies=gAuth["cookies"], data=self.data)
            elif verb == "DELETE":
                if not self.data:
                    self.data= kwargs.get("data", {})
                printinfo(self.name + ":callPbps", "DELETE with data: " + str(self.data))
                if options.prototype:
                    print("->{0}Data:{0}'{1}'".format(logsep, self.data))
                self.r = requests.delete(url, headers=self.headers, verify=self.verify, cookies=gAuth["cookies"], data=self.data)
            else:
                if hasattr(self, "params"):
                    printinfo(self.name + ":callPbps", "GET with PARAMS: " + str(self.params))
                    self.r = requests.get(url, headers=self.headers, verify=self.verify, cookies=gAuth["cookies"], params=self.params)
                    if options.prototype:
                        print("->{0}Params:{0}'{1}'".format(logsep, self.params))
                else:
                    self.r = requests.get(url, headers=self.headers, verify=self.verify, cookies=gAuth["cookies"])
        except requests.exceptions.SSLError:
            printerror("SignIn", "Certificate verification failed - cannot continue!")
            printerror("SignIn", "Try again with -C ./path/to/cacert.")
            self.result=False
            gAuth["auth"]=False
            return False
        except requests.exceptions.ConnectionError:
            printerror("SignIn", "Could not connect to host: " + options.host)
            printerror("SignIn", "  Check your server name or IP and try again.")
            self.result=False
            gAuth["auth"]=False
            return False
        self.result=self.responses[self.r.status_code]['result']
        printdebug(self.name + ":callPbps", "Returning status code: " + str(self.result))
        self.printusererror(**kwargs)
        if options.prototype:
            print("<-HTTP_STATUS:{0}{1}".format(logsep, self.r.status_code))
            if self.result and stub != "/Auth/Signout":
                print("<-{0}{1}".format(logsep, self.r.json()))
        return self.result

    def checkOptions(self, reqlist):
        global gInteractive
        retvals={}
        printdebug(self.name + ":checkOptions", "Entering - reqlist is : {0} and reqdata is: {1}.".format(reqlist, self.reqdata))
        reqlist.update({"getoptions": bool})
        opts=self.checkRequirements(reqlist)
        #opts=dict((k, v) for k, v in opts.iteritems() if v)
        return opts

    def checkRequirements(self, reqlist):
        getrequirements=True
        if "getoptions" in reqlist.keys():
            getrequirements=False

        global gInteractive
        retvals={}
        printdebug(self.name + ":checkRequirements", "reqlist is: " + str(reqlist) + " and reqdata is: " + str(self.reqdata))

        for req in reqlist.keys():
            if req=="getoptions":
                continue
            if options.show:
                if self.reqdata.get(req, False):
                    print("Requires: '{0}', which is currently: '{1}'.".format(req, self.reqdata[req]))
                elif options.defaults and self.defaults.get(req, False):
                    print("Requires: '{0}', which defaults to: '{1}'.".format(req, self.defaults[req]))
                else:
                    print("Requires: '{0}'.".format(req))
            printdebug(self.name + ":checkRequirements", "Looking for requirement: " + req + " in reqdata: " + str(self.reqdata.get(req, "Not Found")))
            if options_lo.get(req, False):
                #and not getrequirements:
                printdebug(self.name + ":requirements", "looking for {0} or {1}.".format(options_lo.get(req, "''"), options_lo.get("--" + req, "''")))
                # options_lo is only populated with fallthrough items, so might as well try those first
                try:
                    retvals[req]=reqlist[req](options_lo[req])
                    printdebug(self.name + ":requirements", "found option {0} in options_lo.".format(req))
                    continue
                except ValueError:
                    printwarn(self.name + ":requirements", "Could not cast {0} to type: {1}.".format(options_lo[req], reqlist[req]))
            if self.reqdata.get(req, False) or (self.reqdata.get(req, False) == "" and not getrequirements) :
                try:
                    retvals[req]=reqlist[req](self.reqdata[req])
                    printdebug(self.name + ":requirements" , "found option " + req + " in self.reqdata.")
                    continue
                except ValueError:
                    printwarn(self.name + ":requirements", "Could not cast {0} to type: {1}.".format(retvals[req], reqlist[req]))
            if self.reqdata.get(req.lower(), False) or (self.reqdata.get(req.lower(), False) == "" and not getrequirements) :
                try:
                    retvals[req.lower()]=reqlist[req](self.reqdata[req])
                    printdebug(self.name + ":requirements" , "found option {0} in self.reqdata.lower().".format(req))
                    continue
                except ValueError:
                    printwarn(self.name + ":requirements", "have the wrong data type for req {0}, can't use it.".format(req))
            if parser.has_option("-" + req) or (parser.has_option("-" + req) == "" and not getrequirements) :
                val=parser.get_option("-" + req)
                if option_dict[req]:
                    retvals[req]=option_dict[req]
                    printdebug(self.name + ":requirements", "passing option_dict: " + req + " with data: " + retvals[req.lower()])
                    continue
            if parser.has_option("-" + req.lower()) or (parser.has_option("-" + req.lower()) == "" and not getrequirements) :
                val=parser.get_option("-" + req.lower())
                if option_dict[req.lower()]:
                    retvals[req]=option_dict[req.lower()]
                    printdebug(self.name + ":requirements", "passing option_dict(lc): {0} with data: {1}".format(req, retvals[req.lower()]))
                    continue
            if parser.has_option("--" + req) or (parser.has_option("--" + req) == "" and not getrequirements) :
                val=parser.get_option("--" + req)
                if option_dict.get(req, False):
                    retvals[req]=option_dict[req]
                    printdebug(self.name + ":requirements", "passing option {0} with data: {1}".format(req, retvals[req]))
                    continue
            if parser.has_option("--" + str(req).lower()) or (parser.has_option("--" + str(req).lower()) == "" and not getrequirements) :
                val=parser.get_option("--" + str(req).lower())
                if option_dict.get(str(req).lower(), False):
                    retvals[str(req).lower()]=option_dict[str(req).lower()]
                    printdebug(self.name + ":requirements", "passing option " + req + " with data: " + retvals[str(req).lower()])
                    continue
            if parser.has_option(req) or (parser.has_option(req) == "" and not getrequirements) :
                val=parser.get_option(req)
                if option_dict[req]:
                    retvals[req]=option_dict[req]
                    printdebug(self.name + ":requirements", "passing option " + req + " with data: " + retvals[req])
                    continue
            if parser.has_option(str(req).lower()) or (parser.has_option(str(req).lower()) == "" and not getrequirements) :
                val=parser.get_option(str(req).lower())
                if option_dict[str(req).lower()]:
                    retvals[str(req).lower()]=option_dict[str(req).lower()]
                    printdebug(self.name + ":requirements", "passing option " + req + " with data: " + retvals[str(req).lower()])
                    continue
            if req=="account":
                printverbose(self.name + ":requirements", "Trying to work around 'account' weirdness in --multiple.")
                if self.reqdata.get("AccountId"):
                    #may be in a --multiple, and have to pull the actual column name.
                    retvals[req] = self.reqdata["AccountId"]
                    printdebug(self.name + ":requirements", "using AccountId instead of account.")
                    continue
                if self.reqdata.get("AccountID"):
                    #may be in a --multiple, and have to pull the actual column name.
                    retvals[req] = self.reqdata["AccountID"]
                    printdebug(self.name + ":requirements", "using AccountID instead of account.")
                    continue
                if self.reqdata.get("ManagedAccountID"):
                    #may be in a --multiple, and have to pull the actual column name.
                    retvals[req] = self.reqdata["ManagedAccountID"]
                    printdebug(self.name + ":requirements", "using ManagedAccountID instead of account.")
                    continue
                if self.reqdata.get("ManagedAccountId"):
                    #may be in a --multiple, and have to pull the actual column name.
                    retvals[req] = self.reqdata["ManagedAccountId"]
                    printdebug(self.name + ":requirements", "using ManagedAccountId instead of account.")
                    continue
                elif self.reqdata.get("AccountName"):
                    #may be in a --multiple, and have to pull the actual column name.
                    # look up "AccountName" here, in case we're doing "create" and want input and output to match
                    retvals[req] = self.reqdata["AccountName"]
                    printdebug(self.name + ":requirements", "using AccountName instead of account.")
                    continue
                else:
                    printverbose(self.name + ":requirements", "have requirements: {0}".format(self.reqdata))
            if req=="system":
                printverbose(self.name + ":requirements", "Trying to work around 'system' weirdness in --multiple.")
                if self.reqdata.get("SystemId"):
                    # may be in a --multiple loop and have to pull the actual column name.
                    retvals[req] = self.reqdata["SystemId"]
                    printdebug(self.name + ":requirements", "using SystemID instead of system.")
                    continue
                elif self.reqdata.get("ManagedSystemId"):
                    retvals[req] = self.reqdata["ManagedSystemId"]
                    printdebug(self.name + ":requirements", "Using ManagedSystemId instead of system.")
                    continue
                elif self.reqdata.get("ManagedSystemID"):
                    retvals[req] = self.reqdata["ManagedSystemID"]
                    printdebug(self.name + ":requirements", "Using ManagedSystemId instead of system.")
                    continue
                elif self.reqdata.get("AssetId"):
                    retvals[req] = self.reqdata["AssetId"]
                    printdebug(self.name + ":requirements", "Using AssetId instead of system.")
                    continue
                elif self.reqdata.get("AssetID"):
                    retvals[req] = self.reqdata["AssetID"]
                    printdebug(self.name + ":requirements", "Using AssetID instead of system.")
                    continue
                elif self.reqdata.get("AssetName"):
                    retvals[req] = self.reqdata["AssetName"]
                    printdebug(self.name + ":requirements", "Using AssetName instead of system.")
                    continue
                elif self.reqdata.get("SystemName"):
                    # if we're creating systems with --multiple, allow column name of "SystemName" to match output
                    retvals[req] = self.reqdata["SystemName"]
                    printdebug(self.name + ":requirements", "Using SystemName instead of system.")
                    continue
                else:
                    printverbose(self.name + ":requirements", "have requirements: {0}".format(self.reqdata))
            if req in option_dict and option_dict.get(req, False) is not None:
                retvals[req]=option_dict[req]
                printdebug(self.name + ":requirements", "passing option_dict native: {0} with data {1}.".format(req, option_dict[req]))
                continue
            if parser.has_option("--defaults"):
                printdebug(self.name + ":requiremeents", "--defaults exists as an option.")
                val=parser.get_option("--defaults")
                if option_dict["defaults"]:
                    printdebug(self.name + "requirements", "was passed --defaults, looking for {0}".format(req))
                    if self.defaults.get(req, None) is not None:
                        retvals[req]=self.defaults[req]
                        printdebug(self.name + ":requirements", "passing default {0} with data: {1}.".format(req, self.defaults[req]))
                        continue
                    #if self.defaults[req.lower()]:
                    #    retvals[req.lower()]=self.defaults[req.lower()]
                    #    printdebug(self.name + ":requirements", "passing default {} with data: {}.".format(req, self.defaults[req]))
                    #    continue
                    # this should be impossible
                    printwarn(self.name + ":requirements", "have --defaults, but no default for this value!")
            printinfo(self.name + ":requirements", "missing option '{0}'. Please run -t type -a help action".format(req))
            if gInteractive and not options.show and getrequirements:
                typeok=False
                while not typeok:
                    try:
                        retvals[req]=input("Please enter the {0}: ".format(req))
                    except NameError:
                        retvals[req]=raw_input("Python 2 requires you to again: Please enter the {0}: ".format(req))
                    except SyntaxError:
                        retvals[req]=""
                        #Python2 raises "SyntaxError: unexpected EOF while parsing" if you enter a blank value for input()
                    try:
                        retvals[req]=reqlist[req](retvals[req])
                        typeok=True
                    except ValueError:
                        print("Wrong value type, need: {0}.".format(reqlist[req]))
            elif (not options.show) and getrequirements:
                printerror(self.name + ":requirements", "Missing requirement {0}, perhaps others, cannot continue!".format(req))
                sys.exit(4)
        # It'd be nice to move the "exit if options.show:" logic to callPbps, but you get a TON of keyerrors, so for now,
        # --show may be incomplete
        printdebug(self.name + ":checkRequirements", "Returning: {0}".format(retvals))
        if options.show:
            printdebug(self.name + ":requirements", "End of required arguments.")
            #sys.exit(2)
        return retvals

    def listObjects(self,  **kwargs):
        printdebug(self.name + ":listObjects", "receieved kwargs: " + str(kwargs))
        kwargs.update({'verb': kwargs.get("verb", "GET")})
        result = self.callPbps(**kwargs)
        if not result:
            printerror(self.name + ":listObjects", "Unable to call " + self.baseurl + kwargs["stub"] + " !")
            return result
        self.doprint(**kwargs)

        printdebug(self.name + ":listObjects", str(self))
        return self.r

    def signAppin(self):
        gAuth["auth"]=True  #set this so that we *can* call into callPbps
        printinfo(self.name + ":signAppin", "Using pbpsapi.py version {0}".format(gVers))
        printdebug(self.name + ":signAppin", "Signing in to PBPS.")
        stub="/Auth/SignAppin"
        printdebug(self.name + ":signAppin", " Signing in using url " + self.baseurl + stub)
        result=self.callPbps(verb="POST", stub=stub)
        gAuth["auth"]=result
        if gAuth["auth"] is True:
            printinfo(self.name + ":signAppin", "Successfully logged in...")
            self.result=True
            gAuth["cookies"]=self.r.cookies
        else:
            printwarn(self.name + ":signAppin", "Failed to log in.")
            self.result=False
        return self.result

    def doprint(self, **kwargs):
        global logsep
        printdebug(self.name + ":doprint", "entering doprint() method.")
        if kwargs.get("doprint", True) == True:
            printdebug(self.name + ":doprint", "supposed to print this.")
            printdebug(self.name + ":doprint", str(self.r.json()))
            fields=self.fields
            if options.format=="json":
                try:
                    print(self.r.json())
                except brokenpipeerror:
                    sys.exit(0)
                return
            if kwargs.get("keyname", False):
                fields=[kwargs["keyname"]]
            if kwargs.get("keyid", False):
                fields.insert(0, kwargs["keyid"])
            if self.printheader:
                try:
                    print(logsep.join(fields))
                except brokenpipeerror:
                    #capturig head -0 or grep or whatever
                    sys.exit(0)
                self.printheader = False
            try:
                x=self.r.json()[fields[0]]
                self.doprintline(fields=fields, json=self.r.json(), **kwargs)
            except TypeError:
                printdebug(self.name + ":doprint", "I think we're printing a list? {0}".format(self.r.json()))
                for line in self.r.json():
                    self.doprintline(fields=fields, json=line, **kwargs)
        else:
            printdebug(self.name + ":doprint", "kwargs said don't print.")

    def doprintline(self, fields, json, **kwargs):
            line=""
            if searchdatare is not None:
                if options.searchfield:
                    result=searchdatare.search(str(json[options.searchfield]))
                else:
                    result=searchdatare.search(str(json))
                if not result:
                    printdebug(self.name + ":doprint", "no field matched the --searchdata regex, ignoring.")
                    return None
            else:
                printdebug(self.name + ":doprint", "searchdatare is None.")
            for field in fields:
                data=""
                try:
                    data=str(json[field])
                except KeyError:
                    data="Null"
                except TypeError:
                    printerror(self.name + ":doprint", "Got a TypeError trying to print field {0}!".format(field))
                    printerror(self.name + ":doprint", str(self.r.json()))
                    printerror(self.name + ":doprint", "Did you try to print a list of a list instead of an object?")
                    sys.exit(16)
                if data.find(logsep)>-1:
                    if data.find('"'):
                        data="'{0}'".format(data)
                    else:
                        data="\'{0}\'".format(data)
                line=line + data + logsep
            line.rstrip(logsep)
            try:
                print(line)
            except brokenpipeerror:
                #capture head -2 or grep or whatever
                sys.exit(0)


    def printusererror(self, **kwargs):
        if kwargs.get("doprint", True) == True and not self.result:
            printerror(self.name, "Failed with error " + str(self.r.status_code) + ": " + self.responses[self.r.status_code]['description'])
            if self.responses[self.r.status_code]['data']:
                printerror(self.name, self.r.text)
    #        else:
    #            printerror(self.name, self.r.text)
    #            self.signAppout()


    def signAppout(self):
        exitcode=0
        stub="/Auth/Signout"
        try:
            exitcode=self.r.status_code
            if 200<=exitcode<300:
                printverbose(self.name + ":signAppout", "casting HTTP success status code {0} to 0 for unix 'success' handling.".format(exitcode))
                exitcode=0;
                #recast all 2xx HTTP status codes to "0" success in Unix.
            else:
                printdebug(self.name + ":signAppout", "Returning HTTP status code {0} directly.".format(exitcode))
                if self.responses[self.r.status_code]['data']:
                    printinfo(self.name + ":signAppout", "Status code {0} has more data.: '{1}'.".format(exitcode, self.r.text))
        except AttributeError:
            exitcode=501
            printdebug(self.name + ":signAppout", "self.r.status_code didn't exist, probably because it wasn't initialized due to a failure in a dependency. Signing out normally, returning 501 instead of actual HTTP code.")

        # this is commented out, because they will probably be destroyed when we close at the end of the script
        #printverbose(self.name, "Signing out using url " + url)
        result=self.callPbps(verb="POST", stub=stub)
        sys.exit(exitcode)
        return result  #fallback in case sys.exit stops working

    def __nonzero__(self):  #support Python 2
        if type(self.result)!=type(None) and type(self.result)!=bool:
            printdebug(self.name + "__bool__", "Object True/False status requested. (Python2), returning: "+ str(self.responses[self.r.status_code]['result']))
            return self.responses[self.r.status_code]['result']
        else:
            return self.result
    def __bool__(self):   #support Python 3
        return self.__nonzero__()

    def __str__(self):
        if not getattr(self, "r", False):
            return ""
        if self.responses[self.r.status_code]['data']:
            printdebug(self.name + ":__str__", "response status code indicaes more data to come...")
            return self.r.text
        else:
            printdebug(self.name + ":__str__", "response status code indicates no more data.")
            return self.responses[self.r.status_code]['description']

#    def __del__(self):
#        # on destruction, we need to log out
#        # no debugging, since we can't be sure external functions still exist.
#        #TODO: Make this work in Python3, not just 2 (commented out since it blows up in 3 - 1.0.0 RCA
#        # TODO: now that the program shares credentials, we can probably delete this idea entirely? 2.4.0 - 20161127 RCA
#        self.signAppout()

class test(PbpsObject):
    def __init__(self, name):
        PbpsObject.__init__(self, name)
        self.actions.update({
            "test": self.test,
            }
            )
        self.id = None
        self.help = '''
Test module - verifies that the API is available on the endpoint you're using.
list: Will report success even if the usernmame/password is wrong.
signAppin: will report success only if username/key are right.


'''

    def test(self, **kwargs):
        if self.signAppin(**kwargs):
            return True

class attributetype(PbpsObject):
    def __init__(self, name):
        PbpsObject.__init__(self, name)
        self.actions.update({
            "list": self.listAT,
            "getById": self.getById,
            "getByName": self.getByName,
            "get": self.get,
            }
            )
        self.help = '''
    List or retrieve Functional Accounts available in PBPS.
    Users need the Functional Account ID for adding ManagedAssets

    Requires: Attribute Management (Read) (or maybe Write)
'''
        self.fields=[
                "AttributeTypeID",
                "Name",
                "IsReadOnly",
                ]

    def listAT(self, **kwargs):
        printdebug(self.name + ":list", "Entering...")
        kwargs["stub"]="/AttributeTypes"
        return self.listObjects(**kwargs)

    def getById(self, **kwargs):
        printdebug(self.name + ":getById", "Entering...")
        senddata=self.checkRequirements({"attributetype": int})
        kwargs["stub"]="/AttributeTypes/{0}".format(senddata["attributetype"])
        result = self.callPbps(verb="GET", **kwargs)
        if result:
            self.id=self.r.json()["AttributeTypeID"]
            self.name=self.r.json()["Name"]
            self.doprint(**kwargs)
        return result

    def get(self, **kwargs):
        printdebug(self.name + ":get", "Entering...")
        try:
            if self.id:
                return self
        except AttributeError:
            printverbose(self.name + ":get", "Not initialized, doing so...")
        senddata=self.checkRequirements({"attributetype": str})
        self.reqdata=senddata
        try:
            senddata["attributetype"]=int(senddata["attributetype"])
            printverbose(self.name + ":get", "Was passed an ID, so searching for that attributeType by ID.")
            return self.getById(**kwargs)
        except ValueError:
            printinfo(self.name + ":get", "was passed a name, so searching for that attribute Type.")
            return self.getByName(**kwargs)


    def getByName(self, **kwargs):
        printdebug(self.name + ":getByName", "Entering...")
        senddata=self.checkRequirements({"attributetype": str})
        # have already returned inside the try, so this is all post-exception...
        olddoprint=kwargs.get("doprint", True)
        kwargs["doprint"]=False
        printdebug(self.name + ":listAttributes", "Updating doprint from {0} to False".format(olddoprint))
        attTypes=self.listAT(**kwargs)
        kwargs["doprint"]=olddoprint
        if attTypes:
            printverbose(self.name + ":getByName", "Got a list of attributeTypes, enumerating to find " + senddata["attributetype"])
            for atttype in self.r.json():
                printdebug(self.name + ":getByName", str(atttype))
                printdebug(self.name + ":getByName", "comparing {0} to {1}.".format(atttype["Name"], senddata["attributetype"]))
                if atttype["Name"] == senddata["attributetype"]:
                    #self.id = int(atttype["AttributeTypeID"])
                    self.reqdata["attributetype"]=atttype["AttributeTypeID"]
                    result = self.getById(**kwargs)
                    self.doprint(**kwargs)
                    return self.id
            printerror(self.name + ":get", "Could not find attributetype: {0} by name in the list of attribute Types.".format(senddata["attributetype"]))
        else:
            printerror(self.name + ":get", "Could not enumerate assets to find {0} by name.".format(senddata["attributetype"]))

        return False


    ## TODO Add Create and Delete

class attribute(PbpsObject):
    def __init__(self, name):
        PbpsObject.__init__(self, name)
        self.actions.update({
            "addToAsset": self.addToAsset,
            "addtoasset": self.addToAsset,
            "add": self.addToAsset,
            "deleteall": self.deleteAllFromAsset,
            "deletefromasset": self.deleteFromAsset,
            "get": self.get,
            "getByAsset": self.getByAsset,
            "getById": self.getById,
            "getByName": self.getByName,
            "list": self.listAttributes,
            "create": self.create,
            }
            )
        self.help = '''
    List or retrieve Attributes available in PBPS.
    Users need the Attribute ID for adding attributes to
    an asset.

    Requires: Attribute Management (Read/Write, depending)
'''
        self.fields=[
                "AttributeID",
                "AttributeTypeID",
                "ParentAttributeID",
                "ShortName",
                "LongName",
                "Description",
                "ValueInt",
                "isReadOnly",
                ]
        self.defaults={
                "attributetype": gAttributeType,
                }

    def addToAsset(self, **kwargs):
        printdebug(self.name + ":addToAsset", "Entering...")
        senddata=self.checkRequirements({"system": str, "attribute":str})
        myasset=asset(senddata["system"])
        myasset.reqdata=senddata
        result=myasset.getAsset(doprint=False, **kwargs)
        if not result:
            printerror(self.name + ":addToAsset", "Could not find asset, bailing!")
            return result
        myattr=self.get(**kwargs)
        if not myattr:
            printerror(self.name + ":addToAsset", "COuld not find attribute ID, bailing!")
            return False
        kwargs["stub"]="/Assets/{0}/Attributes/{1}".format(myasset.id, self.id)
        result=self.callPbps(verb="POST", **kwargs)
        if not result:
            printerror(self.name + ":addToAsset", "Failed adding attribute to asset {0}".format(myasset.name))
            return result
        else:
            if options.multiple:
                myasset.doprint(**kwargs)
            else:
                print("Successfully added attribute {0} to asset: {1}.".format(self.name, myasset.name))
            return True

    def create(self, **kwargs):
        printdebug(self.name + ":create", "Entering...")
        self.senddata=self.checkRequirements({"shortname":str, "longname":str, "description":str, "attributetype":str})
        self.attributetype=attributetype(self.senddata["attributetype"])
        self.attributetype.reqdata=self.senddata
        result=self.attributetype.get(doprint=False)
        if not result:
            printerror(self.name + ":create", "Could not get attribute type, bailing!!")
            return False
        kwargs["stub"]="/AttributeTypes/{0}/Attributes".format(self.attributetype.id)
        kwargs["verb"]="POST"
        self.data={"ShortName": self.senddata["shortname"],
                "LongName": self.senddata["longname"],
                "Description":self.senddata["description"],
                }
        result=self.callPbps(**kwargs)
        if result:
            self.doprint()
        return result

    def deleteAllFromAsset(self, **kwargs):
        printdebug(self.name + ":deleteAllFromAsset", "Entering...")
        senddata=self.checkRequirements({"system":str})
        myasset=asset(senddata["system"])
        myasset.reqdata=senddata
        result = myasset.getAsset(doprint=False, **kwargs)
        if not result:
            printerror(self.name + ":deleteAllFromAsset", "Failed to find asset, bailing!")
            return result
        kwargs["stub"]="/Assets/{0}/Attributes".format(myasset.id)
        result=self.callPbps(verb="DELETE", **kwargs)
        if not result:
            printerror(self.name + ":deleteAllFromAsset", "Failed to delete attributes from asset {0}!".format(myasset.name))
            printerror(self.name + ":deleteAllFromAsset", self.r.text)
            return result
        else:
            if options.multiple:
                self.doprint(**kwargs)
            else:
                print("Successfully deleted all attributes from asset {0}.".format(myasset.name))

    def deleteFromAsset(self, **kwargs):
        printdebug(self.name + ":deleteFromAsset", "Entering...")
        senddata=self.checkRequirements({"system":str, "attribute": str})
        myasset=asset(senddata["system"])
        myasset.reqdata=senddata
        saveprint=kwargs.get("doprint", True)
        kwargs["doprint"]=False
        result = myasset.getAsset(**kwargs)
        if not result:
            printerror(self.name + ":deleteFromAsset", "Failed to find asset, bailing!")
            return result
        self.reqdata=senddata
        result=self.get(**kwargs)
        if not result:
            printerror(self.name + ":deleteFromAsset", "Failed to find attribute id, bailing!")
        kwargs["stub"]="/Assets/{0}/Attributes/{1}".format(myasset.id, self.id)
        result=self.callPbps(verb="DELETE", **kwargs)
        kwargs["doprint"]=saveprint
        if not result:
            printerror(self.name + ":deleteAllFromAsset", "Failed to delete attributes from asset {0}!".format(myasset.name))
            printerror(self.name + ":deleteAllFromAsset", self.r.text)
            return result
        else:
            if options.multiple:
                myasset.doprint(**kwargs)
            else:
                print("Successfully deleted all attributes from asset {0}.".format(myasset.name))


    def get(self, **kwargs):
        printdebug(self.name + ":get", "Entering...")
        if self.id:
            return self
        senddata=self.checkRequirements({"attribute":str})
        self.reqdata=senddata
        try:
            senddata["attribute"]=int(senddata["attribute"])
            printverbose(self.name + ":get", "Was passed an ID, so searching for that attributeType by ID.")
            return self.getById(**kwargs)
        except ValueError:
            printinfo(self.name + ":get", "was passed a name, so searching for that attribute.")
            return self.getByName(**kwargs)

    def getByAsset(self, **kwargs):
        printdebug(self.name + ":getByAsset", "Entering...")
        senddata=self.checkRequirements({"system":str})
        myasset=asset(senddata["system"])
        myasset.reqdata=senddata
        result=myasset.getAsset(doprint=False, **kwargs)
        if not result:
            printerror(self.name + ":GetByAsset", "Could not find asset, bailing!")
            return result
        kwargs["stub"]="/Assets/{0}/Attributes".format(myasset.id)
        self.listObjects(**kwargs)

    def getById(self, **kwargs):
        printdebug(self.name + ":getById", "Entering...")
        if self.id:
            printdebug(self.name + ":getById", "Already initialized, returning self.")
            return self
        senddata=self.checkRequirements({"attribute": str})
        try:
            senddata["attribute"]=int(senddata["attribute"])
        except ValueError:
            printerror(self.name + ":getById", "Attribute field is not a number, can't use for this function.")
            return False
        kwargs["stub"]="/Attributes/{0}".format(senddata["attribute"])
        result = self.callPbps(verb="GET", **kwargs)
        if result:
            self.id=self.r.json()["AttributeID"]
            self.name=self.r.json()["ShortName"]
            self.doprint(**kwargs)
        return result


    def getByName(self, **kwargs):
        printdebug(self.name + ":getByName", "Entering...")
        senddata=self.checkRequirements({"attributetype": str, "attribute":str})
        # have already returned inside the try, so this is all post-exception...
        olddoprint=kwargs.get("doprint", True)
        kwargs["doprint"]=False
        printdebug(self.name + ":getByName", "Storing olddoprint as {0}.".format(olddoprint))
        attributes=self.listAttributes(**kwargs)
        kwargs["doprint"]=olddoprint
        if attributes:
            printverbose(self.name + ":getByName", "Got a list of attributes, enumerating to find " + senddata["attribute"])
            for atttype in self.r.json():
                printdebug(self.name + ":getByName", "comparing {0} to {1}.".format(atttype["ShortName"], senddata["attribute"]))
                if atttype["ShortName"] == senddata["attribute"]:
                    self.reqdata["attribute"]=atttype["AttributeID"]
                    printverbose(self.name + ":getByName", "Matched by ShortName.")
                    result = self.getById(**kwargs)
                    # self.doprint(**kwargs) Not needed, because self.getById() will do it for us.
                    return self.id
                printdebug(self.name + ":getByName", "comparing {0} to {1}.".format(atttype["LongName"], senddata["attribute"]))
                if atttype["LongName"] == senddata["attribute"]:
                    self.reqdata["attribute"]=atttype["AttributeID"]
                    printverbose(self.name + ":getByName", "Matched by LongName.")
                    result=self.getById(**kwargs)
                    #self.doprint(**kwargs) not needed, because self.getById() will do it for us.
                    return self.id
            printerror(self.name + ":getByName", "Could not find attribute: {0} by name in the list of attributes .".format(senddata["attribute"]))
        else:
            printerror(self.name + ":getByName", "Could not enumerate assets to find {0} by name.".format(senddata["attributetype"]))
        return False

    def listAttributes(self, **kwargs):
        global attType
        senddata=self.checkRequirements({"attributetype":str})
        try:
            if attType.id:
                printinfo(self.name + ":listAttributes", "Found AttributeType by ID already initialized.")
        except AttributeError:
            attType=attributetype(senddata["attributetype"])
            attType.reqdata.update({"attributetype": senddata["attributetype"]})
            olddoprint=kwargs.get("doprint", True)
            kwargs["doprint"]=False
            printdebug(self.name + ":listATtributes", "Updating doprint from {0} to False".format(olddoprint))
            attributetypeid=attType.get(**kwargs)
            kwargs["doprint"]=olddoprint
        if not attType.id:
            printerror(self.name + ":listAttribute", "Could not get AttributeType ID from name.")
            self.result=False
            return False
        #self.reqdata.update({"AttributeTypeID": attributetypeid})
        kwargs["stub"]="/AttributeTypes/{0}/Attributes".format(attType.id)
        return self.listObjects(**kwargs)



class asset(PbpsObject):
    global wg, gIPAddress, gMacAddress
    def __init__(self, name):
        global wg
        PbpsObject.__init__(self, name)
        self.actions.update({
            "list": self.listAssets,
#            "getAssetByName": self.getAssetByName,
            "getbyid": self.getAssetById,
            "getById": self.getAssetById,
            "getAsset": self.getAsset,
            "get": self.getAsset,
            "search" : self.searchAssets,
            "searchAssets": self.searchAssets,
            "delete": self.deleteAsset,
            "create": self.createAsset,
            "new": self.createAsset,
            "srlist": self.listBySmartRule,
            "listBySmartRule": self.listBySmartRule,
            }
            )
        self.fields=[
                "AssetID",
                "AssetName",
                "DnsName",
                "DomainName",
                "IPAddress",
                "MacAddress",
                "AssetType",
                "WorkgroupID",
                ]
        self.id=None
        self.wg=wg
        self.try2=False
        self.dnsname=""
        self.defaults={
                "dnsname": self.name,
                "ipaddress": gIpAddress,
                "macaddress": gMacAddress,
                "workgroup": gWorkgroup,
                }
        self.help = '''
     List, create, retrive, or print BeyondInsight Asset Information
      That API user has rights to.

      See the 'Assets' Section of the PBPS API Guide.
        Requires permissions: Asset Management
'''
    def createAsset(self, **kwargs):
        printdebug(self.name + ":createAsset", "Entering...")
        self.reqdata=self.checkRequirements({"workgroup":str, "system":str, "ipaddress":str, "macaddress":str, "dnsname":str})
        #self.reqdata.update(self.checkOptions({"dnsname":str}))
        if self.id:
            printwarn(self.name + ":createAsset", "Already initialized and have an ID, nothing to do.")
            return False
        if hasattr(self.wg, "id"):
            printverbose(self.name + ":createAsset", "Have a workgroup id: " + str(self.wg.id) + ", continuing.")
        else:
            wgdata=self.reqdata
            if not self.wg:
                self.wg = workgroup(wgdata["workgroup"])
            self.wg.reqdata=wgdata
            if kwargs.get("doprint", False):
                kwargs.update({"doprint": False})
                result = self.wg.getWorkgroupId(doprint=False, **kwargs)
                kwargs.update({"doprint": True})
            elif kwargs.get("doprint", None) is None:
                result = self.wg.getWorkgroupId(doprint=False, **kwargs)
            else:
                result = self.wg.getWorkgroupId(**kwargs)
            if not result:
                printerror(self.name + ":createAsset", "Failed to get a workgroup ID, bailing!")
                printerror(self.name + ":createAsset", self.wg.r.json())
                return result
            printverbose(self.name + ":createAsset", "obtained workgroup id: " + str(self.wg.id) + ", continuing.")
        #self.reqdata.update(self.senddata)
        self.data=self.reqdata
        self.data.update({
                "AssetName": self.data["system"],
                })
        if (not "DNSName" in self.data and not "dnsname" in self.data) or (not self.data.get("DNSName", False) and not self.data.get("dnsname", False)):
            printverbose(self.name + ":createAsset", "No DNSName passed in CLI, so we'll use the asset name.")
            self.data.update({
                    "DNSName": self.data["system"],
                    })
        if self.data["ipaddress"] == "1.1.1.1":
            printinfo(self.name + ":createAsset", "Trying to look up an ip instead of 1.1.1.1.")
            ipaddress=None
            try:
                ipaddress=socket.gethostbyname(self.data["system"])
            except socket.gaierror:
                ipaddress=""
            if ipaddress:
                self.data["ipaddress"] = ipaddress
                printinfo(self.name + ":createAsset", "Found IP {0} for asset, using that.".format(ipaddress))
        printverbose(self.name + ":createAsset", "all required values obtained, trying to create...")
        kwargs.update({"stub": "/Workgroups/" + str(self.wg.id) + "/Assets", "verb": "POST", "data": self.data})
        result=self.callPbps(**kwargs)
        if result:
            if not options.multiple:
                print("Success creating asset: " + self.data["system"])
            self.getAsset(system=self.r.json()["AssetID"], doprint=kwargs.get("doprint", True), workgroup=self.wg.id)
        return result


    def deleteAsset(self, **kwargs):
        printdebug(self.name + ":deleteAsset", "Entering...")
        if self.id:
            printinfo(self.name + ":deleteAsset", "Already initialized, deleting self...")
            return deleteAssetById(**kwargs)
        else:
            senddata=self.checkRequirements({"system":str})
            result = self.getAsset(doprint=False)
            if result:
                printinfo(self.name + ":deleteAsset", "Found asset, now deleting it...")
                return self.deleteAssetById(**kwargs)
            else:
                printwarn(self.name + ":deleteAsset", "Asset not found, nothing to delete.")
                return False


    def deleteAssetById(self, **kwargs):
        printverbose(self.name + ":deleteAsset", "Already initialized, deleting self...")
        kwargs.update({'stub': "/Assets/" + str(self.id), 'verb':"DELETE"})
        result=self.callPbps(**kwargs)
        if result:
            if kwargs.get("doprint", True) == True and not options.multiple:
                print("Successfully deleted asset name: " + self.dnsname + " with ID: " + str(self.id))
            self.id=None
            self.wg=None
            self.dnsname=""
            return result
        else:
            printerror(self.name + ":deleteAsset", "Could not delete assset " + self.dnsname + "!!!")
            return result


    def getAsset(self, **kwargs):
        senddata=self.checkRequirements({"system":str})
        printdebug(self.name + ":getAsset", "Entering...")
        if self.id:
            printinfo(self.name + ":getAsset", "Was asked to return an asset, have already been initialized, so returning self.")
            return self.id
        if senddata["system"].isdigit():
            printinfo(self.name + ":getAsset", "was asked to return an asset, lookingup by ID.")
            kwargs.update({'AssetID': senddata["system"]})
            return self.getAssetById(**kwargs)
        else:
            printinfo(self.name + ":getAsset", "must be asked to lookup an asset by name...")
            kwargs.update({'AssetName': senddata["system"]})
            return self.getAssetByName(**kwargs)

    def getAssetById(self, **kwargs):
        printdebug(self.name + ":getAssetById", "Entering...")
        if self.id:
            printverbose(self.name + ":getById", "Already initialized, returning current Id")
            return self.id
        self.reqdata.update(kwargs)
        self.reqdata.update(self.checkRequirements({"system":int}))
        self.reqdata["AssetID"] = self.reqdata["system"]
        kwargs.update({'stub':"/Assets/{0}".format(self.reqdata["AssetID"])})
        result=self.callPbps(verb="GET", **kwargs)
        printdebug(self.name + ":getById", str(self.r.json()))
        if result:
            self.id=self.r.json()["AssetID"]
            self.dnsname = self.r.json()["DnsName"]
            if not hasattr(self.wg, "id"):
                self.wg = workgroup(self.r.json()["WorkgroupID"])
            self.doprint(**kwargs)
            #if kwargs.get("doprint", "yes") == "yes":
            #    print(self.r.json()["AssetName"] + ": " + self.dnsname + " (" + str(self.id) + ")")
            return self.id
        return None

    def getAssetByName(self, **kwargs):
        printdebug(self.name + ":getAssetByName", "Entering...")
        if self.id:
            printverbose(self.name + ":getAssetByName", "Already initialized, returning current id")
            return self.id
        senddata=kwargs
        senddata=self.checkRequirements({"system": str, "workgroup":str})  #overloading "--system" with "--asset" to get the asset name. Fewer options to parse
        senddata["AssetName"] = senddata["system"] #sync the overload for the API JSON
        if hasattr(self.wg, "id"):
            if hasattr(self.wg, "senddata"):
                self.wg.senddata.update({"workgroup": wg.name})
            else:
                self.wg.senddata=senddata
        else:
            printinfo(self.name + ":getAssetByName", "wg exists, but it is False or None, so, we need to initialize it.")
            self.wg=workgroup(senddata["workgroup"])
            self.wg.reqdata=senddata

        #wg.senddata.update({"workgroupname": wg.name})
        workgroupname=self.wg.getWorkgroupName(workgroup=self.wg.name, doprint=False)
        printdebug(self.name + ":getAssetByName", "Using workgroup name: " + self.wg.name + ", with id: " + str(self.wg.id))

        kwargs.update({'stub':"/Workgroups/{0}/Assets/{1}".format(self.wg.name, senddata["system"])})
        self.reqdata.update(senddata)
        result=self.callPbps(verb="GET", **kwargs)
        if result:
            printdebug(self.name + ":getAssetByName", str(self.r.json()))
            printinfo(self.name + ":getAssetByName", "Got a result for lookup by name: {0}!!!".format(senddata["system"]))
            self.id=self.r.json()["AssetID"]
            self.dnsname=self.r.json()["DnsName"]
            if not hasattr(self.wg, "id"):
                self.wg = self.wg.id=self.r.json()["WorkgroupID"]
                pass
            else:
                self.wg = workgroup(self.r.json()["WorkgroupID"])
                self.wg.id=self.r.json()["WorkgroupID"]
            #self.doprint(**kwargs)
            #if kwargs.get("doprint", "yes") == "yes":
            #    print(self.dnsname + " (" + str(self.id) + ")")
            return self.id
        else:
            if senddata["AssetName"].find(".") > -1 and not self.try2:
                printwarn(self.name + ":getAssetByName", "Failed to get a result. May be because of name (dns vs short) or IP construct confusion...")
                parts=senddata["AssetName"].split('.')
                printdebug(self.name + ":getAssetByName", "trying a second time with : " + parts[0] + ", originally had: " + senddata["system"])
                try:
                    parts[0]=int(parts[0])
                    parts[1]=int(parts[1])
                    parts[2]=int(parts[2])
                    parts[3]=int(parts[3])
                    # all of this is in the try block, because it only gets run if we have an IP address.
                    newip=""
                    #they entered an IP address, so pad the numbers with 0s...
                    printverbose(self.name + ":getAssetByName", "converting ip address from " + senddata["AssetName"])
                    for x in parts:
                        if x < 10:
                            newip=newip + "00"+str(x)
                        elif x < 100:
                            newip=newip + "0" + str(x)
                        else:
                            newip=newip + str(x)
                        newip = newip + "."
                    newip=newip.strip(".")
                    printverbose(self.name + ":getAssetByName", "... complete, trying now with name: " + newip)
                    senddata.update({'system':newip, 'AssetName':newip})
                    self.reqdata.update({'system':newip, 'AssetName':newip})
                    kwargs.update({'system':newip, 'AssetName':newip})
                except ValueError:
                    printinfo(self.name + ":getAssetByName", "got a ValueError converting to IP address numbers, must have a DNS name.")
                    #they entered a DNS name. Let's try without it.
                    printverbose(self.name + ":getAssetByName", "converting from DNS name to short name...")
                    senddata.update({'system':parts[0], 'AssetName':parts[0]})
                    kwargs.update({'system': parts[0], 'AssetName': parts[0]})
                    self.reqdata.update(senddata)
                except IndexError:
                    printerror(self.name + ":getAssetByName", "Couldn't find by IP address either, giving up.")
                    printinfo(self.name + ":getAssetByName", "  Failed with IndexError on 2nd try of IP address parsing, this is normal.")
                    return None

                self.senddata=senddata
                printdebug(self.name + ":getAssetByName", "setting try2 to True., now running getAssetByname again with system: " + kwargs["system"])
                self.try2=True
                return self.getAssetByName(**kwargs)
        return None

    def listAssets(self, **kwargs):
        printdebug(self.name + ":listAssets", "Entering...")
        senddata=self.checkRequirements({"workgroup":str})
        if not senddata["workgroup"].isdigit() and not type(senddata["workgroup"]) is int:
            printverbose(self.name + ":listAssets", "workgroup is not an ID, looking it up")
            if hasattr(self.wg, "id"):
                workgroupid=self.wg.getWorkgroupId(workgroup=self.wg.name, doprint=False)
            else:
                self.wg=workgroup(senddata["workgroup"])
                self.wg.reqdata.update({"workgroup": self.wg.name})
                workgroupid=self.wg.getWorkgroupId(workgroup=self.wg.name, doprint=False)
            printdebug(self.name + ":ListAssets", "Using workgroup name: " + self.wg.name + ", with id: " + str(self.wg.id))
            if not workgroupid:
                printerror(self.name + ":listAssets", "Could not get workgroup ID from name.")
                self.result=False
                return False
            self.reqdata.update({"WorkgroupId": workgroupid})
        else:
            self.reqdata.update({"WorkgroupId": senddata["workgroup"]})
        if self.wg is None:
            self.wg=workgroup(senddata["workgroup"])
            self.wg.reqdata.update({"workgroup": senddata["workgroup"]})
            workgroupid=self.wg.getWorkgroupId(workgroup=senddata["workgroup"], doprint=False)
        elif not getattr(self.wg, "id", False):
            self.wg.id=self.reqdata["WorkgroupId"]
        #self.listObjects(stub="/Workgroups/" + str(wg.id) + "/Assets", keyname="DnsName", keyid="AssetID")
        # send through **kwargs in case "doprint="no"" is set.
        result=self.listObjects(stub="/Workgroups/{0}/Assets".format(self.wg.id), **kwargs)
        return result

    def listBySmartRule(self, **kwargs):
        printdebug(self.name + ":SRList", "Entering...")
        senddata=self.checkRequirements({"smartrule":str})
        sr=smartrule(senddata["smartrule"])
        sr.reqdata=senddata
        #srid=sr.getSmartRuleIdByName(doprint=False)
        result=sr.get(doprint=False)
        if not type(sr.id) is int:
            printinfo(self.name + ":SRList", "got SmartRule: {0} of type: {1}".format(sr.id, type(sr.id)))
            printerror(self.name + ":SRList", "Could not find a smart rule matching that name, bailing!")
            return False
        result=self.listObjects(stub="/SmartRules/{0}/Assets".format(sr.id), **kwargs)
        return result

    def searchAssets(self, **kwargs):
        printdebug(self.name + ":search", "Entering...")
        senddata=self.checkRequirements({"searchdata":str, "searchfield":str})
        self.data.update({senddata["searchfield"]: senddata["searchdata"], 'verb':"POST", 'stub':"/Assets/Search"})
        kwargs.update({'verb':"POST", 'stub':"/Assets/Search"})
        printdebug(self.name + ":search", "Calling listObjects with POST and search terms as data.")
        result = self.listObjects(**kwargs)
        return result



class smartrule(PbpsObject):
    def __init__(self, name):
        PbpsObject.__init__(self, name)
        self.actions.update({
            "listsmartrules": self.listSmartRules,
            "list": self.listSmartRules,
            "getRuleById": self.getSmartRuleById,
            "get": self.get,
            }
            )
        self.fields=[
                "SmartRuleID",
                "Title",
                "Description",
                "Category",
                "Status",
                "LastProcessedDate",
                "IsReadOnly",
                ]
        self.help = "\n\
     List, retrive, or print BeyondInsight SmartRule Information\n\
      That API user has rights to.\n\
        "

    def listSmartRules(self, **kwargs):
        self.listObjects(stub="/SmartRules", doprint=True, **kwargs)

    def get(self, **kwargs):
        printdebug(self.name + ":get", "Entering...")
        self.reqdata=self.checkRequirements({"smartrule":str})
        if self.reqdata["smartrule"].isdigit():
            printverbose(self.name + ":get", "Asked to look for a smartRule by ID")
            self.reqdata["smartruleid"]=self.reqdata["smartrule"]
            return self.getSmartRuleById(**kwargs)
        else:
            printverbose(self.name + ":get", "Asked to look for a smartRule by name")
            srid=self.getSmartRuleIdByName(**kwargs)
            if type(srid) is int:
                printinfo(self.name + ":get", "Found smartrule ID: {0}.".format(srid))
                self.reqdata["smartruleid"]=srid
                return self.getSmartRuleById(**kwargs)
        return False


    def getSmartRuleById(self, **kwargs):
        printdebug(self.name + ":getById", "Entering...")
        self.reqdata=self.checkRequirements({"smartruleid":int})
        kwargs["stub"]="/SmartRules/{0}".format(self.reqdata["smartruleid"])
        kwargs["verb"]="GET"
        result=self.callPbps(**kwargs)
        if result:
            self.doprint(**kwargs)
            self.id=self.r.json()["SmartRuleID"]
        return self.id

    def getSmartRuleIdByName(self, **kwargs):
        printdebug(self.name + ":getByName", "Entering...")
        self.reqdata=self.checkRequirements({"smartrule":str})
        printdebug(self.name + ":getByName", "Gathering list of SRs for current user.")
        if kwargs.get("doprint", False):
            kwargs.update({"doprint": False})
            result=self.listObjects(stub="/SmartRules", **kwargs)
            kwargs.update({"doprint": True})
        else:
            kwargs.update({"doprint": False})
            result=self.listObjects(stub="/SmartRules", **kwargs)
        if not result:
            printerror(self.name + ":getByName", "Could not retrieve a list of smartrules - does this user have access to any?")
            return False
        for sr in self.r.json():
            printdebug(self.name + ":getByName", "Looking at SR: {0}".format(sr))
            if sr["Title"] == self.reqdata["smartrule"]:
                printinfo(self.name + ":getByName", "Found matching SmartRule: {0}!".format(sr["SmartRuleID"]))
                self.id=sr["SmartRuleID"]
                return sr["SmartRuleID"]
        printwarn(self.name + ":getByName", "Listed all Smartrules, found no match for {0}.".format(self.reqdata["smartrule"]))
        return False


    def deleteSmartRuleById(self, **kwargs):
        self.reqdata=self.checkRequiresments(["id"])
        kwargs.update({stub:"/SmartRules/" + str(self.reqdata["id"]), verb: "DELETE"})
        callPbps(**kwargs)

class usergroup(PbpsObject):
    def __init__(self, name):
        PbpsObject.__init__(self, name)
        self.actions.update({
            "listgroups": self.listUserGroups,
            "list": self.listUserGroups,
            "get": self.get,
            "getId": self.getUserGroupIdFromName,
            "getById": self.get,
            }
            )
        self.fields=[
                "GroupID",
                "Name",
                "DistinguisedName",
                "GroupType",
                "AccountAttribute",
                "MembershipAttribute",
                ]
        self.help = '''
    List, retrive, or print BeyondInsight AuthGroup Information
      That API user has rights to.

    Requires: User Account Management (Read or Write, depending on operation)
        '''

    def listUserGroups(self, **kwargs):
        self.listObjects(stub="/UserGroups", **kwargs)

    def getUserGroupIdFromName(self, **kwargs):
        reqdata=self.checkRequirements({"account":str})
        kwargs["stub"]="/UserGroups/{0}".format(reqdata["account"])
        result=self.callPbps(verb="GET", **kwargs)
        if result:
            self.doprint(**kwargs)
        return result

    def get(self, **kwargs):
        # UserGroup search by name or ID has the same REST call in 6.2.2, don't need to differentiate here.
        return self.getUserGroupIdFromName(**kwargs)


class managedaccount(PbpsObject):
    def __init__(self, name):
        PbpsObject.__init__(self, name)
        self.actions.update({
            "list": self.listAccounts,
            "getIdsFromNames": self.getIdsFromNames,
            "getidsfromnames": self.getIdsFromNames,
            "listAccounts": self.listAccounts,
            "getById": self.getById,
            "get": self.get,
            "create": self.createManagedAccount,
            "delete": self.delete,
            }
            )
        self.id=None
        self.mansystem=None
        self.fields=[
                "ManagedAccountID",
                "ManagedSystemID",
                "AccountName",
                "DomainName",
                "DistinguishedName",
                "PasswordFallbackFlag",
                "LoginAccountFlag",
                "Description",
                "PasswordRuleID",
                "ApiEnabled",
                "ReleaseNotificationEmail",
                "ChangeServicesFlag",
                "RestartServicesFlag",
                "ReleaseDuration",
                "MaxReleaseDuration",
                "ISAReleaseDuration",
                "MaxConcurrentRequests",
                "AutoManagementFlag",
                "DSSAutoManagementFlag",
                "CheckPasswordFlag",
                "ResetPasswordOnMismatchFlag",
                "ChangePasswordAfterAnyReleaseFlag",
                "ChangeFrequencyType",
                "ChangeFrequencyDays",
                "ChangeTime",
                "IsSubscribedAccount",
                "LastChangeDate",
                "NextChangeDate",
                "IsChanging",
                ]
        printdebug(self.name + ":get", "Entering...")
        self.defaults={
                "password": gNewPassword,
                "description": self.name,
                "apienabled": gApiEnabled,
                "privatekey": gPrivateKey,
                "passphrase": gPassphrase,
                "passwordfallbackflag": gPasswordFallbackFlag,
                "loginaccountflag": gLoginAccountFlag,
                "passwordruleid": gPasswordRuleId,
                "releasenotificationemail" : gEmail,
                "changeservicesflag": gChangeServicesFlag,
                "restartservicesflag": gRestartServicesFlag,
                "releaseduration" : gReleaseDuration,
                "maxreleaseduration" : gMaxReleaseDuration,
                "isareleaseduration" : gIsaReleaseDuration,
                "automanagementflag": gAutoManagementFlag,
                "dssautomanagementflag": gDSSAutoManagementFlag,
                "checkpasswordflag": gCheckPasswordFlag,
                "resetpasswordonmismatchflag": gResetPasswordOnMismatchFlag,
                "changepasswordafteranyreleaseflag": gChangePasswordAfterAnyReleaseFlag,
                "changefrequencytype": gChangeFrequencyType,
                "changefrequencydays": gChangeFrequencyDays,
                "changetime": gChangeTime,
                }
        self.help = '''
     Create, Delete, List, retrive, or print BeyondInsight ManagedAccounts
      That API user has rights to.

      -a create requires approximately 20 values, check with --show
      -a delete can be passed only an account ID, or an account name and
         managed system name or ID.

      -a list  Will mostly only include managed accounts that user can check out.

    Requires PasswordSafe Account Management (Read/Write, depending).
        '''
        self.senddata={}

    def createManagedAccount(self, **kwargs):
        global manaccount
        global mansystem
        #APIWORKAROUND
        printdebug(self.name + ":createManagedAccount", "Entering...")
        if self.id:
            printwarn(self.name + ":createManagedAccount", "Already initialized, bailing!")
            return self.id
        printdebug(self.name + "createManagedAccount", "Calling checkRequirements...")
        self.reqdata=self.checkRequirements({
            "system":str,
            "account":str,
            "password":str,
            "privatekey":str,
            "passphrase":str,
            "passwordfallbackflag":bool,
            "loginaccountflag":bool,
            "description":str,
            "passwordruleid":int,
            "apienabled":bool,
            "releasenotificationemail":str,
            "changeservicesflag":bool,
            "restartservicesflag":bool,
            "releaseduration":int,
            "maxreleaseduration":int,
            "isareleaseduration":int,
            "automanagementflag":bool,
            "dssautomanagementflag":bool,
            "checkpasswordflag":bool,
            "resetpasswordonmismatchflag":bool,
            "changepasswordafteranyreleaseflag":bool,
            "changefrequencytype":str,
            "changefrequencydays":str,
            "changetime":str,
            })
        printdebug(self.name + "createManagedAccount", "Returned from checkRequirements...")
        if hasattr(self.mansystem, "id"):
            printverbose(self.name + ":createManagedAccount", "Have a managedSystemID: {0}, continuing.".format(self.mansystem.id))
        elif hasattr(mansystem, "id"):
            self.mansystem=mansystem
            printverbose(self.name + ":createManagedAccount", "global mansystem exists, using that.")
        else:
            #elif reqdata["system"].isdigit():
            # they already know the asset ID, so let's just get it.
            self.mansystem=managedsystem(self.reqdata["system"])
            self.mansystem.reqdata=self.reqdata
            self.mansystem.get(system=self.reqdata["system"], **kwargs)
        if not hasattr(self.mansystem, "id"):
            printerror(self.name + ":createManagedAccount", "Failed to find or create an asset, cannot continue!")
            return False
        self.reqdata["AccountName"]=self.reqdata["account"]
        kwargs.update({"stub": "/ManagedSystems/{0}/ManagedAccounts".format(self.mansystem.id), "verb": "POST", "data": self.reqdata})
        printdebug(self.name + ":createManagedAccount", "Calling callPbps after pulling requirements.")
        result = self.callPbps(**kwargs)
        if result:
            self.name = self.r.json()["AccountName"]
            self.id = self.r.json()["ManagedAccountID"]
            logline="Successfully created Managed Account: {0} on system: {1}".format(self.name, self.mansystem.id)
            if kwargs.get("doprint", True) and not options.multiple:
                print(logline)
            else:
                self.doprint(**kwargs)
                printinfo(self.name + ":createManagedAccount", logline)

            return result
        else:
            printwarn(self.name + ":createManagedAccount", "Failed to create ManagedAccount!")
            return result
        return False

    def delete(self, **kwargs):
        printdebug(self.name + ":delete", "Entering...")
        reqdata=self.checkRequirements({"account":str})
        # if they use --show, then reqdata won't be filled in, so use get() on the dict instead of calling the key directly.
        if reqdata.get("account", "False").isdigit() or type(reqdata.get("account", False)) is int:
            printdebug(self.name + ":delete", "{0} is a number, so we can delete straight.".format(reqdata["account"]))
            return self.deleteById(**kwargs)
        else:
            printdebug(self.name + ":delete", "{0} is not a number, so we have to delete by managedSystem.".format(reqdata["account"]))
            return self.deleteByName(**kwargs)

    def deleteById(self, **kwargs):
        printdebug(self.name + ":deleteById", "Entering...")
        self.reqdata=self.checkRequirements({"account":str})
        if not (self.reqdata["account"].isdigit() or self.reqdata["account"] is int):
            printerror(self.name + ":deleteById", "Can't call /ManagedAccounts/{0} with a non-number.".format(self.reqdata["account"]))
            return False
        kwargs.update({"verb": "DELETE", "stub": "/ManagedAccounts/{0}".format(self.reqdata["account"])})
        result=self.callPbps(**kwargs)
        if result:
            print("Successfully deleted account {0}.".format(self.reqdata["account"]))
        return result

    def deleteByName(self, **kwargs):
        global mansystem
        printdebug(self.name + ":deleteByName", "Entering...")
        self.reqdata=self.checkRequirements({"account":str, "system":str})
        lookupManSystem=True
        if hasattr(self.mansystem, "id"):
            printverbose(self.name + ":deleteManAcctByName", "Have a managedSystemID: {0}, continuing.".format(self.mansystem.id))
            lookupManSystem=False
        elif hasattr(mansystem, "id"):
            if self.reqdata["system"].isdigit() and mansystem.id == int(self.reqdata["system"]):
                printverbose(self.name + ":deleteManAcctByName", "global mansystem has the same ID as we asked for.")
                lookupManSystem=False
                self.mansystem=mansystem
            elif mansystem.name == self.reqdata["system"]:
                lookupManSystem=False
                printverbose(self.name + ":deleteManAcctByName", "global mansystem has the same name as we asked for.")
                self.mansystem=mansystem
        if lookupManSystem:
            printdebug(self.name + ":deleteManAcctByName", "don't have a managed system object, have to look it up.")
            self.mansystem=managedsystem(self.reqdata["system"])
            self.mansystem.reqdata=self.reqdata
            self.mansystem.get(system=self.reqdata["system"], **kwargs)
        if not hasattr(self.mansystem, "id"):
            printerror(self.name + ":deleteManAcctByName", "Failed to find the managed system, cannot continue!")
            return False
        # save this managed system to the global, in case we're doing --multiple on a single system
        mansystem=self.mansystem
        printverbose(self.name + ":deleteManAcctByName", "Trying to delete account {0} on system {1}.".format(self.reqdata["account"], self.mansystem.id))
        kwargs.update({"verb": "DELETE", "stub": "/ManagedSystems/{0}/ManagedAccounts/{1}".format(self.mansystem.id, self.reqdata["account"])})
        result=self.callPbps(**kwargs)
        if result:
            print("Successfully deleted account {0} on system {1}.".format(self.reqdata["account"], self.mansystem.id))
        else:
            printerror(self.name + ":delete", "Failed to delete account {0} on system {1}.".format(self.reqdata["account"], self.mansystem.id))




    def listAccounts(self, **kwargs):
        self.senddata.update(self.checkRequirements({"system":str}))
        #self.senddata.update({self.checkOptions({"domain":bool})})
        printdebug(self.name + ":listAccounts", "Entering...")
        global mansystem
        if hasattr(self.mansystem, "id") and self.mansystem.id.isdigit():
            printdebug(self.name + ":listAccounts", "Using personal mansystem.id {0}.".format(self.mansystem.id))
        if hasattr(mansystem, "id") and mansystem.id.isdigit():
            printdebug(self.name + ":listAccounts", "Using global mansystem.id {0}.".format(mansystem.id))
            self.mansystem=mansystem
        else:
            printdebug(self.name + ":listAccounts", "No managed system, looking it up for {0}.".format(self.senddata["system"]))
            #if self.senddata["domain"]:
            #    # can't do a "get by asset" for a domain, so we have to scroll through and find it
            mansystem=managedsystem(self.senddata["system"])
            mansystem.senddata=self.senddata
            result=mansystem.get(system=self.senddata["system"], doprint=False)
            if not result:
                printerror(self.name + ":listAccounts", "Could not find managed system!")
                return result
            self.mansystem=mansystem


        kwargs.update({"stub" : "/ManagedSystems/{0}/ManagedAccounts".format(self.mansystem.id)})
        printdebug(self.name + ":listAccounts", "calling listObjects with: " + str(kwargs))
        return self.listObjects(**kwargs)

    def get(self, **kwargs):
        printdebug(self.name + ":get", "Entering...")
        if self.id:
            return self.id
        senddata=self.checkRequirements({"account":str})
        if type(senddata["account"]) is int:
            printverbose(self.name + ":get", "requested account id is int, looking for that.")
            self.reqdata["account"]=senddata["account"]
            return self.getById(**kwargs)
        if senddata["account"].isdigit():
            printverbose(self.name + ":get", "requested account id isdigit, looking for that.")
            senddata["account"]=int(senddata["account"])
            self.reqdata["account"]=senddata["account"]
            return self.getById(**kwargs)
        else:
            printverbose(self.name + ":get", "requested account id is a name, calling getfromnames.")
            self.reqdata["account"]=senddata["account"]
            return self.getIdsFromNames(**kwargs)

    def getById(self, **kwargs):
        printdebug(self.name + ":getById", "Entering...")
        printdebug(self.name + ":get", "Entering...")
        if hasattr(self, "id") and self.id is None:
            printdebug(self.name + ":getById", "managedaccount not initialized, looking for account...")
            senddata=kwargs
            senddata.update(self.checkRequirements({"account":int}))
            kwargs["stub"]="/ManagedAccounts/{0}".format(senddata["account"])
        else:
            printdebug(self.name + ":getById", "managedaccount already initialized, looking for account id {0}.".format(self.id))
            kwargs["stub"]="/ManagedAccounts/{0}".format(self.id)
        kwargs["verb"]="GET"
        result=self.callPbps(**kwargs)
        if result:
            self.doprint(**kwargs)
            self.id=self.r.json()["ManagedAccountID"]
            if self.r.json()["DomainName"] != "":
                self.name="{0}@{1}".format(self.r.json()["AccountName"],self.r.json()["DomainName"])
            else:
                self.name="{0}@{1}".format(self.r.json()["AccountName"],self.r.json()["ManagedSystemID"])

        return result

    def getIdsFromNames(self, **kwargs):
        global mansystem
        #data={}
        printdebug(self.name + ":getIdsFromNames", "Entering...")
        printsave=kwargs.get("doprint", True)
        kwargs["doprint"]=False
        self.senddata.update(self.checkRequirements({"account":str, "system":str}))
        result=self.listAccounts(**kwargs)
        kwargs["doprint"]=printsave
        printdebug(self.name + ":getIdsFromNames", "Got kwargs: " + str(kwargs))
        if not result:
            printerror(self.name + ":getIdsFromNames", "Unable to find requested ManagedAccount: {0}, on ManagedSystem: {1}.".format(self.senddata["account"], self.senddata["system"]))
            return result
        printdebug(self.name + ":getIdsFromNames", str(self.r.json()))
        printdebug(self.name + ":getIdsFromNames", str(self.senddata))
        for ma in self.r.json():
            if ma["AccountName"] == self.senddata["account"]:
                #data["system"] = ma["ManagedSystemID"]
                #data["account"] = ma["ManagedAccountID"]
                self.id = ma["ManagedAccountID"]
                self.name = ma["AccountName"]
                printinfo(self.name + ":getIdsFromNames", "Found account {0} with id {1}".format(self.name, self.id))
                return self.getById(account=self.id)
        else:
            printerror(self.name + ":getIdsFromNames", "Unable to find Managed Account: {0} by name!".format(self.senddata["account"]))
            return False
        #self.doprint(**kwargs)
        #return data

class managedsystem(PbpsObject):
    def __init__(self, name):
        PbpsObject.__init__(self, name)
        self.actions.update({
            "list": self.listSystems,
            "getbyasset": self.getSystemByAsset,
            "getbyid": self.getSystemById,
            "create": self.createManagedSystem,
            "getbyfunacct": self.getSystemByFunAcct,
            "get": self.get,
            "delete": self.delete,
            }
            )
        self.fields=[
                "ManagedSystemID",
                "AssetID",
                "SystemName",
                "DatabaseID",
                "DirectoryID",
                "CloudID",
                "PlatformID",
                "NetBiosName",
                "ContactEmail",
                "Description",
                "Port",
                "Timeout",
                "PasswordRuleID",
                "DSSKeyRuleID",
                "ReleaseDuration",
                "AutoManagementFlag",
                "FunctionalAccountID",
                "ElevationCommand",
                "CheckPasswordFlag",
                "ChangePasswordAfterAnyReleaseFlag",
                "ResetPasswordOnMismatchFlag",
                "ChangeFrequencyType",
                "ChangeFrequencyDays",
                "ChangeTime",
                ]
        self.defaults={
                "platformid": 1,
                "contactemail": gEmail,
                "description": self.name,
                "port": None,
                "timeout": 30,
                "passwordruleid": gPasswordRuleId,
                "dsskeyruleid": gDssKeyRuleId,
                "releaseduration": gReleaseDuration,
                "maxreleaseduration": gMaxReleaseDuration,
                "isareleaseduration": gIsaReleaseDuration,
                "functionalaccountid": gFunctionalAccountId,
                "elevationcommand": gElevationCommand,
                "checkpasswordflag": gCheckPasswordFlag,
                "changepasswordafteranyreleaseflag": gChangePasswordAfterAnyReleaseFlag,
                "resetpasswordonmismatchflag": gResetPasswordOnMismatchFlag,
                "changefrequencytype": gChangeFrequencyType,
                "changefrequencydays": gChangeFrequencyDays,
                "changetime": gChangeTime,
                "automanagementflag": gAutoManagementFlag,
                "elevationcommand": gElevationCommand,
                }
        self.id=None
        self.asset=None
        self.help = '''
    List, retrieve, get, or create PowerBroker PasswordSafe
      Managed Systems.

      Will create underlying Asset, if it does not exist.

    Requires Permissions: "Password Safe System Management (Read/Write, depending)

    Requires a PlatformID.  As of 6.2.0, the PlatformIDs are not retrievable from API, but are:
#PlatformID  PlatformName
#----------- ----------------------------------------------------------------
#1           Windows
#2           Linux
#3           Solaris
#4           AIX
#5           HP-UX
#8           Oracle
#9           Sybase ASE
#10          MySQL
#11          MS SQL Server
#24          HP iLO
#25          Active Directory
#30          RACF
#31          Mac OSX
#32          LDAP
#33          DRAC
#34          vSphere Web API
#35          vSphere SSH
#36          IBMi (AS400)
#37          HP Comware
#38          Cisco
#39          BIG-IP (F5)
#40          Checkpoint
#41          Juniper
#42          Palo Alto Networks
#43          Teradata
#44          Fortinet
#45          SAP
#46          Windows SSH
#47          Amazon
#48          Office 365
#49          LinkedIn
#50          Twitter
#51          Facebook
#52          XING
#53          Pinterest
#54          Instagram
#55          Google
#56          Azure
#57          Rackspace
#58          GoGrid
#59          Workday
#60          Netweaver
#61          Weblogic
#62          JBoss
#63          Tomcat
#64          Xerox
#65          Salesforce
#66          Dropbox
#67          Box
#68          WebSphere AD
#69          WebSphere LDAP
#70          Website
#71          CA Service Desk
#72          ServiceNow
#73          BMC Remedy
#74          MongoDB
#75          Generic Platform
#76          SonicOS
#77          JIRA

'''

    def createManagedSystem(self, **kwargs):
        global myasset
        printdebug(self.name + ":createManagedSystem", "Entering...")
        if self.id:
            printwarn(self.name + ":createManagedSystem", "Already initialized, bailing!")
            return self.id
        self.reqdata=self.checkRequirements({
            "system":str,
            "platformid":int,
            "contactemail":str,
            "description":str,
            "timeout":int,
            "passwordruleid":int,
            "releaseduration":int,
            "maxreleaseduration":int,
            "isareleaseduration":int,
            "automanagementflag":bool,
            "checkpasswordflag":bool,
            "changepasswordafteranyreleaseflag":bool,
            "resetpasswordonmismatchflag":bool,
            "changefrequencytype":str,
            "changefrequencydays":str,
            "changetime":str,
            "functionalaccountid":int,
            })
        reqdata={"system": self.reqdata["system"]}
        if hasattr(self.asset, "id"):
            printverbose(self.name + ":createManagedSystem", "Have an assetid: {0}, continuing.".format(self.asset.id))
        elif hasattr(myasset, "id"):
            self.asset=myasset
            printverbose(self.name + ":createManagedSystem", "global myasset exists, using that.")
        else:
            self.asset=asset(reqdata["system"])
            self.asset.reqdata=reqdata
            printsave=kwargs.get("doprint", None)
            kwargs["doprint"]=False
            self.asset.getAsset(system=reqdata["system"], **kwargs)
            kwargs.update({"doprint": printsave})
        if not self.asset.id:
            printwarn(self.name + "createManagedSystem", "Failed to find, so creating asset by name.")
            self.asset=asset(self.name)
            self.asset.reqdata=reqdata
            if kwargs.get("doprint", True):
                kwargs.update({"doprint": False})
                self.asset.createAsset(**reqdata)
                kwargs.update({"doprint": True})
            else:
                self.asset.createAsset(**reqdata)
        if not self.asset.id:
            printerror(self.name + ":createManagedSystem", "Failed to find or create an asset, cannot continue!")
            return False
        kwargs.update({"stub": "/Assets/{0}/ManagedSystems".format(self.asset.id), "verb": "POST", "data": self.reqdata})
        printdebug(self.name + ":createManagedSystem", "Calling callPbps after pulling requirements.")
        result = self.callPbps(**kwargs)
        if result:
            self.name = self.r.json()["SystemName"]
            self.id = self.r.json()["ManagedSystemID"]
            self.asset = asset(self.r.json()["AssetID"])
            logline="Successfully created Managed System: {0}".format(self.name)
            if kwargs.get("doprint", True) and not options.multiple:
                print(logline)
            else:
                self.doprint(**kwargs)
                printinfo(self.name + ":createManagedSystem", logline)

            return result
        else:
            printwarn(self.name + ":createManagedSystem", "Failed to create ManagedSystem!")
            return result
        return False

    def delete(self, **kwargs):
        printdebug(self.name + ":delete", "Entering...")
        if not self.id:
            self.reqdata=self.checkRequirements({"system":str})
            if kwargs.get("doprint", False):
                kwargs.update({"doprint": False})
                self.get(system=self.reqdata["system"], **kwargs)
                kwargs.update({"doprint": True})
            else:
                self.get(system=self.reqdata["system"], **kwargs)
        printverbose(self.name + ":delete", "Have a system to delete: {0}".format(self.id))
        result=self.callPbps(verb="DELETE", stub="/ManagedSystem/{0}".format(self.id), **kwargs)
        if result:
            if kwargs.get("doprint", True):
                print("Successfully deleted Managed System {0}".format(self.id))
        else:
            printerror(self.name + ":delete", "Failed to delete: {0}".format(self.id))
        return result


    def get(self, **kwargs):
        printdebug(self.name + ":get", "Entering...")
        try:
            if self.id:
                return self
        except AttributeError:
            printverbose(self.name + ":get", "Not initialized, doing so...")
        self.reqdata=self.checkRequirements({"system":str})
        try:
            self.reqdata["system"]=int(self.reqdata["system"])
            printverbose(self.name + ":get", "Was passed an ID, so searching for that system by ID.")
            return self.getSystemById(**kwargs)
        except ValueError:
            printinfo(self.name + ":get", "was passed a name, so searching for that system by assset name.")
            if options.domain:
                # Domain lookup by name requires looping all managed systems in v6.3.1 and 6.4.4
                #APIWORKAROUND
                return self.getDomainByName(**kwargs)
            if options.database:
                # Domain lookup by name requires looping all managed systems in v6.3.1 and 6.4.4
                #APIWORKAROUND
                return self.getDatabaseByName(**kwargs)
            return self.getSystemByAsset(**kwargs)
        except KeyError:
            #KeyError gets thrown if "--show" is passed
            return False

    def getDatabaseByName(self, **kwargs):
        printdebug(self.name + ":getDatabase", "Entering...")
        if self.id:
            printberbose(self.name + ":getDatabase", "Already initialized, returning current.")
            return self.getSystemById(**kwargs)
        self.reqdata=kwargs
        self.reqdata.update(self.checkRequirements({"system":str}))
        result=self.listSystems(doprint=False)
        if not result:
            printerror(self.name + ":getDatabase", "Failed to list managed systems, bailing!!")
            return result
        for ms in self.r.json():
            if ms.get("DatabaseID", False):
                printverbose(self.name+ ":getDatabase", "Have a Database!")
                if ms["SystemName"] == self.reqdata["system"]:
                    self.id=ms["ManagedSystemID"]
                    self.name=ms["SystemName"]
                    self.platformid=ms["PlatformID"]
                    global mansystem
                    mansystem=self
                    return True

    def getDomainByName(self, **kwargs):
        printdebug(self.name + ":getDomain", "Entering...")
        if self.id:
            printberbose(self.name + ":getDomain", "Already initialized, returning current.")
            return self.getSystemById(**kwargs)
        self.reqdata=kwargs
        self.reqdata.update(self.checkRequirements({"system":str}))
        result=self.listSystems(doprint=False)
        if not result:
            printerror(self.name + ":getDomain", "Failed to list managed systems, bailing!!")
            return result
        for ms in self.r.json():
            if ms.get("DirectoryID", False):
                printverbose(self.name+ ":getDomain", "Have a domain!")
                if ms["SystemName"] == self.reqdata["system"]:
                    self.id=ms["ManagedSystemID"]
                    self.name=ms["SystemName"]
                    self.platformid=ms["PlatformID"]
                    global mansystem
                    mansystem=self
                    return True

    def getSystemByAsset(self, **kwargs):
        printdebug(self.name + ":getByAsset", "Entering...")
        if self.id:
            printverbose(self.name + ":getByAsset", "Already initialized, returning currentId")
            return self.id
        reqdata=kwargs
        reqdata=self.checkRequirements({"system":str})
        if hasattr(self.asset, "id"):
            printverbose(self.name + ":createManagedSystem", "Have an assetid: {0}, continuing.".format(self.asset.id))
        elif hasattr(myasset, "id"):
            self.asset=myasset
            printverbose(self.name + ":createManagedSystem", "global myasset exists, using that.")
        else:
            self.asset=asset(reqdata["system"])
            self.asset.reqdata=reqdata
            if kwargs.get("doprint", False):
                reqdata.update({"doprint": False})
                printdebug(self.name + ":getByAsset", "Setting doprint to False.")
                self.asset.getAsset( **reqdata)
                reqdata.update({"doprint": True})
            else:
                self.asset.getAsset(**reqdata)
        if not self.asset.id:
            if kwargs.get("doprint", True):
                printerror(self.name + ":getByAsset", "Failed to find asset!")
                # don't print this at error level if parent method set doprint to "no"
            else:
                printinfo(self.name + ":getByAsset", "Failed to find asset!")
            return False
        kwargs.update({"stub": "/Assets/{0}/ManagedSystems".format(self.asset.id), "verb": "GET"})
        result=self.callPbps(**kwargs)
        if result:
            self.id=self.r.json()["ManagedSystemID"]
            self.name=self.r.json()["SystemName"]
            printinfo(self.name + ":getByAsset", "Found managedsystem for asset.")
            self.doprint(**kwargs)
            return result
        printerror(self.name + ":getByAsset", "Failed to find ManagedSystem on Asset!")
        return False

    def getSystemByFunAcct(self, **kwargs):
        printdebug(self.name + ":getManagedSystemByFunAcct", "Entering...")
        reqdata=self.checkRequirements({"account":str})
        funact=functionalaccount(reqdata["account"])
        result=funact.get(accountname=funact.name, doprint=False)
        if result:
            kwargs["stub"]="/FunctionalAccounts/{0}/ManagedSystems".format(funact.id)
            result=self.listObjects(verb="GET", **kwargs)
        else:
            printerror(self.name+ ":getByFunctionalAccount", "Could not get the functional account ID!")
            return False
        return result

    def getSystemById(self, **kwargs):
        printdebug(self.name + ":getManagedSystemById", "Entering...")
        if self.id:
            printverbose(self.name + ":getManagedSystemById", "Already initialized, returning current Id")
            return self.id
        reqdata=kwargs
        reqdata=self.checkRequirements({"system":int})
        reqdata["ManagedSystemID"] = reqdata["system"]
        kwargs.update({'stub':"/ManagedSystems/{0}".format(reqdata["ManagedSystemID"])})
        result=self.callPbps(verb="GET", **kwargs)
        if result:
            printdebug(self.name + ":getManagedSystemById", str(self.r.json()))
            self.id=self.r.json()["ManagedSystemID"]
            self.name = self.r.json()["SystemName"]
            self.doprint(**kwargs)
            return self.id
        return None

    def listSystems(self, **kwargs):
        kwargs.update({"stub" : "/ManagedSystems"})
        printdebug(self.name + ":listManagedSystems", "calling listObjects with: " + str(kwargs))
        self.listObjects(**kwargs)
        #if not self.result:
        #    return self.result
        #for item in self.r.json():
        #    if item["SystemName"]:
        #        print("{SystemName} ({ManagedSystemID}), Asset: {AssetID}, Description: {Description}".format(**item))
        #    else:
        #        print(str(item))
        return self.result


class credentials(PbpsObject):
    def __init__(self, name):
        PbpsObject.__init__(self, name)
        self.actions.update({
            "request": self.requestPassword,
            "release": self.getCredsFromRequest,
            "getrequest": self.getCredsFromRequest,
            "test": self.testPassword,
            "set": self.setPassword,
            "list": self.listAccounts,
            "getaccount": self.getAccount,
            }
            )
        self.defaults={
                "reason":gCredentialReason,
                "duration": gCredentialDuration,
                "UpdateOnSystem": gUpdateOnSystem,
                "newpassword": gNewPassword,
                "privatekey": gPrivateKey,
                "publickey": gPublicKey,
                "passphrase": gPassphrase,
                }
        self.fields=[
                "SystemId",
                "SystemName",
                "AccountId",
                "AccountName",
                "Password",
                "PrivateKey",
                ]
        self.help = "\n\
     List, retrive, or print BeyondInsight Credential Information\n\
      That API user has rights to.\n\
      \n\
      Will mostly include passwords/SSH keys and password requets that user has requested.\n\
        "

    def getAccount(self, **kwargs):
        printdebug(self.name + ":getAccount", "entering...")
        global manaccount
        senddata=self.checkRequirements({"account":str, "system":str})
        if getattr(manaccount, "id", False):
            if manaccount.name == senddata["system"] or "{0}".format(manaccount.id) == senddata["account"]:
                printdebug(self.name + ":getAccount", "Already have an id, returning existing global manaccount.")
                return manaccount
            else:
                printdebug(self.name + ":getAccount", "Already have an id, looking up existing global manaccount.")
                return manaccount.getById(doprint=False, **senddata)
        kwargs["verb"]="GET"
        kwargs["stub"]="/ManagedAccounts"
        self.params={}
        self.params["systemName"]=senddata["system"]
        self.params["accountName"]=senddata["account"]
        result=self.callPbps(**kwargs)
        if result:
            if not getattr(manaccount, "id", False):
                manaccount=managedaccount(self.r.json()["AccountName"])
            manaccount.id=self.r.json()["AccountId"]
            manaccount.name = self.r.json()["AccountName"]
            if getattr(self.r.json(), "SystemName", False):
                manaccount.mansystem=managedsystem(self.r.json()["SystemName"])
            elif getattr(self.r.json(), "DomainName", False):
                manaccount.mansystem=managedsystem(self.r.json()["DomainName"])
            else:
                manaccount.mansystem=managedsystem(self.r.json()["SystemId"])
            manaccount.mansystem.id = self.r.json()["SystemId"]
            printdebug(self.name + ":getAccount", "Recieved successful lookup! {0}, {1}".format(self.r.json()["AccountName"], self.r.json()["SystemId"]))
            manaccount.result=True
            manaccount.doprint(**kwargs)
            return manaccount

    def getCredsFromRequest(self, **kwargs):
        printdebug(self.name + ":getCredsFromRequest", "reqdata is " + str(self.reqdata))
        global myrequest
        if myrequest is None:
            senddata=self.checkRequirements({"request":int})
            myrequest = pwrequest(senddata["request"])
            result = myrequest.postRequest(request=senddata["request"], **kwargs)
            if result:
                self.reqdata["request"] = myrequest.id
            else:
                printerror(self.name + ":getCreds", "Could not get Request ID!!")
                return False
        else:
            self.reqdata["request"] = myrequest.id
        printdebug(self.name + ":getPassword", "Trying to gather credentials for request {0}".format(myrequest.id))
        self.reqdata.update(self.checkOptions({"requesttype":str}))
        printinfo(self.name + ":getCreds", "Making a request for request type {0}".format(self.reqdata["requesttype"]))
        if self.reqdata.get("requesttype").lower() == "both":
            self.reqdata["requesttype"]="dsskey"
            printverbose(self.name + ":getCreds", "recursing into myself to get the dsskey...")
            print(str(self.getCredsFromRequest(**kwargs)))
            printverbose(self.name + ":getCreds", "back as myself to get the passphrase...")
            self.reqdata["requesttype"]="passphrase"
        if not self.reqdata.get("requesttype", "").lower() == "password":
            self.params={"type": self.reqdata["requesttype"]}
            printdebug(self.name + ":getCreds", "using params: {0}".format(self.params))
        if self.reqdata.get("alias", False):
            self.reqdata.update(self.checkRequirements({"aliasId":int}))
            kwargs.update({"stub": "/Aliases/" + str(self.reqdata["aliasId"]) + "/Credentials/" + str(self.reqdata["request"])})
            result=self.callPbps(verb="GET", stub=kwargs["stub"])
        else:
            kwargs.update({"stub": "/Credentials/{0}".format(myrequest.id)})
            result=self.callPbps(verb="GET", stub=kwargs["stub"])
        if result:
            printdebug(self.name + ":getCreds", str(self.r.json()))
            if kwargs.get("doprint", True) == True:
                # this should just be a string = the password, which is why we're printing it raw
                if options.multiple:
                    printdebug(self.name + ":getPassword", "Trying to print the request for --multiple...")
                    myrequest.doprint(doprint=True)
                    print(str(self.r.json()))
                else:
                    print(str(self.r.json()))
            return self.r.json()
        elif result is None:
            # not yet approved, back off and try again
            sleep(gRequestBackoffTime)
            kwargs["trynum"] = kwargs.get("trynum", 0)
            printwarn(self.name + ":getCreds", "Request not yet approved, sleeping {0} seconds and trying again, try {1}.".format(gRequestBackOffTime, gMaxretries))
            if kwargs["trynum"] > gMaxretries:
                printerror(self.name + ":getPassword", "Could not retrieve credentials in the configured timeout.")
                return ""
            else:
                kwargs["trynum"] = kwargs["trynum"] + 1
                return self.getCredsFromRequest(**kwargs)
        else:
            printerror(self.name + ":getPassword", "Could not retrieve credentials.")
            return ""

    def listAccounts(self, **kwargs):
        self.fields=[
                "AccountId",
                "SystemId",
                "PlatformID",
                "AccountName",
                "SystemName",
                "DomainName",
                "InstanceName",
                "DefaultReleaseDuration",
                "MaximumReleaseDuration",
                "LastChangeDate",
                "NextChangeDate",
                "IsChanging",
                "IsISAAccess",
                ]

        kwargs.update({"stub" : "/ManagedAccounts"})
        printdebug(self.name + ":listAccounts", "calling listObjects with: " + str(kwargs))
        self.listObjects(**kwargs)
        if not self.result:
            return self.result
        return self.result

    def requestPassword(self, **kwargs):
        global myrequest
        printdebug(self.name + ":requestPassword", "Entering by creating new request...")
        senddata=self.checkRequirements({"account":str, "duration":int, "reason":str, "system":str})
        myrequest=pwrequest("{0}@{1}".format(senddata["account"], senddata["system"]))
        myrequest.reqdata=senddata
        result = myrequest.postRequest(doprint=False, **kwargs)
        #manaccount=managedaccount(senddata["account"])
        #senddata.update(manaccount.getIdsFromNames(system=senddata["system"], account=senddata["account"]))
        #self.data={ 'SystemId' : senddata["system"], 'AccountId': senddata["account"], "DurationMinutes": senddata["duration"], "Reason": senddata["reason"] }
        #printdebug(self.name + ":requestPassword", "Requesting password with: " + str(self.data))
        #result = self.callPbps(verb="POST", stub="/Requests", data=self.data)
        #printdebug(self.name + ":requestPassword", str(self.r.json()))
        if result:

            requestid=myrequest.id
            printinfo(self.name + ":requestPassword", "Success, RequestID: {0}".format(requestid))
            self.data={}
            self.reqdata.update({"request": requestid})
            kwargs.update({"request": requestid, "doprint": False})
            password=self.getCredsFromRequest(**kwargs)
            if options.multiple:
                print("{0}@{1}{2}{3}".format(senddata["account"], senddata["system"], logsep, password))
            else:
                print(password)
        elif hasattr(myrequest, "r"):
            if myrequest.r.status_code == 4091 or myrequest.r.status_code == 409:
                #conflicting request, perhaps ours?
                printinfo(self.name + ":requestPassword", "have an existing request open, trying to find it...")
                requestid = None
                result = myrequest.listRequests(doprint=False, **kwargs)
                for request in myrequest.r.json():
                    printdebug(self.name + ":requestPassword", "Checking for match in: {0}".format(request))
                    if request["SystemName"] == myrequest.reqdata["system"] or request["SystemID"] == myrequest.data["SystemId"]:
                        printdebug(self.name + ":requestPassword", "found a matching sytem ID...")
                        if request["AccountName"] == myrequest.reqdata["account"] or request["AccountID"] == myrequest.data["AccountId"]:
                            requestid = request["RequestID"]
                            myrequest.id = requestid
                            printdebug(self.name + ":requestPassword", "Found a matching request, asking for creds from that.")
                            break
                else:
                    printerror(self.name + ":requestPassword", "Failed to get password for this request, or a matching request already opened.")
                if requestid:
                    printinfo(self.name + ":requestPassword", "Found a request to use, RequestID: {0}".format(requestid))
                    self.data={}
                    self.reqdata.update({"request": requestid})
                    kwargs.update({"request": requestid, "doprint": False})
                    password=self.getCredsFromRequest(**kwargs)
                    print(password)
            else:
                printerror(self.name + ":requestPassword", "Failed to get password for this request.")
        else:
            printerror(self.name + ":requestPassword", "Failed to get password for this request.")

        return self

    def testPassword(self, **kwargs):
        global manaccount
        printdebug(self.name + ":testPassword", "Entering...")
        senddata=self.checkRequirements({"account":str})
        manaccount=managedaccount(senddata["account"])
        manaccount.reqdata=senddata
        result=manaccount.get(doprint=False, account=senddata["account"])
        if not result:
            printerror(self.name + ":testPassword", "ERROR: Could not find managed account!")
            return result
        kwargs["verb"]="POST"
        kwargs["stub"]="/ManagedAccounts/{0}/Credentials/Test".format(manaccount.id)
        result=self.callPbps(**kwargs)
        if result:
            value=self.r.json()["Success"]
            print("Test Result:{0}".format(value))
            return value
        else:
            printerror(self.name + ":testPassword", "Credentials test failed!")
            printerror(self.name + ":testPassword", self.r.text)
        return result

    def setPassword(self, **kwargs):
        global manaccount
        printdebug(self.name + ":setCreds", "Entering...")
        acctdata=self.checkRequirements({"account":str})
        senddata=self.checkOptions({"newpassword":str, "publickey":str, "privatekey":str, "passphrase":str})
        senddata.update(self.checkRequirements({"UpdateOnSystem":bool}))
        printdebug(self.name + ":setCreds", "Have senddata: {0}".format(senddata))
        manaccount=managedaccount(acctdata["account"])
        manaccount.reqdata=acctdata
        result=manaccount.get(doprint=False, account=acctdata["account"])
        if not result:
            printerror(self.name + ":setCreds", "Could not find managed account!")
            return result
        if senddata.get("newpassword", False):
            self.data.update({"Password": senddata["newpassword"]})
        if senddata.get("publickey", False):
            self.data.update({"PublicKey": senddata["publickey"]})
        if senddata.get("privatekey", False):
            self.data.update({"PrivateKey": senddata["privatekey"]})
        if senddata.get("passphrase", False):
            self.data.update({"Passphrase": senddata["passphrase"]})
        printdebug(self.name + ":setCreds", "have UpdateOnSystem value of: {0}".format(senddata["UpdateOnSystem"]))
        if senddata.get("UpdateOnSystem", True) or re.search('(yes|true|y|1)', str(senddata.get("UpdateOnSystem", "")), re.I):
            printdebug(self.name + ":setCreds", "Setting UpdateOnSystem to True.")
            self.data.update({"UpdateSystem": True})
        if not senddata.get("UpdateOnSystem", False) or re.search('(no|false|f|n|0)', str(senddata.get("UpdateOnSystem", "")), re.I):
            printdebug(self.name + ":setCreds", "Setting UpdateOnSystem to False.")
            self.data.update({"UpdateSystem": False})
        printdebug(self.name + ":setCreds", "Calling callPbps with self.data = '{0}'".format(self.data))
        kwargs["verb"]="PUT"
        kwargs["stub"]="/ManagedAccounts/{0}/Credentials".format(manaccount.id)
        result=self.callPbps(**kwargs)
        if result:
            if kwargs.get("doprint", True) is True and not options.multiple:
                print("Successfully set new credentials for {0}".format(manaccount.name))
            else:
                self.doprint(**kwargs)
        else:
            printerror(self.name + ":setCreds", "Failed to set new credentials for {0}".format(manaccount.name))
        return result

class pwrequest(PbpsObject):
    def __init__(self, name):
        PbpsObject.__init__(self, name)
        self.actions.update({
            "list": self.listRequests,
            "make": self.postRequest,
            "release": self.releaseRequest,
            "close": self.releaseRequest,
            })
        self.help = '''
    List, request, or release previous request(s) for credentials.

    Users need Requestor access to the managed account referenced.
'''
        self.defaults={
                "reason":gCredentialReason,
                "duration": gCredentialDuration,
                }
        self.fields=[
                "RequestID",
                "SystemID",
                "SystemName",
                "AccountID",
                "AccountName",
                "DomainName",
                "AliasID",
                "RequestReleaseDate",
                "ApprovedDate",
                "ExpiresDate",
                "Status",
                "AccessType",
                ]
        self.manaccount=None
        self.mansystem=None

    def listRequests(self, **kwargs):
        result = self.callPbps(verb="GET", stub="/Requests")
        kwargs.update({"stub" : "/Requests"})
        printdebug(self.name + ":listRequests", "calling listObjects to List Requests with URI: " + str(kwargs))
        self.listObjects(**kwargs)
        return self.result

    def postRequest(self, **kwargs):
        global manaccount
        senddata=self.checkRequirements({"account":str, "duration":int, "reason":str, "system":str})
        senddata.update(self.checkOptions({"accesstype":str, "conflictoption":str}))
        if senddata["account"].isdigit():
            senddata["account"]=int(senddata["account"])
        if senddata["system"].isdigit():
            senddata["system"]=int(senddata["system"])

        if not (type(senddata["system"]) is int and type(senddata["account"]) is int):
            if type(senddata["system"]) is int:
                printerror(self.name, "Cannot look up a system by ID and an account by name, both must be IDs or names.!")
                return False
            if type(senddata["account"]) is int:
                printerror(self.name, "Cannot look up an account by ID and a system by name, both must be IDs or names.!")
                return False
            printdebug(self.name + ":postRequest", "Looking up managed account on managed system, at least one is a name.")
            manaccount=credentials(senddata["account"])
            manaccount.getAccount(system=senddata["system"], account=senddata["account"], doprint=False)
            if not manaccount.result:
                printerror(self.name + ":postRequest", "Failed to get ID for managed account!")
                return manaccount.result
            senddata.update({"system": manaccount.mansystem.id, "account": manaccount.id})

        self.manaccount = manaccount
        self.data={ 'SystemId' : senddata["system"], 'AccountId': senddata["account"], "DurationMinutes": senddata["duration"], "Reason": senddata["reason"] }
        if senddata.get("accesstype", False):
            self.data["AccessType"]=senddata["accesstype"]
        if senddata.get( "conflictoption", False):
            printdebug(self.name + ":postRequest", "Adding --conflictoption to self.data.")
            self.data["ConflictOption"]=senddata["conflictoption"]
        printdebug(self.name + ":requestPassword", "Requesting password with: " + str(self.data))
        result = self.callPbps(verb="POST", stub="/Requests", data=self.data)
        if result:
            printdebug(self.name + ":postRequest", str(self.r.json()))
            self.id = self.r.json()
            self.doprint(**kwargs)
        return result

    def releaseRequest(self, **kwargs):
        printdebug(self.name + ":releaseRequest", "Entering...")
        if self.id:
            self.reqdata["request"] = self.id
        senddata=self.checkRequirements({"request":int, "reason":str})
        printverbose(self.name + ":releaseRequest", "Posting release for requestId: {0}.".format(senddata["request"]))
        self.data={"Reason": senddata["reason"]}
        result = self.callPbps(verb="PUT", stub="/Requests/Release/{0}".format(senddata["request"]), **kwargs)
        return result


class functionalaccount(PbpsObject):
    def __init__(self, name):
        PbpsObject.__init__(self, name)
        self.actions.update({
            "list": self.listFA,
            "getById": self.getById,
            "get": self.get,
            }
            )
        self.help = '''
    List or retrieve Functional Accounts available in PBPS.
    Users need the Functional Account ID for adding ManagedAssets

    Requires: PasswordSafe Account Management (Read)
'''
        self.fields=[
                "FunctionalAccountID",
                "PlatformID",
                "DomainName",
                "AccountName",
                "DisplayName",
                "Description",
                "ElevationCommand",
                "SystemReferenceCount",
                ]

    def listFA(self, **kwargs):
        kwargs["stub"]="/FunctionalAccounts"
        return self.listObjects(**kwargs)

    def get(self, **kwargs):
        printdebug(self.name + ":get", "Entering...")
        senddata=self.checkRequirements({"account":str})
        shortnamematch=re.compile("^{0}$".format(senddata["account"]), re.I)
        domnamematch=re.compile("\\\\{0}$".format(senddata["account"]), re.I)
        if type(senddata["account"]) is int:
            printdebug(self.name + ":get", "Account type is int.")
            return self.getById(**kwargs)
        elif senddata["account"].isdigit():
            printdebug(self.name + ":get", "Acount type is digit.")
            return self.getById(**kwargs)
        else:
            self.listFA(doprint=False, **kwargs)
            for fa in self.r.json():
                if fa["AccountName"] == senddata["account"]:
                    self.reqdata["account"] = fa["FunctionalAccountID"]
                    return self.getByID(**kwargs)
                elif shortnamematch(fa["AccountName"]):
                    self.reqdata["account"] = fa["FunctionalAccountID"]
                    return self.getByID(**kwargs)
                elif domnamematch("{0}\\\\{1}".format(fa["DomainName"], fa["AccountName"])):
                    self.reqdata["account"] = fa["FunctionalAccountID"]
                    return self.getByID(**kwargs)
            printerror(self.name + ":get", "Could not find functional account in full list.")
        return False

    def getById(self, **kwargs):
        senddata=self.checkRequirements({"account":int})
        kwargs["stub"]="/FunctionalAccounts/{0}".format(senddata["account"])
        kwargs["verb"]="GET"
        result = self.callPbps(**kwargs)
        if result:
            self.doprint(**kwargs)
            self.id=self.r.json()["FunctionalAccountID"]
            self.name=self.r.json()["AccountName"]
        return result

class fileimport(PbpsObject):
    global wg
    def __init__(self, name):
        PbpsObject.__init__(self, name)
        self.actions.update({
            "nessus": self.nessus,
            }
            )
        self.help = "\n\
     List, retrive, or print BeyondInsight File Import Information\n\
      That API user has rights to Modify.\n\
      \n\
     Currently Only supports Nessus Imports, which are not fully supported\n\
      By BI 6.0 API.\n\
        "

    def nessus(self, **kwargs):
        stub="/Imports/QueueImportFile"
        senddata=self.checkRequirements({"file":str, "workgroup":str})
        try:
            body = {'FileName': senddata["file"], 'FileContents': open(senddata["file"], 'rb')}    #add to the request body 

            printverbose(self.name + ":nessus", "successfully read in file: " + senddata["file"])
        except FileNotFoundError:
            printerror(self.name + ":nessus", "Could not open file: " + senddata["file"] + ". Please check your file and try again.")
            return False
        if not senddata["workgroup"].isdigit():
            printverbose(self.name + ":nessus", "workgroup is not an ID, looking it up")
            try:
                if wg.id:
                    workgroupid=wg.id
            except NameError:
                wg=workgroup(senddata["workgroup"])
                wg.reqdata.update({"workgroup": wg.name})
                workgroupid=wg.getWorkgroupIdFromName(workgroup=wg.name, doprint=False)
            if not workgroupid:
                printerror(self.name + ":nessus", "Could not get workgroup ID from name.")
                self.result=False
                return False
            self.reqdata.update({"WorkgroupId": workgroupid})
        else:
            self.reqdata.update({"WorkgroupId": senddata["workgroup"]})
        printinfo(self.name + ":nessus", "ready to try to open filename: " + senddata["file"])
        self.reqdata.update({"FileName": senddata["file"]})
        kwargs.update({"verb": "POST", "stub": stub}) #, "files":contents})
        printdebug(self.name + ":nessus", "Trying to upload file: " + senddata["file"] +" to workgroup ID: " + str(senddata["workgroup"]))
        #self.reqdata.update({"data": self.r.json.dumps(body)})
        self.reqdata.update({'Content-type': 'application/json'} )
        #response = session.post(<base>/imports, data=data, headers=datype) #Make an import
        result=self.callPbps(**kwargs)
        kwargs.update({workgroup: kwargs["workgroup"]})
        if result:
            printinfo(self.name + ":nessus", "Recieved import id: " + str(self.r.json()))
        else:
            printerror(self.name + ":nessus", "Import failed!")
        return result

class passwordrule(PbpsObject):
    def __init__(self, name):
        PbpsObject.__init__(self, name)
        self.actions.update({
            "get": self.getById,
            "list": self.listPasswordRules,
            }
            )
        self.help = '''
     Returns list of Password Rules. Useful for getting PasswordRuleID
      for creating Managed Systems and Managed Accounts

    Requires: PasswordSafe System Management (Read)
        '''
        self.fields = [
                "PasswordRuleID",
                "Name",
                "Description",
                "MinimumLength",
                "MaximumLength"
                "FirstCharacterRequirement",
                "LowercaseRequirement",
                "UppercaseRequirement",
                "NumericRequirement",
                "SymbolRequirement",
                "ValidLowercaseCharacters",
                "ValidUppercaseCharacters",
                "ValidSymbols",
                ]
        self.defaults={
                }

    def listPasswordRules(self, **kwargs):
        self.listObjects(stub="/PasswordRules", **kwargs)

    def getById(self, **kwargs):
        printdebug(self.name + ":getById", "Entering...")
        senddata=self.checkRequirements({"passwordrule":int})
        kwargs.update({
            "stub": "/PasswordRules/{0}".format(senddata["passwordrule"]),
            "verb": "GET",
            })
        result=self.callPbps(**kwargs)
        if result:
            self.doprint(**kwargs)
        return result

class dsskeyrule(PbpsObject):
    def __init__(self, name):
        PbpsObject.__init__(self, name)
        self.actions.update({
            "get": self.getById,
            "list": self.listDssKeyRules,
            }
            )
        self.help = '''
     Returns list of DSS Key Rules. Useful for getting PasswordRuleID
      for creating Managed Systems and Managed Accounts

    Requires: PasswordSafe System Management (Read)
        '''
        self.fields = [
                "DSSKeyRuleID",
                "Name",
                "Description",
                "KeyType",
                "KeySize"
                "EncryptionType",
                "PasswordRuleID",
                ]
        self.defaults={
                }

    def listDssKeyRules(self, **kwargs):
        self.listObjects(stub="/DSSKeyRules", **kwargs)

    def getById(self, **kwargs):
        printdebug(self.name + ":getById", "Entering...")
        senddata=self.checkRequirements({"dsskeyruleid":int})
        kwargs.update({
            "stub": "/DssKeyRules/{0}".format(senddata["dsskeyruleid"]),
            "verb": "GET",
            })
        result=self.callPbps(**kwargs)
        if result:
            self.doprint(**kwargs)
        return result




class workgroup(PbpsObject):
    def __init__(self, name):
        PbpsObject.__init__(self, name)
        self.actions.update({
            "list": self.listWorkgroups,
            "getId": self.getWorkgroupById,
            "getIdFromName": self.getWorkgroupIdFromName,
            "create": self.createWorkgroup,
            "getName": self.getWorkgroupName,
            }
            )
        self.wgname = ""
        self.id = None
        self.fields = [
                "OrganizationID",
                "ID",
                "Name",
                ]
        self.help = "\n\
     List, retrive, or print BeyondInsight Workgroup Information\n\
      That API user has rights to.\n\
        "
        self.defaults={
                "workgroup":gWorkgroup,
                }

    def createWorkgroup(self, **kwargs):
        if self.id:
            printwarn(self.name + ":createWg", "Was asked to create a workgroup, but already have an ID!")
            return self.id
        kwargs.update(self.checkRequirements({"workgroup":str, "organizationid":str}))
        result = self.getWorkgroupId(**kwargs)
        if result:
            printwarn(self.name + ":createWg", "This workgroup already exists!")

        self.data={"Name": kwargs["workgroup"], "OrganizationID": kwargs["organizationid"]}
        result = self.callPbps(stub="/Workgroups", verb="POST", **kwargs)
        if result:
            printinfo(self.name + ":createWg", "Created successfully.")
            self.id = self.r.json()["ID"]
            self.wgname = self.r.json()["Name"]
            return self.id
        else:
            printerror(self.name + ":createWg", "Failed to create workgroup: " + self.senddata["workgroup"])

    def listWorkgroups(self, **kwargs):
        self.listObjects(stub="/Workgroups", **kwargs)

    def getWorkgroupId(self, **kwargs):
        printdebug(self.name + ":getId", "Entering...")
        if self.id:
            printverbose(self.name + ":getId", "Was asked to return an ID, so returning the ID we already have.")
            return self.id
        self.reqdata=self.checkRequirements({"workgroup":str})
        kwargs.update({"workgroup": kwargs.get("workgroup", self.reqdata["workgroup"])})
        if kwargs["workgroup"].isdigit():
            # The next 2 commented lines would return a fully-initialized workgroup.  However, if the calling user
            # does not have rights to enumerate workgroups, this will fail.
            # so instead, we will fast-return an ID, if asked for an ID, so that 2 things happen:
            #  1) Users can request objects by ID and get a fast response without network/https time
            #  2) Users can be provisioned with fewer rights, but still ask for things if they know the ID.
            #printverbose(self.name + ":getId", "was asked to return an ID, and passed an int, so returning THAT, after initializing.")
            #self.name = self.getWorkgroupById(**kwargs)

            printverbose(self.name + ":getId", "was asked to return an ID, and passed an int, so returning THAT, even though we're not initialized.")

            self.id = int(kwargs["workgroup"])
            return self.id
        printinfo(self.name + ":getId", "was asked to return an ID, not initialized, so calling getIdByName")
        result=self.getWorkgroupIdFromName(**kwargs)
        self.doprint(**kwargs)
        return result

    def getWorkgroupName(self, **kwargs):
        printdebug(self.name + ":getName", "Entering...")
        if self.name.isdigit():
            printverbose(self.name + ":getName", "Was initialized with an ID, need to look up the corresponding name.")
            result = self.getWorkgroupById(**kwargs)
            if result:
                return self.name
            else:
                return ""
        else:
            # The next commented lines would return a fully-initialized workgroup.  However, if the calling user
            # does not have rights to enumerate workgroups, this will fail.
            # so instead, we will fast-return an ID, if asked for an ID, so that 2 things happen:
            #  1) Users can request objects by ID and get a fast response without network/https time
            #  2) Users can be provisioned with fewer rights, but still ask for things if they know the ID.
            #return getWorkgroupIdFromName(**kwargs)
            return self.name

    def getWorkgroupById(self, **kwargs):
        printdebug(self.name + ":getById", "Entering...")
        if not self.id:
            senddata=self.checkRequirements({"workgroup":str})
            self.id = senddata["workgroup"]
            if not self.id.isdigit():
                printerror(self.name + ":getById", "Was asked to get by ID, but not passed an ID, so... bailing.")
                return False
        if self.wgname and self.wgname == senddata["workgroup"]:
            printinfo(self.name + ":getById", "Already have a name for this workgroup, so returning it fast.")
            return self.wgname
        result = self.callPbps(verb="GET", stub="/Workgroups/" + str(self.id))
        if result:
            self.wgname = self.r.json()["Name"]
            self.name = self.wgname
            printdebug(self.name + ":getById", "Got a name, " + self.wgname)
            return self.wgname
        else:
            printwarn(self.name + ":getById", "Failed to get a name for this workgroup.")
            return False


    def getWorkgroupIdFromName(self, **kwargs):
        printdebug(self.name + ":getWgIdByName", "Entering...")
        self.reqdata.update(**kwargs)
        senddata=self.checkRequirements({"workgroup":str})
        if self.wgname and self.wgname == senddata["workgroup"]:
            printinfo(self.name + ":getWgIdByName", "Already had an id for this workgroup, returning it fast.")
            return self.id
        self.wgname = senddata["workgroup"]
        result=self.callPbps(verb="GET", stub="/Workgroups/" + str(senddata["workgroup"]))
        if result:
            printdebug(self.name + ":getWgIdByName", str(self.r.json()))
            workgroupId=self.r.json()["ID"]
            self.wgname = self.r.json()["Name"]
            self.name = self.wgname
            self.workgroupId=workgroupId
            self.doprint(**kwargs)
            #if kwargs.get("doprint", "yes") == "yes":
            #    print("WorkgroupID: " + str(workgroupId) + ", OrganizationID: "+ str(self.r.json()["OrganizationID"]))
            self.id = workgroupId
            return workgroupId
        else:
            printwarn(self.name + ":getWgIdByName", "Failed to get the workgroup!.")
            #warning, not error, because something higher likely will catch this
        return None

def striplist(l):
    y=[x.lstrip() for x in l]
    return([x.strip() for x in y])

def printline(line):
    line = line.strip()
    try:
        sys.stdout.write(line + "\n")
    except brokenpipeerror:
        sys.exit(0)

def printerr(prefix, host, line):
    global logsep
    line = line.strip()
    if options.filter:
        result = re.search(options.filter, host + " " + line)
        if result:
            printline(prefix + logsep + host + logsep + line)
    else:
        printline(prefix + logsep + host + logsep + line)

def printerror(host, line):
    prefix = "ERROR   "
    if options.loglevel >= 1:
        printerr(prefix, host, line)

def printwarn(host, line):
    prefix = "WARN    "
    if options.loglevel >= 2:
        printerr(prefix, host, line)

def printinfo(host, line):
    prefix = "INFO    "
    if options.loglevel >= 3:
        printerr(prefix, host, line)

def printverbose(host, line):
    prefix = "VERBOSE "
    if options.loglevel >= 4:
        printerr(prefix, host, line)

def printdebug(host, line):
    prefix = "DEBUG   "
    if options.loglevel >= 5:
        printerr(prefix, host, line)

class PassThroughOptionParser(OptionParser):
    """
    An unknown option pass-through implementation of OptionParser.

    When unknown arguments are encountered, bundle with largs and try again,
    until rargs is depleted.

    sys.exit(status) will still be called if a known argument is passed
    incorrectly (e.g. missing arguments or bad argument types, etc.)
    """
    def _process_args(self, largs, rargs, values):
        while rargs:
            try:
                OptionParser._process_args(self,largs,rargs,values)
            except (BadOptionError,AmbiguousOptionError) as e:
                largs.append(e.opt_str)



# add each class here, both in case-insensitive (for the user) and case-sensitive (for the program) formats, as below:
#    "commandline": className,
#    "className": className,
# if you get an error:
#     pbps=gPBPSClasses.get(mytype, False)(mytype)
# TypeError: 'bool' object is not callable
# Then you didn't include the 2nd case-sensitive line
gPBPSClasses={
#    "PbpsObject": PbpsObject,
#    "pbps": PbpsObject,
    "test": test,
    "attributetype": attributetype,
    "attribute": attribute,
    "asset": asset,
    "credentials": credentials,
    "password": credentials,
    "pw": credentials,
    "dsskeyrule": dsskeyrule,
    "fileimport": fileimport,
    "import": fileimport,
    "functionalaccount": functionalaccount,
    "fa": functionalaccount,
    "managedaccount": managedaccount,
    "account": managedaccount,
    "ma": managedaccount,
    "managedsystem": managedsystem,
    "ms": managedsystem,
    "passwordrule": passwordrule,
    "pwrequest": pwrequest,
    "request": pwrequest,
    "smartrule": smartrule,
    "sr": smartrule,
    "usergroup": usergroup,
    "workgroup": workgroup,
    "wg": workgroup,
    }
gPBPStypes={}
for k,v in gPBPSClasses.items():
    gPBPStypes[k] = v.__name__
#gPBPStypes={k:v.__name__ for k,v in gPBPSClasses.items()} #not using this form, because it doesn't work on python 2.6
now=datetime  #so that we can correllate datetime stamps with PBPS logs
options_lo={}  #leftover options that aren't handled, so that we can pass through unknowns to checkRequirements
gAuth= {
        "auth": False,
        "cookies": None,
        "headers": {},
        "r": {},
        }

if __name__ == '__main__':


    usage = "Usage: %prog -h hostname -C './CA-cert.pem' -u username -k key -t {type} -a {action}"
    parser = PassThroughOptionParser(usage=usage, version="%prog " + gVers)

    groupMain=OptionGroup(parser, "Main Script options")
    groupOutput=OptionGroup(parser, "Options to control output")
    groupRequest=OptionGroup(parser, "Request-oriented options")
    groupAsset=OptionGroup(parser, "Asset-oriented options")
    groupAccount=OptionGroup(parser, "Account-oriented options")
    groupOther=OptionGroup(parser, "Single-purpose options outside of other groups")
    groupConnection=OptionGroup(parser, "Options to control PBPS connection paramaters")


    groupOutput.add_option('-d', '--debug', '--loglevel',
            dest="loglevel",
            default=1,
            action="count",
            help="Determine the logging level. Each instance of '-d' increasing logging level by 1. The default is 'Error only'. Currently 5 levels are defined.",
            )
    groupOutput.add_option('--filter',
            dest="filter",
            default="",
            help="Debug search filter (limits debug output), defaults to 'print all'",
            )
    groupOutput.add_option('--prototype', '--json', '-j',
            dest="prototype",
            default=False,
            action="store_true",
            help="Print out the json used to perform this operation",
            )
    groupOutput.add_option('--format',
            dest="format",
            default="tsv",
            help="How to format the output (json, tsv, or csv)",
            )
#    groupOther.add_option('--smartrule',
#            dest="smartrule",
#            help="SmartRule name or ID.",
#            )
    groupAsset.add_option("--ipaddress",
            dest="ipaddress",
            help="IP Address for new asset or search.",
            )
    groupAsset.add_option("--macaddress",
            dest="macaddress",
            help="MAC Address of new asset.",
            )
    groupAsset.add_option("--attributetype",
            dest="attributetype",
            help="Attribute Type Name or ID for finding specific attributes",
            )
    groupAsset.add_option("--attribute",
            dest="attribute",
            help="Attribute Name or ID to add/delete/set",
            )
    groupAsset.add_option("--domain",
            dest="domain",
            default=False,
            action="store_true",
            help="Look up a domain instead of an asset-based system.",
            )
    groupAsset.add_option("--database",
            dest="database",
            default=False,
            action="store_true",
            help="Look up a database instead of an asset-based system.",
            )
    groupRequest.add_option("--duration",
            dest="duration",
            help="Duration of time to request credentials for.",
            )
    groupRequest.add_option("--reason",
            help="Reason for credentils request.",
            dest="reason",
            )
    groupRequest.add_option("--requesttype", "--reqtype",
            help="Type of Credential to request (dsskey, password, passphrase, or 'both' for key and passphrase, in that order.",
            dest="requesttype",
            default=gRequestType,
            )
    groupRequest.add_option("--accesstype", 
            help="Type of Access to request (View, RDP, or SSH)",
            dest="requesttype",
            default=gAccessType,
            )
    groupRequest.add_option("--conflictoption",
            help="The conflict resolution option if an existing request is found for this user/system/account. (resue, or renew).",
            dest="conflictoption",
            )
    groupConnection.add_option('-i', '--ignore',
            dest="verify",
            action="store_false",
            help="Ignore certificate verification entirely."
            )
    groupConnection.add_option('-C', "--capth",
            dest="verify",
            help="Path to CA certifiate, or directory of certificates to use for SSL verification",
            )

    groupConnection.add_option("-s", "--host", "--server",
            dest="host",
            default=gPBPSHost,
            help="Hostname:port of the PBPS Host or API cache to conncet to. Assumes 443 unless otherwise mentioned.",
            )
    groupConnection.add_option("-u", "--user",
            dest="user",
            default=gPBPSUser,
            help="Username to log into PBPS with. Generally, this should be an application account.",
            )
    groupConnection.add_option("-k", "--key",
            dest="key",
            default=gPBPSKey,
            help="PBPS API Key from Configuration -> PasswordSafe -> API Key page.",
            )
    groupMain.add_option("-t", "--type",
            dest="type",
            help="type of object to work with. use '-t help' to get a list of valid types.",
            default="managedaccount",
            )

    groupMain.add_option("-a", "--action",
            dest="action",
            help="action to perform with that object",
            default="list",
            )
    groupAsset.add_option("-S", "--system", "--asset", "--assetid",
            dest="system",
            help="System name or ID to request credentials for, create, get information on, etc.",
            )
    groupAsset.add_option("--platformid",
            dest="platformid",
            help="PlatformID of managed system. Refer to -t ms -a help for a complete list.",
            )
    groupAccount.add_option("-A", "--account",
            dest="account",
            help="Account(Alias) name or ID to request credentials for, create, get information on, etc..",
            )
    groupAccount.add_option("--publickey",
            dest="publickey",
            help="RSA/DSA Public Key in text format",
            )
    groupAccount.add_option("--privatekey",
            dest="privatekey",
            help="RSA/DSA Private Key in text format",
            )
    groupAccount.add_option("--passphrase",
            dest="passphrase",
            help="RSA/DSA private key current passphrase",
            )
    groupAccount.add_option("--newpassword",
            dest="newpassword",
            help="New Password for account.",
            )
    groupAccount.add_option("--passwordruleid",
            dest="passwordruleid",
            help="Password Rule ID - get from '-t passwordrule -a list'",
            type="int",
            )
    groupAccount.add_option("--dsskeyruleid",
            dest="dsskeyruleid",
            help="DSS Key Rule ID - get from -t passwordrule -a list",
            type="int",
            )
    groupAccount.add_option("--updateonsystem", "--UpdateOnSystem",
            dest="UpdateOnSystem",
            help="Should PBPS update the credentials on the target system?",
            type="str",
            )
    groupAccount.add_option("--releaseduration",
            dest="releaseduration",
            help="Default Release Duration for requests made for this account, in minutes.",
            type="int",
            )
    groupAccount.add_option("--maxreleaseduration",
            dest="maxreleaseduration",
            help="Maximum Release Duration requestable for this account, in minutes.",
            type="int",
            )
    groupAccount.add_option("--isareleaseduration",
            dest="isareleaseduration",
            help="Default Release Duration for ISA requests for this account.",
            type="int",
            )
    groupAccount.add_option("--apienabled",
            dest="apienabled",
            action="store_true",
            help="True if API access to this account should be allowed.",
            )
    groupAccount.add_option("--passwordfallback",
            dest="passwordfallbackflag",
            help="Should DSS logon failures fall back to password authentication? Boolean",
            action="store_true",
            )
    groupMain.add_option("--multiple",
            dest="multiple",
            default = False,
            action="store_true",
            help='''Run the same command on multiple objects (for bulk-loading managedsystems, for example).
Uses tab-separated data, and requires a header line, to know what parameters will change.
***It is VERY likely that you want to use '--defaults' as well***.
            '''
            # only works for classes that have self.defaults defined
            )
    groupMain.add_option("--file",
            dest="file",
            help="File to use for data processing. Used for --multiple and --import",
            )
    groupAsset.add_option("--workgroup", "--wg", "-w",
            dest="workgroup",
            #default=gWorkgroup,
            help="Workgroup name or ID",
            )
    groupOutput.add_option("--searchfield", "--sf",
            dest="searchfield",
            help="Field to search inside of when passing --searchdata.",
            )
    groupOutput.add_option("--searchdata", "--sd",
            dest="searchdata",
            help="Actual Search value to search for.",
            )
    groupMain.add_option("--defaults", "-D",
            dest="defaults",
            action="store_true",
            default=False,
            help="Use in-code defaults at top of script for create operations.",
            )
    groupMain.add_option("--examples",
            dest="examples",
            action="store_true",
            default=False,
            help="Show examples of tool usage.",
            )
    groupMain.add_option("--show",
            dest="show",
            action="store_true",
            default=False,
            help="Print requirements for the requested type/action combo.",
            )
    parser.add_option_group(groupOutput)
    parser.add_option_group(groupAsset)
    parser.add_option_group(groupAccount)
    parser.add_option_group(groupRequest)
    parser.add_option_group(groupConnection)
    parser.add_option_group(groupMain)


    options, remainder = parser.parse_args()
    option_dict = vars(options)
    if remainder:
        for i in range(0,len(remainder),2):
            try:
                options_lo.update({remainder[i].strip('-'): remainder[i+1]})
                printdebug("main", "saved {0} as {1}.".format(remainder[i].strip('-'), remainder[i+1]))
            except IndexError:
                options_lo.update({remainder[i].strip('-'): False})
        printinfo("main", "Couldn't parse options: {0}".format(remainder))
        #sys.exit(2)
        #ambiguous statement handling part 1
        #print("FYI: have option_dict={0}".format(option_dict))

    if options.filter:
        options.filterre = re.compile(options.filter)
    else:
        options.filterre = re.compile(".*")
    if options.searchdata:
        searchdatare=re.compile(options.searchdata,re.I)
    if options.examples:
        print(gExamples)
        sys.exit(0)
    if options.format=="csv":
        logsep=","
    elif options.format=="json":
        logsep=";"
    elif options.format=="tsv":
        logsep="\t"

    #gAuth.update({ "headers": {'Authorization':'PS-Auth key="' + options.key + '"; runas="' + options.user + '";' }})
    gAuth["headers"]={'Authorization':'PS-Auth key=' + options.key + '; runas=' + options.user + ';' }
    printdebug("main", "headers are now: " + str(gAuth["headers"]))

    mytype=""
    if options.type in gPBPStypes:
        mytype=gPBPStypes[options.type]
    elif options.type in [ "help", "h", "?" ]:
        print("Valid API classes / types:")
        print("    Type this:".ljust(24, " ") + "= To get this Class")
        print("".ljust(43, "-"))
        for mytype in sorted(gPBPStypes.items(), key=operator.itemgetter(1)):
            print("    " + mytype[0].ljust(20, " ") + "= " + gPBPStypes[mytype[0]])
        sys.exit(1)
    else:
        printerror("main", "invalid type requested. Use -t help for a full list")
        sys.exit(2)
    pbps=None
    printdebug("main", "Trying to launch type: {0}".format(mytype))
    pbps=gPBPSClasses.get(mytype, False)(mytype)

    #pbps can come back as false, so that we can do help statements below
    if pbps:
        printdebug("main", str(pbps))

    if options.action in pbps.actions:
        #action=pbps.actions[options.action]
        # don't need to map this - the dispatch is smarter than that
        printdebug("main", "found action " + options.action + " for type " + options.type)
    elif options.action in [ "help", "h", "?" ]:
        print("Valid Actions for API class: " + mytype)
        for action in pbps.actions:
            print("    " + action )
        print("       " + pbps.help)
        print("Use '-t {0} -a <action> --show' for a list of required arguments for each action.".format(mytype))
        sys.exit(2)
    else:
        printerror("main", "invalid action '" + options.action + "' for type " + mytype)
        sys.exit(2)

    if options.multiple:
        if not sys.stdin.isatty():
            multiple=sys.stdin
            #printerror("main", "Do not support cat file | pbpsabpi.py yet, sorry. Use --file <filename>")
            #exit(1)
        if options.file:
            multiple=open(options.file)

        headerline=multiple.readline().replace('\r', "")
        headerline=headerline.replace('\n', "")
        fields=headerline.split(logsep)
        printdebug("main", "Found {0} fields: {1}".format(len(fields), headerline))
        line=multiple.readline()
        printheader=True
        while line!="":
            line = line.replace('\r', "")
            line = line.replace('\n', "")
            printinfo("main", "Now reading line: {0}".format(line))
            parts=line.split(logsep)
            pbps=gPBPSClasses.get(mytype)(mytype)
            try: 
                for i in range(len(fields)):
                    if (not hasattr(options, fields[i])) or (not getattr(options, fields[i], False)):
                        pbps.reqdata[fields[i]]=parts[i]
                        printverbose("main", "Setting field {0} to value {1}.".format(fields[i], parts[i]))
                    else:
                        printinfo("main", "Overriding {0} from file with {1}.".format(fields[i], getattr(options, fields[i])))
            except IndexError:
                printerror("main", "Field mismatch - there are too few fields in the line: ")
                printerror("main", line)
                printerror("main", "Expected {0} fields.".format(len(fields)))
                sys.exit(4)
            pbps.printheader=printheader
            do(pbps, act=options.action)
            line=multiple.readline()
            printheader=False  #this will disable printing headers in the rest of the objects we print out, so that an easier report can be saved

    else:
        do(pbps, act=options.action)

    printdebug("main", str(pbps))
    pbps.signAppout()
    printverbose("main", "Now we are done.")
    if 200<=pbps.result<300:
        pbps.result=0
        #change 200 status codes to 0 for unix safe exiting
    sys.exit(pbps.result)


#############################################################################################################################
#############################################################################################################################
#############################################################################################################################
#############################################################################################################################
#
# PROGRAMMER INFORMATION BELOW HERE
#
#############################################################################################################################
#############################################################################################################################
#############################################################################################################################
#############################################################################################################################

'''

Version history
0.1: initial version
0.2: add auto-calling of type and action, rather than individual CLI options for each
0.3: add workgroup and import classes
0.4: add SmartRule and UserGroup classes and DELETE action to callPbps
1.0: split managedaccount and credentials types
1.1: fix break of password checkout due to split of credentials/managedaccounts.
        Add asset class
1.2: Add test class
        fix up asset class lookups with trailing "/"
2.0: Add self.doprint() to make cleaner consistent printing
        add self.defaults={} for a new "-D / --default" flag for creations
            So that new creations will pick up defaults. Required checkRequirements changes.
        add --multiple, so that a single logon session can create multiple objects
2.1: Add IP address lookups if the IP is "1.1.1.1" and some exception handling
2.2: replace printing system in pbps.listObjects() and all systems that call it.
        Fix printing with --multiple
        Add pipeline for --multiple
        Add try/catch for requests/urllib warning disables
        List FunctionalAccounts
2.3: Attribute and AttributeType management
2.3.1:  Data cleanup, catch some errors cleaner
2.4: Rewrite doprint to True/False
        Split Requests and Credentials classes
        Remove camelcase from class names, to ease CLI usage
        Clean up a few exit codes for scripting
2.4.1: Add --show handling of requirements
        Fix issues with pipelining multiple-password checkouts from "-t ma -a list" output
        Change myasset and wg from globals to attributes of related/required classes
2.5: Add setcreds, ensure it works with --multiple
        Change internal handling of -t password -a request to reduce API calls required in all cases
        Change printing function to handle more cases, reduce overall code length
        Clean up --show handling slightly.
2.5.1:
        Bugfixes due to test harness
2.5.2:
        Fixes for interactive asset handling and some requirements being requested multiple times.
        make --searchdata useful in "-a list" functions
2.5.3:
        fix a bug in --searchdata
        Make password checkouts properly handle "open request exists, here's your password anyways"
2.5.5:
        Make it work on Python 2.6.6 on RHEL6 !!!
2.6.0:
        Setcreds was incomplete in 2.5. Change some handling of options to be more human-usable.
        Updates to help output ordering and grouping
2.6.1:
        CreateManagedAccount added: -t ma -a create
2.7.0:
        PasswordRule class added
        Update UserGroups to get ID and name both.
        Change callPbps() printing of data to INFO level for easier use by ProServe devs as a self-check tool
2.7.1:
        Update checkRequirements for AccountName and AccountId instead of --account, for use in --multiple
2.8.0:
        managedaccount.delete implemented
2.8.1:
        get checkOptions to handle empty options on CLI
        fix handling of UpdateOnServer for setCredentials
        Test multiple credential setting
2.8.3:  spit out headers sanitized with new --json flag  (2.8.2 printed funny, but is the same change)
3.0.0:  Fix handling of options to use ambiguous names.  If it's something that is printed by "-t <type> -a <action> --show", you can add it verbatim on the CLI.
        Add Managed System Deletion
        Start handling requirement data types in checkRequirements, and enforcing them in there, rather than in the classes
        Version major to 3 because CLI system *may* not be backwards compatible to existing scripts.
3.0.1:  catch error where the --file for --multiple doesn't have consistent field counts
3.0.2:  new checkRequirements had errors with .lower() operations on int types. force them to str() first.
3.1.0:
        Add /SmartRules/{0}/Assets to Asset class
        Add SmartRule.getByName to support new asset search by smart rule
        Error cleanup in --json
        Change default to /usr/bin/env python from python3
3.1.1:  -a attribute -t create added as new action
        fix bug in password set by account name not having an ID
3.2.0:
        Add /DssKeyRules class for lookup
        Add SSH Key upload and retrieval to Credentials Class
        Fix "Alias" lookup in Credentials Class
        Verify SSH key and passphrase storage/retrieval on AD accounts works.
4.0.0:
        To get SSH Keys to work, had to change option handling to check if the option was a file or string.
        Because this is a fundamental change, the version was bumped to 4.0.  3.2 was therefore never released other than
        as a test to a single customer.
4.1.0:
        --smartrule got lost in the option handling update in 4.0, added back in.
        PUT /ManagedAccounts and GET /ManagedAccounts/{id} both use "ManagedAccountId", but "GET /ManagedAccounts" returns "AccountId" - had to add API workaround.
        Change --multiple so that if an entry is passed on the CLI, but *also* in the --file or pipeline, the CLI option will override.

4.2.0:
        Had to move "-t ma -a list" to -t pw -a list" and change "-t ma -a list" to list accounts per managed system.
        Minor fixups to field names
        Change --json to --prototype and add --format <format type> to allow logsep value change from CLI
        Fix -t ma -a list to search by domain or database with "--domain" flag
4.2.1:
        -t ms -a getbyfunacct was printing too much
4.2.2:  --multiple wasn't working right with new CLI override
        Add a few catches for "Id" vs. "ID" in JSON fields and --multiple
4.2.3:  add credentials.getAccount() for finding accounts for password requests, which uses /ManagedAccounts?systemName=x&accountName=y or the managedaccount() class, as appropriate
        Add gConflictOption and gAccessType
4.2.4:  Asset creation with both "--multiple" AND "--defaults" set the dnsname to "asset" This fix makes dnsname required, not optional


 To expand this tool and add a new subclass, do the following:
 1) in gPBPStypes{}, add the new human-typable names, and the class name they refer to (multiple human-typable keys can map to a single class.
 2) Create the class as a subclass of PbpsObject
 3) update the self.actions dict to include the actions specific to that object class
 4) update the gPBPSClasses dict to poing the action value names to the actual classes
 5) reuse as many optparse arguments as you can, but if you need to add more, do that.
 6) remember to use self.listObjects() and self.callPbps() functions to make your life easier
 7) if you add self.fields[] to your class, you can use "self.doprint(doprint=True)" to print all fields of your object

 TODO:
- Push AuthGroups
- smartrule put? others?
- much more exception handling for --show
- Change optparse to argparse
- Change object model to "list" being a list of actual objects?

'''

import traceback
import json
import sys
import random
import string

import httplib2

from Deadline.Cloud import *
from Deadline.Scripting import *
from FranticX import Environment2
from System.IO import *
from System import *

def GetCloudPluginWrapper():
    return SherpaPlugin()

def CleanupCloudPlugin(cloudPlugin):
    cloudPlugin.Cleanup()

class SherpaPlugin(CloudPluginWrapper):
    def __init__(self):
        self.endpoint = None
        self.token = None

        self.VerifyAccessCallback += self.VerifyAccess
        self.AvailableHardwareTypesCallback += self.GetAvailableSizes
        self.AvailableOSImagesCallback += self.GetAvailableImages
        self.GetActiveInstancesCallback += self.GetInstances
        self.CreateInstancesCallback += self.CreateInstances
        self.TerminateInstancesCallback += self.TerminateInstances
        self.CloneInstanceCallback += self.CloneInstance
        self.RebootInstancesCallback += self.RebootInstances
        self.StopInstancesCallback += self.StopInstances
        self.StartInstancesCallback += self.StartInstances

    def Cleanup(self):
        del self.VerifyAccessCallback
        del self.AvailableHardwareTypesCallback
        del self.AvailableOSImagesCallback
        del self.GetActiveInstancesCallback
        del self.CreateInstancesCallback
        del self.TerminateInstancesCallback
        del self.CloneInstanceCallback
        del self.RebootInstancesCallback
        del self.StopInstancesCallback
        del self.StartInstancesCallback

    def RefreshToken(self):
        if self.token == None:
            key = self.GetConfigEntryWithDefault("APIKey", "")

            if len(key) <= 0:
                raise Exception("Please enter your Escape Technology Console API key.")

            secret = self.GetConfigEntryWithDefault("APISecret", "")

            if len(secret) <= 0:
                raise Exception("Please enter your Escape Technology Console API secret.")

            endpoint = self.GetConfigEntryWithDefault("APIEndpoint", "")

            if len(endpoint) <= 0:
                raise Exception("Please enter the Escape Technology Console API endpoint.")

            self.endpoint = endpoint

            try:
                http = httplib2.Http(disable_ssl_certificate_validation=True)

                headers = {
                    "Content-Type": "application/ld+json"
                }

                body = {
                    "username": key,
                    "password": secret
                }

                (response, response_body) = http.request(
                    self.endpoint+"/login",
                    method="POST",
                    headers=headers,
                    body=json.dumps(body)
                )

                if response["status"] not in ["200", "201"]:
                    raise Exception(
                        "Problems getting a token. [%s] %s" % (response["status"], response)
                    )

                data = json.loads(response_body)
                self.token = data["token"]
            except:
                self.token = None

    def VerifyAccess(self):
        self.RefreshToken()

        ok = None

        if self.token != None:
            ok = True
        else:
            ok = False
            raise Exception("Error: invalid Escape Technology Console credentials. " \
                "Please ensure the correct API key and API secret have been entered.")

        return ok

    def GetAvailableSizes(self):
        self.RefreshToken()

        sizes = []

        try:
            if self.token != None:
                projectId = self.GetConfigEntryWithDefault("ProjectId", "")

                if len(projectId) <= 0:
                    raise Exception("Please enter the Escape Technology Console project ID.")

                http = httplib2.Http(disable_ssl_certificate_validation=True)

                headers = {
                    "Authorization": "Bearer "+self.token
                }

                (response, response_body) = http.request(
                    self.endpoint+"/projects/"+projectId,
                    method="GET",
                    headers=headers
                )

                data = json.loads(response_body)

                if response["status"] != "200":
                    raise Exception(
                        "Problems getting project. [%s] %s" % (response["status"], response)
                    )

                if len(data["regions"]) != 1:
                    raise Exception(
                        "Unexpected number of regions found: %s" % (len(data["regions"]))
                    )

                regionId = string.replace(data["regions"][0], "/regions/", "")

                headers = {
                    "Authorization": "Bearer "+self.token
                }

                (response, response_body) = http.request(
                    self.endpoint+"/sizes?@type=NodeSize&region="+regionId+"&pagination=false", # only return sizes related to project's region
                    method="GET",
                    headers=headers
                )

                data = json.loads(response_body)
                members = data["hydra:member"]

                if response["status"] != "200":
                    raise Exception(
                        "Problems getting list of sizes. [%s] %s" % (response["status"], response)
                    )

                for member in members:
                    s = HardwareType()

                    s.ID = member["id"]
                    s.Name = member["name"]

                    sizes.append(s)
        except:
            ClientUtils.LogText(traceback.format_exc())
        finally:
            return sizes

    def GetAvailableImages(self):
        self.RefreshToken()

        images = []

        try:
            if self.token != None:
                projectId = self.GetConfigEntryWithDefault("ProjectId", "")

                if len(projectId) <= 0:
                    raise Exception("Please enter the Escape Technology Console project ID.")

                http = httplib2.Http(disable_ssl_certificate_validation=True)

                headers = {
                    "Authorization": "Bearer "+self.token
                }

                (response, response_body) = http.request(
                    self.endpoint+"/projects/"+projectId,
                    method="GET",
                    headers=headers
                )

                data = json.loads(response_body)

                if response["status"] != "200":
                    raise Exception(
                        "Problems getting project. [%s] %s" % (response["status"], response)
                    )

                if len(data["regions"]) != 1:
                    raise Exception(
                        "Unexpected number of regions found: %s" % (len(data["regions"]))
                    )

                regionId = string.replace(data["regions"][0], "/regions/", "")

                headers = {
                    "Authorization": "Bearer "+self.token
                }

                (response, response_body) = http.request(
                    self.endpoint+"/images?@type=NodeImage&region="+regionId+"&pagination=false", # only return images related to project's region
                    method="GET",
                    headers=headers
                )

                data = json.loads(response_body)
                members = data["hydra:member"]

                if response["status"] != "200":
                    raise Exception(
                        "Problems getting list of sizes. [%s] %s" % (response["status"], response)
                    )

                for member in members:
                    i = OSImage()

                    i.ID = member["id"]
                    i.Description = member["name"]

                    images.append(i)
        except:
            ClientUtils.LogText(traceback.format_exc())
        finally:
            return images

    def GetInstances(self):
        self.RefreshToken()

        instances = []

        try:
            if self.token != None:
                projectId = self.GetConfigEntryWithDefault("ProjectId", "")

                if len(projectId) <= 0:
                    raise Exception("Please enter the Escape Technology Console project ID.")

                http = httplib2.Http(disable_ssl_certificate_validation=True)

                headers = {
                    "Authorization": "Bearer "+self.token
                }

                (response, response_body) = http.request(
                    self.endpoint+"/nodes?project="+projectId+"&pagination=false",
                    method="GET",
                    headers=headers
                )

                data = json.loads(response_body)
                members = data["hydra:member"]

                if response["status"] != "200":
                    raise Exception(
                        "Problems retrieving instances. [%s] %s" % (response["status"], response)
                    )

                for member in members:
                    state = InstanceStatus.Unknown

                    if member["marking"] == "creating":
                        state = InstanceStatus.Pending
                    elif member["marking"] == "created":
                        state = InstanceStatus.Pending
                    elif member["marking"] == "converging":
                        state = InstanceStatus.Pending
                    elif member["marking"] == "converged":
                        state = InstanceStatus.Running
                    elif member["marking"] == "verifying":
                        state = InstanceStatus.Pending
                    elif member["marking"] == "verified":
                        state = InstanceStatus.Running
                    elif member["marking"] == "starting":
                        state = InstanceStatus.Rebooting
                    elif member["marking"] == "started":
                        state = InstanceStatus.Running
                    elif member["marking"] == "stopping":
                        state = InstanceStatus.Stopping
                    elif member["marking"] == "stopped":
                        state = InstanceStatus.Stopped
                    elif member["marking"] == "deleting":
                        state = InstanceStatus.Pending
                    elif member["marking"] == "deleted":
                        state = InstanceStatus.Terminated
                    elif member["marking"] == "destroying":
                        state = InstanceStatus.Terminated
                    elif member["marking"] == "destroyed":
                        state = InstanceStatus.Terminated
                    else:
                        state = InstanceStatus.Unknown

                    instance = CloudInstance()

                    instance.ID = member["id"]
                    instance.Name = member["name"]
                    instance.Provider = "Escape Technology Console"
                    instance.Status = state
                    instance.Hostname = ""
                    instance.PublicIP = ""
                    instance.PrivateIP = ""
                    instance.HardwareID = string.replace(member["size"], "/sizes/", "")
                    instance.ImageID = string.replace(member["image"], "/images/", "")
                    instance.Zone = ""

                    instances.append(instance)
        except:
            ClientUtils.LogText(traceback.format_exc())
        finally:
            return instances

    def CreateInstances(self, sizeId, imageId, count):
        self.RefreshToken()

        instances = []

        try:
            if self.token != None:
                volumeSize = self.GetIntegerConfigEntryWithDefault("VolumeSize", 32)

                projectId = self.GetConfigEntryWithDefault("ProjectId", "")

                if len(projectId) <= 0:
                    raise Exception("Please enter the Escape Technology Console project ID.")

                http = httplib2.Http(disable_ssl_certificate_validation=True)

                headers = {
                    "Authorization": "Bearer "+self.token
                }

                (response, response_body) = http.request(
                    self.endpoint+"/projects/"+projectId,
                    method="GET",
                    headers=headers
                )

                data = json.loads(response_body)

                if response["status"] != "200":
                    raise Exception(
                        "Problems getting project. [%s] %s" % (response["status"], response)
                    )

                if len(data["regions"]) != 1:
                    raise Exception(
                        "Unexpected number of regions found: %s" % (len(data["regions"]))
                    )

                regionId = string.replace(data["regions"][0], "/regions/", "")

                if len(data["providers"]) != 1:
                    raise Exception(
                        "Unexpected number of providers found: %s" % (len(data["providers"]))
                    )

                providerId = string.replace(data["providers"][0], "/providers/", "")

                # service
                http = httplib2.Http(disable_ssl_certificate_validation=True)

                headers = {
                    "Authorization": "Bearer "+self.token
                }

                (response, response_body) = http.request(
                    self.endpoint+"/services?@type=NodeService&provider[]="+providerId, # only return services related to provider(s)
                    method="GET",
                    headers=headers
                )

                data = json.loads(response_body)

                if response["status"] != "200":
                    raise Exception(
                        "Problems getting service. [%s] %s" % (response["status"], response)
                    )

                if len(data["hydra:member"]) != 1:
                    raise Exception(
                        "Unexpected number of services found: %s" % (len(data["hydra:member"]))
                    )

                serviceId = data["hydra:member"][0]["id"]

                r = lambda: random.randint(0, 255)

                nodes = []

                for i in range(count):
                    # use a name with random 3byte hex value
                    name = self.GetConfigEntryWithDefault("InstanceName", "DL-SHERPA")
                    name = name + "-" + ("%02X%02X%02X" % (r(), r(), r()))
                    name = name.lower()

                    nodes.append({
                        "name": name,
                        "description": "",
                        "service": "/services/"+serviceId,
                        "region": "/regions/"+regionId,
                        "image": "/images/"+imageId,
                        "size": "/sizes/"+sizeId,
                        "volumeSize": volumeSize,
                    })

                (response, response_body) = http.request(
                    self.endpoint+"/projects/"+projectId+"/nodes",
                    method="POST",
                    headers={
                        "Authorization": "Bearer "+self.token,
                        "Content-Type": "application/ld+json",
                        "Accept": "application/ld+json"
                    },
                    body=json.dumps({
                        "nodes": nodes
                    })
                )

                data = json.loads(response_body)

                if response["status"] == "201":
                    key = "nodes"

                    if key not in data:
                        raise Exception(
                            "Problems creating instances: unexpected response. [%s] %s" % (response["status"], response)
                        )

                    for node in data[key]:
                        i = CloudInstance()

                        i.ID = node["id"]
                        i.Name = node["name"]
                        i.Hostname = ""
                        i.HardwareID = string.replace(node["size"], "/sizes/", "")
                        i.ImageID = string.replace(node["image"], "/images/", "")

                        instances.append(i)
                else:
                    key = "hydra:description"

                    if response["status"] == "400" and key in data:
                        ClientUtils.LogText("Problems creating instances: %s. [%s]" % (data[key]), response["status"])
                    else:
                        raise Exception(
                            "Problems creating instances: unhandled response. [%s] %s" % (response["status"], response)
                        )
        except:
            ClientUtils.LogText(traceback.format_exc())
        finally:
            return instances

    def TerminateInstances(self, instanceIds):
        if instanceIds == None or len(instanceIds) == 0:
            return []

        self.RefreshToken()

        count = len(instanceIds)
        results = [False] * count

        try:
            projectId = self.GetConfigEntryWithDefault("ProjectId", "")

            if len(projectId.strip()) <= 0:
                raise Exception("Please enter the Escape Technology Console project ID.")

            for i in range(0, count):
                instanceId = instanceIds[i]

                http = httplib2.Http(disable_ssl_certificate_validation=True)

                headers = {
                    "Authorization": "Bearer "+self.token
                }

                (response, response_body) = http.request(
                    self.endpoint+"/nodes/"+instanceId,
                    method="DELETE",
                    headers=headers
                )

                if response["status"] == "204": # "no content"
                    results[i] = True
                else:
                    ClientUtils.LogText(
                        "Problems deleting instance with ID: %s. [%s] %s" % (instanceId, response["status"], response)
                    )
        except:
            ClientUtils.LogText(traceback.format_exc())
        finally:
            return results

    def StopInstances(self, instanceIds):
        if instanceIds == None or len(instanceIds) == 0:
            return []

        self.RefreshToken()

        count = len(instanceIds)
        results = [False] * count

        try:
            projectId = self.GetConfigEntryWithDefault("ProjectId", "")

            if len(projectId.strip()) <= 0:
                raise Exception("Please enter the Escape Technology Console project ID.")

            for i in range(0, count):
                instanceId = instanceIds[i]

                http = httplib2.Http(disable_ssl_certificate_validation=True)

                headers = {
                    "Authorization": "Bearer "+self.token,
                    "Content-Type": "application/ld+json",
                    "Accept": "application/ld+json"
                }

                body = {
                    "marking": "stop"
                }

                (response, response_body) = http.request(
                    self.endpoint+"/nodes/"+instanceId,
                    method="PUT",
                    headers=headers,
                    body=json.dumps(body)
                )

                if response["status"] == "200":
                    results[i] = True
                else:
                    ClientUtils.LogText(
                        "Problems stopping instance with ID: %s. [%s] %s" % (instanceId, response["status"], response)
                    )
        except:
            ClientUtils.LogText(traceback.format_exc())
        finally:
            return results

    def StartInstances(self, instanceIds):
        if instanceIds == None or len(instanceIds) == 0:
            return []

        self.RefreshToken()

        count = len(instanceIds)
        results = [False] * count

        try:
            projectId = self.GetConfigEntryWithDefault("ProjectId", "")

            if len(projectId.strip()) <= 0:
                raise Exception("Please enter the Escape Technology Console project ID.")

            for i in range(0, count):
                instanceId = instanceIds[i]

                http = httplib2.Http(disable_ssl_certificate_validation=True)

                headers = {
                    "Authorization": "Bearer "+self.token,
                    "Content-Type": "application/ld+json",
                    "Accept": "application/ld+json"
                }

                body = {
                    "marking": "start"
                }

                (response, response_body) = http.request(
                    self.endpoint+"/nodes/"+instanceId,
                    method="PUT",
                    headers=headers,
                    body=json.dumps(body)
                )

                if response["status"] == "200":
                    results[i] = True
                else:
                    ClientUtils.LogText(
                        "Problems starting instance with ID: %s. [%s] %s" % (instanceId, response["status"], response)
                    )
        except:
            ClientUtils.LogText(traceback.format_exc())
        finally:
            return results

    def RebootInstances(self, instanceIds):
        raise Exception("Not implemented: RebootInstances")

    def CloneInstance(self, instance, count):
        raise Exception("Not implemented: CloneInstance")

# -*- coding: utf-8 -*-
# Copyright (c) 2022-2023 Hewlett Packard Enterprise, Inc. All rights reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
import os
__metaclass__ = type
#import pandas as pd
import json
import subprocess
import time
from requests.auth import HTTPBasicAuth
from ansible_collections.community.general.plugins.module_utils.redfish_utils import RedfishUtils
from ansible.module_utils.urls import open_url, prepare_multipart
from ansible.module_utils.six.moves.urllib.error import URLError, HTTPError
import configparser

supported_models=["XD675", "MIRAMAR"]
#supported_models=["HPE CRAY XD220V", "HPE CRAY SC XD220V", "HPE CRAY XD225V","HPE CRAY SC XD225V", "HPE CRAY XD295V","HPE CRAY SC XD295V", "HPE CRAY XD665", "HPE CRAY XD675",  "HPE CRAY SC XD665", "HPE CRAY SC XD675 DLC", "HPE CRAY SC XD675"]

#to get inventory, update
partial_models={}
#{"HPE CRAY XD675": "XD675", "HPE CRAY XD675 DLC": "XD675", "HPE CRAY XD675 SC": "XD675", "HPE CRAY XD665": "XD665", "HPE CRAY XD665 SC": "XD665", "HPE CRAY XD220v": "XD220"}
supported_targets={
    "XD675": ["bmc", "bios", "dcscm_fpga", "mb_fpga", "hib_fpga", "gpu"],
    "MIRAMAR": ["bmc", "bios", "dcscm_fpga", "mb_fpga", "hib_fpga", "gpu"],

}

XD675_targets = ['bmc', 'bios', 'dcscm_fpga', 'mb_fpga', 'hib_fpga']
GPU_targets = ['gpu']
all_targets = ['bmc', 'bios', 'dcscm_fpga', 'mb_fpga', 'hib_fpga', 'gpu']

reboot = {
    "bios": ["AC_PC_redfish"],
    "dcscm_fpga": ["AC_PC_ipmi"],
    "mb_fpga": ["AC_PC_ipmi"],
    "hib_fpga": ["AC_PC_ipmi"]
}

routing = {
    "XD675": {
        "dcscm_fpga": "0x30 0x25 0xF 0xD4 0x0 0x00 0x20 0x00 0x00 0x01",
        "mb_fpga": "0x30 0x25 0xF 0xD2 0x0 0x00 0x20 0x00 0x00 0x01",
        "hib_fpga": "0x30 0x25 0xF 0x82 0x0 0x00 0x20 0x00 0x00 0x01"
    },
    "MIRAMAR": {
        "dcscm_fpga": "0x30 0x25 0xF 0xD4 0x0 0x00 0x20 0x00 0x00 0x01",
        "mb_fpga": "0x30 0x25 0xF 0xD2 0x0 0x00 0x20 0x00 0x00 0x01",
        "hib_fpga": "0x30 0x25 0xF 0x82 0x0 0x00 0x20 0x00 0x00 0x01"
    }
}

#config = configparser.ConfigParser()

class CrayRedfishUtils(RedfishUtils):
    def post_multi_request(self, uri, headers, payload):
        username, password, basic_auth = self._auth_params(headers)
        try:
            resp = open_url(uri, data=payload, headers=headers, method="POST",
                            url_username=username, url_password=password,
                            force_basic_auth=basic_auth, validate_certs=False,
                            follow_redirects='all',
                            use_proxy=True, timeout=self.timeout)
            resp_headers = dict((k.lower(), v) for (k, v) in resp.info().items())
            return True
        except Exception as e:
            return False

    def get_model(self):
        try:
            response = self.get_request(self.root_uri + "/redfish/v1/Systems/system")
            if response['ret'] is False:
                return "NA"
        except:
            return "NA"
        model="NA"
        try:
            if 'Model' in response['data']:
                model = response['data'][u'Model'].strip()
        except:
            if 'Model' in response:
                model = response[u'Model'].strip()
            else:
                return "NA"
        if model not in partial_models:
            split_model_array = model.split() #["HPE", "Cray", "XD665"]
            for dum in split_model_array:
                if any(keyword in dum for keyword in ["XD", "MIRAMAR"]):
                    partial_models[model.upper()]=dum.upper()
        return model

    def power_state(self):
        response = self.get_request(self.root_uri + "/redfish/v1/Systems/system")
        if response['ret'] is False:
            return "NA"
        state='None'
        try:
            if 'PowerState' in response['data']:
                state = response['data'][u'PowerState'].strip()
        except:
            if 'PowerState' in response:
                state = response[u'PowerState'].strip()
        return state

    def power_on(self):
        payload = {"ResetType": "On"}
        target_uri = "/redfish/v1/Systems/system/Actions/ComputerSystem.Reset"
        response1 = self.post_request(self.root_uri + target_uri, payload)
        time.sleep(120)

    def power_off(self):
        payload = {"ResetType": "ForceOff"}
        target_uri = "/redfish/v1/Systems/system/Actions/ComputerSystem.Reset"
        response1 = self.post_request(self.root_uri + target_uri, payload)
        time.sleep(120)

    def get_PS_CrayXD675(self,attr):
        ini_path = os.path.join(os.getcwd(),'config.ini')
        config = configparser.ConfigParser()
        IP = attr.get('baseuri')
        config.read(ini_path)
        try:
            option = config.get('Options','power_state')
            if option=="":
                return {'ret': False, 'changed': True, 'msg': 'Must specify the required option for power_state in config.ini'}
        except:
            return {'ret': False, 'changed': True, 'msg': 'Must specify the required option for power_state in config.ini'}

        csv_file_name = attr.get('output_file_name')
        if not os.path.exists(csv_file_name):
            f = open(csv_file_name, "w")
            to_write="IP_Address,Model,Power_State\n"
            f.write(to_write)
            f.close()
        model = self.get_model()
        if any(m in model.upper() for m in supported_models):
            power_state = self.power_state()
            if option.upper()=="NA":
                lis=[IP,model,power_state]
            elif option.upper()=="ON":
                if power_state.upper()=="OFF":
                    self.power_on()
                power_state = self.power_state()
                lis=[IP,model,power_state]
            elif option.upper()=="OFF":
                if power_state.upper()=="ON":
                    self.power_off()
                power_state = self.power_state()
                lis=[IP,model,power_state]
            else:
                return {'ret': False, 'changed': True, 'msg': 'Must specify the correct required option for power_state in config.ini'}

        else:
            lis=[IP,model,"unsupported_model"]
        new_data=",".join(lis)
        return {'ret': True,'changed': True, 'msg': str(new_data)}


    def target_supported(self,model,target):
        try:
            if target in supported_targets[partial_models[model.upper()]]:
                return True
            return False
        except:
            return False

    def get_fw_version(self,target):
        try:
            response = self.get_request(self.root_uri + "/redfish/v1/UpdateService/FirmwareInventory"+"/"+target)
            if response['ret'] is False:
                return "NA"
            try:
                version = response['data']['Version']
                return version
            except:
                version = response['Version']
                return version
        except:
            return "NA"

    def AC_PC_redfish(self):
        payload = {"ResetType": "PowerCycle"}
        target_uri = "/redfish/v1/Systems/system/Actions/ComputerSystem.Reset"
        response1 = self.post_request(self.root_uri + target_uri, payload)
        time.sleep(180)
        target_uri = "/redfish/v1/Chassis/FRU_ADP/Actions/Chassis.Reset"
        response2 = self.post_request(self.root_uri + target_uri, payload)
        time.sleep(180)
        return response1

    def AC_PC_ipmi(self, IP, username, password, routing_value):
        try:
            command='ipmitool -I lanplus -H '+IP+' -U '+username+' -P '+password+' -C 17 raw '+ routing_value    # -C 17 specifies cipher suite, as XD675 restricts -C 3 (default) cipher suite
            subprocess.run(command, shell=True, check=True, timeout=15)
            time.sleep(300)
            self.power_on()
            return True
        except:
            return False

    def get_gpu_inventory(self,attr):
        IP = attr.get('baseuri')
        csv_file_name = attr.get('output_file_name')
        model = self.get_model()
        if not os.path.exists(csv_file_name):
            f = open(csv_file_name, "w")
            to_write="IP_Address,Model,AMC_ACTIVE,AMC_FPGA_ACTIVE,APCFG_ACTIVE,BUNDLE_ACTIVE,IFWI_ACTIVE,RETIMER_ACTIVE,RMI_ACTIVE,ROT_ACTIVE,UBB_FPGA_ACTIVE,VR_BUNDLE_ACTIVE\n"
            all_targets = GPU_targets
            f.write(to_write)
            f.close()
        entry=[]
        entry.append(IP)
        if model=="NA":
            entry.append("unreachable/unsupported_system") #unreachable or not having model field correctly, i.e not even a XD system
            for target in GPU_targets:
                entry.append("NA")
        elif partial_models[model.upper()] not in supported_models: #might be a Cray XD like XD685 which is not yet supported
            entry.append("unsupported_model, ")
            for target in GPU_targets:
                entry.append("NA")
            #return {'ret': True, 'changed': True, 'msg': 'Must specify systems of only the supported models. Please check the model of %s'%(IP)}
        else:
            entry.append(model)
            for target in GPU_targets:
                if target in supported_targets[partial_models[model.upper()]]:
                    version_list=self.get_fw_version(target)
                else:
                    version_list="NA"
                for component in version_list:
                    try:
                        entry.append(component['Version'])
                    except:
                        entry.append(str(component['VRVersion']))
        new_data=",".join(entry)
        return {'ret': True,'changed': True, 'msg': str(new_data)}

    def get_sys_fw_inventory(self,attr):
        IP = attr.get('baseuri')
        csv_file_name = attr.get('output_file_name')
        model = self.get_model()
        if not os.path.exists(csv_file_name):
            f = open(csv_file_name, "w")
            to_write="IP_Address,Model,BMC,BIOS,DCSCM_FPGA,MB_FPGA,HIB_FPGA\n"
            f.write(to_write)
            f.close()
        entry=[]
        entry.append(IP)
        if model=="NA":
            entry.append("unreachable/unsupported_system") #unreachable or not having model field correctly, i.e not even a XD system
            for target in XD675_targets:
                entry.append("NA")
        elif partial_models[model.upper()] not in supported_models: #might be a Cray XD like XD685 which is not yet supported
            entry.append("unsupported_model, ")
            for target in XD675_targets:
                entry.append("NA")
            #return {'ret': True, 'changed': True, 'msg': 'Must specify systems of only the supported models. Please check the model of %s'%(IP)}
        else:
            entry.append(model)
            for target in XD675_targets:
                if target in supported_targets[partial_models[model.upper()]]:
                    version=self.get_fw_version(target)
                else:
                    version = "NA"
                entry.append(version)
        new_data=",".join(entry)
        return {'ret': True,'changed': True, 'msg': str(new_data)}

    def helper_update_GPU(self,update_status,target,image_path,image_type,IP,username,password,model):
        update_status="Update failed"
        response = self.get_request(self.root_uri + "/redfish/v1/Managers")
        if response['ret'] is False:
            update_status="Managers api not found"
            return update_status
        else:
            # Power off the system before update
            self.power_off()
            headers = {'Filename': 'amdfw.pldm'}
            with open(image_path, 'rb') as image_path_rb:
                upload_uri = "/redfish/v1/Managers/Wistron/UploadFile"
                response = self.post_multi_request(self.root_uri + upload_uri, headers=headers, payload=image_path_rb)
                if response is False:
                    update_status="failed_Post_Image_Upload"
                else:
                    #Trigger MI300x GPU update
                    trigger_uri = "/redfish/v1/Managers/bmc/Oem/Wistron/GPU/FwUpdate"
                    trigger_response = self.post_multi_request(self.root_uri + trigger_uri, headers={}, payload=json.dumps({}))
                    if trigger_response is False:
                        update_status="failed_Post_Trigger_update"
                    else:
                        #add time.sleep (for BMC to comeback after flashing )
                        time.sleep(600)
                        #Check GPU update status
                        check_uri = "/redfish/v1/Managers/bmc/Oem/Wistron/GPU/UpdateStatus"
                        status_response = self.get_request(self.root_uri + check_uri)
                        if status_response['ret'] is False:
                            update_status="Check status api not found"
                            return update_status
                        elif status_response['data']['Status'] != "Success":
                            update_status=target.upper()+" update failed"
                            return update_status
                        update_status="success"
        return update_status

    def helper_update_BMC(self,update_status,target,image_path,image_type,IP,username,password,model):
        before_version=None
        after_version=None
        update_status=None
        before_version = self.get_fw_version(target)
        if not before_version.startswith("NA"):
            #proceed for update
            response = self.get_request(self.root_uri + "/redfish/v1/UpdateService")
            if response['ret'] is False:
                update_status="UpdateService api not found"
                after_version="NA"
            else:
                data = response['data']
                if 'HttpPushUri' in data:
                    headers = {'Content-Type': 'application/octet-stream'}
                    targets_uri="/redfish/v1/UpdateService/FirmwareInventory/"+target+"/"
                    with open(image_path, 'rb') as image_path_rb:
                        response = self.post_multi_request(self.root_uri + data['HttpPushUri'], headers=headers, payload=image_path_rb)
                        if response is False:
                            update_status="failed_Post"
                            after_version="NA"
                        else:
                            #add time.sleep (for BMC to comeback after flashing )
                            time.sleep(800)
                            update_status="success"
                            if update_status.lower()=="success":
                                #call version of respective target and store versions after update
                                time.sleep(180) #extra time requiring as of now for systems under test
                                after_version=self.get_fw_version(target)
                            else:
                                after_version="NA"

            return before_version,after_version,update_status
        else:
            update_status="NA"
            after_version="NA"
            return before_version,after_version,update_status

    def helper_update(self,update_status,target,image_path,image_type,IP,username,password,model):
        before_version=None
        after_version=None
        update_status=None
        before_version = self.get_fw_version(target)
        response = self.get_request(self.root_uri + "/redfish/v1/Managers")
        if response['ret'] is False:
            update_status="Managers api not found"
            after_version="NA"
            if "fpga" in target:
                return update_status
            else:
                return before_version,after_version,update_status
        if not before_version.startswith("NA"):
            #proceed for update
            if target=="bios":
                #Turn off HPE Cray XD675 node
                self.power_off()
            headers = {'Content-Type': 'application/octet-stream', 'Filename': 'oem.bin'}
            with open(image_path, 'rb') as image_path_rb:
                upload_uri = "/redfish/v1/Managers/Wistron/UploadFile"
                response = self.post_multi_request(self.root_uri + upload_uri, headers=headers, payload=image_path_rb)
                if response is False:
                    update_status="failed_Post_Image_Upload"
                    after_version="NA"
                else:
                    #Trigger target update
                    trigger_uri = "/redfish/v1/Managers/Wistron/OEMUpdate"
                    if "fpga" in target:
                        updated_target = target.replace("_","-")
                        update_device = {"updateDevice": updated_target}
                    else:
                        update_device = {"updateDevice": target}
                    trigger_response = self.post_multi_request(self.root_uri + trigger_uri, headers={}, payload=json.dumps(update_device))
                    if trigger_response is False:
                        update_status="failed_Post_Trigger_update"
                        after_version="NA"
                    else:
                        #add time.sleep (for BMC to comeback after flashing )
                        time.sleep(600)
                        #Check CPLD update status
                        if "fpga" in target:
                            check_uri = "/redfish/v1/Managers/Wistron/OEMUpdate/CheckStatus"
                            status_response = self.get_request(self.root_uri + check_uri)
                            if status_response['ret'] is False:
                                update_status="Check status api not found"
                                return update_status
                            elif status_response['data']['Result'] != "Success":
                                update_status=target.upper()+" update failed"
                                return update_status
                        if target == "bios":
                            self.power_on()
                        elif "fpga" in target:
                            power_state = self.power_state()
                            if power_state.lower() == "on":
                                self.power_off()
                                power_state = self.power_state()
                                if power_state.lower() == "on":
                                    update_status = target.upper() + " requires node off, tried powering off the node, but failed to power off"
                                    return update_status
                        #call reboot logic based on target
                        update_status="success"
                        if target in reboot:
                            what_reboots = reboot[target]
                            for reb in what_reboots:
                                if reb=="AC_PC_redfish":
                                    result=self.AC_PC_redfish()
                                    if not result:
                                        update_status="reboot_failed"
                                        break
                                    time.sleep(300)
                                elif reb=="AC_PC_ipmi":
                                    result = self.AC_PC_ipmi(IP, username, password, routing[partial_models[model.upper()]][target]) #based on the model end routing code changes
                                    if not result:
                                        update_status="reboot_failed"
                                        break
                        if update_status.lower()=="success":
                            #call version of respective target and store versions after update
                            #time.sleep(180) #extra time requiring as of now for systems under test
                            if target!="dcscm_fpga" and target!="mb_fpga" and target!="hib_fpga" and target!="gpu":
                                after_version=self.get_fw_version(target)
                        else:
                            if target!="dcscm_fpga" and target!="mb_fpga" and target!="hib_fpga" and target!="gpu":
                                after_version="NA"

            if target!="dcscm_fpga" and target!="mb_fpga" and target!="hib_fpga":
                return before_version,after_version,update_status
            else:
                return update_status
        else:
            update_status="NA"
            if target!="dcscm_fpga" and target!="mb_fpga" and target!="hib_fpga":
                after_version="NA"
                return before_version,after_version,update_status
            else:
                return update_status

    def system_fw_update(self, attr):
        ini_path = os.path.join(os.getcwd(),'config.ini')
        config = configparser.ConfigParser()
        config.read(ini_path)
        key = ""
        try:
            target = config.get('Target','update_target')
            image_path_inputs = {
                self.get_model(): config.get('Image', 'update_image_path_XD675'),
                }
        except:
            pass

        ## have a check that at least one image path set based out of the above new logic
        if not any(image_path_inputs.values()):
            return {'ret': False, 'changed': True, 'msg': 'Must specify at least one update_image_path'}
        IP = attr.get('baseuri')
        username = attr.get('username')
        password = attr.get('password')
        update_status = "success"
        before_version=None
        after_version=None
        is_target_supported=False
        # before_version="NA"
        # after_version="NA"
        image_path="NA"
        csv_file_name = attr.get('output_file_name')
        image_type = ""
        if image_type is None:
            image_type = attr.get('update_image_type') 

        if target=="" or target.lower() not in all_targets:
            return {'ret': False, 'changed': True, 'msg': 'Must specify the correct target for firmware update'}    
        model = self.get_model()

        if not os.path.exists(csv_file_name):
            f = open(csv_file_name, "w")
            if target=="dcscm_fpga" or target=="mb_fpga" or target=="hib_fpga":
                to_write="IP_Address,Model,Update_Status,Remarks\n"
            elif target=="gpu":
                to_write="IP_Address,Model,Update_Status,Remarks\n"
            else:
                to_write="IP_Address,Model,"+target+'_Pre_Ver,'+target+'_Post_Ver,'+"Update_Status\n"
            f.write(to_write)
            f.close()
        if model=="NA":
            update_status="unreachable/unsupported_system"
            if target=="gpu" or target=="dcscm_fpga" or target=="mb_fpga" or target=="hib_fpga":
                lis=[IP,model,update_status,"NA"]
            else:
                lis=[IP,model,"NA","NA",update_status]
            new_data=",".join(lis)
            return {'ret': True,'changed': True, 'msg': str(new_data)}
        elif partial_models[model.upper()] not in supported_models:
            update_status="unsupported_model"
            if target=="gpu" or target=="dcscm_fpga" or target=="mb_fpga" or target=="hib_fpga":
                lis=[IP,model,update_status,"NA"]
            else:
                lis=[IP,model,"NA","NA",update_status]
            new_data=",".join(lis)
            return {'ret': True,'changed': True, 'msg': str(new_data)}
        else:
            image_path = image_path_inputs[partial_models[model.upper()]]
            
            if not os.path.isfile(image_path):
                update_status = "NA_fw_file_absent"
                if target=="gpu" or "fpga" in target:
                    lis=[IP,model,update_status,"NA"]
                else:
                    lis=[IP,model,"NA","NA",update_status]
                new_data=",".join(lis)
                return {'ret': False,'changed': True, 'msg': 'NA_fw_file_absent'}
            else:
                is_target_supported = self.target_supported(model,target)
                if not is_target_supported:
                    update_status="target_not_supported"
                    if target=="gpu" or "fpga" in target:
                        lis=[IP,model,update_status,"NA"]
                    else:
                        lis=[IP,model,"NA","NA",update_status]
                    new_data=",".join(lis)
                    return {'ret': True,'changed': True, 'msg': str(new_data)}
                else:
                    if "fpga" in target:
                        update_status=self.helper_update(update_status,target,image_path,image_type,IP,username,password,model)
                        if update_status.lower() == "success":
                            remarks=target.upper()+" firmware update is successfully completed."
                        else:
                            remarks=target.upper()+" firmware update is unsuccessful. Please reflash the firmware."
                        lis=[IP,model,update_status,remarks]
                    elif target == "gpu":
                        update_status=self.helper_update_GPU(update_status,target,image_path,image_type,IP,username,password,model)
                        if update_status.lower() == "success":
                            remarks="GPU firmware update completed successfully. Please perform an AC power cycle to activate the latest firmware."
                        else:
                            remarks="Please reflash the firmware and do not perform AC power cycle."
                        lis=[IP,model,update_status,remarks]
                    else:
                        if target=="bmc" and "bmc_" not in image_path:
                            return {'ret': False, 'changed': True, 'msg': 'Must specify correct image and target'}
                        elif target=="bios" and "DS_" not in image_path:
                            return {'ret': False, 'changed': True, 'msg': 'Must specify correct image and target'}
                        if target=="bmc":
                            bef_ver,aft_ver,update_status=self.helper_update_BMC(update_status,target,image_path,image_type,IP,username,password,model)
                        elif target=="bios":
                            bef_ver,aft_ver,update_status=self.helper_update(update_status,target,image_path,image_type,IP,username,password,model)
                        lis=[IP,model,bef_ver,aft_ver,update_status]
                    new_data=",".join(lis)
                    return {'ret': True,'changed': True, 'msg': str(new_data)}
                
#!/usr/bin/env python3
""" 
Description - This Scritp will get the Today-ec2_findings data from Scout2-History 
        bucket for each account and write Findings data to dynamodb table
        and 
        pull the ec2 security checklist info using crossaccount access role and write the date as per findings

Update Table    -   security-audit-EC2_SecurityGroups

Requrements - python3, Scout2 Report, imported libraries, aws crossaccount role,dynamodb,sns subscription,s3 bucket access

Output - Writing findings data for each rule in to dynamodbTable for each AWS account. 

"""
__author__ = "Chenna Vemula,Brian Rossi"
__COPYRIGHT__ = " Copyright 2018 , Caterpillar"
__email__ = " chenna_vemula@cat.com"
__version__ = " 0.0.4-stable(10/25/2018)" 
import re
import os
import datetime
import dateutil
import requests
#import pytz
import boto3, json, time, datetime, sys
from dateutil.parser import parse
import traceback
from dateutil import tz, parser
from datetime import timedelta, date, datetime, timezone
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
from botocore.config import Config
sts = boto3.client('sts', config=Config(retries={'max_attempts': 10}))
ClientSSM = boto3.client('ssm', 'us-east-2')
ssm_par_name='Scout2-EC2-Startkey'
dynamodb_resource = boto3.resource('dynamodb','us-east-2')
dynamodb_client = boto3.client('dynamodb','us-east-2')
update_table_primarykey='Accountid'
update_table_sort_key='Rulename'
service='ec2'
BUCKET_NAME = 'ue2-scout2-prod-history' 
s3 = boto3.resource('s3')
valid_riskdomain_tags=['riskdomain','RD','rd','RiskDomain','RISKDOMAIN']
today_date=datetime.now()
running_date=today_date.strftime('%Y-%m-%dT%H:%M:%SZ')
accounts_list_table=dynamodb_resource.Table('awsaccounts-crossaccountrole-list')
def get_aws_access_creds(CrossAuditRole):
    assumedRoleObject = sts.assume_role(RoleArn=str(CrossAuditRole), RoleSessionName="ec2_security_audit_lambda")
    credentials = assumedRoleObject['Credentials']
    ec2_client = boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'],config=Config(retries={'max_attempts': 10}),)
    return ec2_client
def get_aws_resource(region,CrossAuditRole):
    assumedRoleObject = sts.assume_role(RoleArn=str(CrossAuditRole), RoleSessionName="ec2_security_audit_lambda")
    credentials = assumedRoleObject['Credentials']
    ec2_resource = boto3.resource('ec2',aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'],region_name= region,config=Config(retries={'max_attempts': 10}),)
    return ec2_resource
def get_region_ec2_client(region,CrossAuditRole):
    assumedRoleObject = sts.assume_role(RoleArn=str(CrossAuditRole), RoleSessionName="ec2_security_audit_lambda")
    credentials = assumedRoleObject['Credentials']
    conn_ec2_reg_client = boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'],region_name= region,config=Config(retries={'max_attempts': 10}),)
    return conn_ec2_reg_client
def check_and_get_parameter(paramname):
    try:
        get_evaluated_key=ClientSSM.get_parameter(Name=paramname)
    except :
        response = ClientSSM.put_parameter(Name=paramname,Description='Ec2LastEvaluatedKey',Value='Null',
        Type='String',Overwrite=True)
        print("Value Updated--Version as",response  )
        get_evaluated_key=ClientSSM.get_parameter(Name=paramname)
    return get_evaluated_key 
def check_and_update_parameter(accounts_list_table_scan):
    if 'LastEvaluatedKey' in accounts_list_table_scan:
        print("----------Updating Last Evaluated Key as",accounts_list_table_scan['LastEvaluatedKey'])
        LastEvaluatedKey=accounts_list_table_scan['LastEvaluatedKey']['AccountID']
        ClientSSM.put_parameter(Name='Scout2-EC2-Startkey',Description='Ec2LastEvaluatedKey',Value=LastEvaluatedKey,Type='String',Overwrite=True)
        print(LastEvaluatedKey)
    else:
        print("---------->LastEvaluatedKey found as null_Updating key as Null and finished all accounts")
        LastEvaluatedKey='Null'
        ClientSSM.put_parameter(Name='Scout2-EC2-Startkey',Description='Ec2LastEvaluatedKey',Value=LastEvaluatedKey,Type='String',Overwrite=True)
    return LastEvaluatedKey
def lambda_handler(event, context):
    alrt=''
    try:
        get_evaluated_key=check_and_get_parameter(ssm_par_name)
        if get_evaluated_key['Parameter']['Value']=="Null":
            accounts_list_table_scan = accounts_list_table.scan(Select='ALL_ATTRIBUTES',Limit=5,ConsistentRead=True,#ExclusiveStartKey='',
                                                                 FilterExpression=Attr("CrossAuditRole").ne('NotFound') & Attr("Scout2dataS3key").ne('N/A'))
        else:                                              
            accounts_list_table_scan = accounts_list_table.scan(Select='ALL_ATTRIBUTES',Limit=5,ExclusiveStartKey={'AccountID':str(get_evaluated_key['Parameter']['Value'])},
                                                            FilterExpression=Attr("CrossAuditRole").ne('NotFound') & Attr("Scout2dataS3key").ne('N/A'))
        accounts_list_table_scan_ext = accounts_list_table_scan['Items']
        ec2_table = dynamodb_resource.Table(verifyLogTable('security-audit-EC2_SecurityGroups',update_table_primarykey,update_table_sort_key))
        #############################################################   
            #DOWNLOADING FINDINGS DATA FROM S3BUCKET
        #############################################################
        for key in accounts_list_table_scan_ext:
            print("Scanning for:"+ key['AccountID'] +':'+key['Alias'] )
            try:
                print("-->Downloading Account S3Key:--",key['Scout2dataS3key'])
                s3.Bucket(BUCKET_NAME).download_file(key['Scout2dataS3key'], '/tmp/findings.js')
                with open("/tmp/findings.js", 'rt') as f:
                    next(f)
                    content = f.read()
                    data = json.loads(content)
            except:
                #alrt+='AccountName:  {} \n '.format(str(key['Alias']))
                print("-----Unable to read Scout2 Data for the account:--"+ key['AccountID'] +':'+key['Name'])
                raise
            ec2_findings = data["services"][service]["findings"]
            ac_ec2_info={}
            ac_ec2_info[key['AccountID']] = {}
            ac_ec2_info[key['AccountID']]['ReportedOn']=data["last_run"]["time"]
            scout2_reportdate=data["last_run"]["time"]
            reportdate=(parser.isoparse(scout2_reportdate)).strftime('%Y-%m-%dT%H:%M:%SZ')
            ac_ec2_info[key['AccountID']]["Scout2_Ac_Number"]=data["aws_account_id"]      
            ################################################################## 
            #  PARSING DATA FILE FOR THE SERVICE 'EC2' FOR EACH SCOUT2EC2-RULE
            ##################################################################
            for key_ec2, key_value in ec2_findings.items():
                #print("------------->Searching for:-",key_value["dashboard_name"],  key_ec2)
                if int(key_value["flagged_items"]) >= 1:
                    try:
                        items_list_found = key_value["items"]
                        #print("-------------------->Items Found As:--",   len(items_list_found))
                        ac_ec2_info[data["aws_account_id"]][key_ec2]={}
                        ac_ec2_info[key['AccountID']][key_ec2]["checked_items"] = key_value['checked_items']
                        ac_ec2_info[key['AccountID']][key_ec2]["flagged_items_count"] = key_value['flagged_items']
                        ac_ec2_info[key['AccountID']][key_ec2]["level"] = key_value['level']
                        ac_ec2_info[key['AccountID']][key_ec2]["dashboard_name"] = key_value['dashboard_name']
                        ac_ec2_info[key['AccountID']][key_ec2]["description"] = key_value['description']
                        ac_ec2_info[key['AccountID']][key_ec2]["rationale"] = key_value['rationale']
                        ac_ec2_info[key['AccountID']][key_ec2]["service"] = key_value['service']
                        ac_ec2_info[key['AccountID']][key_ec2]["Found_List"]=[]
                        ac_ec2_info[key['AccountID']][key_ec2]["Found_Details"] = {}
                        for line in items_list_found:
                            try:
                                split_ec2_words=list(line.split('.'))
                                #print('Region:-'+split_ec2_words[2]+'--vpcIdAs:-'+split_ec2_words[4]+'--SecurityGroup'+split_ec2_words[6])
                                ac_ec2_info[key['AccountID']][key_ec2]["Found_List"].append(str(split_ec2_words[6]))
                                ac_ec2_info[key['AccountID']][key_ec2]["Found_Details"][split_ec2_words[6]]={}
                                found_info=data["services"][service]["regions"][split_ec2_words[2]]["vpcs"][split_ec2_words[4]]["security_groups"][split_ec2_words[6]]
                                ac_ec2_info[key['AccountID']][key_ec2]["Found_Details"][split_ec2_words[6]]=found_info
                            except:
                                raise
                    except Exception as error:   
                        print("Error Reading rule", key_ec2)  
                        raise error 
                    print(ac_ec2_info[key['AccountID']][key_ec2])
                    writedatatodynamodb(ec2_table,ac_ec2_info[key['AccountID']][key_ec2],key,key_ec2,reportdate,running_date,alrt,'Scout2')                  
                else:
                    #print("--------> 0 Found for :--"+   key_ec2 +"Account ID"+  key['AccountID'])
                    try:
                        #print("------Deleting item if it exists from Dynamodb-------------------")
                        response=ec2_table.delete_item (Key={'Accountid':key['AccountID'],'Rulename':key_ec2})
                    except Exception as err:
                        raise err
             #################  EC2-CONNECTION ##########################
            try:
                ec2_client =boto3.client('ec2') if key['AccountID'] =='478226638351' else get_aws_access_creds(key['CrossAuditRole'])
                ec2_regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
                print("Regions As...",ec2_regions  )
            except Exception as botoerror:
                print(botoerror)
                raise botoerror
    # #### SEARCHING FOR UN-ENCRYPTED EBS BUCKETS######
            print("---------Searching for ec2-un-encrypted-ebs-volumes ")
            key_ec2='ec2-un-encrypted-ebs-volumes'
            ac_ec2_info[data["aws_account_id"]][key_ec2]={}
            ac_ec2_info[key['AccountID']][key_ec2]["Found_List"]=[]
            ac_ec2_info[key['AccountID']][key_ec2]["Found_Details"]={}
            for region in ec2_regions:
                volumes=data["services"][service]["regions"][region]
                if (dict(volumes["volumes"]) !={}) or (int(volumes["volumes_count"]) !=0):
                    volumes_checked=volumes["volumes_count"]
                    #ac_ec2_info[key['AccountID']][key_ec2]["Found_Details"]={}
                    all_volumes=volumes["volumes"]
                    for v_key,v_val in all_volumes.items():
                        if v_val["Encrypted"] == False:
                            if v_val["id"]  not in  ac_ec2_info[key['AccountID']][key_ec2]["Found_List"]:
                                ac_ec2_info[key['AccountID']][key_ec2]["Found_List"].append(str(v_val["id"]))
                                ac_ec2_info[key['AccountID']][key_ec2]["Found_Details"][v_val["id"]]={}
                                ac_ec2_info[key['AccountID']][key_ec2]["Found_Details"][v_val["id"]]['name']=all_volumes[v_key]['name']
                                ac_ec2_info[key['AccountID']][key_ec2]["Found_Details"][v_val["id"]]['Attachments']=all_volumes[v_key]['Attachments']     
                        # else:
                        #     print("encryption:",   v_val["Encrypted"] )
                # else:
                #     print("0 un-encrypted volumes found",)    
            if ac_ec2_info[key['AccountID']][key_ec2]["Found_List"] !=[]:
                ac_ec2_info[key['AccountID']][key_ec2]["checked_items"] = data["services"][service]["volumes_count"] 
                ac_ec2_info[key['AccountID']][key_ec2]["flagged_items_count"] = len(ac_ec2_info[key['AccountID']][key_ec2]["Found_List"] )
                ac_ec2_info[key['AccountID']][key_ec2]["level"] = "danger"
                ac_ec2_info[key['AccountID']][key_ec2]["dashboard_name"] = "Ec2:EBSVolumes"
                ac_ec2_info[key['AccountID']][key_ec2]["description"] = "un encrypted data at rest inside the volume"
                ac_ec2_info[key['AccountID']][key_ec2]["rationale"] = ("When dealing with production data that is crucial to your business, it is highly recommended to implement data encryption in order to protect it from attackers or unauthorized personnel")
                ac_ec2_info[key['AccountID']][key_ec2]["service"] = service
                print(ac_ec2_info[key['AccountID']][key_ec2])
    #             writedatatodynamodb(ec2_table,ac_ec2_info[key['AccountID']][key_ec2],key,key_ec2,reportdate,running_date,alrt,'Scout2-Lambda')                  
    #         else:
    #             response=ec2_table.delete_item (Key={'Accountid':key['AccountID'],'Rulename':key_ec2})
    # #### SEARCHING FOR UN-ENCRYPTED EBS SNAPSHOTS######
            print("Searching for ec2-un-encrypted-ebs-snapshots ")
            key_ec2='ec2-un-encrypted-ebs-snapshots'
            ac_ec2_info[key['AccountID']][key_ec2]={}
            ac_ec2_info[key['AccountID']][key_ec2]["Found_List"]=[]
            ac_ec2_info[key['AccountID']][key_ec2]["Found_Details"]={}
            for region in ec2_regions:
                snapshots=data["services"][service]["regions"][region]
                #if (snapshots["snapshots"] !={}) or (snapshots["snapshots_count"] !=0):
                if (dict(snapshots["snapshots"]) !={}) or (int(snapshots["snapshots_count"]) !=0):
                    #ac_ec2_info[data["aws_account_id"]][key_ec2]={}
                    snapshots_checked=snapshots["snapshots_count"]
                    # ac_ec2_info[key['AccountID']][key_ec2]["Found_List"]=[]
                    # ac_ec2_info[key['AccountID']][key_ec2]["Found_Details"]={}
                    all_snapshots=snapshots["snapshots"]
                    for v_key,v_val in all_snapshots.items():
                        if v_val["Encrypted"] == False:
                            if v_val["id"] not in ac_ec2_info[key['AccountID']][key_ec2]["Found_List"] :
                                ac_ec2_info[key['AccountID']][key_ec2]["Found_List"].append(str(v_val["id"]))
                                #ac_ec2_info[key['AccountID']][key_ec2]["Found_Details"]={}
                                ac_ec2_info[key['AccountID']][key_ec2]["Found_Details"][v_val["id"]]={}
                                #ac_ec2_info[key['AccountID']][key_ec2]["Found_Details"][v_val["id"]]={}
                                ac_ec2_info[key['AccountID']][key_ec2]["Found_Details"][v_val["id"]]['Description']=all_snapshots[v_key]['Description']
                                ac_ec2_info[key['AccountID']][key_ec2]["Found_Details"][v_val["id"]]['VolumeId']=all_snapshots[v_key]['VolumeId']
                                ac_ec2_info[key['AccountID']][key_ec2]["Found_Details"][v_val["id"]]['VolumeSize']=all_snapshots[v_key]['VolumeSize']
                                ac_ec2_info[key['AccountID']][key_ec2]["Found_Details"][v_val["id"]]['name']=all_snapshots[v_key]['name']          
                        # else:
                        #     print("encryption:",   v_val["Encrypted"] )
                # else:
                #     print("0 un-encrypted snapshots found")    
            if  ac_ec2_info[key['AccountID']][key_ec2]["Found_List"] !=[]:
                ac_ec2_info[key['AccountID']][key_ec2]["checked_items"] = data["services"][service]["snapshots_count"] 
                ac_ec2_info[key['AccountID']][key_ec2]["flagged_items_count"] = len(ac_ec2_info[key['AccountID']][key_ec2]["Found_List"] )
                ac_ec2_info[key['AccountID']][key_ec2]["level"] = "warning"
                ac_ec2_info[key['AccountID']][key_ec2]["dashboard_name"] = "Ec2:EBSsnapshots"
                ac_ec2_info[key['AccountID']][key_ec2]["description"] = "un encrypted snapshots created from the volume"
                ac_ec2_info[key['AccountID']][key_ec2]["rationale"] = ("Ensure that the  EBS volume snapshots that hold sensitive and critical data are encrypted to fulfill compliance requirements for data-at-rest encryption")
                ac_ec2_info[key['AccountID']][key_ec2]["service"] = service
                print(ac_ec2_info[key['AccountID']][key_ec2])
                writedatatodynamodb(ec2_table,ac_ec2_info[key['AccountID']][key_ec2],key,key_ec2,reportdate,running_date,alrt,'Scout2-Lambda') 
            else:
                response=ec2_table.delete_item(Key={'Accountid':key['AccountID'],'Rulename':key_ec2})
            f.close()
            cleardict(data)
    #### SEARCHING FOR OTHER RULES OF EC2-SECURITYGROUPS######        
            print("-------------------------Searching for RISKDOMAINS")
            ac_ec2_info={} 
            ac_ec2_info[key['AccountID']]={}
            ac_ec2_info[key['AccountID']]['ec2-morethan-2-securitygroups']={}
            ac_ec2_info[key['AccountID']]['ec2-morethan-2-securitygroups']["Found_List"]=[]
            ac_ec2_info[key['AccountID']]['ec2-morethan-2-securitygroups']["Found_Details"]={}
            ac_ec2_info[key['AccountID']]['ec2-missing-riskdomain-tag']={}
            ac_ec2_info[key['AccountID']]['ec2-missing-riskdomain-tag']["Found_List"]=[]
            ac_ec2_info[key['AccountID']]['ec2-missing-riskdomain-tag']["Found_Details"]={}
            ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']={}
            ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["Found_List"]=[]
            ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["Found_Details"]={}
            ac_ec2_info[key['AccountID']]['ec2-rd-tag-mismatching-with-securitygroup']={}
            ac_ec2_info[key['AccountID']]['ec2-rd-tag-mismatching-with-securitygroup']["Found_List"]=[]
            ac_ec2_info[key['AccountID']]['ec2-rd-tag-mismatching-with-securitygroup']["Found_Details"]={}
            inst_count=0
            sgs_count=0
            total_sgs=0
            filters = [{'Name': 'instance-state-name', 'Values': ['running','stopped']}]
            for region in ec2_regions:
                conn_ec2 =boto3.resource('ec2', region_name=region) if key['AccountID'] =='478226638351' else get_aws_resource(region,key['CrossAuditRole'])
                conn_ec2_reg_client = boto3.client('ec2',region_name=region,config=Config(retries={'max_attempts': 10})) if key['AccountID'] =='478226638351' else get_region_ec2_client(region,key['CrossAuditRole'])
                if len([i for i in conn_ec2.instances.filter(Filters=filters)])==0:
                    print("-------->>Founded 0 Instances for this region moving to next",region)
                    continue
                done= False
                NextToken = None
                while not done:
                    if NextToken:
                        instances = [i for i in conn_ec2.instances.filter(Filters=filters,NextToken=NextToken)]
                    else:
                        instances = [i for i in conn_ec2.instances.filter(Filters=filters)]
                    print(instances,   region)
                    print(instances, type(instances))
                    for instance in instances:
                        inst_count +=1
                        instance_tags= instance.tags or []
                        names = [tag.get('Value') for tag in instance_tags if tag.get('Key') in valid_riskdomain_tags]
                        rd_tag_name = names[0] if names else None
                        if rd_tag_name is None:
                            print("---------.found some for:- ec2-missing-riskdomain-tag")
                            if (instance.id) not in ac_ec2_info[key['AccountID']]['ec2-missing-riskdomain-tag']["Found_List"]:
                                ac_ec2_info[key['AccountID']]['ec2-missing-riskdomain-tag']["Found_List"].append(str(instance.id))
                                ac_ec2_info[key['AccountID']]['ec2-missing-riskdomain-tag']["Found_Details"][instance.id]={}
                                ac_ec2_info[key['AccountID']]['ec2-missing-riskdomain-tag']["Found_Details"][instance.id]["InstanceId"]=instance.tags
                                ac_ec2_info[key['AccountID']]['ec2-missing-riskdomain-tag']["Found_Details"][instance.id]["region"]=region
                        else:
                            ac_ec2_info[key['AccountID']]['ec2-rd-tag-mismatching-with-securitygroup']["Found_Details"][str(instance.id+":"+rd_tag_name)]={}
                        all_sg_info = instance.security_groups or []
                        #### SEARCHING FOR INSTANCES WITH MORETHAN 2 SECURITY GROUPS######    
                        if all_sg_info !=[]:
                            if len(all_sg_info) >2:
                                if instance.id not in ac_ec2_info[key['AccountID']]['ec2-morethan-2-securitygroups']["Found_List"]:
                                    ac_ec2_info[key['AccountID']]['ec2-morethan-2-securitygroups']["Found_List"].append(str(instance.id))
                                    ac_ec2_info[key['AccountID']]['ec2-morethan-2-securitygroups']["Found_Details"][instance.id]={}
                                    ac_ec2_info[key['AccountID']]['ec2-morethan-2-securitygroups']["Found_Details"][instance.id]=instance.security_groups
                        get_sg_ids=[id['GroupId'] for id in all_sg_info]
                        if get_sg_ids:
                            sg_id_info=conn_ec2_reg_client.describe_security_groups(GroupIds=get_sg_ids) 
                        else:
                            continue
                        detailed_sg_info=sg_id_info['SecurityGroups'] 
                        for each_sg in detailed_sg_info:
                            sgs_count +=1
                            try:
                                sg_rd_names=[tag.get('Value') for tag in each_sg['Tags'] if tag.get('Key') in valid_riskdomain_tags]
                            except KeyError:
                                if each_sg['GroupId']  not in ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["Found_List"]:
                                    print("---------KeyError found some for:- ec2-securitygroups-missing-riskdomain-tag---Writng to Dict")
                                    ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["Found_List"].append(str(each_sg['GroupId']))
                                    ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["Found_Details"][each_sg['GroupId']]={}
                                    ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["Found_Details"][each_sg['GroupId']]["AttachedTo"]=instance.id
                                    ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["Found_Details"][each_sg['GroupId']]["region"]=region
                                continue
                            sg_rd_final_name= sg_rd_names[0] if sg_rd_names else None
                            if sg_rd_final_name is None:
                                print("---------NOne found some for:- ec2-securitygroups-missing-riskdomain-tag---Writng to Dict")
                                if each_sg['GroupId']  not in ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["Found_List"]:
                                    ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["Found_List"].append(str(each_sg['GroupId']))
                                    ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["Found_Details"][each_sg['GroupId']]={}
                                    ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["Found_Details"][each_sg['GroupId']]["AttachedTo"]=instance.id
                                    ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["Found_Details"][each_sg['GroupId']]["region"]=region
                                continue
                            else:
                                if rd_tag_name != None:
                                    if sg_rd_final_name.lower()==rd_tag_name.lower():
                                        continue
                                    elif sg_rd_final_name.lower()!=rd_tag_name.lower():
                                        print("---------found some for:-ec2-rd-tag-mismatching-with-securitygroupg---Writng to Dict",  str(instance.id+":"+rd_tag_name),   str(each_sg['GroupId']+':'+sg_rd_final_name))
                                        if instance.id not in ac_ec2_info[key['AccountID']]['ec2-rd-tag-mismatching-with-securitygroup']["Found_List"]:
                                            ac_ec2_info[key['AccountID']]['ec2-rd-tag-mismatching-with-securitygroup']["Found_List"].append(str(instance.id+":"+rd_tag_name))
                                            ac_ec2_info[key['AccountID']]['ec2-rd-tag-mismatching-with-securitygroup']["Found_Details"][str(instance.id+":"+rd_tag_name)]["SGInfo"]=[]
                                            ac_ec2_info[key['AccountID']]['ec2-rd-tag-mismatching-with-securitygroup']["Found_Details"][str(instance.id+":"+rd_tag_name)]["SGInfo"].append(str(each_sg['GroupId']+':'+sg_rd_final_name))
                                            ac_ec2_info[key['AccountID']]['ec2-rd-tag-mismatching-with-securitygroup']["Found_Details"][str(instance.id+":"+rd_tag_name)]['Region']=region
                                    else:
                                        print("Nothing to find-Something weird")
                    if 'NextToken' in instances:#['NextToken'] is :
                        NextToken=instances['NextToken']
                        print("Next Token Info",NextToken)
                    else:
                        done = True
                #####SEARCHING FOR MISSING ALL SECURITY GROUPS RD TAGS             
                sg_done= False
                sg_NextToken= None
                while not sg_done:
                    if sg_NextToken:
                        all_sg_list=conn_ec2_reg_client.describe_security_groups(NextToken=sg_NextToken)
                    else:
                        all_sg_list=conn_ec2_reg_client.describe_security_groups()
                    region_sg_info=all_sg_list['SecurityGroups'] 
                    for sg in region_sg_info:
                        print("scanning for:-"+sg['GroupId']+"CountedAs:-"+str(total_sgs))
                        total_sgs +=1
                        try:
                            sg_rd_names=[tag.get('Value') for tag in sg['Tags'] if tag.get('Key') in valid_riskdomain_tags]
                        except KeyError:
                            if sg['GroupId']  not in ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["Found_List"]:
                                print("---------KeyError found some for:- ec2-securitygroups-missing-riskdomain-tag---Writng to Dict")
                                ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["Found_List"].append(str(sg['GroupId']))
                                ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["Found_Details"][sg['GroupId']]={}
                                ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["Found_Details"][sg['GroupId']]['Description']=sg['Description']
                                ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["Found_Details"][sg['GroupId']]["region"]=region
                                ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["Found_Details"][sg['GroupId']]['GroupName']=sg['GroupName']
                                ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["Found_Details"][sg['GroupId']]['VpcId']=sg['VpcId']
                            continue
                    if 'NextToken' in all_sg_list:
                        sg_NextToken=all_sg_list['NextToken']
                    else:
                        sg_done= True
            if ac_ec2_info[key['AccountID']]['ec2-morethan-2-securitygroups']["Found_List"] !=[]:
                ac_ec2_info[key['AccountID']]['ec2-morethan-2-securitygroups']["checked_items"] = str(inst_count)
                ac_ec2_info[key['AccountID']]['ec2-morethan-2-securitygroups']["flagged_items_count"] = len(ac_ec2_info[key['AccountID']]['ec2-morethan-2-securitygroups']["Found_List"] )
                ac_ec2_info[key['AccountID']]['ec2-morethan-2-securitygroups']["level"] = "danger"
                ac_ec2_info[key['AccountID']]['ec2-morethan-2-securitygroups']["dashboard_name"] = "Ec2:securityGroups"
                ac_ec2_info[key['AccountID']]['ec2-morethan-2-securitygroups']["description"] = "Instance running with more than 2 security groups"
                ac_ec2_info[key['AccountID']]['ec2-morethan-2-securitygroups']["rationale"] = ("When multiple security groups are applied to an instance, the rules are aggregated to create one large set of rules. In EC2, security group rules are only permissive, in other words, you cannot add any DENY rules")
                ac_ec2_info[key['AccountID']]['ec2-morethan-2-securitygroups']["service"] = service
                print(ac_ec2_info[key['AccountID']]['ec2-morethan-2-securitygroups'])
                writedatatodynamodb(ec2_table,ac_ec2_info[key['AccountID']]['ec2-morethan-2-securitygroups'],key,'ec2-morethan-2-securitygroups',reportdate,running_date,alrt,'Lambda')
            else:
                response=ec2_table.delete_item(Key={'Accountid':key['AccountID'],'Rulename':'ec2-morethan-2-securitygroups'})
            if ac_ec2_info[key['AccountID']]['ec2-missing-riskdomain-tag']["Found_List"] !=[]:
                ac_ec2_info[key['AccountID']]['ec2-missing-riskdomain-tag']["checked_items"] = str(inst_count)
                ac_ec2_info[key['AccountID']]['ec2-missing-riskdomain-tag']["flagged_items_count"] = len(ac_ec2_info[key['AccountID']]['ec2-missing-riskdomain-tag']["Found_List"] )
                ac_ec2_info[key['AccountID']]['ec2-missing-riskdomain-tag']["level"] = "warning"
                ac_ec2_info[key['AccountID']]['ec2-missing-riskdomain-tag']["dashboard_name"] = "Ec2:Instances"
                ac_ec2_info[key['AccountID']]['ec2-missing-riskdomain-tag']["description"] = "Instances with out Riskdomain tag"
                ac_ec2_info[key['AccountID']]['ec2-missing-riskdomain-tag']["rationale"] = ("if riskdomain tag not exists means that servers dosen't have any access and applications will not work.Allowed values as per CAT-Security DL = Development Layer,AL = Application Layer,WL = Web Layer")
                ac_ec2_info[key['AccountID']]['ec2-missing-riskdomain-tag']["service"] = service
                print(ac_ec2_info[key['AccountID']]['ec2-missing-riskdomain-tag'])
                writedatatodynamodb(ec2_table,ac_ec2_info[key['AccountID']]['ec2-missing-riskdomain-tag'],key,'ec2-missing-riskdomain-tag',reportdate,running_date,alrt,'Lambda')
            else:
                response=ec2_table.delete_item(Key={'Accountid':key['AccountID'],'Rulename':'ec2-missing-riskdomain-tag'})
            if ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["Found_List"] !=[]:
                ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["checked_items"] = str(total_sgs)
                ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["flagged_items_count"] = len(ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["Found_List"] )
                ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["level"] = "danger"
                ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["dashboard_name"] = "Ec2:SecurityGroups"
                ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["description"] = "SecurityGroups with out Riskdomain tag"
                ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["rationale"] = ("if riskdomain tag not exists means that servers dosen't have any access and applications will not work.Allowed values as per CAT-Security DL = Development Layer,AL = Application Layer,WL = Web Layer")
                ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag']["service"] = service
                print(ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag'])
                writedatatodynamodb(ec2_table,ac_ec2_info[key['AccountID']]['ec2-securitygroups-missing-riskdomain-tag'],key,'ec2-securitygroups-missing-riskdomain-tag',reportdate,running_date,alrt,'Lambda')
            else:
                response=ec2_table.delete_item(Key={'Accountid':key['AccountID'],'Rulename':'ec2-securitygroups-missing-riskdomain-tag'})
            if ac_ec2_info[key['AccountID']]['ec2-rd-tag-mismatching-with-securitygroup']["Found_List"] !=[]:
                ac_ec2_info[key['AccountID']]['ec2-rd-tag-mismatching-with-securitygroup']["checked_items"] = str(inst_count)
                ac_ec2_info[key['AccountID']]['ec2-rd-tag-mismatching-with-securitygroup']["flagged_items_count"] = len(ac_ec2_info[key['AccountID']]['ec2-rd-tag-mismatching-with-securitygroup']["Found_List"] )
                ac_ec2_info[key['AccountID']]['ec2-rd-tag-mismatching-with-securitygroup']["level"] = "danger"
                ac_ec2_info[key['AccountID']]['ec2-rd-tag-mismatching-with-securitygroup']["dashboard_name"] = "Ec2:Instances"
                ac_ec2_info[key['AccountID']]['ec2-rd-tag-mismatching-with-securitygroup']["description"] = "Instance RD tag mismatching with SecurityGroup RD tag"
                ac_ec2_info[key['AccountID']]['ec2-rd-tag-mismatching-with-securitygroup']["rationale"] = ("if riskdomain tag not exists means that servers dosen't have any access and applications will not work.Allowed values as per CAT-Security DL = Development Layer,AL = Application Layer,WL = Web Layer")
                ac_ec2_info[key['AccountID']]['ec2-rd-tag-mismatching-with-securitygroup']["service"] = service
                print(ac_ec2_info[key['AccountID']]['ec2-rd-tag-mismatching-with-securitygroup'])
                writedatatodynamodb(ec2_table,ac_ec2_info[key['AccountID']]['ec2-rd-tag-mismatching-with-securitygroup'],key,'ec2-rd-tag-mismatching-with-securitygroup',reportdate,running_date,alrt,'Lambda')
            else:
                response=ec2_table.delete_item(Key={'Accountid':key['AccountID'],'Rulename':'ec2-rd-tag-mismatching-with-securitygroup'})
        #############################################################   
            #CHECK/STORE THE LASTEVALUATEDKEY FROM PARAMATER STORE
        #############################################################
        check_and_update_parameter(accounts_list_table_scan)
    except Exception as error:
        #alrt += '\nFailed Lambda IAM Reporting Function -arn:aws:lambda:us-east-2:478226638351:function:security-audit-IAM:  {} \n '.format(str(error))
        raise error
    #if alrt:
        #alrt+='\nMissing Report As of:  {} \n '.format(str(running_date))
        #alrt+='\nPossible Reason:  {} \n '.format(str("Please check the bucket 'ue2-scout2-prod-history' for missing report with accountid/date and for more details about this account check dynamodb table 'awsaccounts-crossaccountrole-list'"))
        #publish_msg_security_team("AWS SCOUT2 Missing Report for Accounts Attached", alrt)  
    return "success"
def clearlist(slis):  # clearing list
    slis[:] = []
def cleardict(sdict):  # clearing dictonary
    sdict.clear()
#   CREATING NEW TABLE IF UNFOUND WITH NAME 
def verifyLogTable(tablename,primarykey,sortkey):
    """Verifies if the table name provided is exists/not
    Returns:
        The real table name
        TYPE: String
    """
    client = dynamodb_client
    resource = dynamodb_resource
    table = tablename

    response = client.list_tables()
    tableFound = False
    for n, _ in enumerate(response['TableNames']):
        if table in response['TableNames'][n]:
            table = response['TableNames'][n]
            tableFound = True

    if not tableFound:
        # Table not created in CFn, let's check exact name or create it
        try:
            result = client.describe_table(TableName=table)
        except:
            # Table does not exist, create it
            newtable = resource.create_table(
                TableName=table,
                KeySchema=[
                     {
                        'AttributeName': primarykey,
                        'KeyType': 'HASH',
                     },
                     {   ##Hash is primary key 
                        'AttributeName': sortkey, 
                        'KeyType': 'RANGE',  
                     },
                ],   ## Range is sortkey 
                AttributeDefinitions=[
                    {   'AttributeName': primarykey, 
                        'AttributeType': 'S',
                    },
                    {   'AttributeName': sortkey, 
                        'AttributeType': 'S',
                    },
                ],
                ProvisionedThroughput={'ReadCapacityUnits': 10, 'WriteCapacityUnits': 10}
            )
            # Wait for table creation
            newtable.meta.client.get_waiter('table_exists').wait(TableName=table)
    return table
#   CLEANING THE EMPTY VALUES IN DICTONARY
def clean_empty(d):
    if not isinstance(d, (dict, list)):
        return d
    if isinstance(d, list):
        return [v for v in (clean_empty(v) for v in d) if v]
    return {k: v for k, v in ((k, clean_empty(v)) for k, v in d.items()) if v}
#   WRITING DATA TO DYNAMODB FROM COLLECTED ITERATIONS
def writedatatodynamodb(update_table,ec2_finding_info,key,rulename,reportdate,running_date,alrt,ReportedFrom):
        try:
            update_table.put_item ( 
                Item={
                    'Accountid':key['AccountID'],
                    'Rulename':rulename,
                    'Aliasname':key['Alias'],
                    'E-mail':key['Email'],
                    'Risklevel':ec2_finding_info['level'],
                    'Lastexecuteddate':str(running_date),
                    'Foundeddate':str(reportdate),
                    'Rationale':ec2_finding_info['rationale'],
                    'Description':ec2_finding_info["description"],
                    'Totalcheckeditems':str(ec2_finding_info['checked_items']),
                    'Flaggeditemslist':ec2_finding_info['Found_List'],
                    'Flaggeditemscount':str(ec2_finding_info['flagged_items_count']),
                    'Detailedinfo':clean_empty(ec2_finding_info['Found_Details']),
                    'Service':ec2_finding_info['service']+':'+ec2_finding_info['dashboard_name'],
                    'Managedby':key['Managedby'],
                    'Department':key['Department'],
                    'Division':key['Division'],
                    'Type':key['Type'],
                    'Techowner':key['Techowner'],
                    'Dataclassification':key['Dataclassification'],
                    'Businessowner':key['Businessowner'],
                    'Reportedby':ReportedFrom,
                    }
                )
        except Exception as e:
            raise e
            #alrt+=':Error writing data for the rule  {} \n '.format(str(rulename))
            print("Error writing data to dynamdodb")
################################################################## 
    #                END OF AWS-EC2 GAME
##################################################################
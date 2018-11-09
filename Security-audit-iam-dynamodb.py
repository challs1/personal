#!/usr/bin/env python3
""" 
Description - This Scritp will get the Today-IAM_Findings data from Scout2-History 
bucket for each account and write Findings data to dynamodb table

Update Table    -   security-audit-IAM

Requrements - python3, Scout2 Report, imported libraries, aws crossaccount role,dynamodb,sns subscription,s3 bucket access

Output - Writing findings data for each rule in to dynamodbTable for each AWS account. 

"""
__author__ = "Chenna Vemula,Brian Rossi"
__COPYRIGHT__ = " Copyright 2018 , Caterpillar"
__email__ = " chenna_vemula@cat.com"
__version__ = " 0.1.0-(Stable-10/23/2018)" 
import re
import os
import datetime
import dateutil
import pytz
import boto3, json, time, datetime, sys
from dateutil.parser import parse
import traceback
from dateutil import tz, parser
from datetime import timedelta, date, datetime, timezone
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
sts = boto3.client('sts')
ClientSSM = boto3.client('ssm', 'us-east-2')
sns_client = boto3.client('sns')
dynamodb_resource = boto3.resource('dynamodb','us-east-2')
dynamodb_client = boto3.client('dynamodb','us-east-2')  # conection to the dynamo db
update_table_primarykey='Accountid'
update_table_sort_key='Rulename'
service='iam'
BUCKET_NAME = 'ue2-scout2-qa-history'  # replace with your bucket name  
s3 = boto3.resource('s3')
today_date=datetime.now()
accounts_list_table=dynamodb_resource.Table('awsaccounts-crossaccountrole-list')
def lambda_handler(event, context):
    running_date=today_date.strftime('%Y-%m-%dT%H:%M:%SZ')
    alrt=''
    try:
        #############################################################   
            #SCANNING THE LASTEVALUATEDKEY FROM PARAMATER STORE
        #############################################################
        try:
            get_evaluated_key=ClientSSM.get_parameter(Name='Scout2-IAM-Startkey')
        except :
            response = ClientSSM.put_parameter(Name='Scout2-IAM-Startkey',Description='iamLastEvaluatedKey',Value='Null',
            Type='String',Overwrite=True)
            print("Value Updated--Version as",response  )
            get_evaluated_key=ClientSSM.get_parameter(Name='Scout2-IAM-Startkey')
        if get_evaluated_key['Parameter']['Value']=="Null":
            accounts_list_table_scan = accounts_list_table.scan(Select='ALL_ATTRIBUTES',Limit=5,ConsistentRead=True,#ExclusiveStartKey='',
                                                                 FilterExpression=Attr("CrossAuditRole").ne('NotFound') & Attr("Scout2dataS3key").ne('N/A'))
        else:                                              
            accounts_list_table_scan = accounts_list_table.scan(Select='ALL_ATTRIBUTES',Limit=5,ExclusiveStartKey={'AccountID':str(get_evaluated_key['Parameter']['Value'])},
                                                            FilterExpression=Attr("CrossAuditRole").ne('NotFound') & Attr("Scout2dataS3key").ne('N/A'))
        accounts_list_table_scan_ext = accounts_list_table_scan['Items']
        print(accounts_list_table_scan)
        iam_table = dynamodb_resource.Table(verifyLogTable('security-audit-IAM',update_table_primarykey,update_table_sort_key))
        ac_iam_info={}
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
                alrt+='AccountName:  {} \n '.format(str(key['Alias']))
                print("-----Unable to read Scout2 Data for the account:--"+ key['AccountID'] +':'+key['Name'])
                print("-----Moving to next Account Key-------X")
                continue
            iam_findings = data["services"][service]["findings"]
            ac_iam_info[data["aws_account_id"]]={}
            ac_iam_info[key['AccountID']]['ReportedOn']=data["last_run"]["time"]
            scout2_reportdate=data["last_run"]["time"]
            reportdate=(parser.isoparse(scout2_reportdate)).strftime('%Y-%m-%dT%H:%M:%SZ')
            ac_iam_info[key['AccountID']]["Scout2_Ac_Number"]=data["aws_account_id"]
            ac_iam_credential_report=data["services"][service]["credential_report"]
            ################################################################## 
            #  PARSING DATA FILE FOR THE SERVICE 'IAM' FOR EACH SCOUT2IAM-RULE
            ##################################################################
            for key_iam, key_value in iam_findings.items():
                iam_config_findings = data["services"][service]["findings"][key_iam]
                print("------------->Searching for:-",iam_config_findings["dashboard_name"],  key_iam)
                if iam_config_findings["flagged_items"] >= 1:
                    items_list_found = iam_config_findings["items"]
                    print("-------------------->Items Found As:--",   len(items_list_found))
                    ac_iam_info[data["aws_account_id"]][key_iam]={}
                    ac_iam_info[key['AccountID']][key_iam]["checked_items"] = iam_config_findings["checked_items"]
                    ac_iam_info[key['AccountID']][key_iam]["flagged_items_count"] = iam_config_findings["flagged_items"]
                    ac_iam_info[key['AccountID']][key_iam]["level"] = iam_config_findings["level"]
                    ac_iam_info[key['AccountID']][key_iam]["dashboard_name"] = iam_config_findings["dashboard_name"]
                    ac_iam_info[key['AccountID']][key_iam]["description"] = iam_config_findings["description"]
                    ac_iam_info[key['AccountID']][key_iam]["rationale"] = iam_config_findings["rationale"]
                    ac_iam_info[key['AccountID']][key_iam]["service"] = iam_config_findings["service"]
                    ac_iam_info[key['AccountID']][key_iam]["Found_List"]=[]
                    ac_iam_info[key['AccountID']][key_iam]["Found_Details"] = {}
                    strip_id = re.findall(r"(?<=s\.).*?(?=\.)", str(items_list_found))
                    print("Stripped As--",  strip_id)
                    if iam_config_findings["dashboard_name"]=='Roles':
                        found_info=data["services"][service]["roles"]
                        for item in strip_id:
                            ac_iam_info[key['AccountID']][key_iam]["Found_List"].append(found_info[item]['name'])
                            ac_iam_info[key['AccountID']][key_iam]["Found_Details"][found_info[item]['name']]={}
                            ac_iam_info[key['AccountID']][key_iam]["Found_Details"][found_info[item]['name']]=found_info[item]
                    elif iam_config_findings["dashboard_name"]=='groups':
                        found_info=data["services"][service][iam_config_findings["dashboard_name"]]
                        for item in strip_id:
                            ac_iam_info[key['AccountID']][key_iam]["Found_List"].append(found_info[item]['name'])
                            ac_iam_info[key['AccountID']][key_iam]["Found_Details"][found_info[item]['name']]={}
                            ac_iam_info[key['AccountID']][key_iam]["Found_Details"][found_info[item]['name']]=found_info[item]
                    elif iam_config_findings["dashboard_name"]=='Policies':
                        for item in strip_id:
                            try:
                                found_info=data["services"][service]["roles"][item]
                                ac_iam_info[key['AccountID']][key_iam]["Found_List"].append(found_info['name'])
                                ac_iam_info[key['AccountID']][key_iam]["Found_Details"][found_info['name']]={}
                                ac_iam_info[key['AccountID']][key_iam]["Found_Details"][found_info['name']]=found_info
                            except KeyError:
                                try:
                                    found_info=data["services"][service]["policies"][item]
                                    ac_iam_info[key['AccountID']][key_iam]["Found_List"].append(found_info['name'])
                                    ac_iam_info[key['AccountID']][key_iam]["Found_Details"][found_info['name']]={}
                                    ac_iam_info[key['AccountID']][key_iam]["Found_Details"][found_info['name']]=found_info
                                except KeyError:
                                    try:
                                        #print(item)
                                        role_index=(strip_id.index(item))-1
                                        #print(role_index)
                                        #print([strip_id[role_index]])
                                        found_info=data["services"][service]["roles"][strip_id[role_index]]["inline_policies"][item]
                                        ac_iam_info[key['AccountID']][key_iam]["Found_List"].append(found_info['name'])
                                        ac_iam_info[key['AccountID']][key_iam]["Found_Details"][found_info['name']]={}
                                        ac_iam_info[key['AccountID']][key_iam]["Found_Details"][found_info['name']]=found_info        
                                    except KeyError:
                                        try:
                                            #print(item)
                                            role_index=(strip_id.index(item))-1
                                            #print(role_index)
                                            #print([strip_id[role_index]])
                                            found_info=data["services"][service]["users"][strip_id[role_index]]["inline_policies"][item]
                                            ac_iam_info[key['AccountID']][key_iam]["Found_List"].append(found_info['name'])
                                            ac_iam_info[key['AccountID']][key_iam]["Found_Details"][found_info['name']]={}
                                            ac_iam_info[key['AccountID']][key_iam]["Found_Details"][found_info['name']]=found_info
                                        except KeyError:
                                            try:
                                                #print(item)
                                                role_index=(strip_id.index(item))-1
                                                #print(role_index)
                                                print([strip_id[role_index]])
                                                found_info=data["services"][service]["users"][item]["inline_policies"][strip_id[role_index]]
                                                ac_iam_info[key['AccountID']][key_iam]["Found_List"].append(found_info['name'])
                                                ac_iam_info[key['AccountID']][key_iam]["Found_Details"][found_info['name']]={}
                                                ac_iam_info[key['AccountID']][key_iam]["Found_Details"][found_info['name']]=found_info
                                            except KeyError:
                                                #print(item)
                                                role_index=(strip_id.index(item))-1
                                                #print(role_index)
                                                #print([strip_id[role_index]])
                                                found_info=data["services"][service]["roles"][item]["inline_policies"][strip_id[role_index]]
                                                ac_iam_info[key['AccountID']][key_iam]["Found_List"].append(found_info['name'])
                                                ac_iam_info[key['AccountID']][key_iam]["Found_Details"][found_info['name']]={}
                                                ac_iam_info[key['AccountID']][key_iam]["Found_Details"][found_info['name']]=found_info
                            except Exception as error:
                                print("------------>Unable to find info for policies for this rule", key_iam,    strip_id )
                                raise error                              
                    elif iam_config_findings["dashboard_name"]=='Password policy':
                        found_info=data["services"][service]["password_policy"]
                        ac_iam_info[key['AccountID']][key_iam]["Found_Details"]=found_info
                        ac_iam_info[key['AccountID']][key_iam]["Found_List"].append('root_of_'+key['AccountID'])
                    elif iam_config_findings["dashboard_name"]=='Root account':
                        found_info=data["services"][service]["credential_report"]["<root_account>"]
                        ac_iam_info[key['AccountID']][key_iam]["Found_Details"]=found_info
                        ac_iam_info[key['AccountID']][key_iam]["Found_List"].append('root_of_'+key['AccountID'])
                    elif iam_config_findings["dashboard_name"]=='Access keys':
                        found_info=data["services"][service]["users"]
                        for item in strip_id:
                            try:
                                user_details= found_info[item]
                                ac_iam_info[key['AccountID']][key_iam]["Found_List"].append(user_details["name"])
                                ac_iam_info[key['AccountID']][key_iam]["Found_Details"][user_details["name"]]={}
                                ac_iam_info[key['AccountID']][key_iam]["Found_Details"][user_details["name"]]=user_details
                            except KeyError:
                                #print("Item Ignored",   item)
                                continue
                            except Exception as z:
                                print("X****************Error Occured :-", item, key_iam)
                                raise z       
                    elif iam_config_findings["dashboard_name"]=='Users':
                        found_info=data["services"][service]["users"]
                        for item in strip_id:
                            ac_iam_info[key['AccountID']][key_iam]["Found_List"].append(found_info[item]['name'])
                            ac_iam_info[key['AccountID']][key_iam]["Found_Details"][found_info[item]['name']]={}
                            ac_iam_info[key['AccountID']][key_iam]["Found_Details"][found_info[item]['name']]=found_info[item]
                            ac_iam_info[key['AccountID']][key_iam]["Found_Details"][found_info[item]['name']]['UserCredInfo']={}
                            ac_iam_info[key['AccountID']][key_iam]["Found_Details"][found_info[item]['name']]['UserCredInfo']=data["services"][service]["credential_report"][found_info[item]['name']]      
                    else:
                        print("**************XXXError Reading DashBaordXXXX***", iam_config_findings["dashboard_name"])
                    print("  ------------------------>>SUMMARRY OF ",           key_iam)
                    print(ac_iam_info[key['AccountID']][key_iam]) 
                    #print("-------------------------->Writing Data to Dynamodb")
                    writedatatodynamodb(iam_table,ac_iam_info[key['AccountID']][key_iam],key,key_iam,reportdate,running_date,alrt,'Scout2')                  
                else:
                    print("-------->Nothing foud for rule:--"+   key_iam+"X-On-X"+  key['AccountID'])
                    ################################################################## 
                    #              DELETING THE RULE IF FOUND ITEMS 0
                    ##################################################################
                    try:
                        print("--------------Deleting item if it exists from Dynamodb-------------------")
                        response=iam_table.delete_item (Key={'Accountid':key['AccountID'],'Rulename':key_iam})
                    except Exception as err:
                        raise err
            # ################################################################## 
            # #  IDENTIFY IAM-ACCESSKEYS NOT USED FOR 30DAYS/SINCE CREATION
            # ##################################################################
            found_info=data["services"][service]["users"]
            key_iam="iam-accesskeys-unused30day"
            ac_iam_info[data["aws_account_id"]][key_iam]={}
            ac_iam_info[key['AccountID']][key_iam]["rationale"]="Rotating Identity and Access Management (IAM) credentials periodically will significantly reduce the chances that a compromised set of access keys can be used without your knowledge to access certain components within your AWS account \
                    Ensure that all your IAM user access keys are rotated every month in order to decrease the likelihood of accidental exposures and protect your AWS resources against unauthorized access"
            ac_iam_info[key['AccountID']][key_iam]["description"]="iam-accesskeys not used for 30days or since creation"
            ac_iam_info[key['AccountID']][key_iam]["level"]='danger'
            ac_iam_info[key['AccountID']][key_iam]["service"]="IAM"
            ac_iam_info[key['AccountID']][key_iam]["Found_List"]=[]
            ac_iam_info[key['AccountID']][key_iam]["Found_Details"] = {}
            access_key_count=0
            todays_date=today_date.strftime("%Y-%m-%d %H:%M:%S")
            todays_date_UTC=parse(str(datetime.utcnow()))
            for uid,uvalues in found_info.items():
                if uvalues["AccessKeys"] !=[]:
                    accesskeys_for_user=uvalues["AccessKeys"]
                    user_details= found_info[uid]
                    user_name=uvalues["name"]
                    user_cred_report=data["services"][service]["credential_report"][user_name]
                    key_no=0
                    for access_key in accesskeys_for_user:
                        access_key_id=access_key["AccessKeyId"]
                        ac_create_date=parse(access_key["CreateDate"])
                        print("----------->Caluculating age of ",   access_key_id,  user_name )
                        key_no +=1
                        access_key_count +=1
                        access_key_status=access_key["Status"]
                        key_last_used=user_cred_report["access_key_"+str(key_no)+"_last_used_date"]
                        if key_last_used !="N/A":
                            ac_lastused_date=parse(key_last_used)
                            print("TODAY",todays_date_UTC.date(),   type(todays_date_UTC),todays_date_UTC.tzinfo)
                            print("CREATED ON-", ac_create_date.date(),    type(ac_create_date),   ac_create_date.tzinfo)
                            print("LASTUSED ON:-", ac_lastused_date.date(),   type(ac_lastused_date),  ac_lastused_date.tzinfo)
                            print("Diffrence of Today Date with Created adate",days_between(todays_date_UTC.date(), ac_create_date.date()))
                            print("Diffrence of Today Date with Last used Date ",days_between(todays_date_UTC.date(), ac_lastused_date.date()))
                            if int(days_between(todays_date_UTC.date(), ac_lastused_date.date())) >= 31:
                                print("30day since last Login AccessKey Flagged",access_key_id ,  user_name,   ac_lastused_date,   days_between(todays_date_UTC.date(), ac_lastused_date.date())  )
                                ac_iam_info[key['AccountID']][key_iam]["Found_List"].append(str(user_name+":"+access_key["AccessKeyId"]))
                                ac_iam_info[key['AccountID']][key_iam]["Found_Details"][user_name+":"+access_key["AccessKeyId"]]={}
                                ac_iam_info[key['AccountID']][key_iam]["Found_Details"][user_name+":"+access_key["AccessKeyId"]]=user_details
                                ac_iam_info[key['AccountID']][key_iam]["Found_Details"][str(user_name+":"+access_key["AccessKeyId"])]["KeyLastUsedDate"]={}
                                ac_iam_info[key['AccountID']][key_iam]["Found_Details"][str(user_name+":"+access_key["AccessKeyId"])]["KeyLastUsedDate"]=key_last_used
                            else:
                                print("This Accesskey under 30day limit so moving to next accesskey",access_key["AccessKeyId"])
                        elif key_last_used =="N/A":
                            if int(days_between(todays_date_UTC.date(), ac_create_date.date())) >= 31:
                                print("30Day No Activity AccessKey Flagged",user_name+":"+access_key["AccessKeyId"])
                                ac_iam_info[key['AccountID']][key_iam]["Found_List"].append(user_name+":"+access_key["AccessKeyId"])
                                ac_iam_info[key['AccountID']][key_iam]["Found_Details"][user_name+":"+access_key["AccessKeyId"]]={}
                                ac_iam_info[key['AccountID']][key_iam]["Found_Details"][user_name+":"+access_key["AccessKeyId"]]=user_cred_report
                            else:
                                print("This Accesskey under 30day limit so moving to next accesskey",access_key["AccessKeyId"])
                else:
                    print("No Access keys for the user", found_info[uid]["name"])
            print("======TOTAlAccessKeys",  access_key_count)
            ac_iam_info[key['AccountID']][key_iam]["dashboard_name"]="Access Keys"
            ac_iam_info[key['AccountID']][key_iam]["checked_items"]=str(access_key_count)
            ac_iam_info[key['AccountID']][key_iam]["flagged_items_count"]=str(len(ac_iam_info[key['AccountID']][key_iam]["Found_List"]))
            print(ac_iam_info[key['AccountID']][key_iam])
            if int(ac_iam_info[key['AccountID']][key_iam]["flagged_items_count"]) >=1:
                writedatatodynamodb(iam_table,ac_iam_info[key['AccountID']][key_iam],key,key_iam,reportdate,running_date,alrt,'Lambda')        
            else: 
                print("-------->Nothing foud for rule:--"+   key_iam+"X-On-X"+  key['AccountID'])
                ################################################################## 
                #              DELETING THE RULE IF FOUND ITEMS ==0
                ##################################################################
                try:
                    print("--------------Deleting item if it exists from Dynamodb-------------------")
                    response=iam_table.delete_item (Key={'Accountid':key['AccountID'],'Rulename':key_iam})
                except Exception as err:
                    raise err
            # ################################################################## 
            # SCHEDULED-DELETE WARNING IAM-ACCESSKEYS NOT USED FOR 30DAYS/SINCE CREATION
            # ##################################################################
            found_info=data["services"][service]["users"]
            key_iam="iam-accesskeys-scheduleddelete-warning-unused25thday" #Ensure alerts are in place for any scheduled key deletions
            ac_iam_info[data["aws_account_id"]][key_iam]={}
            ac_iam_info[key['AccountID']][key_iam]["rationale"]="Rotating Identity and Access Management (IAM) credentials periodically will significantly reduce the chances that a compromised set of access keys can be used without your knowledge to access certain components within your AWS account \
                    Ensure that all your IAM user access keys are rotated every month in order to decrease the likelihood of accidental exposures and protect your AWS resources against unauthorized access"
            ac_iam_info[key['AccountID']][key_iam]["description"]="Warning-scheduled key deletion alert not used for 30days or since creation"
            ac_iam_info[key['AccountID']][key_iam]["level"]='warning'
            ac_iam_info[key['AccountID']][key_iam]["service"]="IAM"
            ac_iam_info[key['AccountID']][key_iam]["Found_List"]=[]
            ac_iam_info[key['AccountID']][key_iam]["Found_Details"] = {}
            access_key_count=0
            todays_date=today_date.strftime("%Y-%m-%d %H:%M:%S")
            todays_date_UTC=parse(str(datetime.utcnow()))
            for uid,uvalues in found_info.items():
                if uvalues["AccessKeys"] !=[]:
                    accesskeys_for_user=uvalues["AccessKeys"]
                    user_details= found_info[uid]
                    user_name=uvalues["name"]
                    user_cred_report=data["services"][service]["credential_report"][user_name]
                    key_no=0
                    for access_key in accesskeys_for_user:
                        access_key_id=access_key["AccessKeyId"]
                        ac_create_date=parse(access_key["CreateDate"])
                        print("----------->Caluculating age of ",   access_key_id,  user_name )
                        key_no +=1
                        access_key_count +=1
                        access_key_status=access_key["Status"]
                        key_last_used=user_cred_report["access_key_"+str(key_no)+"_last_used_date"]
                        if key_last_used !="N/A":
                            ac_lastused_date=parse(key_last_used)
                            print("TODAY",todays_date_UTC.date(),   type(todays_date_UTC),todays_date_UTC.tzinfo)
                            print("CREATED ON-", ac_create_date.date(),    type(ac_create_date),   ac_create_date.tzinfo)
                            print("LASTUSED ON:-", ac_lastused_date.date(),   type(ac_lastused_date),  ac_lastused_date.tzinfo)
                            print("Diffrence of Today Date with Created adate",days_between(todays_date_UTC.date(), ac_create_date.date()))
                            print("Diffrence of Today Date with Last used Date ",days_between(todays_date_UTC.date(), ac_lastused_date.date()))
                            if int(days_between(todays_date_UTC.date(), ac_lastused_date.date())) >= 25 and (int(days_between(todays_date_UTC.date(), ac_create_date.date())) <=30):
                                print("30day since last Login AccessKey Flagged",access_key_id ,  user_name,   ac_lastused_date,   days_between(todays_date_UTC.date(), ac_lastused_date.date())  )
                                ac_iam_info[key['AccountID']][key_iam]["Found_List"].append(str(user_name+":"+access_key["AccessKeyId"]))
                                ac_iam_info[key['AccountID']][key_iam]["Found_Details"][user_name+":"+access_key["AccessKeyId"]]={}
                                ac_iam_info[key['AccountID']][key_iam]["Found_Details"][user_name+":"+access_key["AccessKeyId"]]=user_details
                                ac_iam_info[key['AccountID']][key_iam]["Found_Details"][str(user_name+":"+access_key["AccessKeyId"])]["KeyLastUsedDate"]={}
                                ac_iam_info[key['AccountID']][key_iam]["Found_Details"][str(user_name+":"+access_key["AccessKeyId"])]["KeyLastUsedDate"]=key_last_used
                            else:
                                print("This Accesskey under 30day limit so moving to next accesskey",access_key["AccessKeyId"])
                        elif key_last_used =="N/A":
                            if (int(days_between(todays_date_UTC.date(), ac_create_date.date())) >= 25) and (int(days_between(todays_date_UTC.date(), ac_create_date.date())) <=30) :
                                print("30Day No Activity AccessKey Flagged",user_name+":"+access_key["AccessKeyId"])
                                ac_iam_info[key['AccountID']][key_iam]["Found_List"].append(user_name+":"+access_key["AccessKeyId"])
                                ac_iam_info[key['AccountID']][key_iam]["Found_Details"][user_name+":"+access_key["AccessKeyId"]]={}
                                ac_iam_info[key['AccountID']][key_iam]["Found_Details"][user_name+":"+access_key["AccessKeyId"]]=user_cred_report
                            else:
                                print("This Accesskey under 30day limit so moving to next accesskey",access_key["AccessKeyId"])
                else:
                    print("No Access keys for the user", found_info[uid]["name"])
            print("======TOTAlAccessKeys",  access_key_count)
            ac_iam_info[key['AccountID']][key_iam]["dashboard_name"]="Access Keys"
            ac_iam_info[key['AccountID']][key_iam]["checked_items"]=str(access_key_count)
            ac_iam_info[key['AccountID']][key_iam]["flagged_items_count"]=str(len(ac_iam_info[key['AccountID']][key_iam]["Found_List"]))
            print(ac_iam_info[key['AccountID']][key_iam])
            if int(ac_iam_info[key['AccountID']][key_iam]["flagged_items_count"]) >=1:
                writedatatodynamodb(iam_table,ac_iam_info[key['AccountID']][key_iam],key,key_iam,reportdate,running_date,alrt,'Lambda')        
            else: 
                print("-------->Nothing foud for rule:--"+   key_iam+"X-On-X"+  key['AccountID'])
                ################################################################## 
                #              DELETING THE RULE IF FOUND ITEMS ==0
                ##################################################################
                try:
                    print("--------------Deleting item if it exists from Dynamodb-------------------")
                    response=iam_table.delete_item (Key={'Accountid':key['AccountID'],'Rulename':key_iam})
                except Exception as err:
                    raise err
            f.close()
            print("-------------------->>FINAL SUMMARRY",   ac_iam_info[key['AccountID']])
            cleardict(data)
        #############################################################   
            #CHECK/STORE THE LASTEVALUATEDKEY FROM PARAMATER STORE
        #############################################################
        if 'LastEvaluatedKey' in accounts_list_table_scan:
            print("----------Updating Last Evaluated Key as",accounts_list_table_scan['LastEvaluatedKey'])
            LastEvaluatedKey=accounts_list_table_scan['LastEvaluatedKey']['AccountID']
            ClientSSM.put_parameter(Name='Scout2-IAM-Startkey',Description='iamLastEvaluatedKey',Value=LastEvaluatedKey,Type='String',Overwrite=True)
            print(LastEvaluatedKey)
        else:
            print("---------->LastEvaluatedKey found as null_Updating key as Null and finished all accounts")
            LastEvaluatedKey='Null'
            ClientSSM.put_parameter(Name='Scout2-IAM-Startkey',Description='iamLastEvaluatedKey',Value=LastEvaluatedKey,Type='String',Overwrite=True)
    except Exception as error:
        alrt += '\nFailed Lambda IAM Reporting Function -arn:aws:lambda:us-east-2:478226638351:function:security-audit-IAM:  {} \n '.format(str(error))
        raise error
    if alrt:
        alrt+='\nMissing Report As of:  {} \n '.format(str(running_date))
        alrt+='\nPossible Reason:  {} \n '.format(str("Please check the bucket 'ue2-scout2-prod-history' for missing report with accountid/date and for more details about this account check dynamodb table 'awsaccounts-crossaccountrole-list'"))
        publish_msg_security_team("AWS SCOUT2 Missing Report for Accounts Attached", alrt)  
    return "success"
def clearlist(slis):  # clearing list
    slis[:] = []
def cleardict(sdict):  # clearing dictonary
    sdict.clear()
################################################################## 
    #   CONVERTING TIMEZONE IN TO CHICAGO/US-CENTRAL
##################################################################
def timeconverter(srctime):
    totimezone = 'US/Central'
    curtime = srctime.strftime("%m-%d-%Y %I:%M:%S %p")
    from_zone = tz.tzutc()
    to_zone = tz.gettz(totimezone)
    utc = datetime.strptime(curtime, '%m-%d-%Y %I:%M:%S %p')
    utc = utc.replace(tzinfo=from_zone)
    tocentral = utc.astimezone(to_zone).strftime("%m-%d-%Y %I:%M:%S %p")
    return tocentral
def publish_msg_security_team(Subject, Message):
    try:
        print("sending sns")
        sns_client.publish(TopicArn='arn:aws:sns:us-east-2:478226638351:AWS_Security_Scan_Alerts', Message=Message, Subject=Subject, MessageStructure='string')
        #sns_client.publish(TopicArn='arn:aws:sns:us-east-2:478226638351:test_sns_poc_personal', Message=Message, Subject=Subject, MessageStructure='string')
    except Exception as err:
        print (error)
def days_between(d1, d2):
    print("caluculating Days")
    # d1 = datetime.strptime(d1, "%Y-%m-%d")
    # d2 = datetime.strptime(d2, "%Y-%m-%d")
    return abs((d2 - d1).days)     
################################################################## 
    #   CREATING NEW TABLE IF UNFOUND WITH NAME 
##################################################################
def verifyLogTable(tablename,primarykey,sortkey):
    """Verifies if the table name provided is exists/not
    Returns:
        The real table name
        TYPE: String
    """
    client = boto3.client('dynamodb')
    resource = boto3.resource('dynamodb')
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
################################################################## 
    #   CLEANING THE EMPTY VALUES IN DICTONARY
##################################################################
def clean_empty(d):
    if not isinstance(d, (dict, list)):
        return d
    if isinstance(d, list):
        return [v for v in (clean_empty(v) for v in d) if v]
    return {k: v for k, v in ((k, clean_empty(v)) for k, v in d.items()) if v}
################################################################## 
    #   WRITING DATA TO DYNAMODB FROM COLLECTED ITERATIONS
##################################################################
def writedatatodynamodb(update_table,service_finding_info,key,rulename,reportdate,running_date,alrt,ReportedFrom):
        try:
            update_table.put_item ( 
                Item={
                    'Accountid':key['AccountID'],
                    'Rulename':rulename,
                    'Aliasname':key['Alias'],
                    'E-mail':key['Email'],
                    'Risklevel':service_finding_info['level'],
                    'Lastexecuteddate':str(running_date),
                    'Foundeddate':str(reportdate),
                    'Rationale':service_finding_info['rationale'],
                    'Description':service_finding_info["description"],
                    'Totalcheckeditems':str(service_finding_info['checked_items']),
                    'Flaggeditemslist':service_finding_info['Found_List'],
                    'Flaggeditemscount':str(service_finding_info['flagged_items_count']),
                    'Detailedinfo':clean_empty(service_finding_info['Found_Details']),
                    'Service':str(service_finding_info['service']+':'+service_finding_info['dashboard_name']),
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
            alrt+=':Error writing data for the rule  {} \n '.format(str(rulename))
            print("Error writing data to dynamdodb")
################################################################## 
    #                END OF AWS-IAM GAME
##################################################################
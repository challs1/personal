#!/usr/bin/env python3
""" 
Description - This Scritp will get the Today-Scout2_findings data from Scout2-History 
        bucket for each account and write Findings data to dynamodb table
        and 
        pull the CAt security checklist info using crossaccount access role and write the date as per findings
        for 
        ["rds", "cloudtrail", "elb", "elbv2", "redshift",  "vpc", "emr", "elasticache", "route53"]

Update Table    -   security-audit-service_SecurityGroups

Requrements - python3, Scout2 Report, imported libraries, aws crossaccount role,dynamodb,sns subscription,s3 bucket access

Output - Writing findings data for each rule in to dynamodbTable for each AWS account. 

"""
__author__ = "Chenna Vemula,Brian Rossi"
__COPYRIGHT__ = " Copyright 2018 , Caterpillar"
__email__ = " chenna_vemula@cat.com"
__version__ = " 0.0.1" 
import re
import os
import datetime
import dateutil
import requests
import decimal
import json
#import pytz
import boto3, json, time, datetime, sys
from dateutil.parser import parse
import traceback
from dateutil import tz, parser
from datetime import timedelta, date, datetime, timezone
from boto3.dynamodb.types import DYNAMODB_CONTEXT
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
from botocore.config import Config
sts = boto3.client('sts', config=Config(retries={'max_attempts': 10}))
ClientSSM = boto3.client('ssm', 'us-east-2')
ssm_par_name='Scout2-Lambda-Startkey'
sns_client = boto3.client('sns')
dynamodb_resource = boto3.resource('dynamodb','us-east-2')
dynamodb_client = boto3.client('dynamodb','us-east-2')
update_table_primarykey='Accountid'
update_table_sort_key='Rulename'
#services=["elb", "elbv2"]#["rds","redshift"]
services=["rds","redshift", "vpc", "elb", "elbv2","cloudtrail"]
BUCKET_NAME = 'ue2-scout2-qa-history' 
s3 = boto3.resource('s3')
valid_riskdomain_tags=['riskdomain','RD','rd','RiskDomain','RISKDOMAIN']
today_date=datetime.now()
running_date=today_date.strftime('%Y-%m-%dT%H:%M:%SZ')
accounts_list_table=dynamodb_resource.Table('awsaccounts-crossaccountrole-list')
def get_service_client(CrossAuditRole,ServiceName):
    assumedRoleObject = sts.assume_role(RoleArn=str(CrossAuditRole), RoleSessionName="security_audit_lambda")
    credentials = assumedRoleObject['Credentials']
    service_client = boto3.client(ServiceName,aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'],config=Config(retries={'max_attempts': 10}),)
    return service_client
def get_service_resource(region,CrossAuditRole,ServiceName):
    assumedRoleObject = sts.assume_role(RoleArn=str(CrossAuditRole), RoleSessionName="security_audit_lambda")
    credentials = assumedRoleObject['Credentials']
    service_resource = boto3.resource('service',aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'],region_name= region,config=Config(retries={'max_attempts': 10}),)
    return service_resource
def get_reg_service_client(region,CrossAuditRole,ServiceName):
    assumedRoleObject = sts.assume_role(RoleArn=str(CrossAuditRole), RoleSessionName="security_audit_lambda")
    credentials = assumedRoleObject['Credentials']
    conn_reg_service_client = boto3.client(ServiceName,aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'],region_name= region,config=Config(retries={'max_attempts': 10}),)
    return conn_reg_service_client
def check_and_get_parameter(paramname):
    try:
        get_evaluated_key=ClientSSM.get_parameter(Name=paramname)
    except :
        response = ClientSSM.put_parameter(Name=paramname,Description='LambdaLastEvaluatedKey',Value='Null',
        Type='String',Overwrite=True)
        print("Value Updated--Version as",response  )
        get_evaluated_key=ClientSSM.get_parameter(Name=paramname)
    return get_evaluated_key 
def check_and_update_parameter(accounts_list_table_scan):
    if 'LastEvaluatedKey' in accounts_list_table_scan:
        print("----------Updating Last Evaluated Key as",accounts_list_table_scan['LastEvaluatedKey'])
        LastEvaluatedKey=accounts_list_table_scan['LastEvaluatedKey']['AccountID']
        ClientSSM.put_parameter(Name='Scout2-Lambda-Startkey',Description='LambdaLastEvaluatedKey',Value=LastEvaluatedKey,Type='String',Overwrite=True)
        print(LastEvaluatedKey)
    else:
        print("---------->LastEvaluatedKey found as null_Updating key as Null and finished all accounts")
        LastEvaluatedKey='Null'
        ClientSSM.put_parameter(Name='Scout2-Lambda-Startkey',Description='LambdaLastEvaluatedKey',Value=LastEvaluatedKey,Type='String',Overwrite=True)
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
                continue
            for service in services:
                print("###############################")
                print("#######--"+service.upper()+"###")
                print("##############################")
                service_table_name="security-audit-"+service.upper()
                service_table = dynamodb_resource.Table(verifyLogTable(service_table_name,update_table_primarykey,update_table_sort_key))
                service_findings = data["services"][service]["findings"]
                ac_service_info={}
                ac_service_info[key['AccountID']] = {}
                ac_service_info[key['AccountID']]['ReportedOn']=data["last_run"]["time"]
                scout2_reportdate=data["last_run"]["time"]
                reportdate=(parser.isoparse(scout2_reportdate)).strftime('%Y-%m-%dT%H:%M:%SZ')
                ac_service_info[key['AccountID']]["Scout2_Ac_Number"]=data["aws_account_id"]      
                for key_service, key_value in service_findings.items():
                    print("------------->Searching for:-",key_value["dashboard_name"],  key_service)
                    if int(key_value["flagged_items"]) >= 1:
                        try:
                            items_list_found = key_value["items"]
                            #print("-------------------->Items Found As:--",   len(items_list_found))
                            ac_service_info[data["aws_account_id"]][key_service]={}
                            ac_service_info[key['AccountID']][key_service]["checked_items"] = key_value['checked_items']
                            ac_service_info[key['AccountID']][key_service]["flagged_items_count"] = key_value['flagged_items']
                            ac_service_info[key['AccountID']][key_service]["level"] = key_value['level']
                            ac_service_info[key['AccountID']][key_service]["dashboard_name"] = key_value['dashboard_name']
                            ac_service_info[key['AccountID']][key_service]["description"] = key_value['description']
                            ac_service_info[key['AccountID']][key_service]["rationale"] = key_value['rationale']
                            ac_service_info[key['AccountID']][key_service]["service"] = key_value['service']
                            ac_service_info[key['AccountID']][key_service]["Found_List"]=[]
                            ac_service_info[key['AccountID']][key_service]["Found_Details"] = {}
                            if service=='rds':
                                for line in items_list_found:
                                    split_service_words=list(line.split('.')) 
                                    if ac_service_info[key['AccountID']][key_service]["dashboard_name"]=="Instances":
                                       ac_service_info[key['AccountID']][key_service]["Found_List"].append(str(split_service_words[6]))
                                       ac_service_info[key['AccountID']][key_service]["Found_Details"][split_service_words[6]]={}
                                       found_info=data["services"][service]["regions"][split_service_words[2]]["vpcs"][split_service_words[4]]["instances"][split_service_words[6]]
                                       ac_service_info[key['AccountID']][key_service]["Found_Details"][split_service_words[6]]=found_info
                                    elif ac_service_info[key['AccountID']][key_service]["dashboard_name"]=="Security Groups":
                                        ac_service_info[key['AccountID']][key_service]["Found_List"].append(str(split_service_words[6]))
                                        ac_service_info[key['AccountID']][key_service]["Found_Details"][split_service_words[6]]={}
                                        found_info=data["services"][service]["regions"][split_service_words[2]]["vpcs"][split_service_words[4]]["security_groups"][split_service_words[6]]
                                        ac_service_info[key['AccountID']][key_service]["Found_Details"][split_service_words[6]]=found_info
                                    elif ac_service_info[key['AccountID']][key_service]["dashboard_name"]=="Snapshots":
                                        ac_service_info[key['AccountID']][key_service]["Found_List"].append(str(split_service_words[6]))
                                        ac_service_info[key['AccountID']][key_service]["Found_Details"][split_service_words[6]]={}
                                        found_info=data["services"][service]["regions"][split_service_words[2]]["vpcs"][split_service_words[4]]["snapshots"][split_service_words[6]]
                                        ac_service_info[key['AccountID']][key_service]["Found_Details"][split_service_words[6]]=found_info
                                    else:
                                        print("Didnt find this dashboard",  ac_service_info[key['AccountID']][key_service]["dashboard_name"])
                            if service=='redshift':
                                for line in items_list_found:
                                    split_service_words=list(line.split('.'))     
                                    if ac_service_info[key['AccountID']][key_service]["dashboard_name"]=="Clusters":
                                        redshift_name=data["services"][service]["regions"][split_service_words[2]]["vpcs"][split_service_words[4]]["clusters"][split_service_words[6]]['name']
                                        if redshift_name not in ac_service_info[key['AccountID']][key_service]["Found_List"]:   
                                            ac_service_info[key['AccountID']][key_service]["Found_List"].append(str(redshift_name))
                                            ac_service_info[key['AccountID']][key_service]["Found_Details"][redshift_name]={}
                                            found_info=data["services"][service]["regions"][split_service_words[2]]["vpcs"][split_service_words[4]]["clusters"][split_service_words[6]]
                                            ac_service_info[key['AccountID']][key_service]["Found_Details"][redshift_name]=found_info
                                    elif ac_service_info[key['AccountID']][key_service]["dashboard_name"]=="Parameter Groups":
                                        redshift_name=data["services"][service]["regions"][split_service_words[2]]["parameter_groups"][split_service_words[4]]['name']
                                        if redshift_name not in ac_service_info[key['AccountID']][key_service]["Found_List"]: 
                                            ac_service_info[key['AccountID']][key_service]["Found_List"].append(str(redshift_name))
                                            ac_service_info[key['AccountID']][key_service]["Found_Details"][redshift_name]={}
                                            found_info=data["services"][service]["regions"][split_service_words[2]]["parameter_groups"][split_service_words[4]]
                                            ac_service_info[key['AccountID']][key_service]["Found_Details"][redshift_name]=found_info
                                    elif ac_service_info[key['AccountID']][key_service]["dashboard_name"]=="Security Groups":
                                        redshift_name=data["services"][service]["regions"][split_service_words[2]]["security_groups"][split_service_words[4]]['name']
                                        if redshift_name not in ac_service_info[key['AccountID']][key_service]["Found_List"]: 
                                            ac_service_info[key['AccountID']][key_service]["Found_List"].append(str(redshift_name))
                                            ac_service_info[key['AccountID']][key_service]["Found_Details"][redshift_name]={}
                                            found_info=data["services"][service]["regions"][split_service_words[2]]["security_groups"][split_service_words[4]]['name']
                                            ac_service_info[key['AccountID']][key_service]["Found_Details"][redshift_name]=found_info
                                    else:
                                        print("Didnt find this dashboard",  ac_service_info[key['AccountID']][key_service]["dashboard_name"])
                            if service=='vpc':
                                for line in items_list_found:
                                    split_service_words=list(line.split('.')) 
                                    if ac_service_info[key['AccountID']][key_service]["dashboard_name"]=="Network ACLs":
                                       ac_service_info[key['AccountID']][key_service]["Found_List"].append(str(split_service_words[6]))
                                       ac_service_info[key['AccountID']][key_service]["Found_Details"][split_service_words[6]]={}
                                       found_info=data["services"][service]["regions"][split_service_words[2]]["vpcs"][split_service_words[4]]["network_acls"][split_service_words[6]]
                                       ac_service_info[key['AccountID']][key_service]["Found_Details"][split_service_words[6]]=found_info
                                    elif ac_service_info[key['AccountID']][key_service]["dashboard_name"]=="Subnets":
                                        ac_service_info[key['AccountID']][key_service]["Found_List"].append(str(split_service_words[6]))
                                        ac_service_info[key['AccountID']][key_service]["Found_Details"][split_service_words[6]]={}
                                        found_info=data["services"][service]["regions"][split_service_words[2]]["vpcs"][split_service_words[4]]["subnets"][split_service_words[6]]
                                        found_info["network_acls"]={}
                                        found_info["network_acls"]=data["services"][service]["regions"][split_service_words[2]]["vpcs"][split_service_words[4]]["network_acls"][found_info["network_acl"]]
                                        ac_service_info[key['AccountID']][key_service]["Found_Details"][split_service_words[6]]=found_info
                                    else:
                                        print("Didnt find this dashboard",  ac_service_info[key['AccountID']][key_service]["dashboard_name"])
                            if service=='elb':
                                for line in items_list_found:
                                    split_service_words=list(line.split('.')) 
                                    if ac_service_info[key['AccountID']][key_service]["dashboard_name"]=="Load Balancer Attributes":
                                        elb_name=data["services"][service]["regions"][split_service_words[2]]["vpcs"][split_service_words[4]]["elbs"][split_service_words[6]]['name']
                                        ac_service_info[key['AccountID']][key_service]["Found_List"].append(str(elb_name))
                                        ac_service_info[key['AccountID']][key_service]["Found_Details"][elb_name]={}
                                        found_info=data["services"][service]["regions"][split_service_words[2]]["vpcs"][split_service_words[4]]["elbs"][split_service_words[6]]
                                        ac_service_info[key['AccountID']][key_service]["Found_Details"][elb_name]=found_info
                            if service=='elbv2':
                                for line in items_list_found:
                                    split_service_words=list(line.split('.')) 
                                    if ac_service_info[key['AccountID']][key_service]["dashboard_name"]=="Load Balancer Attributes":
                                        elb_name=data["services"][service]["regions"][split_service_words[2]]["vpcs"][split_service_words[4]]["lbs"][split_service_words[6]]['name']
                                        ac_service_info[key['AccountID']][key_service]["Found_List"].append(str(elb_name))
                                        ac_service_info[key['AccountID']][key_service]["Found_Details"][elb_name]={}
                                        found_info=data["services"][service]["regions"][split_service_words[2]]["vpcs"][split_service_words[4]]["lbs"][split_service_words[6]]
                                        ac_service_info[key['AccountID']][key_service]["Found_Details"][elb_name]=found_info       
                                    elif ac_service_info[key['AccountID']][key_service]["dashboard_name"]=="Load Balancer Listeners":
                                        elb_name=data["services"][service]["regions"][split_service_words[2]]["vpcs"][split_service_words[4]]["lbs"][split_service_words[6]]['name']
                                        ac_service_info[key['AccountID']][key_service]["Found_List"].append(str(elb_name))
                                        ac_service_info[key['AccountID']][key_service]["Found_Details"][elb_name]={}
                                        found_info=data["services"][service]["regions"][split_service_words[2]]["vpcs"][split_service_words[4]]["lbs"][split_service_words[6]]
                                        ac_service_info[key['AccountID']][key_service]["Found_Details"][elb_name]=found_info
                                    else:
                                        print("Didnt find this dashboard",  ac_service_info[key['AccountID']][key_service]["dashboard_name"])
                            if service=='cloudtrail':
                                for line in items_list_found:
                                    split_service_words=list(line.split('.')) 
                                    if ac_service_info[key['AccountID']][key_service]["dashboard_name"]=="Trails":
                                        #cloudtrail.regions.id.trails.id
                                        trail_name=data["services"][service]["regions"][split_service_words[2]]["trails"][split_service_words[4]]['name']
                                        ac_service_info[key['AccountID']][key_service]["Found_List"].append(str(trail_name))
                                        ac_service_info[key['AccountID']][key_service]["Found_Details"][trail_name]={}
                                        found_info=data["services"][service]["regions"][split_service_words[2]]["trails"][split_service_words[4]]
                                        ac_service_info[key['AccountID']][key_service]["Found_Details"][trail_name]=found_info       
                                    elif ac_service_info[key['AccountID']][key_service]["dashboard_name"]=="Configuration":
                                        #cloudtrail.IncludeGlobalServiceEvents
                                        #trail_name=data["services"][service]["regions"][split_service_words[1]]["region"]
                                        ac_service_info[key['AccountID']][key_service]["Found_List"].append(str(split_service_words[1]))
                                        ac_service_info[key['AccountID']][key_service]["Found_Details"][split_service_words[1]]={}
                                        #found_info=data["services"][service]["regions"][split_service_words[1]]
                                        ac_service_info[key['AccountID']][key_service]["Found_Details"][split_service_words[1]]=split_service_words[1]
                                        # elb_name=data["services"][service]["regions"][split_service_words[2]]["vpcs"][split_service_words[4]]["lbs"][split_service_words[6]]['name']
                                        # ac_service_info[key['AccountID']][key_service]["Found_List"].append(str(elb_name))
                                        # ac_service_info[key['AccountID']][key_service]["Found_Details"][elb_name]={}
                                        # found_info=data["services"][service]["regions"][split_service_words[2]]["vpcs"][split_service_words[4]]["lbs"][split_service_words[6]]
                                        # ac_service_info[key['AccountID']][key_service]["Found_Details"][elb_name]=found_info
                                    elif ac_service_info[key['AccountID']][key_service]["dashboard_name"]=="Regions":
                                        #cloudtrail.regions.id
                                        trail_name=data["services"][service]["regions"][split_service_words[2]]["region"]
                                        ac_service_info[key['AccountID']][key_service]["Found_List"].append(str(trail_name))
                                        ac_service_info[key['AccountID']][key_service]["Found_Details"][trail_name]={}
                                        found_info=data["services"][service]["regions"][trail_name]
                                        ac_service_info[key['AccountID']][key_service]["Found_Details"][trail_name]=found_info 
                                    else:
                                        print("Didnt find this dashboard",  ac_service_info[key['AccountID']][key_service]["dashboard_name"])
                        except Exception as error:   
                            print("Error Reading rule", key_service)  
                            raise error 
                        data_format=ac_service_info[key['AccountID']][key_service]
                        try:
                            writedatatodynamodb(service_table,data_format,key,key_service,reportdate,running_date,alrt,'Scout2')    
                        except TypeError:
                            try:
                                new_for_data=json.dumps(data_format["Found_Details"])
                                new_for_data1=json.loads(new_for_data, parse_float=decimal.Decimal)
                                data_format["Found_Details"]=new_for_data1
                                writedatatodynamodb(service_table,data_format,key,key_service,reportdate,running_date,alrt,'Scout2')
                            except Exception as edr:
                                print(edr)
                                raise edr
                    else:
                        print("--------> 0 Found for :--"+   key_service +"Account ID"+  key['AccountID'])
                        try:
                            pass
                            print("------------------------Deleting item if it exists from Dynamodb-------------------")
                            response=service_table.delete_item (Key={'Accountid':key['AccountID'],'Rulename':key_service})
                        except Exception as err:
                            raise err
                # #################  service-CONNECTION ##########################
                # try:
                #     service_client =boto3.client('ec2') if key['AccountID'] =='478226638351' else get_service_client(key['CrossAuditRole'],'ec2')
                #     service_regions = [region['RegionName'] for region in service_client.describe_regions()['Regions']]
                #     #print("Regions As...",service_regions  )
                # except Exception as botoerror:
                #     print(botoerror)
                #     raise botoerror
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
                ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
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
            #print(service_finding_info)
            #alrt+=':Error writing data for the rule  {} \n '.format(str(rulename))
            print("Error writing data to dynamdodb")
            raise e
################################################################## 
    #                END OF AWS-service GAME
##################################################################


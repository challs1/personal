#!/usr/bin/env python3
""" 
Description - This Scritp will get the IAM_Findings data from Scout2-History 
bucket for each account and sends the SNS notification on Findings and write data to dynamodb table

Requrements - python3, imported libraries, aws crossaccount role,dynamodb,sns subscription,s3 bucket access

Output - Writing data to dynamodb and sends sns notification for each account. 

"""
__author__ = "Sairaja Challagulla,Brian Rossi"
__COPYRIGHT__ = " Copyright 2018 , Caterpillar"
__email__ = " Challagulla_Sairaja@cat.com"
__version__ = " 0.0.1" 
import json
import pprint
import re
import boto3
import botocore
import tempfile
import time
import os
from datetime import datetime
import datetime
import traceback
from dateutil import tz
from datetime import timedelta, date, datetime
from botocore.exceptions import ClientError
sts = boto3.client('sts')
sns_client = boto3.client('sns')
dynamodb_resource = boto3.resource('dynamodb')
dynamodb_client = boto3.client('dynamodb')  # conection to the dynamo db
update_table_primarykey='AccountID'
update_table_sort_key='Rule_Name'
#table = dynamodb_resource.Table('iam_security_audit_dev')  # Retreive the table in dynomo db.
BUCKET_NAME = 'ue2-scout2-prod-history'  # replace with your bucket name  
s3 = boto3.resource('s3')
iam_exclude = ['iam-assume-role-lacks-external-id-and-mfa', 'iam-ec2-role-without-instances', 'iam-group-with-inline-policies',
               'iam-inline-group-policy-allows-NotActions', 'iam-inline-group-policy-allows-iam-PassRole', 'iam-inline-group-policy-allows-sts-AssumeRole',
               'iam-inline-role-policy-allows-NotActions', 'iam-inline-role-policy-allows-iam-PassRole', 'iam-inline-role-policy-allows-sts-AssumeRole',
               'iam-inline-user-policy-allows-NotActions', 'iam-inline-user-policy-allows-iam-PassRole', 'iam-inline-user-policy-allows-sts-AssumeRole',
               'iam-managed-policy-allows-NotActions', 'iam-managed-policy-allows-iam-PassRole', 'iam-managed-policy-allows-sts-AssumeRole',
               'iam-role-with-inline-policies','iam-root-account-used-recently','iam-user-with-multiple-access-keys']
Accounts= {"478226638351":"secops1", "799824181982":"Intranet-Sandbox", "002710387481":"Internet-Sandbox", "620890749476":"sharedservices",
           "656990482673":"orgbilling" ,"128389660555":"caastaging", "944573716837":"ddswhadoopdev", "263363729850":"ddswhadoopprod",
           "828711334708":"ecatinnovation", "141576945838":"edsdev", "238298454097":"edsprod","520111439412":"mdmdev","610872094909":"mdmprod" ,
           "009617208910":"secriskmgmt","054518192585":"symphonycntlplane", "205231843124":"symphonyprod" , "355391146408":"symphonydev" ,
           "100178607838":"catweardev" ,"642500132467":"catwearprod","043691484226":"catwearstaging" ,"327349948073":"shareddev1" ,
           "006172073716":"sharedprod1","063913871427":"EXD_Dev","132602501915":"c3prod","333602505810":"c3-dev",
           "342101340642":"commerce_prod","158134245097":"commerce_dev","944898352560":"symphony_sdr" }
Accounts_Exclude=['132602501915','333602505810']
today_date=datetime.now()
running_date=today_date.strftime("%m-%d-%Y")
bucket_keys_1=[]
accounts_list_table=dynamodb_resource.Table('org_accounts_list_dev')
def get_keys():
    #accounts_list = get_account_ids()
    accounts_list_table_scan = accounts_list_table.scan(AttributesToGet=['AccountID','Status'],Limit=40)
    accounts_list_table_scan_ext = accounts_list_table_scan['Items']
    # print(accounts_list_table_scan_ext)
    # print(len(accounts_list_table_scan_ext))
    notify_security_msg=''
    for key in accounts_list_table_scan_ext:
        if ((key['AccountID'] not in Accounts_Exclude) and (key['Status'] !='SUSPENDED')):
            try:
                if (key['AccountID']=='478226638351'):
                    b_key= key['AccountID']+'/'+running_date+'/inc-awsconfig/'+'aws_config.js'
                    bucket_keys_1.append(b_key)
                    print(b_key)
                else:
                    b_key= key['AccountID']+'/'+running_date+'/inc-awsconfig/'+'aws_config-'+ Accounts[key['AccountID']]+'.js'
                    bucket_keys_1.append(b_key)
                    print(b_key)    
            except KeyError:
                notify_security_msg+= '\nUnable to Find report for :  {} \n '.format(str(key['AccountID']))
                print("Unable to get key for the account",key['AccountID'])
    if notify_security_msg:
        notify_security_msg+='\nMORE_INFO:  {} \n '.format(str("This notification sending to alert the security team about missing Scout2 report or New AWS Account Detected. Please check the bucket 'ue2-scout2-prod-history' for missing report with date and for more details about this account check dynamodb table 'org_accounts_list_dev'"))
        publish_msg_security_team("SCOUT2_IAM New Account Detected as of-"+str(running_date), notify_security_msg)
        notify_security_msg=''        
    return 'done'
def lambda_handler(event, context):
    get_keys()
    table = dynamodb_resource.Table(verifyLogTable('iam_security_audit_dev',update_table_primarykey,update_table_sort_key))
    for k_object in bucket_keys_1:
        #print(k_object)
        try:
            try:
                s3.Bucket(BUCKET_NAME).download_file(k_object, '/tmp/findings.js')
                with open("/tmp/findings.js", 'rt') as f:
                    next(f)
                    content = f.read()
                    data = json.loads(content)
                accnt_ID = data["aws_account_id"]
            except:
                print('Error reading Object:-',k_object)
                alrt=''
                alrt+='AccountName:  {} \n '.format(str(Accounts[k_object[:12]]))
                alrt+='\nMissing Report As of:  {} \n '.format(str(running_date))
                alrt+='\nPossible Reason:  {} \n '.format(str("Please check the bucket 'ue2-scout2-prod-history' for missing report with accountid/date and for more details about this account check dynamodb table 'org_accounts_list_dev'"))
                publish_msg_security_team("AWS SCOUT2 Missing Report for--"+k_object[:12] , alrt)
                print("Unable to read the IAM config for the account:--"+ k_object[:12] +':'+Accounts[k_object[:12]])
                continue
            #print(accnt_ID)
            service_List = data["service_list"]
            i = 0
            while len(service_List) > i:
                try:
                    service = service_List[i]
                    keys = data["services"][service]["findings"]
                except:
                    print(
                        "_____________________%s does not have findings___________________________________" % service)
                    pass
                if (service == "iam"):
                    print("*********************" + accnt_ID + "-------------"+ service +"*************************")
                    iam_findings = data["services"][service]["findings"]
                    msg=''
                    for key_iam, key_value in iam_findings.items():
                        iam_config_findings = data["services"][service]["findings"][key_iam]
                        try:
                            if iam_config_findings["flagged_items"] >= 1:
                                iam_items = iam_config_findings["items"]
                                #print(key_iam)
                                rule = {}
                                rule["Rule_Name"] = key_iam
                                rule["flagged_items"] = iam_config_findings["flagged_items"]
                                rule["level"] = iam_config_findings["level"]
                                rule["dashboard_name"] = iam_config_findings["dashboard_name"]
                                rule["description"] = iam_config_findings["description"]
                                rule["rationale"] = iam_config_findings["rationale"]
                                rule["found_items"] = {"policies":[], "roles":[], "inline_policies":[], "users":[], "other_id":[]}
                                strip_id = re.findall(
                                    r"(?<=s\.).*?(?=\.)", str(iam_items))
                                #print(strip_id)
                                for znat in strip_id:
                                    try:
                                        # mactch and find the name of policy accroding to found ID in items
                                        iam = data["services"][service]["policies"][znat]["name"]
                                        rule["found_items"]["policies"].append(iam)
                                        #print("policy" + "id: " +znat + "| "+"name: " + iam)
                                        IAM.setdefault(accnt_ID,{}).setdefault(service,{}).setdefault("problem", {}).setdefault(key_iam,{}).setdefault("Findings", {}).setdefault("policy", {})
                                        IAM.setdefault(accnt_ID,{}).setdefault(service,{}).setdefault("problem", {}).setdefault(key_iam,{}).setdefault("Findings", {}).setdefault("policy", {})[znat] = iam
                                    except:
                                        try:
                                            # if does not belong to policy then look for the name under roles
                                            iam = data["services"][service]["roles"][znat]["name"]
                                            rule["found_items"]["roles"].append(iam)
                                            #print("role: " + "id: " +znat + "| "+"name: " + iam)
                                            IAM.setdefault(accnt_ID,{}).setdefault(service,{}).setdefault("problem", {}).setdefault(key_iam,{}).setdefault("Findings", {}).setdefault("roles", {})
                                            IAM.setdefault(accnt_ID,{}).setdefault(service,{}).setdefault("problem", {}).setdefault(key_iam,{}).setdefault("Findings", {}).setdefault("roles", {})[znat] = iam

                                        except:
                                            try:
                                                for multi_Dom in strip_id:
                                                    iam = data["services"][service][multi_Dom]["inline_policies"][znat]["name"]
                                                    rule["found_items"]["inline_policies"].append(iam)
                                                    #print("inline-policy: " +znat + "| "+"name: " + iam)
                                                    IAM.setdefault(accnt_ID,{}).setdefault(service,{}).setdefault("problem", {}).setdefault(key_iam,{}).setdefault("Findings", {}).setdefault("inline-policy", {})
                                                    IAM.setdefault(accnt_ID,{}).setdefault(service,{}).setdefault("problem", {}).setdefault(key_iam,{}).setdefault("Findings", {}).setdefault("inline-policy", {})[znat] = iam
                                            except:
                                                try:
                                                    iam = data["services"][service]["users"][znat]["name"]
                                                    rule["found_items"]["users"].append(iam)
                                                    #print("users:  " + znat + "| "+"name: " + iam)
                                                    IAM.setdefault(accnt_ID,{}).setdefault(service,{}).setdefault("problem", {}).setdefault(key_iam,{}).setdefault("Findings", {}).setdefault("users", {})
                                                    IAM.setdefault(accnt_ID,{}).setdefault(service,{}).setdefault("problem", {}).setdefault(key_iam,{}).setdefault("Findings", {}).setdefault("users", {})[znat] = iam
                                                except:
                                                    continue
                        except:
                            print("could not find id of the rule: " + str(key_iam))
                            #rule["found_items"]["other_id"].append(strip_id)
                        finally:
                            if rule:
                                #print(rule)
                                if rule["Rule_Name"] not in iam_exclude:
                                    #msg=''
                                    if rule["Rule_Name"]== "iam-user-with-inline-policies":
                                        rationale="IAM Policies must only be assigned to groups or roles, and not individual users"
                                        found_items=rule["found_items"]["users"]
                                        #msg=''
                                        #msg+='\n DESCRIPTION:' rule["description"]
                                        msg+='RULE:  {} \n '.format(str(rule["Rule_Name"]))
                                        msg+='\nDESCRIPTION:  {} \n '.format(str(rule["description"]))
                                        msg+='\nRATIONALE:  {} \n '.format(str(rationale))
                                        msg +='\nFLAGGED_USERS:  {} \n'.format(str(found_items))
                                        msg += '\n*************NEXT******************** \n'
                                        format_data = {'AccountID':str(accnt_ID), 'RuleName':rule["Rule_Name"], 'Rationale':str(rationale), 'AccountName':str(Accounts[accnt_ID]), 'Description':rule["description"], 'Flagged_Users': found_items, 'Run_Time': str(data["last_run"]["time"]), 'items_count': len(found_items)}
                                        #print(format_data)
                                        table.put_item ( 
                                                Item={
                                                    'AccountID':str(accnt_ID),
                                                    'Rule_Name':format_data["RuleName"],
                                                    'Rationale': str(format_data["Rationale"]),
                                                    'AccountName':str(format_data["AccountName"]),
                                                    'Description':format_data["Description"],
                                                    'Flagged_Users':found_items,
                                                    'Run_Time':format_data["Run_Time"],
                                                    'items_count':len(found_items),
                                                    }
                                                )
                                        cleardict(format_data)
                                        #publish_msg_cloud_team("Scout2 AWS Findings-<"+Accounts[accnt_ID]+">-" + accnt_ID , msg)
                                        #msg=''
                                    elif rule["Rule_Name"]== "iam-user-without-mfa":
                                        rationale_1='Multi-Factor Authentication (MFA) adds an extra layer of protection on top of a user name and password. With MFA enabled, when a user signs in to an AWS website, they will be prompted for their user name and password as well as for an authentication code from their AWS MFA device. It is recommended that MFA be enabled for all accounts that have a console password.'
                                        found_items_1=rule["found_items"]["users"]
                                        #msg=''
                                        msg+='RULE:  {} \n '.format(str(rule["Rule_Name"]))
                                        msg+='\nDESCRIPTION:  {} \n '.format(str(rule["description"]))
                                        msg+='\nRATIONALE:  {} \n '.format(str(rationale_1))
                                        msg +='\nFLAGGED_USERS:  {} \n'.format(str(found_items_1))
                                        msg += '\n*************NEXT******************** \n'
                                        table.put_item ( 
                                                Item={
                                                    'AccountID':str(accnt_ID),
                                                    'Rule_Name':rule["Rule_Name"],
                                                    'Rationale': rationale_1,
                                                    'AccountName':Accounts[accnt_ID],
                                                    'Description':rule["description"],
                                                    'Flagged_Users':found_items_1,
                                                    'Run_Time':str(data["last_run"]["time"]),
                                                    'items_count':len(found_items_1),
                                                    }
                                                )
                                        #publish_msg_cloud_team("Scout2 AWS Findings-<"+Accounts[accnt_ID]+">-" + accnt_ID , msg)
                                        #msg=''
                                    elif rule["Rule_Name"]== "iam-user-no-Active-key-rotation" or rule["Rule_Name"]== "iam-user-no-Inactive-key-rotation" :
                                        rationale_2='In case of access key compromise, the lack of credential rotation increases the period during which an attacker has access to the AWS account. AWS IAM users can access AWS resources using different types of credentials, such as passwords or access keys. It is recommended that all credentials that have been unused in 90 or greater days be removed or deactivated'
                                        found_items_2=rule["found_items"]["users"]
                                        #msg=''
                                        msg+='RULE:  {} \n '.format(str(rule["Rule_Name"]))
                                        msg+='\nDESCRIPTION:  {} \n '.format(str(rule["description"]))
                                        msg+='\nRATIONALE:  {} \n '.format(str(rationale_2))
                                        msg +='\nFLAGGED_USERS:  {} \n'.format(str(found_items_2))
                                        msg += '\n*************NEXT******************** \n'
                                        table.put_item ( 
                                                Item={
                                                    'AccountID':str(accnt_ID),
                                                    'Rule_Name':rule["Rule_Name"],
                                                    'Rationale': rationale_2,
                                                    'AccountName':Accounts[accnt_ID],
                                                    'Description':rule["description"],
                                                    'Flagged_Users':found_items_2,
                                                    'Run_Time':str(data["last_run"]["time"]),
                                                    'items_count':len(found_items_2),
                                                    }
                                                )
                                        #publish_msg_cloud_team("Scout2 AWS Findings-<"+Accounts[accnt_ID]+">-" + accnt_ID , msg)
                                        #msg=''
                                    elif rule["Rule_Name"]=="iam-root-account-with-active-keys":
                                        rationale_3='The root account is the most privileged user in an AWS account. AWS Access Keys provide programmatic access to a given AWS account. It is recommended that all access keys associated with the root account be removed.'
                                        description='Therefore, protect your AWS account access key like you would your credit card numbers or any other sensitive secret. Here are some ways to do that:<https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials>'
                                        found_items_3= accnt_ID+':'+Accounts[accnt_ID]
                                        #msg=''
                                        msg+='RULE:  {} \n '.format(str(rule["Rule_Name"]))
                                        msg+='\nDESCRIPTION:  {} \n '.format(str(description))
                                        msg+='\nRATIONALE:  {} \n '.format(str(rationale_3))
                                        msg +='\nFLAGGED_ACCOUNT:  {} \n'.format(str(found_items_3))
                                        msg += '\n*************NEXT******************** \n'
                                        table.put_item ( 
                                                Item={
                                                    'AccountID':str(accnt_ID),
                                                    'Rule_Name':rule["Rule_Name"],
                                                    'Rationale': rationale_3,
                                                    'AccountName':Accounts[accnt_ID],
                                                    'Description':rule["description"],
                                                    'Flagged_Users':str("root of_"+accnt_ID),
                                                    'Run_Time':str(data["last_run"]["time"]),
                                                    'items_count':len(found_items_3),
                                                    }
                                                )
                                        #publish_msg_cloud_team("Scout2 AWS Findings-<"+Accounts[accnt_ID]+">-" + accnt_ID , msg)
                                        #msg=''
                                    elif rule["Rule_Name"]=="iam-password-policy-minimum-length":
                                        rationale_4='Ensure IAM password policy requires minimum length of 12(CAT)/14(CIS) or greater'
                                        description='Password policies are, in part, used to enforce password complexity requirements. IAM password policies can be used to ensure password are at least a given length. It is recommended that the password policy require a minimum password length 12 for current version.'
                                        found_items_4= accnt_ID+':'+Accounts[accnt_ID]
                                        #msg=''
                                        msg+='RULE:  {} \n '.format(str(rule["Rule_Name"]))
                                        msg+='\nDESCRIPTION:  {} \n '.format(str(description))
                                        msg+='\nRATIONALE:  {} \n '.format(str(rationale_4))
                                        msg +='\nFLAGGED_ACCOUNT:  {} \n'.format(str(found_items_4))
                                        msg += '\n*************NEXT******************** \n'
                                        table.put_item ( 
                                                Item={
                                                    'AccountID':str(accnt_ID),
                                                    'Rule_Name':rule["Rule_Name"],
                                                    'Rationale': rationale_4,
                                                    'AccountName':Accounts[accnt_ID],
                                                    'Description':rule["description"],
                                                    'Flagged_Users':str("root of_"+accnt_ID),
                                                    'Run_Time':str(data["last_run"]["time"]),
                                                    'items_count':str("1"),
                                                    }
                                                )
                                        #publish_msg_cloud_team("Scout2 AWS Findings-<"+Accounts[accnt_ID]+">-" + accnt_ID , msg)
                                        #msg=''
                                    else:
                                        #msg=''
                                        msg+='RULE:  {} \n '.format(str(rule["Rule_Name"]))
                                        msg+='\nDESCRIPTION:  {} \n '.format(str(rule["description"]))
                                        msg+='\nRATIONALE:  {} \n '.format(str(rule["rationale"]))
                                        msg +='\nFLAGGED_ITEMS: {} \n'.format(str(rule["found_items"]))
                                        msg += '\n*************NEXT******************** \n'
                                        table.put_item ( 
                                            Item={
                                                'AccountID':str(accnt_ID),
                                                'Rule_Name':rule["Rule_Name"],
                                                'Rationale': rule["rationale"],
                                                'AccountName':Accounts[accnt_ID],
                                                'Description':rule["description"],
                                                'Flagged_Users':rule["found_items"],
                                                'Run_Time':str(data["last_run"]["time"]),
                                                'items_count':len(rule["found_items"]),
                                                }
                                            )
                                        #publish_msg_cloud_team("Scout2 AWS Findings-<"+Accounts[accnt_ID]+">-" + accnt_ID , msg)
                                        #msg=''
                                    # publish_msg_cloud_team("AWS_IAM Findings-<"+Accounts[accnt_ID]+">-" + accnt_ID , msg)
                                    # msg=''
                                cleardict(rule)
                    #publish_msg_cloud_team("AWS_IAM Findings-<"+Accounts[accnt_ID]+">-" + accnt_ID , msg)
                    #msg=''
                    cleardict(iam_findings)
                    cleardict(iam_config_findings)
                    clearlist(iam_items)
                    strip_id = []
                    print(msg)
                    if msg:
                        publish_msg_cloud_team("AWS_IAM Findings-<"+Accounts[accnt_ID]+">-" + accnt_ID , msg)
                i += 1
            f.close()
            cleardict(data)
            clearlist(service_List)
            #cleardict(content)
        except :   
            continue   
    return "success"
def publish_msg_cloud_team(Subject, Message):
    try:
        print("sending sns")
        sns_client.publish(TopicArn='arn:aws:sns:us-east-2:478226638351:Scout2_IAM_Notify', Message=Message, Subject=Subject, MessageStructure='string')
        #sns_client.publish(TopicArn='arn:aws:sns:us-east-2:478226638351:test_sns_poc_personal', Message=Message, Subject=Subject, MessageStructure='string')
    except Exception as e:
        raise e
def clearlist(slis):  # clearing list
    slis[:] = []
def cleardict(sdict):  # clearing dictonary
    sdict.clear()
def publish_msg_security_team(Subject, Message):
    try:
        print("sending sns")
        sns_client.publish(TopicArn='arn:aws:sns:us-east-2:478226638351:AWS_Security_Scan_Alerts', Message=Message, Subject=Subject, MessageStructure='string')
        #sns_client.publish(TopicArn='arn:aws:sns:us-east-2:478226638351:test_sns_poc_personal', Message=Message, Subject=Subject, MessageStructure='string')
    except Exception as e:
        raise e
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
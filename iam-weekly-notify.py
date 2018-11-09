#!/usr/bin/env python3
""" 
Description - This Script will collect the IAM-Findings from DynamoDb table and sends out SNS notification

Requrements - python3, imported libraries, aws crossaccount role,dynamodb,sns subscription,s3 bucket access

Output - sends SNS notification for each account 

"""
__author__ = "Chenna Vemula,Brian Rossi"
__COPYRIGHT__ = " Copyright 2018 , Caterpillar"
__email__ = " chenna_vemula@cat.com"
__version__ = " 0.0.1(Stable-10/23/2018)" 
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
import boto3, json, time, datetime, sys
from dateutil.parser import parse
import traceback
from dateutil import tz, parser
from dateutil import tz
from datetime import timedelta, date, datetime
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr
sts = boto3.client('sts')
sns_client = boto3.client('sns')
dynamodb_resource = boto3.resource('dynamodb',region_name='us-east-2')
dynamodb_client = boto3.client('dynamodb')  # conection to the dynamo db
today_date=datetime.now()
running_date=today_date.strftime('%Y-%m-%dT%H:%M:%SZ')
iam_findings_table=dynamodb_resource.Table('security-audit-IAM')
def lambda_handler(event, context):
    account_numbers=[]
    done= False
    NextToken = None
    while not done:
        if NextToken:
            flagged_accounts=iam_findings_table.scan(AttributesToGet=['Aliasname','Accountid'],Limit=100,ConsistentRead=True,ExclusiveStartKey=NextToken)#,
                                                                     #FilterExpression=Attr("Risklevel").eq('danger'))
        else:
            flagged_accounts=iam_findings_table.scan(AttributesToGet=['Aliasname','Accountid'],Limit=100,ConsistentRead=True)#,
                                                                     #FilterExpression=Attr("Risklevel").eq('danger'))
        for acc_item in flagged_accounts['Items']:
            if acc_item not in  account_numbers:
                account_numbers.append(acc_item)
        if 'LastEvaluatedKey' in flagged_accounts:
            NextToken=flagged_accounts['LastEvaluatedKey']
        else:
            done = True                                                       
    for item in account_numbers:
        msg=''
        print("Searching for-", item['Accountid'])
        iam_findings_table_scan = iam_findings_table.query(KeyConditionExpression=Key('Accountid').eq(item['Accountid']),FilterExpression=Attr("Risklevel").eq('danger'))
        print(iam_findings_table_scan)
        for findg in iam_findings_table_scan['Items']:
            timeed_date = timeconvertertoCST(findg['Foundeddate'])
            msg+='RuleName:  {} \n '.format(str(findg['Rulename']))
            msg+='\nDescription:  {} \n '.format(str(findg["Description"]))
            msg+='\nRationale:  {} \n '.format(str(findg["Rationale"]))
            #msg+='\nReportedon: {}\n'.format(str(timeed_date+'-CST'))
            msg +='\nFlagged_Items:  {} \n'.format(str(findg["Flaggeditemslist"]))
            msg += '\n------------------------------------------------------------------\n'
        if msg:
            print(str("AWS_IAM Findings:"+item['Accountid']+":"+item['Aliasname']))
            print(msg)
            publish_msg_cloud_team("AWS_IAM Findings:"+item['Accountid']+":"+item['Aliasname']+":_Dated-("+str(timeed_date+'-CST')+")" , msg) 
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
def timeconvertertoCST(srctime):
    totimezone = 'US/Central'
    utc_time1=datetime.strptime(srctime, '%Y-%m-%dT%H:%M:%SZ')
    from_zone = tz.gettz('UTC')
    to_zone = tz.gettz('US/Central')
    utc = utc_time1.replace(tzinfo=from_zone)
    tocentral = utc.astimezone(to_zone).strftime("%m-%d-%Y %I:%M:%S %p")
    return tocentral
   
   
   
   
   
   
  
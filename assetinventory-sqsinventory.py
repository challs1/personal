"""
Author          :   Sairaja Challagulla(Challagulla_Sairaja@cat.com)
Description     :   This Lambda Function will get an inventory of all SQS queues and put into a Dynamo DB
Regions         :   All Regions
Version         :   1.2(Stable)
Caterpillar: Confidential Yellow
"""
import boto3
import json
from dateutil import tz
import datetime
from datetime import tzinfo, timedelta, datetime

def lambda_handler(event, context):

    sts_client = boto3.client('sts')
    sts_response = sts_client.assume_role(RoleArn='arn:aws:iam::620890749476:role/Assetsinventory_Trusted_DynamoDB',
                                          RoleSessionName='AssumeMyRole', DurationSeconds=900)
    dynamodb_resource = boto3.resource(service_name='dynamodb', region_name='us-east-1',
                                  aws_access_key_id = sts_response['Credentials']['AccessKeyId'],
                                  aws_secret_access_key = sts_response['Credentials']['SecretAccessKey'],
                                  aws_session_token = sts_response['Credentials']['SessionToken'])
    sqs_table = dynamodb_resource.Table('sqsinventory')

    def timeconverter(srctime) :
        totimezone = 'US/Central'
        curtime = srctime.strftime('%Y-%m-%d %H:%M:%S')
        from_zone = tz.tzutc()
        to_zone = tz.gettz(totimezone)
        utc = datetime.strptime(curtime, '%Y-%m-%d %H:%M:%S')
        utc = utc.replace(tzinfo=from_zone)
        # Convert time zone
        tocentral = utc.astimezone(to_zone).strftime('%Y-%m-%d %H:%M:%S')
        return tocentral

    def updateDynamoDB(SQSName,SQSCount):
        sqs_table.update_item(Key={
                                        'SQSName': SQSName,
                                        'SQSCount' : SQSCount
                                    },
                                    UpdateExpression="set QueueStatus = :r",
                                    ExpressionAttributeValues={
                                        ':r' : 'Deleted'
                                    })
        print("Updated DynamoDB")

    def SQSStatus(SQSName,region,SQSCount):
        sqs_client = boto3.client('sqs', region_name=region)
        response = sqs_client.list_queues(QueueNamePrefix=SQSName)
        try:
            QueueUrl = response['QueueUrls'][0]
            print(SQSName+" Queue is Active")
        except Exception as e:
            print(SQSName+" Queue is Deleted")
            print("Updating DynamoDB ...")
            updateDynamoDB(SQSName,SQSCount)

    def searchSQS():
        account_id_self = boto3.client("sts").get_caller_identity()["Account"]
        for singleSQS in sqs_table.scan()['Items']:
            if singleSQS['SQSCount'].startswith(account_id_self) and singleSQS['QueueStatus'] != 'Deleted':
                region = singleSQS['SQSArn'].split(':')[3]
                SQSName = singleSQS['SQSName']
                SQSCount = singleSQS['SQSCount']
                SQSStatus(SQSName,region,SQSCount)
            else:
                pass

    def putintable(SQSName,SQSCount,ApxNoOfMsgs,ApxNoOfMsgsNV,ApxNoOfMsgsDlyd,CreatedDate,LastModifiedDate,VisibilityTimeout,
    MaxMsgSize,MsgRetention,DelaySeconds,RcvMsgWaitTime,FifoQueue,SQSQueType,ContentBasedDeduplication,QueueArn,SQSUrl,Policy):

        sqs_table.put_item (
                Item={
                        'SQSName': SQSName, #Primary Key
                        'SQSCount' : SQSCount, #Sort Key
                        'SQSQueType' : SQSQueType,
                        'ApxNoOfMsgs' : ApxNoOfMsgs,
                        'ApxNoOfMsgsNV' : ApxNoOfMsgsNV,
                        'ApxNoOfMsgsDlyd' : ApxNoOfMsgsDlyd,
                        'CreatedDate' : CreatedDate,
                        'LastModifiedDate' : LastModifiedDate,
                        'VisibilityTimeout' : VisibilityTimeout,
                        'MaxMsgSize(KB)' : MaxMsgSize,
                        'MsgRetention' : MsgRetention,
                        'DelaySeconds' : DelaySeconds,
                        'RcvMsgWaitTime' : RcvMsgWaitTime,
                        'FifoQueue' : FifoQueue,
                        'ContentBasedDeduplication' : ContentBasedDeduplication,
                        'SQSArn' : QueueArn,
                        'SQSUrl' : SQSUrl,
                        'QueueStatus' : 'Active',
                        'Policy' : Policy
                    }
                )

        print("Success")

    def getSQSlist(sqs_client):
        sqs_response = sqs_client.list_queues()
        return sqs_response

    print("Checking for deleted SQS Queues...")
    try:
        searchSQS()
    except Exception as e:
        # print(e)
        pass

    print("Checking SQS Queues for all regions...")
    regions = [region['RegionName'] for region in boto3.client('ec2').describe_regions()['Regions']]
    for region in regions:
        sqs_client = boto3.client('sqs', region_name=region)
        print("SQS Inventory started for "+region+" region")
        sqs_response = getSQSlist(sqs_client)
        try:
            for queURL in range(len(sqs_response['QueueUrls'])):
                SQSUrl = sqs_response['QueueUrls'][queURL]
                response = sqs_client.get_queue_attributes(QueueUrl=SQSUrl, AttributeNames=['All'])
                QueueArn = response['Attributes']['QueueArn']
                account_id = boto3.client("sts").get_caller_identity()["Account"]
                CreatedTimestamp = response['Attributes']['CreatedTimestamp']
                LastModifiedTimestamp = response['Attributes']['LastModifiedTimestamp']

                SQSName = QueueArn.split(':')[5]
                SQSCount = (account_id+"-"+region+"-"+SQSName+"-"+CreatedTimestamp)
                ApxNoOfMsgs = int(response['Attributes']['ApproximateNumberOfMessages'])
                ApxNoOfMsgsNV = int(response['Attributes']['ApproximateNumberOfMessagesNotVisible'])
                ApxNoOfMsgsDlyd = int(response['Attributes']['ApproximateNumberOfMessagesDelayed'])
                CreatedDate = timeconverter(datetime.utcfromtimestamp(int(CreatedTimestamp))) + ' CST'
                LastModifiedDate = timeconverter(datetime.utcfromtimestamp(int(LastModifiedTimestamp))) + ' CST'
                VisibilityTimeout = int(response['Attributes']['VisibilityTimeout'])
                MaxMsgSize = int(int(response['Attributes']['MaximumMessageSize'])/1024)
                MsgRetention = int(response['Attributes']['MessageRetentionPeriod'])
                DelaySeconds = int(response['Attributes']['DelaySeconds'])
                RcvMsgWaitTime = int(response['Attributes']['ReceiveMessageWaitTimeSeconds'])
                try:
                    Policy = response['Attributes']['Policy']
                    Policy = json.loads(Policy)
                except Exception as e:
                    Policy = "N/A"
                try:
                    FifoQueue = response['Attributes']['FifoQueue']
                    SQSQueType = "FIFO"
                except Exception as e:
                    SQSQueType = "Standard"
                    FifoQueue = 'false'
                try:
                    ContentBasedDeduplication = response['Attributes']['ContentBasedDeduplication']
                except Exception as e:
                    ContentBasedDeduplication = 'N/A'

                putintable(SQSName,SQSCount,ApxNoOfMsgs,ApxNoOfMsgsNV,ApxNoOfMsgsDlyd,CreatedDate,LastModifiedDate,VisibilityTimeout,
                MaxMsgSize,MsgRetention,DelaySeconds,RcvMsgWaitTime,FifoQueue,SQSQueType,ContentBasedDeduplication,QueueArn,SQSUrl,Policy)
        except Exception as e:
            # print(e)
            print("There are no SQS Queues in "+region)

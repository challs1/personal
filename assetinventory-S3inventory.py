####################################################################################
#AUTHOR          : Sairaja Challagulla
#DESCRIPTION     : THIS FUNCTION GETS S3 INVENTORY AND PUTS IN DYNAMODB TABLE.
#REGIONS         : ALL REGIONS
#EMAIL           : Challagulla_Sairaja@cat.com
####################################################################################
#prerequisites
#need dynamodb tables
#ec2inventory with InstanceId as primary key and OwnerId as sort key
#s3inventory with BucketName as primary keykey

import boto3
import traceback
import itertools
from datetime import datetime
from dateutil import tz
from boto3.dynamodb.conditions import Attr

def lambda_handler(event, context):
		#############################################################

                            #S3BUCKET INVENTORY

        #############################################################
        def s3inven() :
            bucketlist = []
            bucketcountlist = []
            try :

                sts_response = sts_client.get_caller_identity()
                BOwnerId = sts_response['Account']

                s3_client = boto3.client('s3')
                s3_list_response = s3_client.list_buckets()

                s3_table = dynamodb_resource.Table('s3inventory')
                print('-----------------------------------------------')
                print('S3 Bucket Inventory Started')
                #print(s3_list_response['Owner']['DisplayName'])
                for bucket in s3_list_response['Buckets']:
                    bucketlist.append(bucket['Name'])
                    print(' ')
                    print(bucket['CreationDate'])
                    creationdate = timeconverter(bucket['CreationDate']) + ' CST'

                    #printing bucket name
                    print(bucket['Name'])


                    try :

                            s3_acl_response = s3_client.get_bucket_acl(Bucket= bucket['Name'])
                            for grant in s3_acl_response['Grants'] :
                                bucketaccess = grant['Permission']
                                #buri = grant['Grantee']['URI']

                            try:
                                s3_tag_response = s3_client.get_bucket_tagging(Bucket = bucket['Name'])
                                for tag in s3_tag_response['TagSet'] :
                                    if tag['Value'] :
                                        tagdict[tag['Key']] = tag['Value']
                                    else :
                                        tagdict[tag['Key']] = 'null'
                            except Exception :
                                print('No Tags')

                            try:
                                s3_version_response = s3_client.get_bucket_versioning(Bucket = bucket['Name'])
                                s3_version = s3_version_response['Status']
                            except Exception :
                                s3_version = 'Suspended'
                                print('Versions Suspended')
                            s3_location_response = s3_client.get_bucket_location(Bucket = bucket['Name'])

                            if s3_location_response['LocationConstraint'] :
                                s3_locat = s3_location_response['LocationConstraint']
                            else :
                                s3_locat = 'us-east-1' #s3_location_response['LocationConstraint']
                    except Exception as e:
                        print('Access Denied')
                        tagdict['Access Denied'] = 'Access Denied'
                        s3_locat = 'Access Denied'
                        s3_version = 'Access Denied'
                        bucketaccess = 'Access Denied'
                        #buri = 'Access Denied'
                    bucketcount = sts_response['Account'] + ' - ' + creationdate
                    bucketcountlist.append(bucketcount)
                    s3_table.put_item ( #inserting items into table
                                                        Item={
                                                            'BucketName': bucket['Name'], #primary key
															'BucketCount' : bucketcount,
                                                            'CreatonDate' : creationdate,
                                                            'OwnerId' : sts_client_account,
                                                            'OwnerAlias' : account_alias,
                                                            #'OwnerName' : s3_list_response['Owner']['DisplayName'], #grants['Grantee']['DisplayName'],
                                                            'CanonicalId' : s3_list_response['Owner']['ID'],
                                                            'Tags': tagdict,
                                                            'Versioning' : s3_version,
                                                            'ACLS' : bucketaccess,
                                                            'Region' : s3_locat,
                                                            'LastExecutedTime' : todaysdatetime,
                                                            'BState' : 'Active',
                                                            #'BURI' : buri,

                                                        }
                                                    )
                    cleardict(tagdict)
                if not bucketlist :
                    bucketlist.append('emptylist')
                searchdeletedbucket(bucketlist,bucketcountlist,s3_table,sts_client_account)
            except Exception as e:
                print(traceback.format_exc())
        #############################################################

                          #SEARCHING FOR DELETED BUCKET

        #############################################################
        def searchdeletedbucket(bucketlist,bucketcountlist,s3_table,bownerid) :
            try :
                s3_table_scan = s3_table.scan(FilterExpression=Attr('OwnerId').eq(bownerid) & Attr('BState').ne('Deleted'))
                s3_table_scan_ext = s3_table_scan['Items']
                print(len(s3_table_scan['Items']))
                while s3_table_scan.get('LastEvaluatedKey'):
                        s3_table_scan = s3_table.scan(ExclusiveStartKey=s3_table_scan['LastEvaluatedKey'],FilterExpression=Attr('OwnerId').eq(bownerid) & Attr('BState').ne('Deleted'))
                        print('-------extension---------')
                        print(len(s3_table_scan['Items']))
                        s3_table_scan_ext += s3_table_scan['Items']
                        print(len(s3_table_scan_ext))
                print('---------------------------------------')

                print('Looking for Deleted Bucket')

                for items in s3_table_scan_ext :

                    #print(items['OwnerId'])

                    if items['BState'] != 'Deleted' :
                        for bucket in bucketlist :
                            if items['BucketName'] == bucket:
                                matid = 'matched'
                                break
                            else :
                                matid = 'not matched'
                        if matid == 'matched' :
                            for bucketcount in bucketcountlist :
                                if items['BucketCount'] == bucketcount:
                                    matid = 'matched'
                                    break
                                else :
                                    matid = 'not matched'

                        if matid == 'not matched' : #and ownerid == items['OwnerId']:
                            print("Found Deleted Bucket")
                            print(items['BucketName'])
                            print('================================')
                            response = s3_table.update_item(
                                       Key={
                                            'BucketName':items['BucketName'],
                                            'BucketCount' : items['BucketCount']
                                        },
                                        UpdateExpression="set BState= :r, DeletedTime= :d",
                                        ExpressionAttributeValues={
                                            ':r' : 'Deleted',
                                            ':d' : todaysdatetime
                                        },
                                        ReturnValues="UPDATED_NEW"
                            )

            except Exception as e:
                print(traceback.format_exc())

        def timeconverter(srctime) :
            totimezone = 'US/Central'
            curtime = srctime.strftime("%m-%d-%Y %I:%M:%S %p")

            from_zone = tz.tzutc()
            to_zone = tz.gettz(totimezone)
            utc = datetime.strptime(curtime, '%m-%d-%Y %I:%M:%S %p')
            utc = utc.replace(tzinfo=from_zone)
            # Convert time zone
            tocentral = utc.astimezone(to_zone).strftime("%m-%d-%Y %I:%M:%S %p")

            return tocentral


        #############################################################

                            #MAIN FUNCTION

        #############################################################

        try :

            tagdict = {} #temproary dict to store tags for each iteration
            region_list = ['us-east-1','us-east-2', 'us-west-1', 'us-west-2']

            def clearlist(tlis): #clearing list
                    tlis[:] = []
            def cleardict(tdict): #clearing dictonary
                    tdict.clear()

            iam_client = boto3.client('iam')
            iam_response = iam_client.list_account_aliases()
            if iam_response.get('AccountAliases') :
                account_alias = iam_response['AccountAliases'][0]
            else :
                account_alias = 'No Alias'

            sts_client_account = boto3.client('sts').get_caller_identity()['Account']

            sts_client = boto3.client('sts')
            assumedRoleObject = sts_client.assume_role(
            RoleArn="arn:aws:iam::620890749476:role/Assetsinventory_Trusted_DynamoDB",
            RoleSessionName="assumerole2"
            )
            credentials = assumedRoleObject['Credentials']
            dynamodb_resource = boto3.resource('dynamodb', region_name = 'us-east-1', aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])

            todaysdatetime = str(timeconverter(datetime.now())) + ' CST'


            s3inven()


        except Exception as e:
            print(traceback.format_exc())

        return "Success"

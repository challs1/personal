#################################################################
#AUTHOR          : Sairaja Challagulla
#REGIONS         : ALL REGIONS
#EMAIL           : Challagulla_Sairaja@cat.com
#################################################################
import boto3
import traceback
from datetime import datetime
from dateutil import tz
from boto3.dynamodb.conditions import Attr

###########################################################
                #MAIN FUNCTION
###########################################################

def lambda_handler(event, context):

    try :
        ###########################################################
                #GET CodePipeline INVENTORY AND PUT IN DYNAMODB
        ###########################################################
        def codepipelineinventory():
            codepipelinelist = []
            codepipelinecountlist = []
            codepipelinestagelist = []
            dynamodb_table = dynamodb_resource.Table('codepipelineinventory')
            sts_client_account = boto3.client('sts').get_caller_identity()['Account']
            ec2_region = boto3.client('ec2').describe_regions()['Regions']
            for region in ec2_region:
                print(region['RegionName'])
                print('==================================================')
                if not region['RegionName'] == 'eu-west-3' :
                    codepipeline_client = boto3.client('codepipeline', region_name = region['RegionName'])
                    codepipeline_response = codepipeline_client.list_pipelines()
                    print(codepipeline_response)
                    for coderes in codepipeline_response['pipelines'] :
                        codepipelinelist.append(coderes['name'])
                        updateddatetime = timeconverter(coderes['updated']) + ' CST'
                        creationdatetime = timeconverter(coderes['created']) + ' CST'
                        codepipeline_count = sts_client_account+ ' - '+region['RegionName']+ ' - '+creationdatetime
                        codepipelinecountlist.append(codepipeline_count)
                        codepipeline_get_response = codepipeline_client.get_pipeline(name=coderes['name'])['pipeline']
                        print(codepipeline_get_response)
                        for codestage in codepipeline_get_response['stages']:
                            print(codestage['name'])
                            #codepipelinestagelist.append(codestage['name'])
                            for codeaction in codestage['actions'] :

                                print(codeaction['actionTypeId']['category'])
                                print(codeaction['actionTypeId']['owner'])
                                print(codeaction['actionTypeId']['provider'])
                                if codeaction['actionTypeId']['category'] == "Source":
                                    if codeaction['actionTypeId']['provider'] == "S3":
                                        codeactiontype = codestage['name']+ ' - '+codeaction['actionTypeId']['category']+ ' - '+codeaction['actionTypeId']['owner']+ ' - '+codeaction['actionTypeId']['provider']+ ' - '+codeaction['configuration']['S3ObjectKey']
                                        codepipelinestagelist.append(codeactiontype)
                                    else:
                                        codeactiontype = codestage['name']+ ' - '+codeaction['actionTypeId']['category']+ ' - '+codeaction['actionTypeId']['owner']+ ' - '+codeaction['actionTypeId']['provider']
                                        codepipelinestagelist.append(codeactiontype)
                                if codeaction['actionTypeId']['category'] == "Deploy":
                                    if codeaction['actionTypeId']['provider'] == "CloudFormation":
                                        codeactiontype = codestage['name']+ ' - '+codeaction['actionTypeId']['category']+ ' - '+codeaction['actionTypeId']['owner']+ ' - '+codeaction['actionTypeId']['provider']+ ' - '+codeaction['configuration']['StackName']
                                        codepipelinestagelist.append(codeactiontype)
                                    else:
                                        codeactiontype = codestage['name']+ ' - '+codeaction['actionTypeId']['category']+ ' - '+codeaction['actionTypeId']['owner']+ ' - '+codeaction['actionTypeId']['provider']
                                        codepipelinestagelist.append(codeactiontype)



                        dynamodb_table.put_item (
                                Item={
                                    'PipelineName': coderes['name'],
                                    'PipelineCount' : codepipeline_count,
                                    'OwnerId' : sts_client_account,
                                    'OwnerAlias' : account_alias,
                                    'Region' : region['RegionName'],
                                    'PipelineStatus' : 'Active',
                                    'CreationDate' : creationdatetime,
                                    'UpdatedDate' : updateddatetime,
                                    'LastExecutedTime' : todaysdatetime,
                                    'Stages' : codepipelinestagelist,
                                })
                        clearlist(codepipelinestagelist)
            if not codepipelinelist :
                codepipelinelist.append('emptylist')
            searchdeletedpipeline(codepipelinelist,codepipelinecountlist,dynamodb_table,sts_client_account)

        ###########################################################
                #SEARCH FOR DELETED LAMBDA
        ###########################################################
        def searchdeletedpipeline(reslist,rescountlist,res_table,sts_client_account) :
                print(reslist)
                print(rescountlist)
                res_table_scan = res_table.scan(FilterExpression=Attr('OwnerId').eq(sts_client_account) & Attr('PipelineStatus').ne('Deleted'))
                print(len(res_table_scan['Items']))
                res_table_scan_ext = res_table_scan['Items']

                while res_table_scan.get('LastEvaluatedKey'):
                    res_table_scan = res_table.scan(ExclusiveStartKey=res_table_scan['LastEvaluatedKey'],FilterExpression=Attr('OwnerId').eq(sts_client_account) & Attr('PipelineStatus').ne('Deleted'))
                    print('-------extension---------')
                    print(len(res_table_scan['Items']))
                    res_table_scan_ext += res_table_scan['Items']
                    print(len(res_table_scan_ext))
                print('---------------------------------------')
                print('Looking for Deleted Pipeline')
                for items in res_table_scan_ext :

                    if items['PipelineStatus'] != 'Deleted' :
                        for res in reslist :
                            print(res)
                            if items['PipelineName'] == res:
                                matid = 'matched'
                                break
                            else :
                                matid = 'not matched'
                        if matid == 'matched' :
                            for rescount in rescountlist :
                                print(rescount)
                                if items['PipelineCount'] == rescount:
                                    matid = 'matched'
                                    break
                                else :
                                    matid = 'not matched'
                        if matid == 'not matched' : #and ownerid == items['OwnerId']:
                            print("Found Deleted Pipeline")
                            print(items['PipelineName'])
                            print('================================')
                            response = res_table.update_item(
                                       Key={
                                            'PipelineName':items['PipelineName'],
                                            'PipelineCount' : items['PipelineCount']
                                        },
                                        UpdateExpression="set PipelineStatus= :r, DeletedTime= :d",
                                        ExpressionAttributeValues={
                                            ':r' : 'Deleted',
                                            ':d' : todaysdatetime
                                        },
                                        ReturnValues="UPDATED_NEW"
                            )


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
        def cleardict(tdict):
            tdict.clear()
        def clearlist(tlis): #clearing list
            tlis[:] = []



    ###########################################################
                #CodePipeline starts here
    ###########################################################
        todaysdatetime = timeconverter(datetime.now()) + ' CST'
        tagdict = {}
        iam_client = boto3.client('iam')
        iam_response = iam_client.list_account_aliases()
        if iam_response.get('AccountAliases') :
            account_alias = iam_response['AccountAliases'][0]
        else :
            account_alias = 'No Alias'

        sts_client = boto3.client('sts')
        assumedRoleObject = sts_client.assume_role(
        RoleArn="arn:aws:iam::620890749476:role/Assetsinventory_Trusted_DynamoDB",
        RoleSessionName="assumerole2"
        )
        credentials = assumedRoleObject['Credentials']
        dynamodb_resource = boto3.resource('dynamodb', region_name = 'us-east-1', aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])

        codepipelineinventory()
        return 'success'
    except Exception :
        print(traceback.format_exc())
        return 'failed'

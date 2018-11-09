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
                #GET LAMBDA INVENTORY AND PUT IN DYNAMODB
        ###########################################################
        def lambdainventory() :
            lambda_id  = []
            lambdacountlist = []
            lambda_table = dynamodb_resource.Table('lambdainventory')
            sts_client_account = boto3.client('sts').get_caller_identity()['Account']
            ec2_region = boto3.client('ec2').describe_regions()['Regions']
            for region in ec2_region:
                print(region['RegionName'])
                print('==================================================')
                lambda_client = boto3.client('lambda', region_name = region['RegionName'])
                lambda_response =lambda_client.list_functions()['Functions']
                for lambdares in lambda_response :
                    #lastmodified  = timeconverter(lambdares['LastModified']) + ' CST'
                    lambdacount = sts_client_account + ' - ' + region['RegionName'] #+ ' - ' + lambdares['CodeSha256']
                    lambda_id.append(lambdares['FunctionName'])
                    lambdacountlist.append(lambdacount)
                    print(lambdares['FunctionName'])
                    lambda_tags = lambda_client.list_tags(Resource=lambdares['FunctionArn'])
                    if lambda_tags.get('Tags') :
                        tag1 = lambda_tags['Tags']
                        for tag in tag1: #tag iteration
                            if tag1[tag] :
                                tagdict[tag] = tag1[tag] #storing tags in dictonary 
                            else :
                                tagdict[tag] = 'null'
                    else :
                        print('No Tags')
                    print('-------------------------------------')
                    
                    
                    
                    lambda_table.put_item(
                        Item ={
                        'LambdaName' : lambdares['FunctionName'],
                        'LambdaCount' : lambdacount,
                        'OwnerId' : sts_client_account,
                        'OwnerAlias' : account_alias,
                        'Region' : region['RegionName'],
                        'Role' : lambdares['Role'],
                        'Timeout' :lambdares['Timeout'],
                        'Runtime' : lambdares['Runtime'],
                        'LastExecutedTime' :todaysdatetime,
                        'LambdaStatus' : 'Active',
                        'Tags' : tagdict,
                        
                    })  
                    cleardict(tagdict)
            if not lambda_id :
                lambda_id.append('emptylist')
            searchdeletedlambda(lambda_id,lambdacountlist,lambda_table,sts_client_account)    
        ###########################################################
                #SEARCH FOR DELETED LAMBDA
        ###########################################################
        def searchdeletedlambda(lambda_id,lambdacountlist,lambda_table,sts_client_account) :
                lambda_table_scan = lambda_table.scan(FilterExpression=Attr('OwnerId').eq(sts_client_account) & Attr('LambdaStatus').ne('Deleted'))
                print(len(lambda_table_scan['Items']))
                lambda_table_scan_ext = lambda_table_scan['Items']
                
                while lambda_table_scan.get('LastEvaluatedKey'):
                    lambda_table_scan = lambda_table.scan(ExclusiveStartKey=lambda_table_scan['LastEvaluatedKey'],FilterExpression=Attr('OwnerId').eq(sts_client_account) & Attr('LambdaStatus').ne('Deleted'))
                    print('-------extension---------')
                    print(len(lambda_table_scan['Items']))
                    lambda_table_scan_ext += lambda_table_scan['Items']
                    print(len(lambda_table_scan_ext))
                print('---------------------------------------')
                print("Looking for Deleted Lambda")
                for items in lambda_table_scan_ext :
                    
                    if items['LambdaStatus'] != 'Deleted' :
                        for lid in lambda_id :
                            if items['LambdaName'] == lid:
                                matid = 'matched'
                                break
                            else :
                                matid = 'not matched'
                        if matid == 'matched' :
                            for lcount in lambdacountlist :
                                if items['LambdaCount'] == lcount:
                                    matid = 'matched'
                                    break
                                else :
                                    matid = 'not matched'
                        if matid == 'not matched' : #and ownerid == items['OwnerId']:
                            print("Found Deleted Lambda")
                            print(items['LambdaName'])
                            print('================================')
                            response = lambda_table.update_item(
                                       Key={
                                            'LambdaName':items['LambdaName'],
                                            'LambdaCount' : items['LambdaCount']
                                        },
                                        UpdateExpression="set LambdaStatus= :r, DeletedTime= :d",
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
            
        def clearlist(tlist) :
            tlist[:] = []
        def cleardict(tdict): 
            tdict.clear()
        ###########################################################
                #LAMBDA 
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
        
        lambdainventory()
        return 'success'
    except Exception :
        print(traceback.format_exc())
        return 'failed'
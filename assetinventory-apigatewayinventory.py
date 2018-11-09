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
                #GET APIGateway INVENTORY AND PUT IN DYNAMODB
        ###########################################################
        def apigatewayinventory() :
            resource_id  = []
            resourcecountlist = []
            tagstagelist = []
            tagdict = {}
            
            resource_table = dynamodb_resource.Table('apigatewayinventory')
            sts_client_account = boto3.client('sts').get_caller_identity()['Account']
            ec2_region = boto3.client('ec2').describe_regions()['Regions']
            for region in ec2_region:
                print(region['RegionName'])
                print('==================================================')
                
                apigateway_client = boto3.client('apigateway', region_name=region['RegionName'])
                apigateway_list_response = apigateway_client.get_rest_apis(limit=500)
                print(apigateway_list_response['items'])
                for apigatewaylist in apigateway_list_response['items']:
                    
                    print(apigatewaylist['name'])
                    
                    creationdate  = timeconverter(apigatewaylist['createdDate']) + ' CST'
                    apigatewaycount = sts_client_account + ' - ' + region['RegionName']+' - '+apigatewaylist['id']+' - ' + creationdate
                    
                    resource_id.append(apigatewaylist['name'])
                    resourcecountlist.append(apigatewaycount)
                    
                    for entype in apigatewaylist['endpointConfiguration']['types']:
                        apiendpoint = entype
                    
                    apigateway_resource_res = apigateway_client.get_resources(restApiId= apigatewaylist['id'],embed=['methods'])
                    print('---------------- Resources --------------------')
                    print(apigateway_resource_res['items'])
                    
                    apigateway_stages_res = apigateway_client.get_stages(restApiId=apigatewaylist['id'])
                    print('---------------- Stages --------------------')
                    print(apigateway_stages_res['item'])
                    for aitem in apigateway_stages_res['item']:
                        print(aitem['stageName'])
                        if aitem.get('tags'):
                            tagstagelist.append(aitem['tags'])
                    
                    apigateway_auth_res = apigateway_client.get_authorizers(restApiId=apigatewaylist['id'])
                    print('---------------- Authorizers --------------------')
                    print(apigateway_auth_res['items'])
                    
                    resource_table.put_item(
                        Item ={
                        'APIName' : apigatewaylist['name'],
                        'APICount' : apigatewaycount,
                        'APIGatewayStatus' : 'Active',
                        #'APIResources' : apigateway_resource_res['items'],
                        #'APIStages': apigateway_stages_res['item'],
                        #'APIAuth' : apigateway_auth_res['items'],
                        'Endpointconfigurations': apiendpoint,
                        'APICreationDate' : creationdate,
                        'OwnerId' : sts_client_account,
                        'OwnerAlias' : account_alias,
                        'Region' : region['RegionName'],
                        'LastExecutedTime' : todaysdatetime,
                        'Tags' : tagstagelist,
                        
                    })  
                    clearlist(tagstagelist)
                    #cleardict(tagdict)
                    
                    
            if not resource_id :
                resource_id.append('emptylist')
            searchdeletedapigateway(resource_id,resourcecountlist,resource_table,sts_client_account)    
        ###########################################################
                #SEARCH FOR DELETED EMR
        ###########################################################
        
        def searchdeletedapigateway(reslist,rescountlist,res_table,sts_client_account) :
                print(reslist)
                print(rescountlist)
                res_table_scan = res_table.scan(FilterExpression=Attr('OwnerId').eq(sts_client_account) & Attr('APIGatewayStatus').ne('Deleted'))
                print(len(res_table_scan['Items']))
                res_table_scan_ext = res_table_scan['Items']

                while res_table_scan.get('LastEvaluatedKey'):
                    res_table_scan = res_table.scan(ExclusiveStartKey=res_table_scan['LastEvaluatedKey'],FilterExpression=Attr('OwnerId').eq(sts_client_account) & Attr('APIGatewayStatus').ne('Deleted'))
                    print('-------extension---------')
                    print(len(res_table_scan['Items']))
                    res_table_scan_ext += res_table_scan['Items']
                    print(len(res_table_scan_ext))
                print('---------------------------------------')
                print('Looking for Deleted ApiGateway')
                for items in res_table_scan_ext :

                    if items['APIGatewayStatus'] != 'Deleted' :
                        for res in reslist :
                            print(res)
                            if items['APIName'] == res:
                                matid = 'matched'
                                break
                            else :
                                matid = 'not matched'
                        if matid == 'matched' :
                            for rescount in rescountlist :
                                print(rescount)
                                if items['APICount'] == rescount:
                                    matid = 'matched'
                                    break
                                else :
                                    matid = 'not matched'
                        if matid == 'not matched' : #and ownerid == items['OwnerId']:
                            print("Found Deleted ApiGateway")
                            print(items['APIName'])
                            print('================================')
                            response = res_table.update_item(
                                       Key={
                                            'APIName':items['APIName'],
                                            'APICount' : items['APICount']
                                        },
                                        UpdateExpression="set APIGatewayStatus= :r, DeletedTime= :d",
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
        
        apigatewayinventory()
        return 'success'
    except Exception :
        print(traceback.format_exc())
        return 'failed'
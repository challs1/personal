#################################################################
#AUTHOR          : Sairaja Challagulla
#REGIONS         : ALL REGIONS
#EMAIL           : Challagulla_Sairaja@cat.com
#################################################################
import boto3
import json
import traceback
from datetime import datetime
from dateutil import tz
from boto3.dynamodb.conditions import Attr

###########################################################
                #MAIN FUNCTION
###########################################################

waf_id = []
wafcountlist = []
SNSTopicARN = "arn:aws:sns:us-east-1:620890749476:wafnotification"
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'eu-west-1','eu-central-1','ap-southeast-2', 'ap-northeast-1']

def waftable(waf_client, account,account_alias, region, waf_table,sns_client, waftype, todaysdatetime):
    print(waf_id)
    waflistaclsres = waf_client.list_web_acls()
    waflistacls = waflistaclsres['WebACLs']
    while waflistaclsres.get('NextMarker'):
        waflistaclsres = waf_client.list_web_acls(NextMarker=waflistaclsres['NextMarker'])
        waflistacls += waflistaclsres['WebACLs']
    print(waflistacls)
    for waflist in waflistacls :
        #creationdate  = timeconverter(rdsres['InstanceCreateTime']) + ' CST'
        wafcount = account + ' - ' + region
        waf_id.append(waflist['WebACLId'])
        wafcountlist.append(wafcount)
        wafgetitem = waf_table.get_item(Key ={'WAFId' : waflist['WebACLId'],'WAFCount' : wafcount})
        #print(wafgetitem)
        if wafgetitem['ResponseMetadata']['HTTPStatusCode'] == 200:
            if wafgetitem.get('Item') :
                print("WAF Already Exists")
            else:
                if waftype == "GlobalWAF":
                    sns_client.publish(TopicArn=SNSTopicARN,Subject="WAF Added",Message=json.dumps({'default':'Something went wrong','email':waftype+' '+waflist['Name']+' with id '+waflist['WebACLId']+' is added in '+account_alias+'('+account+') account.'}), MessageStructure='json')
                else:
                    sns_client.publish(TopicArn=SNSTopicARN,Subject="WAF Added",Message=json.dumps({'default':'Something went wrong','email':waftype+' '+waflist['Name']+' with id '+waflist['WebACLId']+' is added in '+account_alias+'('+account+') account in '+region+' region.'}), MessageStructure='json')
                waf_table.put_item(
                        Item ={
                       'WAFId' : waflist['WebACLId'],
                       'WAFCount' : wafcount,
                       'WAFName' : waflist['Name'],
                       'WAFType' : waftype,
                       'OwnerId' : account,
                       'OwnerAlias' : account_alias,
                       'Region' : region,
                       'LastExecutedTime' : todaysdatetime,
                       'WAFStatus' : 'Active',
                   })  

def lambda_handler(event, context):
    try :
        ###########################################################
                #GET WAF INVENTORY AND PUT IN DYNAMODB
        ###########################################################
        def wafinventory() :
            
            count = 0
            waf_table = dynamodb_resource.Table('wafinventory')
            sts_client_account = boto3.client('sts').get_caller_identity()['Account']
            ec2_region = boto3.client('ec2').describe_regions()['Regions']
            #WAF is not available in all regions
            for region in regions:
                print(region)
                print('==================================================')
                if count == 0:
                    waf_client = boto3.client('waf')
                    waftable(waf_client, sts_client_account,account_alias, region, waf_table, sns_client, 'GlobalWAF', todaysdatetime)
                    count=count+1
                    
                wafregional_client = boto3.client('waf-regional', region_name = region)
                waftable(wafregional_client, sts_client_account, account_alias, region, waf_table, sns_client, 'RegionalWAF', todaysdatetime)
            #print(waf_id)
            if not waf_id :
                waf_id.append('emptylist')
            searchdeletedwaf(waf_id,wafcountlist,waf_table,sts_client_account)
            clearlist(waf_id)
            clearlist(wafcountlist)
        ###########################################################
                #SEARCH FOR DELETED WAF
        ###########################################################
        def searchdeletedwaf(reslist,rescountlist,res_table,sts_client_account) :
                print(reslist)
                print(rescountlist)
                res_table_scan = res_table.scan(FilterExpression=Attr('OwnerId').eq(sts_client_account) & Attr('WAFStatus').ne('Deleted'))
                print(len(res_table_scan['Items']))
                res_table_scan_ext = res_table_scan['Items']
                
                while res_table_scan.get('LastEvaluatedKey'):
                    res_table_scan = res_table.scan(ExclusiveStartKey=res_table_scan['LastEvaluatedKey'],FilterExpression=Attr('OwnerId').eq(sts_client_account) & Attr('WAFStatus').ne('Deleted'))
                    print('-------extension---------')
                    print(len(res_table_scan['Items']))
                    res_table_scan_ext += res_table_scan['Items']
                    print(len(res_table_scan_ext))
                print('---------------------------------------')
                print('Looking for Deleted WAF')
                for items in res_table_scan_ext :
                    
                    if items['WAFStatus'] != 'Deleted' :
                        for res in reslist :
                            #print(res)
                            if items['WAFId'] == res:
                                matid = 'matched'
                                break
                            else :
                                matid = 'not matched'
                        if matid == 'matched' :
                            for rescount in rescountlist :
                                #print(rescount)
                                if items['WAFCount'] == rescount:
                                    matid = 'matched'
                                    break
                                else :
                                    matid = 'not matched'
                        if matid == 'not matched' : #and ownerid == items['OwnerId']:
                            print("Found Deleted WAF")
                            print(items['WAFId'])
                            print('================================')
                            if items['WAFType'] == "GlobalWAF":
                                sns_client.publish(TopicArn=SNSTopicARN,Subject="WAF Removed",Message=json.dumps({'default':'Something went wrong','email':items['WAFType']+' '+items['WAFName']+' with id '+items['WAFId']+' is removed in '+items['OwnerAlias']+'('+items['OwnerId']+ ') account.'}), MessageStructure='json')
                            else:
                                sns_client.publish(TopicArn=SNSTopicARN,Subject="WAF Removed",Message=json.dumps({'default':'Something went wrong','email':items['WAFType']+' '+items['WAFName']+' with id '+items['WAFId']+' is removed in '+items['OwnerAlias']+'('+items['OwnerId']+ ') account in '+items['Region']+' region.'}), MessageStructure='json')
                
                            response = res_table.update_item(
                                       Key={
                                            'WAFId':items['WAFId'],
                                            'WAFCount' : items['WAFCount']
                                        },
                                        UpdateExpression="set WAFStatus= :r, DeletedTime= :d",
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
        sns_client = boto3.client('sns', region_name = 'us-east-1', aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
        wafinventory()
        return 'success'
    except Exception :
        print(traceback.format_exc())
        return 'failed'
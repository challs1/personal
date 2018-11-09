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
                #GET Subnet INVENTORY AND PUT IN DYNAMODB
        ###########################################################
        def subnetinventory() :
            resource_id  = []
            resourcecountlist = []
            
            tagdict = {}
            resource_table = dynamodb_resource.Table('subnetinventory')
            sts_client_account = boto3.client('sts').get_caller_identity()['Account']
            ec2_region = boto3.client('ec2').describe_regions()['Regions']
            for region in ec2_region:
                print(region['RegionName'])
                print('==================================================')
                
                subnet_client = boto3.client('ec2', region_name=region['RegionName'])
                subnet_client_response = subnet_client.describe_subnets()
                print(subnet_client_response['Subnets'])
                    
                for subnetlist in subnet_client_response['Subnets']:
                    print(subnetlist['SubnetId'])
                    
                    subnetcount = sts_client_account + ' - ' + region['RegionName']
                    
                    resource_id.append(subnetlist['SubnetId'])
                    resourcecountlist.append(subnetcount)
                    
                    subnetname = 'No Name'
                    if subnetlist.get('Tags') :
                        for tag in subnetlist['Tags']: #tag iteration
                            print(tag)
                            if tag['Value'] :
                                tagdict[tag['Key']] = tag['Value'] #storing tags in dictonary 
                            else :
                                tagdict[tag['Key']] = 'null'
                            if tag['Key'] == 'Name':
                                print(tag['Value'])
                                if tag['Value']:
                                    subnetname = tag['Value']
                                else:
                                    subnetname = 'No Name'
                    
                    resource_table.put_item(
                        Item ={
                        'SubnetId' : subnetlist['SubnetId'],
                        'SubnetCount' : subnetcount,
                        'SubnetName': subnetname,
                        'SubnetStatus' : subnetlist['State'],
                        'CidrBlock': subnetlist['CidrBlock'],
                        'VpcId' : subnetlist['VpcId'],
                        'AvailabilityZone' : subnetlist['AvailabilityZone'],
                        'AvailableIpAddressCount': subnetlist['AvailableIpAddressCount'],
                        'AssignIpv6AddressOnCreation': subnetlist['AssignIpv6AddressOnCreation'],
                        'Ipv6CidrBlockAssociationSet': subnetlist['Ipv6CidrBlockAssociationSet'],
                        'OwnerId' : sts_client_account,
                        'OwnerAlias' : account_alias,
                        'Region' : region['RegionName'],
                        'LastExecutedTime' : todaysdatetime,
                        'Tags' : tagdict,
                        
                    })  
                    cleardict(tagdict)
                    
                    
            if not resource_id :
                resource_id.append('emptylist')
            searchdeletedapigateway(resource_id,resourcecountlist,resource_table,sts_client_account)    
        ###########################################################
                #SEARCH FOR DELETED EMR
        ###########################################################
        
        def searchdeletedapigateway(reslist,rescountlist,res_table,sts_client_account) :
                print(reslist)
                print(rescountlist)
                res_table_scan = res_table.scan(FilterExpression=Attr('OwnerId').eq(sts_client_account) & Attr('SubnetStatus').ne('Deleted'))
                print(len(res_table_scan['Items']))
                res_table_scan_ext = res_table_scan['Items']

                while res_table_scan.get('LastEvaluatedKey'):
                    res_table_scan = res_table.scan(ExclusiveStartKey=res_table_scan['LastEvaluatedKey'],FilterExpression=Attr('OwnerId').eq(sts_client_account) & Attr('SubnetStatus').ne('Deleted'))
                    print('-------extension---------')
                    print(len(res_table_scan['Items']))
                    res_table_scan_ext += res_table_scan['Items']
                    print(len(res_table_scan_ext))
                print('---------------------------------------')
                print('Looking for Deleted Subnet')
                for items in res_table_scan_ext :

                    if items['SubnetStatus'] != 'Deleted' :
                        for res in reslist :
                            print(res)
                            if items['SubnetId'] == res:
                                matid = 'matched'
                                break
                            else :
                                matid = 'not matched'
                        if matid == 'matched' :
                            for rescount in rescountlist :
                                print(rescount)
                                if items['SubnetCount'] == rescount:
                                    matid = 'matched'
                                    break
                                else :
                                    matid = 'not matched'
                        if matid == 'not matched' : #and ownerid == items['OwnerId']:
                            print("Found Deleted Subnet")
                            print(items['SubnetId'])
                            print('================================')
                            response = res_table.update_item(
                                       Key={
                                            'SubnetId':items['SubnetId'],
                                            'SubnetCount' : items['SubnetCount']
                                        },
                                        UpdateExpression="set SubnetStatus= :r, DeletedTime= :d",
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
        
        subnetinventory()
        return 'success'
    except Exception :
        print(traceback.format_exc())
        return 'failed'
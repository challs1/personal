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
import dateutil.parser

###########################################################
                #MAIN FUNCTION
###########################################################



def lambda_handler(event, context):
    try :
        ###########################################################
                #GET Glacier INVENTORY AND PUT IN DYNAMODB
        ###########################################################
        def glacierinventory() :
            glacier_id  = []
            glaciercountlist = []
            
            tagdict = {}
            
            
            glacier_table = dynamodb_resource.Table('glacierinventory')
            sts_client_account = boto3.client('sts').get_caller_identity()['Account']
            ec2_region = boto3.client('ec2').describe_regions()['Regions']
            for region in ec2_region:
                if region['RegionName'] != 'sa-east-1':
                    print(region['RegionName'])
                    print('==================================================')
                    glacier_client = boto3.client('glacier', region_name=region['RegionName'])
                    glacier_list_response = glacier_client.list_vaults()
                    print(glacier_list_response['VaultList'])
                    for glacierlist in glacier_list_response['VaultList']:
                        
                        
                        creationdate = dateutil.parser.parse(glacierlist['CreationDate'])
                        print(creationdate)
                        creationdate  = timeconverter(creationdate) + ' CST'
                        glaciercount = sts_client_account + ' - ' + region['RegionName'] + ' - ' + creationdate
                        
                        glacier_id.append(glacierlist['VaultName'])
                        glaciercountlist.append(glaciercount)
                        print(glacierlist['VaultName'])
                        
                        glacier_list_job_response = glacier_client.list_jobs(vaultName=glacierlist['VaultName'])
                        print(glacier_list_job_response['JobList'])
                        #for glalistjob in glacier_list_job_response['JobList']:
                            
                        
                        glaciet_tag_list = glacier_client.list_tags_for_vault(vaultName=glacierlist['VaultName'])
                        if glaciet_tag_list:
                                
                            for tag in glaciet_tag_list['Tags']: #tag iteration
                                print(tag)
                                if glaciet_tag_list['Tags'][tag] :
                                    tagdict[tag] = glaciet_tag_list['Tags'][tag] #storing tags in dictonary 
                                else :
                                    tagdict[tag] = 'null'
                                
                        else :
                            print('No Tags')
                        print(tagdict)
                        print('-------------------------------------')
                        
                     
                        
                        glacier_table.put_item(
                            Item ={
                            'GlacierName' : glacierlist['VaultName'],
                            'GlacierCount' : glaciercount,
                            'SizeinBytes' : glacierlist['SizeInBytes'],
                            'NumberOfArchives' : glacierlist['NumberOfArchives'],
                            'GlacierStatus' : 'Active',
                            'VaultCreationDate' : creationdate,
                            'OwnerId' : sts_client_account,
                            'OwnerAlias' : account_alias,
                            'Region' : region['RegionName'],
                            'LastExecutedTime' : todaysdatetime,
                            'Tags' : tagdict,
                            
                        })  
                        cleardict(tagdict)
                       
                        
            if not glacier_id :
                glacier_id.append('emptylist')
            searchdeletedglacier(glacier_id,glaciercountlist,glacier_table,sts_client_account)    
        ###########################################################
                #SEARCH FOR DELETED EMR
        ###########################################################
        
        def searchdeletedglacier(reslist,rescountlist,res_table,sts_client_account) :
                print(reslist)
                print(rescountlist)
                res_table_scan = res_table.scan(FilterExpression=Attr('OwnerId').eq(sts_client_account) & Attr('GlacierStatus').ne('Deleted'))
                print(len(res_table_scan['Items']))
                res_table_scan_ext = res_table_scan['Items']

                while res_table_scan.get('LastEvaluatedKey'):
                    res_table_scan = res_table.scan(ExclusiveStartKey=res_table_scan['LastEvaluatedKey'],FilterExpression=Attr('OwnerId').eq(sts_client_account) & Attr('GlacierStatus').ne('Deleted'))
                    print('-------extension---------')
                    print(len(res_table_scan['Items']))
                    res_table_scan_ext += res_table_scan['Items']
                    print(len(res_table_scan_ext))
                print('---------------------------------------')
                print('Looking for Deleted Glacier Vault')
                for items in res_table_scan_ext :

                    if items['GlacierStatus'] != 'Deleted' :
                        for res in reslist :
                            print(res)
                            if items['GlacierName'] == res:
                                matid = 'matched'
                                break
                            else :
                                matid = 'not matched'
                        if matid == 'matched' :
                            for rescount in rescountlist :
                                print(rescount)
                                if items['GlacierCount'] == rescount:
                                    matid = 'matched'
                                    break
                                else :
                                    matid = 'not matched'
                        if matid == 'not matched' : #and ownerid == items['OwnerId']:
                            print("Found Deleted Glacier")
                            print(items['GlacierName'])
                            print('================================')
                            response = res_table.update_item(
                                       Key={
                                            'GlacierName':items['GlacierName'],
                                            'GlacierCount' : items['GlacierCount']
                                        },
                                        UpdateExpression="set GlacierStatus= :r, DeletedTime= :d",
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
        
        glacierinventory()
        return 'success'
    except Exception :
        print(traceback.format_exc())
        return 'failed'
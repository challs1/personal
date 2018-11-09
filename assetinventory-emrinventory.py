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
                #GET EMR INVENTORY AND PUT IN DYNAMODB
        ###########################################################
        def emrinventory() :
            emr_id  = []
            emrcountlist = []
            emr_additional_master_sg = []
            emr_additional_slave_sg = []
            tagdict = {}
            inslist = []
            
            emr_table = dynamodb_resource.Table('emrinventory')
            sts_client_account = boto3.client('sts').get_caller_identity()['Account']
            ec2_region = boto3.client('ec2').describe_regions()['Regions']
            for region in ec2_region:
                print(region['RegionName'])
                print('==================================================')
                emr_client = boto3.client('emr', region_name=region['RegionName'])
                emr_list_response = emr_client.list_clusters(ClusterStates=['BOOTSTRAPPING','RUNNING','WAITING'])
                print(emr_list_response['Clusters'])
                for emrlist in emr_list_response['Clusters']:
                    
                    
                    emr_list_ins = emr_client.list_instances(ClusterId=emrlist['Id'])
                    print(emr_list_ins['Instances'])
                    
                    creationdate  = timeconverter(emrlist['Status']['Timeline']['CreationDateTime']) + ' CST'
                    emrcount = sts_client_account + ' - ' + region['RegionName']+' - '+emrlist['Id']+' - ' + creationdate
                    
                    emrnameid= emrlist['Name']
                    emr_id.append(emrnameid)
                    emrcountlist.append(emrcount)
                    print(emrnameid)
                    
                    emr_cluster_response = emr_client.describe_cluster(ClusterId=emrlist['Id'])
                    print(emr_cluster_response['Cluster'])
                    emr_cluster_response_clu = emr_cluster_response['Cluster']['Ec2InstanceAttributes']
                    print(emr_cluster_response_clu)
                    
                    
                    
                    if emr_cluster_response_clu.get('AdditionalMasterSecurityGroups'):
                        emr_additional_master_sg.append(emr_cluster_response_clu['AdditionalMasterSecurityGroups'])
                    
                    if emr_cluster_response_clu.get('AdditionalSlaveSecurityGroups'):
                        emr_additional_slave_sg.append(emr_cluster_response_clu['AdditionalSlaveSecurityGroups'])
                    
                    if emr_cluster_response_clu.get('Ec2KeyName'):
                        keyname = emr_cluster_response_clu['Ec2KeyName']
                    else:
                        keyname = 'No'
                    
                   
                    if emr_cluster_response['Cluster']['Tags'] :
                        for tag in emr_cluster_response['Cluster']['Tags']: #tag iteration
                            print(tag)
                            if tag['Value'] :
                                tagdict[tag['Key']] = tag['Value'] #storing tags in dictonary 
                            else :
                                tagdict[tag['Key']] = 'null'
                    else :
                        print('No Tags')
                    print('-------------------------------------')
                    
                    for emrlistins in emr_list_ins['Instances']:
                        
                        inslistidtype = emrlistins['Ec2InstanceId']+' - '+emrlistins['InstanceType']+' - '+emrlistins['PrivateIpAddress']
                        inslist.append(inslistidtype)
                    
                    
                    emr_table.put_item(
                        Item ={
                        'EMRName' : emrnameid,
                        'EMRCount' : emrcount,
                        'EC2KeyName' : keyname,
                        'Ec2SubnetId' : emr_cluster_response['Cluster']['Ec2InstanceAttributes']['Ec2SubnetId'],
                        'RequestedEc2SubnetIds' : emr_cluster_response['Cluster']['Ec2InstanceAttributes']['RequestedEc2SubnetIds'],
                        'IamInstanceProfile' : emr_cluster_response['Cluster']['Ec2InstanceAttributes']['IamInstanceProfile'],
                        'EmrManagedMasterSecurityGroup' : emr_cluster_response['Cluster']['Ec2InstanceAttributes']['EmrManagedMasterSecurityGroup'],
                        'EmrManagedSlaveSecurityGroup': emr_cluster_response['Cluster']['Ec2InstanceAttributes']['EmrManagedSlaveSecurityGroup'],
                        'ServiceAccessSecurityGroup': emr_cluster_response['Cluster']['Ec2InstanceAttributes']['ServiceAccessSecurityGroup'],
                        'AdditionalMasterSecurityGroups': emr_additional_master_sg,
                        'AdditionalSlaveSecurityGroups': emr_additional_slave_sg,
                        'InstanceCollectionType' : emr_cluster_response['Cluster']['InstanceCollectionType'],
                        'LogUri' : emr_cluster_response['Cluster']['LogUri'],
                        'ReleaseLabel': emr_cluster_response['Cluster']['ReleaseLabel'],
                        'AutoTerminate' : emr_cluster_response['Cluster']['AutoTerminate'],
                        'VisibleToAllUsers' : emr_cluster_response['Cluster']['VisibleToAllUsers'],
                        'Applications' : emr_cluster_response['Cluster']['Applications'],
                        'MasterPublicDnsName' : emr_cluster_response['Cluster']['MasterPublicDnsName'],
                        'Configurations' : emr_cluster_response['Cluster']['Configurations'],
                        'InstanceList' : inslist,
                        'EMRStatus' : emrlist['Status']['State'],
                        'EMRCreationDate' : creationdate,
                        'OwnerId' : sts_client_account,
                        'OwnerAlias' : account_alias,
                        'Region' : region['RegionName'],
                        'LastExecutedTime' : todaysdatetime,
                        'Tags' : tagdict,
                        
                    })  
                    cleardict(tagdict)
                    clearlist(emr_additional_master_sg)
                    clearlist(emr_additional_slave_sg)
                    clearlist(inslist)
                    
            if not emr_id :
                emr_id.append('emptylist')
            searchdeletedemr(emr_id,emrcountlist,emr_table,sts_client_account)    
        ###########################################################
                #SEARCH FOR DELETED EMR
        ###########################################################
        
        def searchdeletedemr(reslist,rescountlist,res_table,sts_client_account) :
                print(reslist)
                print(rescountlist)
                res_table_scan = res_table.scan(FilterExpression=Attr('OwnerId').eq(sts_client_account) & Attr('EMRStatus').ne('Deleted'))
                print(len(res_table_scan['Items']))
                res_table_scan_ext = res_table_scan['Items']

                while res_table_scan.get('LastEvaluatedKey'):
                    res_table_scan = res_table.scan(ExclusiveStartKey=res_table_scan['LastEvaluatedKey'],FilterExpression=Attr('OwnerId').eq(sts_client_account) & Attr('EMRStatus').ne('Deleted'))
                    print('-------extension---------')
                    print(len(res_table_scan['Items']))
                    res_table_scan_ext += res_table_scan['Items']
                    print(len(res_table_scan_ext))
                print('---------------------------------------')
                print('Looking for Deleted EMR')
                for items in res_table_scan_ext :

                    if items['EMRStatus'] != 'Deleted' :
                        for res in reslist :
                            print(res)
                            if items['EMRName'] == res:
                                matid = 'matched'
                                break
                            else :
                                matid = 'not matched'
                        if matid == 'matched' :
                            for rescount in rescountlist :
                                print(rescount)
                                if items['EMRCount'] == rescount:
                                    matid = 'matched'
                                    break
                                else :
                                    matid = 'not matched'
                        if matid == 'not matched' : #and ownerid == items['OwnerId']:
                            print("Found Deleted EMR")
                            print(items['EMRName'])
                            print('================================')
                            response = res_table.update_item(
                                       Key={
                                            'EMRName':items['EMRName'],
                                            'EMRCount' : items['EMRCount']
                                        },
                                        UpdateExpression="set EMRStatus= :r, DeletedTime= :d",
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
        
        emrinventory()
        return 'success'
    except Exception :
        print(traceback.format_exc())
        return 'failed'
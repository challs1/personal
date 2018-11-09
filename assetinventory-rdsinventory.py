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
                #GET RDS INVENTORY AND PUT IN DYNAMODB
        ###########################################################
        def rdsinventory() :
            rds_id  = []
            rdscountlist = []
            readreplica = []
            rdsvpcsecuritygroup = []
            rdsdbsubnetgroup = []
            dbsecuritygroup = []
            rds_table = dynamodb_resource.Table('rdsinventory')
            sts_client_account = boto3.client('sts').get_caller_identity()['Account']
            ec2_region = boto3.client('ec2').describe_regions()['Regions']
            for region in ec2_region:
                print(region['RegionName'])
                print('==================================================')
                rds_client = boto3.client('rds', region_name = region['RegionName'])
                rds_response =rds_client.describe_db_instances()['DBInstances']
                for rdsres in rds_response :
                    creationdate  = timeconverter(rdsres['InstanceCreateTime']) + ' CST'
                    rdscount = sts_client_account + ' - ' + region['RegionName'] + ' - ' + creationdate
                    rds_id.append(rdsres['DBInstanceIdentifier'])
                    rdscountlist.append(rdscount)
                    print(rdsres['DBInstanceIdentifier'])
                    if rdsres.get('DBSecurityGroups') :
                        dbsecuritygroup.append(rdsres['DBSecurityGroups'])
                        #for dbsg in rdsres['DBSecurityGroups'] :
                            #dbsecuritygroup = dbsg['DBSecurityGroupName']
                            #dbsgstatus = dbsg['Status']
                    else :
                        dbsecuritygroup = []
                        #dbsecuritygroup = 'null'
                        #dbsgstatus= 'null'
                    if rdsres.get('VpcSecurityGroups') :
                        rdsvpcsecuritygroup.append(rdsres['VpcSecurityGroups'])
                    else :
                        rdsvpcsecuritygroup = []
                       
                    if rdsres.get('DBSubnetGroup'):
                        rdsdbsubnetgroup.append(rdsres['DBSubnetGroup'])
                    else:
                        rdsdbsubnetgroup = []
                        
                    if rdsres.get('SecondaryAvailabilityZone') :
                        secondaryavazone = rdsres['SecondaryAvailabilityZone']
                    else :
                        secondaryavazone = 'No'
                    if rdsres.get('ReadReplicaDBInstanceIdentifiers') :
                        readreplica = rdsres['ReadReplicaDBInstanceIdentifiers']
                    else:
                        readreplica = []
                    if rdsres.get('Iops') :
                        rdsiops = rdsres['Iops']
                    else:
                        rdsiops = 'No'
                    rds_tags = rds_client.list_tags_for_resource(ResourceName=rdsres['DBInstanceArn'])['TagList']
                    if rds_tags :
                        for tag in rds_tags: #tag iteration
                            print(tag)
                            if tag['Value'] :
                                tagdict[tag['Key']] = tag['Value'] #storing tags in dictonary 
                            else :
                                tagdict[tag['Key']] = 'null'
                    else :
                        print('No Tags')
                    print('-------------------------------------')
                    
                    
                    
                    rds_table.put_item(
                        Item ={
                        'DBInstanceName' : rdsres['DBInstanceIdentifier'],
                        'RDSCount' : rdscount,
                        'DBInstanceClass' : rdsres['DBInstanceClass'],
                        'Engine' :rdsres['Engine'],
                        'EngineVersion' : rdsres['EngineVersion'],
                        'Encrypted' : rdsres['StorageEncrypted'],
                        'BackupWindow' : rdsres['PreferredBackupWindow'],
                        'MaintenanceWindow' : rdsres['PreferredMaintenanceWindow'],
                        'DBInstanceStatus' : rdsres['DBInstanceStatus'],
                        'AllocatedStorage' : rdsres['AllocatedStorage'],
                        'DBSecurityGroup' : dbsecuritygroup,
                        #'DBSecurityGrouStatus' : dbsgstatus,
                        'VPCId' : rdsres['DBSubnetGroup']['VpcId'],
                        'InsCreationDate' : creationdate,
                        'BackupRetentionPeriod' : rdsres['BackupRetentionPeriod'],
                        'EndPoint' : rdsres['Endpoint']['Address'],
                        'Port' : rdsres['Endpoint']['Port'],
                        'AvailabilityZone' : rdsres['AvailabilityZone'],
                        'SecondaryAvailabilityZone' : secondaryavazone,
                        'PubliclyAccessible' : rdsres['PubliclyAccessible'],
                        'MultiAZ' : rdsres['MultiAZ'],
                        'ReadReplicaDBInstanceIdentifiers' : readreplica,
                        'Iops' : rdsiops,
                        'VpcSecurityGroups': rdsvpcsecuritygroup,
                        'DBSubnetGroup' : rdsdbsubnetgroup,
                        'OwnerId' : sts_client_account,
                        'OwnerAlias' : account_alias,
                        'Region' : region['RegionName'],
                        'LastExecutedTime' : todaysdatetime,
                        'Tags' : tagdict,
                        
                    })  
                    cleardict(tagdict)
                    clearlist(dbsecuritygroup)
                    clearlist(readreplica)
                    clearlist(rdsvpcsecuritygroup)
                    clearlist(rdsdbsubnetgroup)
            if not rds_id :
                rds_id.append('emptylist')
            searchdeletedrds(rds_id,rdscountlist,rds_table,sts_client_account)    
        ###########################################################
                #SEARCH FOR DELETED RDS
        ###########################################################
        def searchdeletedrds(rds_id,rdscountlist,rds_table,sts_client_account) :
                rds_table_scan = rds_table.scan(FilterExpression=Attr('OwnerId').eq(sts_client_account) & Attr('DBInstanceStatus').ne('Deleted'))
                print(len(rds_table_scan['Items']))
                rds_table_scan_ext = rds_table_scan['Items']
                
                while rds_table_scan.get('LastEvaluatedKey'):
                    rds_table_scan = rds_table.scan(ExclusiveStartKey=rds_table_scan['LastEvaluatedKey'],FilterExpression=Attr('OwnerId').eq(sts_client_account) & Attr('DBInstanceStatus').ne('Deleted'))
                    print('-------extension---------')
                    print(len(rds_table_scan['Items']))
                    rds_table_scan_ext += rds_table_scan['Items']
                    print(len(rds_table_scan_ext))
                print('---------------------------------------')
                print('Looking for Deleted RDS')
                for items in rds_table_scan_ext :
                    
                    if items['DBInstanceStatus'] != 'Deleted' :
                        for rid in rds_id :
                            if items['DBInstanceName'] == rid:
                                matid = 'matched'
                                break
                            else :
                                matid = 'not matched'
                        if matid == 'matched' :
                            for rcount in rdscountlist :
                                if items['RDSCount'] == rcount:
                                    matid = 'matched'
                                    break
                                else :
                                    matid = 'not matched'
                        if matid == 'not matched' : #and ownerid == items['OwnerId']:
                            print("Found Deleted RDS")
                            print(items['DBInstanceName'])
                            print('================================')
                            response = rds_table.update_item(
                                       Key={
                                            'DBInstanceName':items['DBInstanceName'],
                                            'RDSCount' : items['RDSCount']
                                        },
                                        UpdateExpression="set DBInstanceStatus= :r, DeletedTime= :d",
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
        #dbsecuritygroup = []
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
        
        rdsinventory()
        return 'success'
    except Exception :
        print(traceback.format_exc())
        return 'failed'
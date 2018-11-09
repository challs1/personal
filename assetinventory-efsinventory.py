#################################################################
#AUTHOR          : Sairaja Challagulla
#REGIONS         : ALL REGIONS
#EMAIL           : Challagulla_Sairaja@cat.com
#################################################################
import boto3
from datetime import datetime
from dateutil import tz
from boto3.dynamodb.conditions import Key, Attr

account_id = boto3.client("sts").get_caller_identity()["Account"]
#dynamodb_resource = boto3.resource('dynamodb', region_name = 'us-east-1')
client = boto3.client('sts')
sts_response = client.assume_role(RoleArn='arn:aws:iam::620890749476:role/Assetsinventory_Trusted_DynamoDB',
                                      RoleSessionName='AssumeMyRole', DurationSeconds=900)

dynamodb_resource = boto3.resource(service_name='dynamodb', region_name='us-east-1',
                              aws_access_key_id = sts_response['Credentials']['AccessKeyId'],
                              aws_secret_access_key = sts_response['Credentials']['SecretAccessKey'],
                              aws_session_token = sts_response['Credentials']['SessionToken'])

#print("dynamodb_resource",dynamodb_resource)
efs_table = dynamodb_resource.Table('efsinventory')



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


def get_available_efs_inventory_from_db(region):
    try:
        response = efs_table.scan(
            FilterExpression=Attr('isDeleted').eq('No') & Attr('RegionName').eq(region)
        )
    except Exception as e:
        print(e.response['Error']['Message'])
        return []
    else:
        items = response['Items']
        print("GetItems succeeded:", items)
        return items

def get_deleted_efs_ids(efs_response, all_efs_from_db):
    all_efs = []
    efs_from_db = []
    deleted_efs = []

    for efs in efs_response:
       all_efs.append(efs['FileSystemId'])

    for efs in all_efs_from_db:
       efs_from_db.append(efs['FileSystemId'])

    for efs in efs_from_db:
        if efs not in all_efs:
            deleted_efs.append(efs)

    return deleted_efs


def update_deleted_efs(deleted_efs_ids):
    for efs_id in deleted_efs_ids:
        current_time = timeconverter(datetime.now()) + ' CST'
        response = efs_table.update_item(
            Key={
                'FileSystemId': efs_id
            },
            UpdateExpression="set isDeleted = :r, DeletionTime=:p, UpdateTime=:a",
            ExpressionAttributeValues={
                ':r': 'Yes',
                ':p': current_time,
                ':a': current_time
            },
            ReturnValues="UPDATED_NEW"
        )
        print("UpdateItem succeeded FileSystemId: "+efs_id)

def lambda_handler(event, context):
    print("Checking EFS for all regions...")

    # EFS service is not available for all regions, it is available for below 8 regions only (as of now)
    efs_region = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ap-northeast-2', 'ap-southeast-2', 'eu-central-1', 'eu-west-1']
    #print("efs_region", efs_region)

    for regionName in efs_region:

        efs_client = boto3.client('efs', region_name=regionName)
        print("EFS Inventory started for "+regionName+" region!")

        efs_response = efs_client.describe_file_systems()

        all_efs = efs_response['FileSystems']
        #print("all_efs in "+regionName, all_efs)

        all_efs_from_db = get_available_efs_inventory_from_db(regionName)

        deleted_efs_ids = get_deleted_efs_ids(all_efs, all_efs_from_db)

        if(len(all_efs)<1):
            print('No EFS found in '+regionName+' region!')
            #continue

        for efs in all_efs:
            ownerId = efs['OwnerId']
            creationToken = efs['CreationToken']
            fileSystemId = efs['FileSystemId']
            creationTime = timeconverter(efs['CreationTime']) + ' CST'
            lifeCycleState = efs['LifeCycleState']
            numberOfMountTargets = efs['NumberOfMountTargets'] # integer
            sizeInBytes = efs['SizeInBytes']['Value'] # integer
            performanceMode = efs['PerformanceMode']
            encrypted = efs['Encrypted'] # boolean
            #kmsKeyId = 'None'
            #if(encrypted==True):
            #    kmsKeyId = efs['KmsKeyId']
            name = 'undefined'
            if 'Name' in efs:
                name = efs['Name']

            mounted_targets_res = efs_client.describe_mount_targets(FileSystemId=fileSystemId)
            mountedTargets = mounted_targets_res['MountTargets']

            tags_response = efs_client.describe_tags(FileSystemId=fileSystemId)
            tags = tags_response['Tags']

            updateTime = timeconverter(datetime.now()) + ' CST'
            #print("ownerId: "+ownerId+", creationToken: "+creationToken+", fileSystemId: "+fileSystemId+", creationTime: "+creationTime+", lifeCycleState: "+lifeCycleState+", numberOfMountTargets: "+str(numberOfMountTargets)+", sizeInBytes: "+str(sizeInBytes)+", performanceMode: "+performanceMode+", encrypted: "+str(encrypted)+", kmsKeyId: "+kmsKeyId)

            print("Inserting Efs inventory data into DynamoDB table")
            efs_table.put_item ( #inserting items into table
                    Item={
                            'fileSystemId' : fileSystemId, #primary key
                            'EFSCount' : account_id + ' - ' +  regionName + ' - ' + creationTime, #SortKey
                            'Name' : name,
                            'OwnerId' : ownerId,
                            'CreationToken': creationToken,
                            'CreationTime' : creationTime,
                            'LifeCycleState' : lifeCycleState,
                            'NumberOfMountTargets': numberOfMountTargets,
                            'SizeInBytes': sizeInBytes,
                            'PerformanceMode': performanceMode,
                            'Encrypted': encrypted,
                            #'KmsKeyId' : kmsKeyId,
                            'isDeleted' : 'No',
                            'DeletionTime' : 'NA',
                            'UpdateTime' : updateTime,
                            'MountTargets' : str(mountedTargets),
                            'Tags' : str(tags),
                            'RegionName' : regionName
                        }
                    )

        if(len(deleted_efs_ids)>0):
            print("updating deleted efs for "+regionName+" region...")
            update_deleted_efs(deleted_efs_ids)

        print('EFS Inventory completed for '+regionName+' region')

    print('EFS Inventory completed for all regions!')

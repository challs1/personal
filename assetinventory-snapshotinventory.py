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
def lambda_handler(event,context) :
    try :

        ###########################################################
                #GET SNAP INVENTORY AND PUT IN DYNAMODB
        ###########################################################
        def snapshotinventory() :
            snapshot_id  = []
            snapshotcountlist = []
            snapshot_table = dynamodb_resource.Table('snapshotinventory')
            sts_client_account = boto3.client('sts').get_caller_identity()['Account']
            ec2_region = boto3.client('ec2').describe_regions()['Regions']
            for region in ec2_region:
                print(region['RegionName'])
                print('==================================================')
                ec2_client = boto3.client('ec2', region_name = region['RegionName'])
                snapshot_response =ec2_client.describe_snapshots(OwnerIds=[sts_client_account])['Snapshots']
                for snapshot in snapshot_response :
                    creationdate  = timeconverter(snapshot['StartTime']) + ' CST'
                    snapshotcount = sts_client_account + ' - ' + region['RegionName'] + ' - ' + creationdate
                    snapshot_id.append(snapshot['SnapshotId'])
                    snapshotcountlist.append(snapshotcount)
                    print(snapshot['SnapshotId'])
                    if snapshot.get('Tags') :
                        for tag in snapshot['Tags']: #tag iteration
                            if tag['Value'] :
                                tagdict[tag['Key']] = tag['Value'] #storing tags in dictonary
                            else :
                                tagdict[tag['Key']] = 'null'
                    else :
                        print('No Tags')
                    print('-------------------------------------')

                    if snapshot['VolumeId'] == 'vol-ffffffff' :
                        print('It is a copied snapshot', snapshot['Description'])
                        svolumeid = 'vol-ffffffff'
                        if snapshot['Description'] :
                            sinstanceid = snapshot['Description']
                        else :
                            sinstanceid = 'null'
                        siamgeid = "It's a copied snap"
                        simgname = "It's a copied snap"

                    else :
                        try :
                            volume_response = ec2_client.describe_volumes(VolumeIds=[snapshot['VolumeId']])
                            svolumeid = snapshot['VolumeId']
                            #print(volume_response)
                            for volumes in volume_response['Volumes'] :
                                #print(volumes)
                                if not volumes.get('Attachments') :
                                    print('Volume is detached')
                                    sinstanceid = "Volume is detached"
                                    siamgeid = "Volume is detached"
                                    simgname = "Volume is detached"

                                else :
                                    for attachments in volumes['Attachments'] :
                                            sinstanceid = attachments['InstanceId']
                                            ec2_response =ec2_client.describe_instances(InstanceIds=[sinstanceid])['Reservations']
                                            for ins in ec2_response :
                                                for imageid1 in ins['Instances'] :
                                                    siamgeid = imageid1['ImageId']
                                                    imageid_response = ec2_client.describe_images(ImageIds = [imageid1['ImageId']])['Images']
                                                    if imageid_response:
                                                        for imgid1 in imageid_response:
                                                            simgname = imgid1['Name']
                                                    else:
                                                        simgname= "Cannot load details for " + siamgeid+ " You may not be permitted to view it"

                        except Exception as e:
                            svolumeid = 'Volume is Deleted'
                            sinstanceid = "Can't Find InstanceId"
                            siamgeid = "Can't Find ImageId"
                            simgname = "Can't Find IamgeVersion"
                            print(e)
                            print('No VolumeId')

                    snapshot_table.put_item(
                        Item ={
                        'SnapshotId' : snapshot['SnapshotId'],
                        'SnapshotCount' : snapshotcount,
                        'InstanceId' : sinstanceid,
                        'Region' : region['RegionName'],
                        'VolumeId' : svolumeid,
                        'OwnerId' : snapshot['OwnerId'],
                        'CreationDate' : creationdate,
                        'Encrypted' : snapshot['Encrypted'],
                        'SnapStatus' : snapshot['State'],
                        'LastExecutedTime' : todaysdatetime,
                        'SImageId' : siamgeid,
                        'SImageIdVersion' : simgname,
                        'OwnerAlias' :account_alias,
                        'Tags' : tagdict,

                    })
                    cleardict(tagdict)

            if not snapshot_id :
                snapshot_id.append('emptylist')
            searchdeletedsnapshot(snapshot_id,snapshotcountlist,snapshot_table,sts_client_account)
        ###########################################################
                #SEARCH FOR DELETED SNAPSHOT
        ###########################################################
        def searchdeletedsnapshot(snapshot_id,snapshotcountlist,snapshot_table,sts_client_account) :
                snapshot_table_scan = snapshot_table.scan(FilterExpression=Attr('OwnerId').eq(sts_client_account) & Attr('SnapStatus').ne('Deleted'))
                print(len(snapshot_table_scan['Items']))
                snapshot_table_scan_ext = snapshot_table_scan['Items']

                while snapshot_table_scan.get('LastEvaluatedKey'):
                    snapshot_table_scan = snapshot_table.scan(ExclusiveStartKey=snapshot_table_scan['LastEvaluatedKey'],FilterExpression=Attr('OwnerId').eq(sts_client_account) & Attr('SnapStatus').ne('Deleted'))
                    print('-------extension---------')
                    print(len(snapshot_table_scan['Items']))
                    snapshot_table_scan_ext += snapshot_table_scan['Items']
                    print(len(snapshot_table_scan_ext))
                print('---------------------------------------')
                print('Looking for Deleted Snapshots')
                for items in snapshot_table_scan_ext :

                    if items['SnapStatus'] != 'Deleted' :
                        for sshot in snapshot_id :
                            if items['SnapshotId'] == sshot:
                                matid = 'matched'
                                break
                            else :
                                matid = 'not matched'
                        if matid == 'matched' :
                            for scount in snapshotcountlist :
                                if items['SnapshotCount'] == scount:
                                    matid = 'matched'
                                    break
                                else :
                                    matid = 'not matched'

                        if matid == 'not matched' : #and ownerid == items['OwnerId']:
                            print("Found Deleted Snap")
                            print(items['SnapshotId'])
                            print('================================')
                            response = snapshot_table.update_item(
                                       Key={
                                            'SnapshotId':items['SnapshotId'],
                                            'SnapshotCount' : items['SnapshotCount']
                                        },
                                        UpdateExpression="set SnapStatus= :r, DeletedTime= :d",
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

        snapshotinventory()
        return 'success'
    except Exception :
        print(traceback.format_exc())
        return 'failed'

"""
Author          :   Sairaja Challagulla(Challagulla_Sairaja@cat.com)
Description     :   1.  Create backup of the volumes of all the instances
                        tagged with key 'backup' and value 'yes'
                    2.  This script will also tag the created snapshot with
                        respected instanceid, devicename, Name, & add retention
                        depending on ec2 or account basis
Regions         :   ['us-east-1','us-east-2','us-west-2','ap-northeast-1','ap-southeast-1','ap-south-1','ap-northeast-2','eu-central-1','sa-east-1']
Version         :   3.1(Stable)
"""
import boto3
import time
import os
## Variables
InstChargeCodeTagKey = 'chargecode'
InstChargeCodeTagValue = 'N/A'
InstAppIdKey = 'applicationid'
InstAppIdValue = 'N/A'
SnapshotTags = [ InstChargeCodeTagKey, InstAppIdKey, 'Name', 'instanceid', 'devicename', 'retention' ]
RETENTION = int(os.environ['RETENTION'])
InstRetTagKey = 'retention'
InstFilter = [{'Name': 'tag:backup', 'Values': ['yes']}]
LegalHold = 'legalhold'
##Main funciton called by Lambda
def lambda_handler(event, context):
    ## For Regions
    #Regions = [region['RegionName'] for region in boto3.client('ec2').describe_regions()['Regions']]
    Regions = ['us-east-1','us-east-2','us-west-2','ap-northeast-1','ap-southeast-1','ap-south-1','ap-northeast-2','eu-central-1','sa-east-1']
    for Region in Regions:
        ## For all Snapshots in Region
        EC2R = boto3.resource('ec2', Region)
        EC2C = boto3.client('ec2', Region)
        ## For each running instances
        AllInstances = [inst.id for inst in EC2R.instances.filter(Filters=InstFilter)]
        for InstID in AllInstances:
           # Take snap of each attached volumes & tag
           actions(EC2R, EC2C, Region, InstID, SnapshotTags, RETENTION, InstChargeCodeTagValue, InstAppIdValue)
#Snapshot creation
def actions(EC2R, EC2C, Region, InstID, SnapshotTags, RETENTION, InstChargeCodeTagValue, InstAppIdValue):
    print("\n\n- - - - Region: {} -> InstanceId: {} - - - - ".format(Region, InstID))
    ## Get list of attached volumes
    try:
        # Get 'applicationid' tag of instance
        try:
            CurrentTags = {}
            for AppIdTag in EC2R.Instance(InstID).tags:
                CurrentTags[AppIdTag['Key']] = AppIdTag['Value']
            if InstAppIdKey in CurrentTags and CurrentTags.get(InstAppIdKey) != '':
                InstAppIdValue = CurrentTags.get(InstAppIdKey)
            else:
                InstAppIdValue = InstAppIdValue
        except Exception as error:
            print("Getting 'applicationid' Failed: {}".format(error))
            InstAppIdValue = InstAppIdValue
        # Get 'chargecode' tag of instance
        try:
            for TAG in EC2R.Instance(InstID).tags:
                CurrentTags[TAG['Key']] = TAG['Value']
            if InstChargeCodeTagKey in CurrentTags and CurrentTags.get(InstChargeCodeTagKey) != '':
                InstChargeCodeTagValue = CurrentTags.get(InstChargeCodeTagKey)
            else:
                InstChargeCodeTagValue = InstChargeCodeTagValue
        except Exception as error:
            print("Getting 'chargecode' Failed: {}".format(error))
            InstChargeCodeTagValue = InstChargeCodeTagValue
        #Get 'retention' tag of instance
        try:
            for TAGR in EC2R.Instance(InstID).tags:
                CurrentTags[TAGR['Key']] = TAGR['Value']
            if InstRetTagKey in CurrentTags and CurrentTags.get(InstRetTagKey) != LegalHold and CurrentTags.get(InstRetTagKey) != '':
                RETENTION = int(CurrentTags.get(InstRetTagKey))
            elif InstRetTagKey in CurrentTags and CurrentTags.get(InstRetTagKey) == LegalHold:
                RETENTION = CurrentTags.get(InstRetTagKey)
            else:
                RETENTION = RETENTION
        except Exception as error:
            print("Getting 'retention' Failed: {}".format(error))
            RETENTION = RETENTION
        #Get Volume information & create snaps
        for ResVolume in EC2R.Instance(InstID).block_device_mappings:
            DeviceName=ResVolume['DeviceName']
            VolumeID=ResVolume['Ebs']['VolumeId']
            print("-> Device Name: {}".format(DeviceName))
            print("-> Volume ID: {}".format(VolumeID))
            #  Snap description
            SnapDes = "Backup snapshot of Instance: {}, Device: {}, Volume: {}".format(InstID, DeviceName, VolumeID)
            # Create snapshot and get snapid
            SnapID = EC2R.Volume(VolumeID).create_snapshot(Description=SnapDes).id
            print("-> Snapshot ID: {} , tagging now".format(SnapID))
            # Tag snapshot
            EC2R.Snapshot(SnapID).create_tags(
                        Tags=[
                            { 'Key': SnapshotTags[0], 'Value': str(InstChargeCodeTagValue) },
                            { 'Key': SnapshotTags[1], 'Value': str(InstAppIdValue) },
                            { 'Key': SnapshotTags[2], 'Value': str(InstID)+" - "+str(DeviceName) },
                            { 'Key': SnapshotTags[3], 'Value': str(InstID) },
                            { 'Key': SnapshotTags[4], 'Value': str(DeviceName) },
                            { 'Key': SnapshotTags[5], 'Value': str(RETENTION) },
                        ]
            )
            # Print snap tags
            print("-> Snapshot tags .. ")
            for TAG in EC2R.Snapshot(SnapID).tags:
                print("{0:20} -> {1}".format(TAG['Key'], TAG['Value']))
            print("-> Done..")
    except Exception as error:
        print("Failed: {}".format(error))
##### END #####

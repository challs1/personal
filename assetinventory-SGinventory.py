####################################################################################
#AUTHOR          : Sairaja Challagulla
#DESCRIPTION     : THIS FUNCTION GETS SG INVENTORY AND PUTS IN DYNAMODB TABLE.
#REGIONS         : ALL REGIONS
#EMAIL           : Challagulla_Sairaja@cat.com
####################################################################################
#prerequisites
#need dynamodb tables


import boto3
import traceback
import itertools
from datetime import datetime
from dateutil import tz
from boto3.dynamodb.conditions import Attr

def lambda_handler(event, context):
		#############################################################

                    #SECURITYGROUP INVENTORY

        #############################################################
        def sginven():
            sggroupids = ''
            sginstanceidlist = []
            sgallowingsource = []
            outsgallowingsource = []
            sgownerid = ''

            try :
                sg_table = dynamodb_resource.Table('sginventory')
                ec2_region = boto3.client('ec2').describe_regions()['Regions']
                print("SG Asset Inventory started")
                for region1 in ec2_region : #region iteration
                        region = region1['RegionName']
                        print(region)
                        ec2_client = boto3.client('ec2', region_name= region)
                        sg_response = ec2_client.describe_security_groups()

                        print('------------------------')
                        for sg in sg_response['SecurityGroups']:
                            print(sg['GroupName'])
                            print(sg['GroupId'])
                            sgownerid = sg['OwnerId']


                            for ipper,ipperegress in itertools.zip_longest(sg['IpPermissions'],sg['IpPermissionsEgress']) :
                                print("For In Bound")
                                #############################################################
                                                       #INBOUND FILTER
                                #############################################################

                                if ipper:
                                    if ipper['IpProtocol'] == '-1':
                                        inipprotocol = 'All'
                                    else :
                                        inipprotocol = ipper['IpProtocol']

                                    if str(ipper.get('FromPort')) == 'None' and str(ipper.get('ToPort')) == 'None' :
                                        insgports = '0 - 65535'
                                    else :
                                        insgports = str(ipper.get('FromPort'))+ ' - '+str(ipper.get('ToPort'))

                                    if ipper['IpRanges'] :
                                        print('IPv4 is there')
                                        for sgipranges in ipper['IpRanges'] :
                                            sgallowingsource.append(sgipranges)
                                    else :
                                        print('No Ipv4')

                                    if ipper['Ipv6Ranges'] :
                                        print('IPv6 is there')
                                        for sgipv6ranges in ipper['Ipv6Ranges'] :
                                            sgallowingsource.append(sgipv6ranges)
                                    else :
                                        print('No Ipv6')

                                    if ipper['PrefixListIds'] :
                                        print('PrefixListIds is there')
                                        for sgprefixlistids in ipper['PrefixListIds'] :
                                            sgallowingsource.append(sgprefixlistids)
                                    else :
                                        print('No PrefixListIds')

                                    if ipper['UserIdGroupPairs'] :
                                        print('UserIdGroupPairs is there')
                                        for sguseridgrouppairs in ipper['UserIdGroupPairs'] :
                                            sgallowingsource.append(sguseridgrouppairs)
                                    else :
                                        print('No UserIdGroupPairs')
                                else :
                                    inipprotocol ='None'
                                    insgports = 'None'
                                    sgallowingsource.append('None')


                                #############################################################
                                                   #OUTBOUND FILTER
                                #############################################################
                                print('For outbound')
                                #print(ipperegress)
                                if ipperegress :
                                    if ipperegress['IpProtocol'] == '-1':
                                        outipprotocol = 'All'
                                    else :
                                        outipprotocol = ipperegress['IpProtocol']
                                    print(outipprotocol)
                                    if str(ipperegress.get('FromPort')) == 'None' and str(ipperegress.get('ToPort')) == 'None' :
                                        outsgports = '0 - 65535'
                                    else :
                                        outsgports = str(ipperegress.get('FromPort'))+ ' - '+str(ipperegress.get('ToPort'))

                                    if ipperegress['IpRanges'] :
                                        print('IPv4 is there')
                                        for outsgipranges in ipperegress['IpRanges'] :
                                            outsgallowingsource.append(outsgipranges)
                                    else :
                                        print('No Ipv4')

                                    if ipperegress['Ipv6Ranges'] :
                                        print('IPv6 is there')
                                        for outsgipv6ranges in ipperegress['Ipv6Ranges'] :
                                            outsgallowingsource.append(outsgipv6ranges)
                                    else :
                                        print('No Ipv6')

                                    if ipperegress['PrefixListIds'] :
                                        print('PrefixListIds is there')
                                        for outsgprefixlistids in ipperegress['PrefixListIds'] :
                                            outsgallowingsource.append(outsgprefixlistids)
                                    else :
                                        print('No PrefixListIds')

                                    if ipperegress['UserIdGroupPairs'] :
                                        print('UserIdGroupPairs is there')
                                        for outsguseridgrouppairs in ipperegress['UserIdGroupPairs'] :
                                            outsgallowingsource.append(outsguseridgrouppairs)
                                    else :

                                        print('No UserIdGroupPairs')
                                else :
                                    outipprotocol = 'None'
                                    outsgports = 'None'
                                    outsgallowingsource.append('None')


                                print('======')
                                #print(sgallowingsource)
                                #print(outsgallowingsource)
                                for insgallsrc,outsgallsrc in itertools.zip_longest(sgallowingsource,outsgallowingsource) :

                                    if sg['GroupId'] != sggroupids :
                                        sgcount = 1
                                    else :
                                        sgcount += 1
                                    sggroupids = sg['GroupId']

                                    if insgallsrc is None :
                                        insgallsrc = 'None'
                                        insgports = 'None'
                                        inipprotocol = 'None'
                                    if outsgallsrc is None :
                                        outsgallsrc = 'None'
                                        outsgports = 'None'
                                        outipprotocol = 'None'

                                    rulescount = str(sgcount) + ' - ' + sg['OwnerId']
                                    #print('------------------------')
                                    sg_table.put_item ( #inserting items into table
                                                            Item={
                                                                    'SecurityGroupId': sg['GroupId'], #primary key
                                                                    'RulesCount' : rulescount,
                                                                    'OwnerId' : sts_client_account,
                                                                    'OwnerAlias' : account_alias,
                                                                    'GroupName' : sg['GroupName'],
                                                                    'Region' : region,
                                                                    'LastExecutedTime' : todaysdatetime,
                                                                    'InstanceId' : sginstanceidlist,
                                                                    'Inbound-FromPort-ToPort' : insgports,
                                                                    'InboundIpProtocol' : inipprotocol,
                                                                    'InboundSource' : insgallsrc,
                                                                    'Outbound-FromPort-ToPort' : outsgports,
                                                                    'OutboundIpProtocol' : outipprotocol,
                                                                    'OutboundSource' : outsgallsrc,
                                                            }
                                                            )

                                clearlist(sgallowingsource)
                                clearlist(outsgallowingsource)


                    ############################################################

                                #LOOKING FOR INSTANCES WHICH HAS SAME SG

                    ############################################################
                        if sgownerid:
                            ec2_response = ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running','stopped','stopping','pending']}])
                            sg_table_scan = sg_table.scan(FilterExpression=Attr('OwnerId').eq(sg['OwnerId']) & Attr('Region').eq(region))
                            print(len(sg_table_scan['Items']))
                            print(sg_table_scan)
                            sg_table_scan_ext = sg_table_scan['Items']
                            
                            while sg_table_scan.get('LastEvaluatedKey'):
                                sg_table_scan = sg_table.scan(ExclusiveStartKey=sg_table_scan['LastEvaluatedKey'])
                                print('-------extension---------')
                                print(len(sg_table_scan['Items']))
                                sg_table_scan_ext += sg_table_scan['Items']
                                print(len(sg_table_scan_ext))
                            for item in sg_table_scan_ext:
                                #if region == item['Region'] :
                                    
                                    for r in ec2_response['Reservations']: #describe instance iteration
                                        for i in r['Instances'] : #instance iteration

                                            for csg in i['SecurityGroups']: #security group iteration for getting securityId
                                                if item['SecurityGroupId'] == csg['GroupId'] :
                                                        sginstanceidlist.append(i['InstanceId'])

                                    sg_table.update_item ( #inserting items into table
                                            Key={
                                                'SecurityGroupId':item['SecurityGroupId'],
                                                'RulesCount' : item['RulesCount']
												#'OwnerId' : item['OwnerId']
                                            },
                                            UpdateExpression="set InstanceId= :r",
                                            ExpressionAttributeValues={
                                                ':r' : sginstanceidlist,

                                            },
                                            ReturnValues="UPDATED_NEW"
														)
                                    clearlist(sginstanceidlist)


            except Exception :
                print(traceback.format_exc())

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


        #############################################################

                            #MAIN FUNCTION

        #############################################################

        try :

            tagdict = {} #temproary dict to store tags for each iteration
            region_list = ['us-east-1','us-east-2', 'us-west-1', 'us-west-2']

            def clearlist(tlis): #clearing list
                    tlis[:] = []
            def cleardict(tdict): #clearing dictonary
                    tdict.clear()

            iam_client = boto3.client('iam')
            iam_response = iam_client.list_account_aliases()
            if iam_response.get('AccountAliases') :
                account_alias = iam_response['AccountAliases'][0]
            else :
                account_alias = 'No Alias'

            sts_client_account = boto3.client('sts').get_caller_identity()['Account']

            sts_client = boto3.client('sts')
            assumedRoleObject = sts_client.assume_role(
            RoleArn="arn:aws:iam::620890749476:role/Assetsinventory_Trusted_DynamoDB",
            RoleSessionName="assumerole2"
            )
            credentials = assumedRoleObject['Credentials']
            dynamodb_resource = boto3.resource('dynamodb', region_name = 'us-east-1', aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])

            todaysdatetime = str(timeconverter(datetime.now())) + ' CST'

            sginven()

        except Exception as e:
            print(traceback.format_exc())

        return "Success"

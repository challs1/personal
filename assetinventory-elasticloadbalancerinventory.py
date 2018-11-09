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
                #GET ELB INVENTORY AND PUT IN DYNAMODB
        ###########################################################
        def elbinventory() :
            elb_id  = []
            elbcountlist = []
            elbtagdict = {}
            elblistener = {}
            elbinstances = []
            elbsg = []
            
            dynamodb_table = dynamodb_resource.Table('elasticloadbalancerinventory')
            sts_client_account = boto3.client('sts').get_caller_identity()['Account']
            ec2_region = boto3.client('ec2').describe_regions()['Regions']
            for region in ec2_region:
                marker = None
                marker1= None
                inimarkercheck = True
                inimarkercheckv2 = True
                print(region['RegionName'])
                print('==================================================')
                
                elb_client = boto3.client('elb', region_name = region['RegionName'])
                elbv2_client = boto3.client('elbv2', region_name = region['RegionName'])
                
               
                while inimarkercheck:
                    if marker:
                        elb_response = elb_client.describe_load_balancers(Marker=marker)
                    else:
                        elb_response = elb_client.describe_load_balancers()
                    print(elb_response)
                    if elb_response.get('Marker'):
                        marker = elb_response['Marker']
                    else:
                        inimarkercheck  = False
                    for elbres in elb_response['LoadBalancerDescriptions']:
                        
                        #createdtime = timeconverter(elbres['CreatedTime'])
                        elbcount = sts_client_account + ' - ' + region['RegionName'] + ' - ' + timeconverter(elbres['CreatedTime']) + ' CST'
                        print(elbcount)
                        elbcountlist.append(elbcount)
                        elb_id.append(elbres['LoadBalancerName'])
                        for elblisite in elbres['ListenerDescriptions']:
                            elblistener.update(elblisite['Listener'])
                            elblis = elblisite['Listener']
                            if elblis.get('SSLCertificateId'):
                                sslCertficate = elblis['SSLCertificateId']
                            else:
                                sslCertficate = "No Certficate"
                                
                        for elbins in elbres['Instances']:
                            elbinstances.append(elbins['InstanceId'])
                        for esg in elbres['SecurityGroups']:
                            elbsg.append(esg)
                            
                        elb_tags = elb_client.describe_tags(LoadBalancerNames=[elbres['LoadBalancerName']])
                        print(elb_tags)
                        for elbtags in elb_tags['TagDescriptions']:
                            print(elbtags['Tags'])
                            if elbtags['Tags']:
                                for etag in elbtags['Tags']:
                                    elbtagdict[etag['Key']] = etag['Value']
                            
                            else:
                                print("No tags")
                        
                        
                        insertelbdataintodynamodb(dynamodb_table,elbres['LoadBalancerName'],elbcount,sts_client_account,region['RegionName'], elbres['DNSName'],elblistener,sslCertficate,elbres['VPCId'],elbinstances,elbsg,'classic',elbtagdict)
                        
                        elbsg[:] = []
                        elbinstances[:] = []
                        elblistener.clear()
                        elbtagdict.clear()
                    
                    
                while inimarkercheckv2:
                    if marker1:
                        elbv2_response =elbv2_client.describe_load_balancers(Marker=marker1)
                    else:
                        elbv2_response = elbv2_client.describe_load_balancers()
                    print(elbv2_response)
                    if elbv2_response.get('Marker'):
                        marker = elbv2_response['Marker']
                    else:
                        inimarkercheckv2  = False
                    for elbresv2 in elbv2_response['LoadBalancers']:
                        elbcountv2 = sts_client_account + ' - ' + region['RegionName'] + ' - ' + timeconverter(elbresv2['CreatedTime']) + ' CST'
                        print(elbcountv2)
                        elbcountlist.append(elbcountv2)
                        elb_id.append(elbresv2['LoadBalancerName'])
                       
                        for esgv2 in elbresv2['SecurityGroups']:
                            elbsg.append(esg)
                            
                        elbv2_lis_res=elbv2_client.describe_listeners(LoadBalancerArn=elbresv2['LoadBalancerArn'])
                        for elbv2lisite in elbv2_lis_res['Listeners']:
                            elblistener['Port'] = elbv2lisite['Port']
                            elblistener['Protocol'] = elbv2lisite['Protocol']
                            if elbv2lisite.get('Certificates'):
                                for sslcert in elbv2lisite['Certificates']:
                                    sslcertficatev2 = sslcert['CertificateArn']
                            else:
                                sslcertficatev2 = "No Certficate"
                        
                        elbv2_tags = elbv2_client.describe_tags(ResourceArns=[elbresv2['LoadBalancerArn']])
                        print(elbv2_tags)
                        for elbv2tags in elbv2_tags['TagDescriptions']:
                            print(elbv2tags['Tags'])
                            if elbv2tags['Tags']:
                                for ev2tag in elbv2tags['Tags']:
                                    elbtagdict[ev2tag['Key']] = ev2tag['Value']
                            
                            else:
                                print("No tags")
                        
                        insertelbdataintodynamodb(dynamodb_table,elbresv2['LoadBalancerName'],elbcountv2,sts_client_account,region['RegionName'], elbresv2['DNSName'],elblistener,sslcertficatev2,elbresv2['VpcId'],elbinstances,elbsg,elbresv2['Type'],elbtagdict)
                        
                        elbsg[:] = []
                        elbinstances[:] = []
                        elblistener.clear()      
                        elbtagdict.clear()
               
            print(elb_id)
            print(elbcountlist)
            if not elb_id :
                elb_id.append('emptylist')
            searchdeletedelb(elb_id,elbcountlist,dynamodb_table,sts_client_account)     
            
            
        ############################################################
                        #INserting data into dynamodb
        ############################################################
                    
        def insertelbdataintodynamodb(dynamodb_table,elbname,elbcount,sts_client_account,region, elbdnsname,elblistener,sslCertficate,elbvpcid,elbinstances,elbsg,elbtype,elbtagdict):
            dynamodb_table.put_item (
                    Item={
                        'ELBName': elbname,
                        'ELBCount' : elbcount,
                        'OwnerId' : sts_client_account,
                        'OwnerAlias': account_alias,
                        'Region' : region,
                        'LastExecutedTime' : todaysdatetime,
                        'DNSName' : elbdnsname,
                        'Listener' : elblistener,
                        'SSLCertificateId' : sslCertficate,
                        'VPC' : elbvpcid,
                        'Instances' : elbinstances,
                        'SG' : elbsg,
                        'Type' : elbtype,
                        'ELBStatus' : 'Active',
                        'Tags' : elbtagdict,
                        
                    })
                   
             
        ###########################################################
                #SEARCH FOR DELETED ELB
        ###########################################################
        def searchdeletedelb(rds_id,rdscountlist,rds_table,sts_client_account) :
                rds_table_scan = rds_table.scan(FilterExpression=Attr('OwnerId').eq(sts_client_account) & Attr('ELBStatus').ne('Deleted'))
                print(len(rds_table_scan['Items']))
                rds_table_scan_ext = rds_table_scan['Items']
                
                while rds_table_scan.get('LastEvaluatedKey'):
                    rds_table_scan = rds_table.scan(ExclusiveStartKey=rds_table_scan['LastEvaluatedKey'],FilterExpression=Attr('OwnerId').eq(sts_client_account) & Attr('ELBStatus').ne('Deleted'))
                    print('-------extension---------')
                    print(len(rds_table_scan['Items']))
                    rds_table_scan_ext += rds_table_scan['Items']
                    print(len(rds_table_scan_ext))
                print('---------------------------------------')
                print('Looking for Deleted ELB')
                for items in rds_table_scan_ext :
                    
                    if items['ELBStatus'] != 'Deleted' :
                        for rid in rds_id :
                            if items['ELBName'] == rid:
                                matid = 'matched'
                                break
                            else :
                                matid = 'not matched'
                        if matid == 'matched' :
                            for rcount in rdscountlist :
                                if items['ELBCount'] == rcount:
                                    matid = 'matched'
                                    break
                                else :
                                    matid = 'not matched'
                        if matid == 'not matched' : #and ownerid == items['OwnerId']:
                            print("Found Deleted ELB")
                            print(items['ELBName'])
                            print('================================')
                            response = rds_table.update_item(
                                       Key={
                                            'ELBName':items['ELBName'],
                                            'ELBCount' : items['ELBCount']
                                        },
                                        UpdateExpression="set ELBStatus= :r, DeletedTime= :d",
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
        
        elbinventory()
        return 'success'
    except Exception :
        print(traceback.format_exc())
        return 'failed'
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
                #GET DynamoDB INVENTORY AND PUT IN DYNAMODB
        ###########################################################
     
        def elasticbeanstalkinventory():
            elasticbeanstalklist = []
            elasticbeanstalkcountlist = []
            securitygroupidslist = []
            ebs_ins_name = []
            elbsg = []
            
            dynamodb_table = dynamodb_resource.Table('elasticbeanstalkinventory')
            sts_client_account = boto3.client('sts').get_caller_identity()['Account']
            ec2_region = boto3.client('ec2').describe_regions()['Regions']
            for region in ec2_region:
                if region['RegionName'] != "ap-northeast-3": 
                    print(region['RegionName'])
                    print('==================================================')
                    elasticbeanstalk_client = boto3.client('elasticbeanstalk', region_name = region['RegionName'])
                    elasticbeanstalk_response = elasticbeanstalk_client.describe_applications()
                    print(elasticbeanstalk_response)
                    for ebsres in elasticbeanstalk_response['Applications'] :
                        elasticbeanstalklist.append(ebsres['ApplicationName']) 
                        creationdatetime = timeconverter(ebsres['DateCreated']) + ' CST'
                        ebscount = sts_client_account+ ' - ' +region['RegionName']+ ' - ' +creationdatetime
                        
                        elasticbeanstalk_env_response= elasticbeanstalk_client.describe_environments(ApplicationName=ebsres['ApplicationName'])
                        
                        print(elasticbeanstalk_env_response)
                       
                        for ebsenv in elasticbeanstalk_env_response['Environments'] :
                            if ebsenv['Status'] != 'Terminated' :
                                envcreationdatetime1 = timeconverter(ebsenv['DateCreated']) + ' CST'
                                print(creationdatetime)
                                ebscount1 = ebsenv['EnvironmentName']+ ' - '+envcreationdatetime1
                                ebscount2 = ebscount+ ' - '+ebscount1
                                print(ebscount1)
                                
                                print(ebscount1)
                                elasticbeanstalkcountlist.append(ebscount2)
                                
                                print(ebsenv['Health'])
                                ebshealth = ebsenv['Health']
                                
                                if ebsenv.get('HealthStatus'):
                                    healthstatus = ebsenv['HealthStatus']
                                else:
                                    healthstatus = 'no status'
                                
                                
                                ebstier = ebsenv['Tier']['Name']
                                print(ebsenv['Tier']['Name'])
                                
                                envname = ebsenv['EnvironmentName']
                                print(ebsenv['EnvironmentName'])
                                envid = ebsenv['EnvironmentId']
                                
                                envupdated = timeconverter(ebsenv['DateUpdated']) + ' CST'
                                print(ebsenv['DateUpdated'])
                                
                                envstatus ='Active'
                                
                               
                                
                                ebs_resource = elasticbeanstalk_client.describe_environment_resources(EnvironmentId=envid)['EnvironmentResources']
                                print(ebs_resource)
                                
                                if ebs_resource['AutoScalingGroups']:
                                    print(ebs_resource['AutoScalingGroups'])
                                    for ebs_asg in ebs_resource['AutoScalingGroups']:
                                        ebs_asg_name = ebs_asg["Name"]
                                else:
                                    ebs_asg_name = "None"
                                        
                                if ebs_resource['LaunchConfigurations']:
                                    print(ebs_resource['LaunchConfigurations'])
                                    for ebs_lconfig in ebs_resource['LaunchConfigurations']:
                                        ebs_lconfig_name = ebs_lconfig['Name']
                                        print(ebs_lconfig_name)
                                        
                                        
                                else:
                                    ebs_lconfig_name = "None"
                                            
                                if ebs_resource['Instances']:
                                    print(ebs_resource['Instances'])
                                    for ebs_ins in ebs_resource['Instances']:
                                            ebs_ins_name.append(ebs_ins['Id'])
                                            ec2_client_sg = boto3.client('ec2', region_name = region['RegionName'])
                                            ec2_sg_res = ec2_client_sg.describe_instances(InstanceIds=[ebs_ins['Id']])
                                            print(ec2_sg_res)
                                            for reservat in ec2_sg_res['Reservations']:
                                                for insres in reservat['Instances']:
                                                    for sg in insres['SecurityGroups']: 
                                                        print(sg)
                                                        securitygroupidslist.append(sg['GroupId']) 
                                else:
                                    ebs_ins_name.append("None")
                                    
                                if ebs_resource['LoadBalancers']:
                                    print(ebs_resource['LoadBalancers'])
                                    for ebs_lbal in ebs_resource['LoadBalancers']:
                                        ebs_lbal_name = ebs_lbal['Name']
                                        
                                        
                                else:
                                    ebs_lbal_name = "None"
                                    #elbdns = "None"
                                    #elbsg.append("None")
                                
                                elasticbeanstalk_tag_response=elasticbeanstalk_client.list_tags_for_resource(ResourceArn=ebsenv['EnvironmentArn'])
                                for tags in elasticbeanstalk_tag_response['ResourceTags']:
                                    if tags['Value'] :
                                        tagdict[tags['Key']] = tags['Value']    
                                    else:
                                        tagdict[tags['Key']] = 'null'
                                print(tagdict) 
                                print()
                                dynbinsertdata(dynamodb_table,ebsres['ApplicationName'],region['RegionName'],sts_client_account,creationdatetime,ebscount2,ebshealth,healthstatus,ebstier,envname,envcreationdatetime1,envupdated,envstatus,tagdict,ebs_lbal_name,envid,ebs_asg_name,ebs_lconfig_name,ebs_ins_name,securitygroupidslist)
                                ebscount2 = ''
                                securitygroupidslist[:] = []
                                ebs_ins_name[:] = []
                                #elbsg[:] = []
                        if not elasticbeanstalk_env_response['Environments']:
                                ebshealth = 'No'
                                healthstatus = 'No'
                                ebstier = 'No'
                                envname = 'No Environment'
                                envupdated = 'No'
                                envcreationdatetime1 ='No'
                                envstatus = 'No'
                                ebs_lbal_name = "No"
                                envid = "No"
                                ebs_asg_name = "No"
                                ebs_lconfig_name = "No"
                                #elbdns = "No"
                                
                                
                                elasticbeanstalkcountlist.append(ebscount)
                                dynbinsertdata(dynamodb_table,ebsres['ApplicationName'],region['RegionName'],sts_client_account,creationdatetime,ebscount,ebshealth,healthstatus,ebstier,envname,envcreationdatetime1,envupdated,envstatus,tagdict,ebs_lbal_name,envid,ebs_asg_name,ebs_lconfig_name,ebs_ins_name,securitygroupidslist)
                
            if not elasticbeanstalklist :
                elasticbeanstalklist.append('emptylist')
            searchdeleteddynamodb(elasticbeanstalklist,elasticbeanstalkcountlist,dynamodb_table,sts_client_account)
        ###########################################################
                #SEARCH FOR DELETED EBS
        ###########################################################
        def searchdeleteddynamodb(reslist,rescountlist,res_table,sts_client_account) :
                print(reslist)
                print(rescountlist)
                res_table_scan = res_table.scan(FilterExpression=Attr('OwnerId').eq(sts_client_account) & Attr('EnvStatus').ne('Deleted'))
                print(len(res_table_scan['Items']))
                res_table_scan_ext = res_table_scan['Items']
                
                while res_table_scan.get('LastEvaluatedKey'):
                    res_table_scan = res_table.scan(ExclusiveStartKey=res_table_scan['LastEvaluatedKey'],FilterExpression=Attr('OwnerId').eq(sts_client_account) & Attr('EnvStatus').ne('Deleted'))
                    print('-------extension---------')
                    print(len(res_table_scan['Items']))
                    res_table_scan_ext += res_table_scan['Items']
                    print(len(res_table_scan_ext))
                print('---------------------------------------')
                print('Looking for Deleted Elastic Bean Stalk')
                for items in res_table_scan_ext :
                    
                    if items['EnvStatus'] != 'Deleted' :
                        for res in reslist :
                            print(res)
                            if items['EBSAppName'] == res:
                                matid = 'matched'
                                break
                            else :
                                matid = 'not matched'
                        if matid == 'matched' :
                            for rescount in rescountlist :
                                print(rescount)
                                if items['EBSAppCount'] == rescount:
                                    matid = 'matched'
                                    break
                                else :
                                    matid = 'not matched'
                        if matid == 'not matched' : #and ownerid == items['OwnerId']:
                            print("Found Deleted EBS")
                            print(items['EBSAppName'])
                            print('================================')
                            response = res_table.update_item(
                                       Key={
                                            'EBSAppName':items['EBSAppName'],
                                            'EBSAppCount' : items['EBSAppCount']
                                        },
                                        UpdateExpression="set EnvStatus= :r, DeletedTime= :d",
                                        ExpressionAttributeValues={
                                            ':r' : 'Deleted',
                                            ':d' : todaysdatetime
                                        },
                                        ReturnValues="UPDATED_NEW"
                            )
        
        ###########################################################
                #INERT DATA INTO DYNAMODB
        ###########################################################
        def dynbinsertdata(dynamodb_table,ebsappname,region,sts_client_account,creationdatetime,ebscount,ebshealth,healthstatus,ebstier,envname,envcreationdatetime1,envupdated,envstatus,tagdict,ebs_lbal_name,envid,ebs_asg_name,ebs_lconfig_name,ebs_ins_name,securitygroupidslist):                
                dynamodb_table.put_item (
                    Item={
                                    'EBSAppName': ebsappname,
                                    'EBSAppCount' : ebscount,
                                    'OwnerId' : sts_client_account,
                                    'OwnerAlias' : account_alias,
                                    'EnvironmentName' : envname,
                                    'EnvironmentId' : envid,
                                    'EnvCreationDate' : envcreationdatetime1,
                                    'EnvUpdatedDate' : envupdated,
                                    'EbsTier' : ebstier,
                                    'Health' : ebshealth,
                                    "HealthStatus" : healthstatus,
                                    'Region' : region,
                                    'EnvStatus' : envstatus,
                                    'LoadBalancer': ebs_lbal_name,
                                    'AutoScalingGroups': ebs_asg_name, 
                                    'LaunchConfigurations' :  ebs_lconfig_name,
                                    'Instances': ebs_ins_name,
                                    'SecurityGroups' : securitygroupidslist,
                                    #'LBSecurityGroups' : elbsg,
                                    #'DNSName' : elbdns,
                                    'AppCreationDate' : creationdatetime,
                                    'Tags' : tagdict,
                                    'LastExecutedTime' : todaysdatetime,
                                })  
                cleardict(tagdict)
                        
    
    
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
        def cleardict(tdict): 
            tdict.clear()
        def clearlist(tlis): #clearing list
            tlis[:] = []
            
    
    ###########################################################
                #Elastic Bean stalk starts here
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
        
        elasticbeanstalkinventory()
        return 'success'
    except Exception :
        print(traceback.format_exc())
        return 'failed'

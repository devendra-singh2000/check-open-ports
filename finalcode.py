import boto3
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
s=''
region = ['us-east-1','us-east-2']
for i in region:
    s=s+"*******   Security Group for Region "+i+" ***"+"\n\n"
    ec2 = boto3.client('ec2', region_name=i)
    response = ec2.describe_security_groups()
    for sg in response['SecurityGroups']:
        allport=[] # to list all open port
        other_port=[] # to list those port which are opened publicly
        port80and443=[] # to list only port 80 and 443 if they open publicly 
        s=s+"*******************  "+sg['GroupId']+"  ******************"+"\n\n"
        for ippermission in sg['IpPermissions']: 
            if((ippermission["IpRanges"][0]['CidrIp']=='0.0.0.0/0' and ippermission['IpProtocol'] != '-1') and (ippermission['FromPort'] not in [80,443])):
                other_port.append(ippermission['FromPort'])
                allport.append(ippermission['FromPort'])
            elif(ippermission["IpRanges"][0]['CidrIp']=='0.0.0.0/0' and ippermission['IpProtocol'] == '-1'):
                allport.append(-1) # -1 represent All port All traffic 
                other_port.append(-1)
            elif((ippermission["IpRanges"][0]['CidrIp']=='0.0.0.0/0' and ippermission['IpProtocol'] != '-1') and (ippermission['FromPort'] in [80,443])):
                port80and443.append(ippermission['FromPort'])
                allport.append(ippermission['FromPort'])
            else:
                if(ippermission['IpProtocol']=='-1'):
                    allport.append(-1)
                else:
                    allport.append(ippermission['FromPort'])
        s=s+"******************* All Ports ***************************\n"        
        s=s+"All port open for this security group that is , "+sg['GroupId']+" = " + str(allport)+"\n"
        s=s+"******************* Publicly Open Ports  ***************************\n"
        s=s+"Ports of security group "+sg['GroupId']+" which are open publicly on the internet = "+str(other_port)+"\n"
        if(len(port80and443)>0):
            s=s+"Ports "+ str(port80and443) +" are also open publicly for the security group " +sg['GroupId']+"\n"
        s=s+"\n\n"
        s=s+"------\n\n"
    s=s+"\n\n\n"
text_file = open("final_data.txt", "w")
n = text_file.write(s)
text_file.close()
fromaddr = "EMAIL address of the sender"
toaddr = "EMAIL address of the receiver"
msg = MIMEMultipart()
msg['From'] = fromaddr
msg['To'] = toaddr
msg['Subject'] = "AWS Security Group  to Check Open Ports " # Subject of the Mail
body = s # "Body of the mail"
msg.attach(MIMEText(body, 'plain'))
filename = "final_data.txt"        # "File name with extension"
attachment = open("final_data.txt", "rb")   # "Path of the file"
p = MIMEBase('application', 'octet-stream')
p.set_payload((attachment).read())
encoders.encode_base64(p)
p.add_header('Content-Disposition', "attachment; filename= %s" % filename)
msg.attach(p)
s1 = smtplib.SMTP('smtp.gmail.com', 587)
s1.starttls()
s1.login(fromaddr, "Password_of_the_sender")
text = msg.as_string()  
s1.sendmail(fromaddr, toaddr, text)  
s1.quit()
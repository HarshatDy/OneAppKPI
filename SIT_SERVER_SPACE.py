import paramiko
import getpass
import os
import re 


def ssh_login(ip):
    result = []
    remote_path="/"
    port=22
    username='ognb'
    #password=getpass.getpass()
    password="ognb123"
    ssh=paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip,port,username,password, allow_agent=False)
    return ssh


def ssh_close(ssh: paramiko.SSHClient) -> None:
    if ssh:
        ssh.close()
        print("Sfkkig")



def bash_command(ssh: paramiko.SSHClient, cmd):
    result= []
    stdin, stdout, stderr = ssh.exec_command(cmd)
    output = stdout.read().decode()
    errors = stderr.read().decode()
    print(f" **********************************Running command {cmd} *********************************");
    result.append(output)
    result.append(errors)
    return result
    

def get_du_file(ssh: paramiko.SSHClient) -> None:
    sftp_client=ssh.open_sftp()
    sftp_client.get("/rsysfs/opt/radisys/oam-services/netconf_client/oam_du/config/oam_3gpp_odu_push.sh" , "./tmp_config/oam_3gpp_ognb_cu_push.sh")
    with open('./tmp_config/oam_3gpp_ognb_cu_push.sh') as t:
        print("OPNED TMP CONFIG")
        for line in t :
            pattern = "/opt/radisys/oam-services/netconf_client/(.*xml)"
            reg = re.search(pattern, line)
            if reg: 
                print(reg.group())
                pattern1 = '/config/(.*xml)'
                reg1 = re.search(pattern1, reg.group(1))
                filename = reg1.group(1)
                print(f"Downloaded {filename}")
                # exit(0)
                try: 
                    sftp_client.get(reg.group() , "tmp_config/"+filename)
                except IOError as e:
                    print(f"Error while downloading {filename}")


def get_cu_file(ssh: paramiko.SSHClient) -> None:
    sftp_client=ssh.open_sftp()
    sftp_client.get("/rsysfs/opt/radisys/oam-services/netconf_client/oam_cu/config/oam_3gpp_netconf_gnb_cu_push.sh" , "./tmp_config/oam_3gpp_ognb_cu_push.sh")
    with open('./tmp_config/oam_3gpp_ognb_cu_push.sh') as t:
        for line in t :
            pattern = '/opt/radisys/oam-services/netconf_client/(.*xml)'
            reg = re.search(pattern, line)
            if reg: 
                pattern1 = '/config/(.*xml)'
                reg1 = re.search(pattern1, reg.group(1))
                filename = reg1.group(1)
                print(f"Downloaded {filename}")
                # exit(0)
                sftp_client.get(reg.group() , "tmp_config/"+filename)            


def clean_config_files(flag):
    if flag:
        dir_name = './tmp_config'
        for filename in os.listdir(dir_name):
            file_path = os.path.join(dir_name, filename)
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)
                    print(f"Deleted {file_path}")
            except OSError as e:
                print(f"Error while Deleting file {file_path}")
        




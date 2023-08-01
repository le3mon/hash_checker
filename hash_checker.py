import argparse
import os
import json
import hashlib
import requests

work_dir = os.getcwd()
check_extension = ('.exe', '.dll')

def hash_parser(json, path):
    os.chdir(path)
    file_list = os.listdir(path)
    dir_list = []
    
    for i in file_list:
        if os.path.isdir(i):
            dir_list.append(i)
        
        else:
            if i.endswith(check_extension) == True:
                try:
                    with open(i, 'rb') as f:
                        data = f.read()
                        json['detail'].append({
                        'file_name':i,
                        'path':path+'\\'+i,
                        'md5':hashlib.md5(data).hexdigest(),
                        'sha-1':hashlib.sha1(data).hexdigest(),
                        'sha-256':hashlib.sha256(data).hexdigest()
                        })
                except:
                    print('{}\\{} file open error'.format(path, i))
            else:
                continue
    for i in dir_list:
        hash_parser(json, path+'\\'+i)

key_list = ('', '')
def hash_check(data:dict):
    headers = {'accept': 'application/json',
            'x-apikey': ''}
    i = 0
    for file in data['detail']:
        print(file['file_name'])
        
        headers['x-apikey'] = key_list[i%2]
        i += 1
        hash = file['sha-256']
        url = 'https://www.virustotal.com/api/v3/files/{}'.format(hash)
    
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                file['virus'] = 'True'
                file['malicious'] = res_json['data']['attributes']['last_analysis_stats']['malicious']
                file_path = '{}\\{}.json'.format(work_dir, file['sha-256'])
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(res_json, f, indent=2, ensure_ascii=False)
            else:
                file['virus'] = 'False'
        else:
            file['virus'] = 'Unknown'

parser = argparse.ArgumentParser()
parser.add_argument('-j', '--json', default=False, help='result json file Path')
parser.add_argument('-d', '--dir', default=False, help='source directory path')
args = parser.parse_args()

dir_list = []
dir_path = ''
dest_path = ''
json_data = {
    'detail':[]
}

if args.__dict__['dir']:
    dir_path = args.__dict__['dir']
    hash_parser(json_data, dir_path)
    # hash_check(json_data)
elif args.__dict__['json']:
    json_path = args.__dict__['json']
    j_f = open(json_path, 'r', encoding='utf-8')
    json_data = json.load(j_f)
    hash_check(json_data)

with open(work_dir+'\\result.json', 'w', encoding='utf-8') as f:
    json.dump(json_data, f, indent=2, ensure_ascii=False)
import argparse
import os
import json
import hashlib

def hash_parse(json, path):
    os.chdir(path)
    dir_num = 0
    file_list = os.listdir(path)
    dir_list = []
    
    for i in file_list:
        if os.path.isdir(i):
            dir_num += 1
            dir_list.append(i)
        
        else:
            with open(i, 'rb') as f:
                data = f.read()
                json['detail'].append({
                'file_name':i,
                'path':path+'\\'+i,
                'md5':hashlib.md5(data).hexdigest(),
                'sha-1':hashlib.sha1(data).hexdigest(),
                'sha-256':hashlib.sha256(data).hexdigest()
                })    
            
    for i in dir_list:
        hash_parse(json, path+'\\'+i)

parser = argparse.ArgumentParser()
parser.add_argument('-j', '--json', default=False, help='result json file Path')
parser.add_argument('-d', '--dir', default=False, help='source directory path')
parser.add_argument('-f', '--file', default=False, help='file path')
args = parser.parse_args()

dir_list = []
dir_path = ''
dest_path = ''
json_data = {
    'test':'test',
    'detail':[]
}

# if args.__dict__['dir']:
    # dir_path = args.__dict__['dir']
    # dir_list = os.listdir(dir_path)
    # os.chdir(dir_path)

hash_parse(json_data, dir_path)

with open(dest_path+'\\result.json', 'w') as f:
    json.dump(json_data, f, indent=2, ensure_ascii=False)
from ruamel import yaml
import os
import re
import json

source_dir = "C:\\Users\\Jon\\Documents\\SIGMA\\rules"
sigma_githead = "C:\\Users\\Jon\\Documents\\SIGMA\\.git\\refs\\heads\\master"

with open(sigma_githead, 'r') as fin:
    commit = fin.read().rstrip()

files_list = []
ttp_list = {}

# Walk entire SIGMA repo for YAML rule files, append to file list
for dp, dn, fn in os.walk(source_dir):
    for file in fn:
        if file.endswith(".yml"):
            files_list.append(os.path.join(dp, file))

# Go through file list and load YAML one file at a time
for yaml_file in files_list:
    with open(yaml_file, 'r') as stream:
        current_file = yaml_file.rsplit("\\", 1)[1]
        try:
            # Some YAML files have multiple YAML files in one, use load all
            full_yaml_data = list(yaml.safe_load_all(stream))
            for yaml_data in full_yaml_data:
                # Only interested on YAML that has tags section
                if 'tags' in yaml_data:
                    # print(yaml_data['title'])
                    # Check tags for attack techniques
                    for tag in yaml_data['tags']:
                        ttp = re.search(r"attack.t(\d{4})", tag)
                        # If we find a technique ID, extract it and add/increment entry in TTP list
                        if ttp:
                            ttp_num = ttp[1]
                            if ttp_num not in ttp_list:
                                ttp_list[ttp_num] = [1, []]
                                ttp_list[ttp_num][1].append(current_file)
                            else:
                                ttp_list[ttp_num][0] += 1
                                ttp_list[ttp_num][1].append(current_file)
        except yaml.YAMLError as exc:
            print(exc)

# Print sorted TTP list by count of rules
# s = [(k, ttp_list[k]) for k in sorted(ttp_list, key=ttp_list.get, reverse=True)]
# for k, v in s:
#     print("TTP: " + k + "\t Count: " + str(v))

# Save max score for the layer
# max_score = max(ttp_list.values())

# Time to modify the navigator layer
with open("layer.json", "r") as json_read_file:
    data = json.load(json_read_file)

data['name'] = "SIGMA Rule Coverage"
# Set scaling for gradient
data['gradient']['minValue'] = 0
data['gradient']['maxValue'] = 2
data['description'] = "Accurate to commit #: " + commit + '\n' \
    + "https://github.com/Neo23x0/sigma/commit/" + commit

for technique in data['techniques']:
    ttp_id = technique['techniqueID'].lstrip("T")
    if ttp_id in ttp_list.keys():
        technique['score'] = ttp_list[ttp_id][0]
        technique['comment'] = "\n".join(ttp_list[ttp_id][1])

# Dump updates into output layer
with open("layer_test.json", "w") as output:
    json.dump(data, output, indent='\t')

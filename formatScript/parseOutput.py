import json
import subprocess

recap_tab = []

def add_entry_to_recap_tab(binary, path,function):
    entry = {
        "binary": binary,
        "function":function,
        "path": path
    }
    recap_tab.append(entry)
    write_recap_tab()

    
def write_recap_tab():
    with open('recap.json', 'w') as file:
        json.dump(recap_tab, file, indent=4)


command="kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f"

process = subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
i=0

for line in iter(process.stdout.readline, ''):
    # Process each line as needed
    try:
        ind=-1
        print (f'\n\nNEW OBJECT:{i}\n')
        i+=1
        json_data = json.loads(line)
        if list(json_data.keys())[0]=='process_kprobe':
            # Access and check the values of available fields
            if 'binary' in json_data['process_kprobe']['process']:
                binary_value = json_data['process_kprobe']['process']['binary']
                print(f"Binary value: {binary_value}")

            if 'function_name' in json_data['process_kprobe']:
                function_name=json_data['process_kprobe']['function_name']
                print(f"Function used: {function_name}")
            else:
                function_name='no function'

            if 'args' in json_data['process_kprobe']:
                args_value = json_data['process_kprobe']['args']
                for j,item in enumerate(args_value):
                    if 'file_arg' in item:
                        ind=j
                if ind != -1:
                    path=args_value[ind]['file_arg']['path']
                    print(f"PATH:{path}")
                else:
                    path='no path'
                

            add_entry_to_recap_tab(binary_value,path,function_name)
            # ... Add more checks for other fields as needed

            # Print the complete JSON object
            #print(json.dumps(json_data, indent=4))
        else:
            print(list(json_data.keys())[0])
            if list(json_data.keys())[0]=='process_exec':
                json_data=json_data['process_exec']
                if 'binary' in json_data['process']:
                    binary_value = json_data['process']['binary']
                    if 'arguments' in json_data:
                        path=json_data['process']['arguments']
                    else:
                        path='no path'
                    print(f"Binary value: {binary_value}")
                    add_entry_to_recap_tab(binary_value,path,'exec')
    except json.JSONDecodeError:
        # Handle non-JSON lines if needed
        pass




# Wait for the process to finish
process.wait()

# # Parse the JSON input
# data = json.loads(input_json)

# # Print the constructed Python object
# if 'binary' in data['process_kprobe']['process']:
#     binary_value = data['process_kprobe']['process']['binary']
#     print(f"Binary value: {binary_value}")

# if 'args' in data['process_kprobe']:
#     args_value = data['process_kprobe']['args'][0]['file_arg']['path']
#     print(f"Args value: {args_value}")
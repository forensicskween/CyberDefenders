import subprocess
import os

path = 'winevt/Logs'
for filename in os.listdir(path):
    f = os.path.join(path, filename)
    if os.path.isfile(f):
        output_dir = 'output/' + filename.replace('.evtx', '')
        if os.path.isdir(output_dir):
            print("Exists")
        else:
            print("Doesn't exists")
            os.mkdir(folder)
        with open(output_name, 'wb') as out:
            parser = subprocess.Popen(["evtxtract","-s", f, "-o", output_dir], shell=False, stdout=out,
            stderr=subprocess.PIPE)
            out.close()

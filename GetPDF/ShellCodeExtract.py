from binascii import unhexlify
import pylibemu
import os
import argparse

def get_payloads(in_file):
 result = []
 with open(in_file, 'r') as f:
    for line in f.readlines():
        if 'unescape' in line:
            result.append(line.split("="))
    f.close()
    big = [i for i in result if i and len(i[1]) >= 80]
    for l in big:
       l[:] = [x[x.find("(")+1:x.find(")")] for x in l]
       l[:] = [x.replace('\t', '') for x in l]
       l[:] = [x.replace('"', '') for x in l]
       l[:] = [x.lstrip('var ') for x in l]
       l[1] = l[1].replace('%u','').encode('unicode-escape')
       l[1] = unhexlify(l[1])
       l[1] = bytes([c for t in zip(l[1][1::2], l[1][::2]) for c in t])
    return big

def sctest_save(list):
    for l in list:
     do_sctest_item(l)

def do_files(ls):
 for l in ls:
   filename = "%s" % l[0]
   i = 0
   while os.path.exists(f"{filename}{i}.sc"):
    i += 1
   outfile = open(f"{filename}{i}.sc", "wb")
   outfile.write(l[1])
   outfile.close

def do_sctest(file):
        item = open(file, 'rb').read()
        maxSteps = 10000000
        emu = pylibemu.Emulator(2048)
        shellcodeOffset = 8
        emu.prepare(item, shellcodeOffset)
        emu.test(maxSteps)
        output = emu.emu_profile_output
        print('sctest ', output)

def do_sctest_item(el):
        item = el[1]
        maxSteps = 10000000
        emu = pylibemu.Emulator(2048)
        shellcodeOffset = 0
        emu.prepare(item, shellcodeOffset)
        emu.test(maxSteps)
        output = emu.emu_profile_output
        filename = "%s" % el[0]
        i = 0
        while os.path.exists(f"{filename}{i}.txt"):
            i += 1
        outfile = open(f"{filename}{i}.txt", "wb")
        outfile.write(output)
        outfile.close

def main():
    parser = argparse.ArgumentParser(description='Extract Shellcode')
    parser.add_argument('-f', '--file', nargs=1, help='path to PS1', required=True)
    parser.add_argument('-x',  '--export', help='export shellcodes', required=False, action='store_true')
    
    args = parser.parse_args()
    
    file = args.file[0]
    export = 0
    if args.export is not None:
     export = 1
    
    list = get_payloads(file)
    sctest_save(list)
    
    if export :
     do_files(list)
     
if __name__ == "__main__":
    main()

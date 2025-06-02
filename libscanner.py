import lief
import argparse
from pathlib import Path
from time import sleep

parser = argparse.ArgumentParser(description='Search for potentially interesting calls to sprintf')
parser.add_argument('path', help='Path to root folder')
parser.add_argument('--output', help='CSV output file containing interesting calls to analyze', default=None)

args = parser.parse_args()

rootPath = Path(args.path)
paths = []
exported_functions = []
imported_functions = []

imports = []


for filePath in rootPath.rglob('*'):
    #print(filePath)
    if filePath.is_file() and lief.is_elf(str(filePath)):
        bin = lief.ELF.parse(filePath)
        if bin:
            for func in bin.exported_functions:
                exported_functions.append({"path":filePath, "func": func.name})

for filePath in rootPath.rglob('*'):
    if filePath.is_file() and lief.is_elf(str(filePath)):
        bin = lief.ELF.parse(filePath)
        if bin:
            for func in bin.imported_functions:
                exps = list(filter(lambda exp: exp['func'] == func.name, exported_functions))
                
                for exp in exps:
                    print(str(filePath) +"," + func.name +","+ str(exp['path']))


# Checks all jar files for Jndilookup.class. Lists out any files containing this class. 
from logging import exception
import os
import fnmatch
import zipfile
import json
import socket

path = '/'

jarfiles = []
jndimatch = []
jarfiles.extend([os.path.join(dirpath, f)
    for dirpath, dirnames, files in os.walk(path)
    for f in fnmatch.filter(files, '*.jar')])

def iter_jarfile(fobj, parents=None, stats=None):
    """
    Yields (zfile, zinfo, zpath, parents) for each file in zipfile that matches `FILENAMES` or `JAR_EXTENSIONS` (recursively)
    """
    parents = parents or []
    
    try :
        with zipfile.ZipFile(fobj) as zfile:
            for zinfo in zfile.infolist():
                if fnmatch.fnmatch((zinfo.filename),"*JNDILookup.class"):
                    jndimatch.append(fobj)
    except:
        print(exception)

for f in jarfiles:
    iter_jarfile(f)

if jndimatch:
    hostname=socket.gethostname()
    domain=socket.getfqdn()
    stringJNDI = str(jndimatch)
    vulnfiles = stringJNDI
    filecount = len(jndimatch)
    print('WARNING: ', filecount , 'potentially vulnerable files detected')
    print('Vulnerable Files:' , vulnfiles)

else:
    print('No vulnerable files detected')



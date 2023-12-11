import os.path
import subprocess

from pywin import *

if os.path.exists('\\\\vm-winsrv16-1\\shared'):
    command = f"net use Z: \\\\vm-winsrv16-1\\shared /user:leonardots N!1ra.29xSB"

    try:
        subprocess.check_output(command, shell=True)
        print('Success')
    except subprocess.CalledProcessError:
        print('Failed')

# def mapDrive(drive, networkPath, user, password, force=0):
#     print networkPath
#     if (os.path.exists(drive)):
#         print drive, " Drive in use, trying to unmap..."
#         if force:
#             try:
#                 win32wnet.WNetCancelConnection2(drive, 1, 1)
#                 print drive, "successfully unmapped..."
#             except:
#                 print drive, "Unmap failed, This might not be a network drive..."
#                 return -1
#         else:
#             print "Non-forcing call. Will not unmap..."
#             return -1
#     else:
#         print drive, " drive is free..."
#     if (os.path.exists(networkPath)):
#         print networkPath, " is found..."
#         print "Trying to map ", networkPath, " on to ", drive, " ....."
#         try:
#             win32wnet.WNetAddConnection2(win32netcon.RESOURCETYPE_DISK, drive, networkPath, None, user, password)
#         except:
#             print "Unexpected error..."
#             return -1
#         print "Mapping successful"
#         return 1
#     else:
#         print "Network path unreachable..."
#         return -1
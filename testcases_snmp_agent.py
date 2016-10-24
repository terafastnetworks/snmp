import nose
import time
import sys
from snmp import Snmp
from snmp_get_set_tables import TABLE_DICT

pol_dict = eval(open("snmp_config.txt").read())

host_addr = pol_dict['destinationHost']
version = pol_dict['version']
community = pol_dict['community']
community_ro = pol_dict['community_ro']
community_rw = pol_dict['community_rw']
community = pol_dict['community']
sec_user = pol_dict['security_user']
sec_level = pol_dict['security_level']
auth_protocol = pol_dict['auth_protocol']
auth_key = pol_dict['auth_key']
priv_protocol = pol_dict['priv_protocol']
priv_key = pol_dict['priv_key']
polatisOxcSize = pol_dict['polatisOxcSize']
prtlst = polatisOxcSize.split('x')


class TestSnmpAgent:


    @classmethod
    def setUpClass(cls):
        """
        Snmp Instance Created to access the test cases
        """
        
        cls.snmp_session = Snmp(host_addr, version, community, Timeout=10000000)
        cls.snmp_ro_session = Snmp(host_addr, version, community=community_ro, Timeout=10000000)
        cls.snmp_wr_session = Snmp(host_addr, version, community=community_rw, Timeout=10000000)
        cls.snmp_invalid_session = Snmp(host_addr, version, community='Invalid')
        cls.snmp_v3_session = Snmp(host_addr, version=3, SecName=sec_user, AuthProto=auth_protocol, SecLevel=sec_level,
                                   AuthPass=auth_key, PrivProto=priv_protocol,
                                   PrivPass=priv_key, Timeout=10000000)
        #cls.snmp_v3_invalid_user_session = Snmp(host_addr, version=3, SecName='InvalidUser', SecLevel='noAuthNoPriv', Timeout=10000000)
        #cls.snmp_v3_invalid_authkey_session = Snmp(host_addr, version=3, SecName=sec_user, AuthProto=auth_protocol,
                                                   #SecLevel='authNoPriv', AuthPass='InvalidAuthKey', Timeout=10000000)
        #cls.snmp_v3_invalid_privkey_session = Snmp(host_addr, version=3, SecName=sec_user, AuthProto=auth_protocol,
        #                                           SecLevel='authPriv', AuthPass=auth_key,
        #                                           PrivProto=priv_protocol, PrivPass='InvalidPrivKey', Timeout=10000000)

    "POLATIS SYS MIB"

    "SNMP v1 & v2c COMBINED TEST CASES"

    if version == 1 or version == 2:

        def test_get_polatisproductcode(self):
            """
            Query Snmpget for Polatis System Info ProductCode
            """
 
            self.snmp_session.create_box('test_get_polatisproductcode')
            try:
                result = self.snmp_session.snmp_get('polatisSysInfoProductCode.0')
            except BaseException as err:
                raise err
            if result['polatisSysInfoProductCode.0'] is not None:
                nose.tools.assert_equal(TABLE_DICT['polatisProductCode'], result['polatisSysInfoProductCode.0'],
                                        'Wrong value for GetPolatisSysInfoProduct'
                                        'Code: %s' % result['polatisSysInfoProductCode.0'])
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_getnext_polatisproductcode(self):
            """
            Query Snmpgetnext for Polatis System Info ProductCode
            """
            self.snmp_session.create_box('test_getnext_polatisproductcode')
            try:
                result = self.snmp_session.snmp_get_next('polatisSysInfoProductCode')
            except BaseException as err:
                raise err
            if 'polatisSysInfoProductCode.0' in result:
                nose.tools.assert_equal(TABLE_DICT['polatisProductCode'], result['polatisSysInfoProductCode.0'],
                                        'Wrong value for GetNextPolatisSysInfoProduct'
                                        'Code: %s' % result['polatisSysInfoProductCode.0'])
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_walk_polatisproductcode(self):
            """
            Query Snmpwalk for Polatis System Info ProductCode
            """
            self.snmp_session.create_box('test_walk_polatisproductcode')
            try:
                result = self.snmp_session.snmp_walk('polatisSysInfoProductCode')
            except BaseException as err:
                raise err
            if result:
                nose.tools.assert_equal(TABLE_DICT['polatisProductCode'], result['polatisSysInfoProductCode.0'],
                                        'Wrong value for Snmp WalkPolatisSysInfoProduct'
                                        'Code: %s' % result['polatisSysInfoProductCode.0'])
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_get_polatiserialnumber(self):
            """
            Query SnmpGet for Polatis System Info SerialNumber
            """
            self.snmp_session.create_box('test_get_polatiserialnumber')
            try:
                result = self.snmp_session.snmp_get('polatisSysInfoSerialNumber.0')
            except BaseException as err:
                raise err
            if result['polatisSysInfoSerialNumber.0'] is not None:
                nose.tools.assert_equal(TABLE_DICT['polatisSerialNumber'], result['polatisSysInfoSerialNumber.0'],
                                        'Wrong value for GetPolatisSysInfoSerial'
                                        'Number: %s' % result['polatisSysInfoSerialNumber.0'])
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_getnext_polatiserialnumber(self):
            """
            Query SnmpGetNext for Polatis System Info SerialNumber
            """
            self.snmp_session.create_box('test_getnext_polatiserialnumber')
            try:
                result = self.snmp_session.snmp_get_next('polatisSysInfoSerialNumber')
            except BaseException as err:
                raise err
            nose.tools.assert_equal(TABLE_DICT['polatisSerialNumber'], result['polatisSysInfoSerialNumber.0'],
                                    'Wrong value for GetNextPolatisSysInfoSerial'
                                    'Number: %s' % result)

        def test_walk_polatiserialnumber(self):
            """
            Query Snmpwalk for Polatis System Info Serial Number
            """
            self.snmp_session.create_box('test_walk_polatiserialnumber')
            try:
                result = self.snmp_session.snmp_walk('polatisSysInfoSerialNumber')
            except BaseException as err:
                raise err
            if result:
                nose.tools.assert_equal(TABLE_DICT['polatisSerialNumber'], result['polatisSysInfoSerialNumber.0'],
                                        'Wrong value for WalkPolatisSysInfoSerial'
                                        'Number: %s' % result['polatisSysInfoSerialNumber.0'])
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_get_polatisfirmwareversion(self):
            """
            Query Snmpget for Polatis System Info FirmWare Version
            """
            self.snmp_session.create_box('test_get_polatisfirmwareversion')
            try:
                result = self.snmp_session.snmp_get('polatisSysInfoFirmwareVersion.0')
            except BaseException as err:
                raise err
            if result['polatisSysInfoFirmwareVersion.0'] is not None:
                nose.tools.assert_equal(TABLE_DICT['polatisFirmwareVersion'], result['polatisSysInfoFirmwareVersion.0'],
                                        'Wrong value for GetPolatisSysInfoFirmware'
                                        'Version: %s' % result['polatisSysInfoFirmwareVersion.0'])
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_getnext_polatisfirmwareversion(self):
            """
            Query SnmpGetNext for Polatis System Info FirmWare Version
            """
            self.snmp_session.create_box('test_getnext_polatisfirmwareversion')
            try:
                result = self.snmp_session.snmp_get_next('polatisSysInfoFirmwareVersion')
            except BaseException as err:
                raise err

            nose.tools.assert_equal(TABLE_DICT['polatisFirmwareVersion'], result['polatisSysInfoFirmwareVersion.0'],
                                    'Wrong value for GetNextPolatisSysInfoFirmware'
                                    'Version: %s ' % result)

        def testWalkPolatisSysInfoFirmwareVersion(self):
            """
            Query Snmpwalk for Polatis System Info FirmWare Version
            """
            self.snmp_session.create_box('testWalkPolatisSysInfoFirmwareVersion')
            try:
                result = self.snmp_session.snmp_walk('polatisSysInfoFirmwareVersion')
            except BaseException as err:
                raise err
            if result:
                nose.tools.assert_equal(TABLE_DICT['polatisFirmwareVersion'], result['polatisSysInfoFirmwareVersion.0'],
                                        'Wrong value for WalkPolatisSysInfoFirmware'
                                        'Version: %s' % result['polatisSysInfoFirmwareVersion.0'])
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        "POLATIS SYSTEM CONTROL RESTART AGENT"

        if community == community_rw:
        #if 0:
            def test_restart_polatisystemcontrolagent(self):
                """
                SNMP Set Restart Polatis System Control Agent
                """
                self.snmp_session.create_box('test_restart_polatisystemcontrolagent')
                try:
                    uptime1 = self.snmp_session.snmp_get('sysUpTime.0')
                except BaseException as err:
                    raise Exception("Get SysUpTime Error:", err)
                try:
                    result = self.snmp_wr_session.snmp_set('polatisSysCtrlRestartAgent.0', 2, 'INTEGER')
                    #print "result : ", result
                except BaseException as err:
                    raise Exception("Get SysUpTime Error:", err)
                self.snmp_session.snmp_get('sysUpTime.0')
                while self.snmp_session.snmp_session.ErrorStr is not '':
                    print "Agent Service Restarting..."
                    self.snmp_session.snmp_get('sysUpTime.0')
                print "Agent is up now...!!!"
                uptime2 = self.snmp_session.snmp_get('sysUpTime.0')
                # Switch output while restart
                #POLATIS-SYS-MIB::polatisSysCtrlRestartAgent.0 = INTEGER: restart(2)
                nose.tools.assert_equal(1, result, "No Proper Output for the command..Timeout exception thrown:%s" % result)
                nose.tools.assert_greater(int(uptime1['sysUpTimeInstance.']), int(uptime2['sysUpTimeInstance.']),
                                          "Snmp Agent Not restarted")

            "POLATIS SYSTEM CONTROL REBOOT SYSTEM"

            def test_reboot_polatiscontrolsystem(self):
                """
                SNMP Set Polatis System Control Restart Agent
                """
                self.snmp_session.create_box('test_reboot_polatiscontrolsystem')
                try:
                    output = self.snmp_wr_session.snmp_set('polatisSysCtrlRebootSys.0', 2, 'INTEGER')
                except BaseException as err:
                    raise err
                nose.tools.assert_equal(1, output, 'Switch Reboot Action Not Successful: %s ' % output)
                nose.tools.assert_equal('', self.snmp_wr_session.snmp_session.ErrorStr,
                                        'Wrong Message while rebooting the '
                                        'switch:%s' % self.snmp_wr_session.snmp_session.ErrorStr)
                tme = 0.2
                while self.snmp_wr_session.snmp_session.ErrorStr is not '':
                    if tme < 100:
                        print "Switch Rebooting...Completed: %s" % tme
                    else:
                        print "Loading Configuration..."
                    self.snmp_wr_session.snmp_get('sysUpTime.0')
                    tme += 5.2
                print "Switch is up now...!!!"

        "POLATIS NETWORK CONFIGURATION TABLE"

        def test_snmptable_netconfigtable(self):
            """
            Query Polatis Netconfig Table through SnmpTable
            """
            self.snmp_session.create_box('test_snmptable_netconfigtable')
            try:
                output = self.snmp_session.snmp_table('polatisNetConfigTable')
            except BaseException as err:
                raise NameError(err)
            for key, value in output.iteritems():
                #print "key : " , key
                #print "TABLE_DICT[key] :", type(TABLE_DICT[key])
                #print "output[key]", type(output[key])
                #print "TABLE_DICT[key] :", TABLE_DICT[key]
                #print "output[key]", output[key]
                #strip_key = key[:-2]
                #nose.tools.assert_equal(TABLE_DICT[strip_key], output[key], 'Wrong Value for Get SnmpTable against Pola'
                                                                            #'tisNetconfigTable:{%s:%s}' % (key, value))
                nose.tools.assert_equal(TABLE_DICT[key], output[key], 'Wrong Value for Get SnmpTable against Pola'
                                                                            'tisNetconfigTable:{%s:%s}' % (key, value))

        def test_walk_netconfigtable(self):
            """
            Query Polatis Netconfig Table through SnmpWalk
            """
            self.snmp_session.create_box('test_walk_netconfigtable')
            try:
                output = self.snmp_session.snmp_walk('polatisNetConfigTable')
            except BaseException as err:
                raise err
            ##print output
            for key, value in output.iteritems():
                #strip_key = key[:-2]
                #nose.tools.assert_equal(TABLE_DICT[strip_key], output[key],
                #                        'Wrong Value for Get SnmpWalk against '
                #                        'PolatisNetconfigTable:{%s:%s}' % (key, value))
                nose.tools.assert_equal(TABLE_DICT[key], output[key],
                                        'Wrong Value for Get SnmpWalk against '
                                        'PolatisNetconfigTable:{%s:%s}' % (key, value))

        def test_get_eth0_netconfigipaddress(self):
            """
            Query Polatis Network Config IpAddress through SnmpGet
            """
            self.snmp_session.create_box('test_get_eth0_netconfigipaddress')
            try:
                result = self.snmp_session.snmp_get('polatisNetConfigIpAddress.1')
                #print "result : ", result
            except BaseException as err:
                raise err
            if result['polatisNetConfigIpAddress.1'] is not None:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigIpAddress.1'], result['polatisNetConfigIpAddress.1'],
                                        'Wrong value for GetPolatisNetConfigIpAddress')
            else:    
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_get_eth1_netconfigipaddress(self):
            """
            Query Polatis Network Config IpAddress through SnmpGet
            """
            self.snmp_session.create_box('test_get_eth1_netconfigipaddress')
            try:
                result = self.snmp_session.snmp_get('polatisNetConfigIpAddress.2')
                #print "result : ", result
            except BaseException as err:
                raise err
            if result['polatisNetConfigIpAddress.2'] is not None:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigIpAddress.2'], result['polatisNetConfigIpAddress.2'],
                                        'Wrong value for GetPolatisNetConfigIpAddress')
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_getnext_eth0_netconfigipaddress(self):
            """
            Query Polatis Network Config IpAddress through SnmpGetNext
            """
            self.snmp_session.create_box('test_getnext_eth0_netconfigipaddress')
            try:
                result = self.snmp_session.snmp_get_next('polatisNetConfigIpAddress.1')
                #print "result : ", result
            except BaseException as err:
                raise err
            nose.tools.assert_equal(TABLE_DICT['polatisNetConfigIpAddress.2'], result['polatisNetConfigIpAddress.2'],
                                    'Wrong value for GetNextPolatisNetConfigIpAddress: %s' % result)

        def test_getnext_eth1_netconfigipaddress(self):
            """
            Query Polatis Network Config IpAddress through SnmpGetNext
            """
            self.snmp_session.create_box('test_getnext_eth1_netconfigipaddress')
            try:
                result = self.snmp_session.snmp_get_next('polatisNetConfigIpAddress.2')
                #print "result : ", result
            except BaseException as err:
                raise err
            nose.tools.assert_equal(TABLE_DICT['polatisNetConfigGateway.1'], result['polatisNetConfigGateway.1'],
                                    'Wrong value for GetNextPolatisNetConfigIpAddress: %s' % result)

        def test_walk_netconfigipaddress(self):
            """
            Query Polatis Network Config IpAddress through SnmpWalk
            """
            self.snmp_session.create_box('test_walk_netconfigipaddress')
            try:
                result = self.snmp_session.snmp_walk('polatisNetConfigIpAddress')
            except BaseException as err:
                raise err

            for key, value in result.iteritems():
                nose.tools.assert_equal(TABLE_DICT[key], result[key],
                                        'Wrong value for WalkPolatisNetConfigIpAddress')
            #if result:
            #    nose.tools.assert_equal(TABLE_DICT['polatisNetConfigIpAddress'], result['polatisNetConfigIpAddress.1'],
            #                            'Wrong value for WalkPolatisNetConfigIpAddress')
            #else:
            #    raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_get_eth0_netconfigateway(self):
            """
            Query Polatis Network Config Gateway through SnmpGet
            """
            self.snmp_session.create_box('test_get_eth0_netconfigateway')
            try:
                result = self.snmp_session.snmp_get('polatisNetConfigGateway.1')
                #print "result : ", result
            except BaseException as err:
                raise err
            if result['polatisNetConfigGateway.1'] is not None:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigGateway.1'], result['polatisNetConfigGateway.1'],
                                        'Wrong value for GetPolatisNetConfigGateway')
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_get_eth1_netconfigateway(self):
            """
            Query Polatis Network Config Gateway through SnmpGet
            """
            self.snmp_session.create_box('test_get_eth1_netconfigateway')
            try:
                result = self.snmp_session.snmp_get('polatisNetConfigGateway.2')
                #print "result : ", result
            except BaseException as err:
                raise err
            if result['polatisNetConfigGateway.2'] is not None:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigGateway.2'], result['polatisNetConfigGateway.2'],
                                        'Wrong value for GetPolatisNetConfigGateway')
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)


        def test_getnext_eth0_netconfigateway(self):
            """
            Query Polatis Network Config Gateway through SnmpGetNext
            """
            self.snmp_session.create_box('test_getnext_eth0_netconfigateway')
            try:
                result = self.snmp_session.snmp_get_next('polatisNetConfigGateway.1')
            except BaseException as err:
                raise err
            nose.tools.assert_equal(TABLE_DICT['polatisNetConfigGateway.2'], result['polatisNetConfigGateway.2'],
                                    'Wrong value for GetNextPolatisNetConfigGateway: %s' % result)

        def test_getnext_eth1_netconfigateway(self):
            """
            Query Polatis Network Config Gateway through SnmpGetNext
            """
            self.snmp_session.create_box('test_getnext_eth1_netconfigateway')
            try:
                result = self.snmp_session.snmp_get_next('polatisNetConfigGateway.2')
            except BaseException as err:
                raise err
            nose.tools.assert_equal(TABLE_DICT['polatisNetConfigSubnet.1'], result['polatisNetConfigSubnet.1'],
                                    'Wrong value for GetNextPolatisNetConfigGateway: %s' % result)

        def test_walk_netconfigateway(self):
            """
            Query Polatis Network Config Gateway through SnmpWalk
            """
            self.snmp_session.create_box('test_walk_netconfigateway')
            try:
                result = self.snmp_session.snmp_walk('polatisNetConfigGateway')
            except BaseException as err:
                raise err


            for key, value in result.iteritems():
                nose.tools.assert_equal(TABLE_DICT[key], result[key], 'Wrong value for WalkpolatisNetConfigGateway')

            #if result:
            #    nose.tools.assert_equal(TABLE_DICT['polatisNetConfigGateway'], result['polatisNetConfigGateway.1'],
            #                            'Wrong value for walkPolatisNetConfigGateway')
            #else:
            #    raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_get_eth0_netconfigsubnet(self):
            """
            Query Polatis Network Config Subnet through SnmpGet
            """
            self.snmp_session.create_box('test_get_eth0_netconfigsubnet')
            try:
                result = self.snmp_session.snmp_get('polatisNetConfigSubnet.1')
            except BaseException as err:
                raise err
            if result['polatisNetConfigSubnet.1'] is not None:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigSubnet.1'], result['polatisNetConfigSubnet.1'],
                                        'Wrong value for GetPolatisNetConfigSubnet')
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_get_eth1_netconfigsubnet(self):
            """
            Query Polatis Network Config Subnet through SnmpGet
            """
            self.snmp_session.create_box('test_get_eth1_netconfigsubnet')
            try:
                result = self.snmp_session.snmp_get('polatisNetConfigSubnet.2')
            except BaseException as err:
                raise err
            if result['polatisNetConfigSubnet.2'] is not None:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigSubnet.2'], result['polatisNetConfigSubnet.2'],
                                        'Wrong value for GetPolatisNetConfigSubnet')
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_getnext_eth0_netconfigsubnet(self):
            """
            Query Polatis Network Config Subnet through SnmpGetNext
            """
            self.snmp_session.create_box('test_getnext_eth0_netconfigsubnet')
            try:
                result = self.snmp_session.snmp_get_next('polatisNetConfigSubnet.1')
            except BaseException as err:
                raise err
            nose.tools.assert_equal(TABLE_DICT['polatisNetConfigSubnet.2'], result['polatisNetConfigSubnet.2'],
                                    'Wrong value for GetNextPolatisNetConfigSubnet:%s' % result)

        def test_getnext_eth1_netconfigsubnet(self):
            """
            Query Polatis Network Config Subnet through SnmpGetNext
            """
            self.snmp_session.create_box('test_getnext_eth1_netconfigsubnet')
            try:
                result = self.snmp_session.snmp_get_next('polatisNetConfigSubnet.2')
            except BaseException as err:
                raise err
            nose.tools.assert_equal(TABLE_DICT['polatisNetConfigBroadcast.1'], result['polatisNetConfigBroadcast.1'],
                                    'Wrong value for GetNextPolatisNetConfigSubnet:%s' % result)

        def test_walk_netconfigsubnet(self):
            """
            Query Polatis Network Config Subnet through SnmpWalk
            """
            self.snmp_session.create_box('test_walk_netconfigsubnet')
            try:
                result = self.snmp_session.snmp_walk('polatisNetConfigSubnet')
            except BaseException as err:
                raise err
   
            for key, value in result.iteritems():
                nose.tools.assert_equal(TABLE_DICT[key], result[key], 'Wrong value for WalkPolatisNetConfigSubnet')
            #if result:
            #    nose.tools.assert_equal(TABLE_DICT['polatisNetConfigSubnet'], result['polatisNetConfigSubnet.1'],
            #                            'Wrong value for WalkPolatisNetConfigSubnet')
            #else:
            #    raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_get_eth0_netconfigbroadcast(self):
            """
            Query Polatis Network Config Broadcast through SnmpGet
            """
            self.snmp_session.create_box('test_get_eth0_netconfigbroadcast')
            try:
                result = self.snmp_session.snmp_get('polatisNetConfigBroadcast.1')
            except BaseException as err:
                raise err
            if result['polatisNetConfigBroadcast.1'] is not None:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigBroadcast.1'], result['polatisNetConfigBroadcast.1'],
                                        'Wrong value for GetPolatisNetConfigBroadcast')
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_get_eth1_netconfigbroadcast(self):
            """
            Query Polatis Network Config Broadcast through SnmpGet
            """
            self.snmp_session.create_box('test_get_eth1_netconfigbroadcast')
            try:
                result = self.snmp_session.snmp_get('polatisNetConfigBroadcast.2')
            except BaseException as err:
                raise err
            if result['polatisNetConfigBroadcast.2'] is not None:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigBroadcast.2'], result['polatisNetConfigBroadcast.2'],
                                        'Wrong value for GetPolatisNetConfigBroadcast')
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_getnext_eth0_netconfigbroadcast(self):
            """
            Query Polatis Network Config Broadcast through SnmpGetNext
            """
            self.snmp_session.create_box('test_getnext_eth0_netconfigbroadcast')
            try:
                result = self.snmp_session.snmp_get_next('polatisNetConfigBroadcast.1')
            except BaseException as err:
                raise err
            nose.tools.assert_equal(TABLE_DICT['polatisNetConfigBroadcast.2'], result['polatisNetConfigBroadcast.2'],
                                    'Wrong value for GetNextPolatisNetConfigBroadcast: %s' % result)

        def test_getnext_eth1_netconfigbroadcast(self):
            """
            Query Polatis Network Config Broadcast through SnmpGetNext
            """
            self.snmp_session.create_box('test_getnext_eth1_netconfigbroadcast')
            try:
                result = self.snmp_session.snmp_get_next('polatisNetConfigBroadcast.2')
            except BaseException as err:
                raise err
            nose.tools.assert_equal(TABLE_DICT['polatisNetConfigAutoAddr.1'], result['polatisNetConfigAutoAddr.1'],
                                    'Wrong value for GetNextPolatisNetConfigBroadcast: %s' % result)

        def test_walk_netconfigbroadcast(self):
            """
            Query Polatis Network Config Broadcast through SnmpWalk
            """
            self.snmp_session.create_box('test_walk_netconfigbroadcast')
            try:
                result = self.snmp_session.snmp_walk('polatisNetConfigBroadcast')
            except BaseException as err:
                raise err

            for key, value in result.iteritems():
                nose.tools.assert_equal(TABLE_DICT[key], result[key], 'Wrong value for WalkPolatisNetConfigBroadcast')
            #if result:
            #    nose.tools.assert_equal(TABLE_DICT['polatisNetConfigBroadcast'], result['polatisNetConfigBroadcast.1'],
            #                            'Wrong value for WalkPolatisNetConfigBroadcast')
            #else:
            #    raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_get_eth0_netconfigautoaddr(self):
            """
            Query Polatis Network Config AutoAddr through SnmpGet
            """
            self.snmp_session.create_box('test_get_eth0_netconfigautoaddr')
            try:
                result = self.snmp_session.snmp_get('polatisNetConfigAutoAddr.1')
            except BaseException as err:
                raise err
            if result['polatisNetConfigAutoAddr.1'] is not None:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigAutoAddr.1'], result['polatisNetConfigAutoAddr.1'],
                                        'Wrong value for GetPolatisNetConfigAutoAddr')
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_get_eth1_netconfigautoaddr(self):
            """
            Query Polatis Network Config AutoAddr through SnmpGet
            """
            self.snmp_session.create_box('test_get_eth1_netconfigautoaddr')
            try:
                result = self.snmp_session.snmp_get('polatisNetConfigAutoAddr.2')
            except BaseException as err:
                raise err
            if result['polatisNetConfigAutoAddr.2'] is not None:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigAutoAddr.2'], result['polatisNetConfigAutoAddr.2'],
                                        'Wrong value for GetPolatisNetConfigAutoAddr')
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_getnext_eth0_netconfigautoaddr(self):
            """
            Query Polatis Network Config AutoAddr through SnmpGetNext
            """
            self.snmp_session.create_box('test_getnext_eth0_netconfigautoaddr')
            try:
                result = self.snmp_session.snmp_get_next('polatisNetConfigAutoAddr.1')
            except BaseException as err:
                raise err
            nose.tools.assert_equal(TABLE_DICT['polatisNetConfigAutoAddr.2'], result['polatisNetConfigAutoAddr.2'],
                                    'Wrong value for GetNextPolatisNetConfigAutoAddr: %s' % result)

        def test_getnext_eth1_netconfigautoaddr(self):
            """
            Query Polatis Network Config AutoAddr through SnmpGetNext
            """
            self.snmp_session.create_box('test_getnext_eth1_netconfigautoaddr')
            try:
                result = self.snmp_session.snmp_get_next('polatisNetConfigAutoAddr.2')
            except BaseException as err:
                raise err
            nose.tools.assert_equal(TABLE_DICT['polatisNetConfigStatus.1'], result['polatisNetConfigStatus.1'],
                                    'Wrong value for GetNextPolatisNetConfigAutoAddr: %s' % result)

        def test_walk_netconfigautoaddr(self):
            """
            Query Polatis Network Config AutoAddr through SnmpWalk
            """
            self.snmp_session.create_box('test_walk_netconfigautoaddr')
            try:
                result = self.snmp_session.snmp_walk('polatisNetConfigAutoAddr')
            except BaseException as err:
                raise err

            for key, value in result.iteritems():
                nose.tools.assert_equal(TABLE_DICT[key], result[key], 'Wrong value for WalkpolatisNetConfigAutoAddr')

            #if result:
            #    nose.tools.assert_equal(TABLE_DICT['polatisNetConfigAutoAddr'], result['polatisNetConfigAutoAddr.1'],
            #                            'Wrong value for WalkPolatisNetConfigAutoAddr')
            #else:
            #    raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_get_eth0_netconfigstatus(self):
            """
            Query Polatis Network Config Status through SnmpGet
            """
            self.snmp_session.create_box('test_get_eth0_netconfigstatus')
            try:
                result = self.snmp_session.snmp_get('polatisNetConfigStatus.1')
            except BaseException as err:
                raise err
            if result['polatisNetConfigStatus.1'] is not None:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigStatus.1'], result['polatisNetConfigStatus.1'],
                                        'Wrong value for GetPolatisNetConfigStatus')
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_get_eth1_netconfigstatus(self):
            """
            Query Polatis Network Config Status through SnmpGet
            """
            self.snmp_session.create_box('test_get_eth1_netconfigstatus')
            try:
                result = self.snmp_session.snmp_get('polatisNetConfigStatus.2')
            except BaseException as err:
                raise err
            if result['polatisNetConfigStatus.2'] is not None:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigStatus.2'], result['polatisNetConfigStatus.2'],
                                        'Wrong value for GetPolatisNetConfigStatus')
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_getnext_eth0_netconfigstatus(self):
            """
            Query Polatis Network Config Status through SnmpGetNext
            """
            self.snmp_session.create_box('test_getnext_eth0_netconfigstatus')
            try:
                result = self.snmp_session.snmp_get_next('polatisNetConfigStatus.1')
            except BaseException as err:
                raise err

            nose.tools.assert_equal(TABLE_DICT['polatisNetConfigStatus.2'], result['polatisNetConfigStatus.2'],
                                    'Wrong value for GetNextPolatisNetConfigStatus:%s' % result)

        def test_getnext_eth1_netconfigstatus(self):
            """
            Query Polatis Network Config Status through SnmpGetNext
            """
            self.snmp_session.create_box('test_getnext_eth1_netconfigstatus')
            try:
                result = self.snmp_session.snmp_get_next('polatisNetConfigStatus.2')
            except BaseException as err:
                raise err
            #print "TABLE_DICT['polatisInterfaceConfigProtocol.1']", TABLE_DICT['PolatisInterfaceConfigProtocol'][0]
            nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigProtocol'][0], result['polatisInterfaceConfigProtocol.1'],
                                    'Wrong value for GetNextPolatisNetConfigStatus:%s' % result)
        def test_walk_netconfigstatus(self):
            """
            Query Polatis Network Config Status through SnmpWalk
            """
            self.snmp_session.create_box('test_walk_netconfigstatus')
            try:
                result = self.snmp_session.snmp_walk('polatisNetConfigStatus')
            except BaseException as err:
                raise err

            for key, value in result.iteritems():
                nose.tools.assert_equal(TABLE_DICT[key], result[key], 'Wrong value for WalkpolatisNetConfigStatus')

            #if result:
            #    nose.tools.assert_equal(TABLE_DICT['polatisNetConfigStatus'], result['polatisNetConfigStatus.1'],
            #                            'Wrong value for WalkPolatisNetConfigStatus')
            #else:
            #    raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        "POLATIS INTERFACE CONFIGURATION TABLE"

        def test_snmptable_interfaceconfigtable(self):
            """
            Query Polatis Interface Config Table through SnmpTable
            """
            self.snmp_session.create_box('test_snmptable_interfaceconfigtable')
            try:
                output = self.snmp_session.snmp_table('polatisInterfaceConfigTable')
            except BaseException as err:
                raise NameError(err)
            ##print output
            for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigStatus'])) + 1):
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigStatus'][(value - 1)],
                                        output['polatisInterfaceConfigStatus.%s' % value],
                                        "Wrong Value for Get SnmpWalk against PolatisInterfaceConfig"
                                        "Table: {'%s':'%s'}" % ('polatisInterfaceConfigStatus.%s' % value,
                                                                output['polatisInterfaceConfigStatus.%s' % value]))
            for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigProtocol'])) + 1):
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigProtocol'][(value - 1)],
                                        output['polatisInterfaceConfigProtocol.%s' % value],
                                        "Wrong Value for Get SnmpWalk against PolatisInterfaceConfig"
                                        "Table: {'%s':'%s'}" % ('polatisInterfaceConfigProtocol.%s' % value,
                                                                output['polatisInterfaceConfigProtocol.%s' % value]))
            for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigDevice'])) + 1):
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigDevice'][(value - 1)],
                                        output['polatisInterfaceConfigDevice.%s' % value],
                                        "Wrong Value for Get SnmpWalk against PolatisInterfaceConfig"
                                        "Table:{'%s':'%s'}" % ('polatisInterfaceConfigDevice.%s' % value,
                                                               output['polatisInterfaceConfigDevice.%s' % value]))

        def test_walk_interfaceconfigtable(self):
            """
            Query Polatis Interface Config Table through SnmpWalk
            """
            self.snmp_session.create_box('test_walk_interfaceconfigtable')
            try:
                output = self.snmp_session.snmp_walk('polatisInterfaceConfigTable')
            except BaseException as err:
                raise NameError(err)
            ##print output
            for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigStatus'])) + 1):
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigStatus'][(value - 1)],
                                        output['polatisInterfaceConfigStatus.%s' % value],
                                        "Wrong Value for Get SnmpWalk against PolatisInterfaceConfig"
                                        "Table: {'%s':'%s'}" % ('polatisInterfaceConfigStatus.%s' % value,
                                                                output['polatisInterfaceConfigStatus.%s' % value]))
            for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigProtocol'])) + 1):
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigProtocol'][(value - 1)],
                                        output['polatisInterfaceConfigProtocol.%s' % value],
                                        "Wrong Value for Get SnmpWalk against PolatisInterfaceConfig"
                                        "Table: {'%s':'%s'}" % ('polatisInterfaceConfigProtocol.%s' % value,
                                                                output['polatisInterfaceConfigProtocol.%s' % value]))
            for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigDevice'])) + 1):
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigDevice'][(value - 1)],
                                        output['polatisInterfaceConfigDevice.%s' % value],
                                        "Wrong Value for Get SnmpWalk against PolatisInterfaceConfig"
                                        "Table:{'%s':'%s'}" % ('polatisInterfaceConfigDevice.%s' % value,
                                                               output['polatisInterfaceConfigDevice.%s' % value]))

        def test_get_interfaceconfigprotocol(self):
            """
            Query Polatis Interface Config Protocol through SnmpGet
            """
            self.snmp_session.create_box('test_get_interfaceconfigprotocol')
            try:
                result = self.snmp_session.snmp_get('polatisInterfaceConfigProtocol.2')
            except BaseException as err:
                raise err
            if result['polatisInterfaceConfigProtocol.2'] is not None:
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigProtocol'][1],
                                        result['polatisInterfaceConfigProtocol.2'],
                                        'Wrong value for Get PolatisInterfaceConfigProtocol: '
                                        '{%s:%s}' % ('polatisInterfaceConfigProtocol.2',
                                                     result['polatisInterfaceConfigProtocol.2']))
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_getnext_interfaceconfigprotocol(self):
            """
            Query Polatis Interface Config Protocol through SnmpGetNext
            """
            self.snmp_session.create_box('test_getnext_interfaceconfigprotocol')
            try:
                result = self.snmp_session.snmp_get_next('polatisInterfaceConfigProtocol')
            except BaseException as err:
                raise err
            nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigProtocol'][0],
                                    result['polatisInterfaceConfigProtocol.1'],
                                    'Wrong value for GetNext PolatisInterfaceConfigProtocol: '
                                    '{%s:%s}' % ('polatisInterfaceConfigProtocol.1',
                                                 result['polatisInterfaceConfigProtocol.1']))

        def test_walk_interfaceconfigprotocol(self):
            """
            Query Polatis Interface Config Protocol through SnmpWalk
            """
            self.snmp_session.create_box('test_walk_interfaceconfigprotocol')
            try:
                result = self.snmp_session.snmp_walk('polatisInterfaceConfigProtocol')
            except BaseException as err:
                raise err
            if result:
                for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigProtocol'])) + 1):
                    nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigProtocol'][(value - 1)],
                                            result['polatisInterfaceConfigProtocol.%s' % value],
                                            "Wrong Value for SnmpWalk against PolatisInterfaceConfigTable: "
                                            "{'%s':'%s'}" % ('polatisInterfaceConfigProtocol.%s' % value,
                                                             result['polatisInterfaceConfigProtocol.%s' % value]))
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_get_interfaceconfigdevice(self):
            """
            Query Polatis Interface Config Device through SnmpGet
            """
            self.snmp_session.create_box('test_get_interfaceconfigdevice')
            try:
                result = self.snmp_session.snmp_get('polatisInterfaceConfigDevice.2')
            except BaseException as err:
                raise err
            if result['polatisInterfaceConfigDevice.2'] is not None:
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigDevice'][1],
                                        result['polatisInterfaceConfigDevice.2'],
                                        'Wrong value for Get PolatisInterfaceConfigDevice: '
                                        '{%s:%s}' % ('polatisInterfaceConfigDevice.2',
                                                     result['polatisInterfaceConfigDevice.2']))
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_getnext_interfaceconfigdevice(self):
            """
            Query Polatis Interface Config Device through SnmpGetNext
            """
            self.snmp_session.create_box('test_getnext_interfaceconfigdevice')
            try:
                result = self.snmp_session.snmp_get_next('polatisInterfaceConfigDevice')
            except BaseException as err:
                raise err
            nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigDevice'][0],
                                    result['polatisInterfaceConfigDevice.1'],
                                    'Wrong value for GetNext PolatisInterfaceConfigDevice: '
                                    '{%s:%s}' % ('polatisInterfaceConfigDevice.1',
                                                 result['polatisInterfaceConfigDevice.1']))

        def test_walk_interfaceconfigdevice(self):
            """
            Query Polatis Interface Config Device through SnmpWalk
            """
            self.snmp_session.create_box('test_walk_interfaceconfigdevice')
            try:
                result = self.snmp_session.snmp_walk('polatisInterfaceConfigDevice')
            except BaseException as err:
                raise err
            if result:
                for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigDevice'])) + 1):
                    nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigDevice'][(value - 1)],
                                            result['polatisInterfaceConfigDevice.%s' % value],
                                            "Wrong Value for Get SnmpWalk against PolatisInterfaceConfigDevice: "
                                            "{'%s':'%s'}" % ('PolatisInterfaceConfigDevice.%s' % value,
                                                             result['polatisInterfaceConfigDevice.%s' % value]))
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_get_interfaceconfigstatus(self):
            """
            Query Polatis Interface Config Status through SnmpGet
            """
            self.snmp_session.create_box('test_get_interfaceconfigstatus')
            try:
                result = self.snmp_session.snmp_get('polatisInterfaceConfigStatus.2')
            except BaseException as err:
                raise err
            if result['polatisInterfaceConfigStatus.2'] is not None:
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigStatus'][1],
                                        result['polatisInterfaceConfigStatus.2'],
                                        'Wrong value for GetPolatisInterfaceConfigStatus: '
                                        '{%s:%s}' % ('polatisInterfaceConfigStatus.2',
                                                     result['polatisInterfaceConfigStatus.2']))
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_getnext_interfaceconfigstatus(self):
            """
            Query Polatis Interface Config Status through SnmpGetNext
            """
            self.snmp_session.create_box('test_getnext_interfaceconfigstatus')
            try:
                result = self.snmp_session.snmp_get_next('polatisInterfaceConfigStatus')
            except BaseException as err:
                raise err
            nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigStatus'][0],
                                    result['polatisInterfaceConfigStatus.1'],
                                    'Wrong value for GetNext PolatisInterfaceConfigStatus: '
                                    '{%s:%s}' % ('polatisInterfaceConfigStatus.1',
                                                 result['polatisInterfaceConfigStatus.1']))

        def test_walk_interfaceconfigstatus(self):
            """
            Query Polatis Interface Config Status through SnmpWalk
            """
            self.snmp_session.create_box('test_walk_interfaceconfigstatus')
            try:
                result = self.snmp_session.snmp_walk('polatisInterfaceConfigStatus')
            except BaseException as err:
                raise err
            if result:
                for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigStatus'])) + 1):
                    nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigStatus'][(value - 1)],
                                            result['polatisInterfaceConfigStatus.%s' % value],
                                            "Wrong Value for SnmpWalk against PolatisInterfaceConfigStatus: "
                                            "{'%s':'%s'}" % ('PolatisInterfaceConfigStatus.%s' % value,
                                                             result['polatisInterfaceConfigStatus.%s' % value]))
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)


        "POLATIS VACM SECURITY TO GROUP TABLE"

        def test_snmptable_vacmsecuritytogrouptable(self):
            """
            Query Vacm Security To Group Table through SnmpTable
            """
            self.snmp_session.create_box('test_snmptable_vacmsecuritytogrouptable')
            try:
                output = self.snmp_session.snmp_table('vacmSecurityToGroupTable')
            except BaseException as err:
                raise NameError(err)
            for key, value in output.iteritems():
                nose.tools.assert_equal(TABLE_DICT[key], output[key], 'Wrong Value for Get SnmpTable against '
                                                                            'vacmSecurityToGroupTable:{%s:%s}' % (key, value))
        def test_walk_vacmsecuritytogrouptable(self):
            """
            Query Vacm Security To Group Table through SnmpWalk
            """
            self.snmp_session.create_box('test_walk_vacmsecuritytogrouptable')
            try:
                output = self.snmp_session.snmp_walk('vacmSecurityToGroupTable')
            except BaseException as err:
                raise err
            for key, value in output.iteritems():
                nose.tools.assert_equal(TABLE_DICT[key], output[key],
                                        'Wrong Value for Get SnmpWalk against '
                                        'vacmSecurityToGroupTable:{%s:%s}' % (key, value))

        def test_get_vacmgroupname(self):
            """
            Query Vacm Group Name through SnmpGet
            """
            self.snmp_session.create_box('test_get_vacmGroupName')
            try:
                result = self.snmp_session.snmp_get('vacmGroupName.1.6.112.117.98.108.105.99')
            except BaseException as err:
                raise err
            if result['vacmGroupName.1.6.112.117.98.108.105.99'] is not None:
                nose.tools.assert_equal(TABLE_DICT['vacmGroupName.1.6.112.117.98.108.105.99'], result['vacmGroupName.1.6.112.117.98.108.105.99'],
                                        'Wrong value for Get Vacm Group Name')
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_getnext_vacmgroupname(self):
            """
            Query Vacm Group Name through SnmpGetNext
            """
            self.snmp_session.create_box('test_getnext_vacmGroupName')
            try:
                result = self.snmp_session.snmp_get_next('vacmGroupName.1.6.112.117.98.108.105.99')
            except BaseException as err:
                raise err
            if result['vacmGroupName.1.7.112.114.105.118.97.116.101'] is not None:
                nose.tools.assert_equal(TABLE_DICT['vacmGroupName.1.7.112.114.105.118.97.116.101'], result['vacmGroupName.1.7.112.114.105.118.97.116.101'],
                                        'Wrong value for Get Next Vacm Group Name')
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_walk_vacmgroupname(self):
            """
            Query Vacm Group Name through SnmpWalk
            """
            self.snmp_session.create_box('test_walk_vacmgroupname')
            try:
                result = self.snmp_session.snmp_walk('vacmGroupName')
            except BaseException as err:
                raise err

            for key, value in result.iteritems():
                nose.tools.assert_equal(TABLE_DICT[key], result[key],
                                        'Wrong value for Walk vacmGroupName')

        def test_get_vacmsecuritytogroupstoragetype(self):
            """
            Query vacm Security To Group Storage Type through SnmpGet
            """
            self.snmp_session.create_box('test_get_vacmsecuritytogroupstoragetype')
            try:
                result = self.snmp_session.snmp_get('vacmSecurityToGroupStorageType.1.6.112.117.98.108.105.99')
            except BaseException as err:
                raise err
            if result['vacmSecurityToGroupStorageType.1.6.112.117.98.108.105.99'] is not None:
                nose.tools.assert_equal(TABLE_DICT['vacmSecurityToGroupStorageType.1.6.112.117.98.108.105.99'], result['vacmSecurityToGroupStorageType.1.6.112.117.98.108.105.99'],
                                        'Wrong value for Get vacmSecurityToGroupStorageType')
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_getnext_vacmsecuritytogroupstoragetype(self):
            """
            Query vacm Security To Group Storage Type through SnmpGetNext
            """
            self.snmp_session.create_box('test_getnext_vacmsecuritytogroupstoragetype')
            try:
                result = self.snmp_session.snmp_get_next('vacmSecurityToGroupStorageType.1.6.112.117.98.108.105.99')
            except BaseException as err:
                raise err
            if result['vacmSecurityToGroupStorageType.1.7.112.114.105.118.97.116.101'] is not None:
                nose.tools.assert_equal(TABLE_DICT['vacmSecurityToGroupStorageType.1.7.112.114.105.118.97.116.101'], result['vacmSecurityToGroupStorageType.1.7.112.114.105.118.97.116.101'],
                                        'Wrong value for Get Next vacmSecurityToGroupStorageType')
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_walk_vacmsecuritytogroupstoragetype(self):
            """
            Query vacm Security To Group Storage Type through SnmpWalk
            """
            self.snmp_session.create_box('test_walk_vacmsecuritytogroupstoragetype')
            try:
                result = self.snmp_session.snmp_walk('vacmSecurityToGroupStorageType')
            except BaseException as err:
                raise err

            for key, value in result.iteritems():
                nose.tools.assert_equal(TABLE_DICT[key], result[key],
                                        'Wrong value for Walk vacmSecurityToGroupStorageType')

        def test_get_vacmsecuritytogroupstatus(self):
            """
            Query vacm Security To Group Status through SnmpGet
            """
            self.snmp_session.create_box('test_get_vacmsecuritytogroupstatus')
            try:
                result = self.snmp_session.snmp_get('vacmSecurityToGroupStatus.1.6.112.117.98.108.105.99')
            except BaseException as err:
                raise err
            if result['vacmSecurityToGroupStatus.1.6.112.117.98.108.105.99'] is not None:
                nose.tools.assert_equal(TABLE_DICT['vacmSecurityToGroupStatus.1.6.112.117.98.108.105.99'], result['vacmSecurityToGroupStatus.1.6.112.117.98.108.105.99'],
                                        'Wrong value for Get vacm Security To Group Status')
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_getnext_vacmsecuritytogroupstatus(self):
            """
            Query vacm Security To Group Status through SnmpGetNext
            """
            self.snmp_session.create_box('test_getnext_vacmsecuritytogroupstatus')
            try:
                result = self.snmp_session.snmp_get_next('vacmSecurityToGroupStatus.1.6.112.117.98.108.105.99')
            except BaseException as err:
                raise err
            if result['vacmSecurityToGroupStatus.1.7.112.114.105.118.97.116.101'] is not None:
                nose.tools.assert_equal(TABLE_DICT['vacmSecurityToGroupStatus.1.7.112.114.105.118.97.116.101'], result['vacmSecurityToGroupStatus.1.7.112.114.105.118.97.116.101'],
                                        'Wrong value for Get Next vacm Security To Group Status')
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_walk_vacmsecuritytogroupstatus(self):
            """
            Query vacm Security To Group Status through SnmpWalk
            """
            self.snmp_session.create_box('test_walk_vacmsecuritytogroupstatus')
            try:
                result = self.snmp_session.snmp_walk('vacmSecurityToGroupStatus')
            except BaseException as err:
                raise err

            for key, value in result.iteritems():
                nose.tools.assert_equal(TABLE_DICT[key], result[key],
                                        'Wrong value for Walk VacmSecurityToGroupStatus')

        "NEGATIVE TEST CASES"

        def test_get_productcode_with_invalid_community(self):
            """
            Negative SNMP Get Polatis System Info Product Code With Invalid Community
            """
            self.snmp_session.create_box('test_get_productcode_with_invalid_community')
            try:
                result = self.snmp_invalid_session.snmp_get('polatisSysInfoProductCode.0')
            except BaseException as err:
                raise err
            #print "self.snmp_invalid_session.snmp_session.ErrorStr", self.snmp_invalid_session.snmp_session.ErrorStr
            #print "result : ", result

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP Get with Invalid Community')
            nose.tools.assert_is_none(result['polatisSysInfoProductCode.0'],
                                      'Result Obtained for Invalid Community Snmp Get')

        def test_getnext_productcode_with_invalid_community(self):
            """
            Negative SNMP GetNext Polatis System Info Product Code With Invalid Community
            """
            self.snmp_session.create_box('test_getnext_productcode_with_invalid_community')
            try:
                result = self.snmp_invalid_session.snmp_get_next('polatisSysInfoProductCode')
            except BaseException as err:
                raise err
            ##print self.snmp_invalid_session.snmp_session.ErrorStr
            if 'polatisSysInfoProductCode.' in result:
                nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                        'Wrong or No exception for SNMP GetNext with Invalid '
                                        'Community: %s' % self.snmp_invalid_session.snmp_session.ErrorStr)
            else:
                raise Exception('Result Obtained for Invalid Community Snmp Get Next: %s' % result)

        def test_walk_productcode_with_invalid_community(self):
            """
            Negative SNMP Walk Polatis System Info Product Code With Invalid Community
            """
            self.snmp_session.create_box('test_walk_productcode_with_invalid_community')
            try:
                result = self.snmp_invalid_session.snmp_walk('polatisSysInfoProductCode')
            except BaseException as err:
                raise err
            ##print self.snmp_invalid_session.snmp_session.ErrorStr
            if not result:
                nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                        'Wrong exception for SNMP Walk with Invalid '
                                        'Community: %s' % self.snmp_invalid_session.snmp_session.ErrorStr)
            else:
                raise Exception('Result Obtained for Invalid Community Snmp Get Next: %s' % result)

        def test_get_serialnumber_with_invalid_community(self):
            """
            Negative SNMP Get Polatis System Info Serial Number With Invalid Community
            """
            self.snmp_session.create_box('test_get_serialnumber_with_invalid_community')
            try:
                result = self.snmp_invalid_session.snmp_get('polatisSysInfoSerialNumber.0')
            except BaseException as err:
                raise err

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'Wrong or No exception for SNMP Get with Invalid '
                                    'Community: %s' % self.snmp_invalid_session.snmp_session.ErrorStr)
            nose.tools.assert_is_none(result['polatisSysInfoSerialNumber.0'],
                                      'Result Obtained for Invalid Community Snmp '
                                      'Get: %s' % result['polatisSysInfoSerialNumber.0'])

        def test_getnext_serialnumber_with_invalid_community(self):
            """
            Negative SNMP GetNext Polatis System Info Serial Number With Invalid Community
            """
            self.snmp_session.create_box('test_getnext_serialnumber_with_invalid_community')
            try:
                result = self.snmp_invalid_session.snmp_get_next('polatisSysInfoSerialNumber')
            except BaseException as err:
                raise err

            ##print self.snmp_invalid_session.snmp_session.ErrorStr
            if 'polatisSysInfoSerialNumber.' in result:
                nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                        'Wrong or No exception for SNMP GetNext with Invalid '
                                        'Community: %s' % self.snmp_invalid_session.snmp_session.ErrorStr)
            else:
                raise Exception('Result Obtained for Invalid Community SNMP '
                                'GetNext: %s' % result)

        def test_walk_serialnumber_with_invalid_community(self):
            """
            Negative SNMP Walk Polatis System Info Serial Number With Invalid Community
            """
            self.snmp_session.create_box('test_walk_serialnumber_with_invalid_community')
            try:
                result = self.snmp_invalid_session.snmp_walk('polatisSysInfoSerialNumber')
            except BaseException as err:
                raise err

            ##print self.snmp_invalid_session.snmp_session.ErrorStr
            if not result:
                nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                        'Wrong exception for SNMP Walk with Invalid '
                                        'Community: %s' % self.snmp_invalid_session.snmp_session.ErrorStr)
            else:
                raise Exception('Result Obtained for Invalid Community Snmp Get Next: %s' % result)

        def test_get_firmwareversion_with_invalid_community(self):
            """
            Negative SNMP Get Polatis System Info Firmware Version With Invalid Community
            """
            self.snmp_session.create_box('test_get_firmwareversion_with_invalid_community')
            try:
                result = self.snmp_invalid_session.snmp_get('polatisSysInfoFirmwareVersion.0')
            except BaseException as err:
                raise err

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'Wrong or No exception for SNMP Get with Invalid '
                                    'Community: %s ' % self.snmp_invalid_session.snmp_session.ErrorStr)
            nose.tools.assert_is_none(result['polatisSysInfoFirmwareVersion.0'],
                                      'Result Obtained for Invalid Community Snmp '
                                      'Get: %s' % result['polatisSysInfoFirmwareVersion.0'])

        def test_getnext_firmwareversion_with_invalid_community(self):
            """
            Negative SNMP GetNext Polatis System Info Firmware Version With Invalid Community
            """
            self.snmp_session.create_box('test_getnext_firmwareversion_with_invalid_community')
            try:
                result = self.snmp_invalid_session.snmp_get_next('polatisSysInfoFirmwareVersion')
            except BaseException as err:
                raise err
            ##print self.snmp_invalid_session.snmp_session.ErrorStr
            if 'polatisSysInfoFirmwareVersion.' in result:
                nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                        'Wrong or No exception for SNMP GetNext with Invalid '
                                        'Community: %s ' % self.snmp_invalid_session.snmp_session.ErrorStr)
            else:
                raise Exception('Result Obtained for Invalid Community SNMP GetNext: %s' % result)

        def test_walk_firmwareversion_with_invalid_community(self):
            """
            Negative SNMP Walk Polatis System Info Firmware Version With Invalid Community
            """
            self.snmp_session.create_box('test_walk_firmwareversion_with_invalid_community')
            try:
                result = self.snmp_invalid_session.snmp_walk('polatisSysInfoFirmwareVersion')
            except BaseException as err:
                raise err
            #print self.snmp_invalid_session.snmp_session.ErrorStr
            if not result:
                nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                        'Wrong or No exception for SNMP Walk with Invalid '
                                        'Community: %s' % self.snmp_invalid_session.snmp_session.ErrorStr)
            else:
                raise Exception('Result Obtained for Invalid Community Snmp Get Next: %s' % result)
 

        def testSetPolatisSysCtrlRestartAgentInROCommunity(self):
            """
            Negative SNMP Set Polatis System Control Restart Agent with Readonly Community
            """
            self.snmp_session.create_box('testSetPolatisSysCtrlRestartAgentInROCommunity')

            try:
                result = self.snmp_ro_session.snmp_set('polatisSysCtrlRestartAgent.0', 2, 'INTEGER')
            except BaseException as err:
                raise err
            ##print self.snmp_ro_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_ro_session.snmp_session.ErrorStr, 'Timeout',
                                    'No Exception when restarting SNMP agent with Public Community')
            nose.tools.assert_equal(0, result, "Snmp Agent Restarted")

        def testSetPolatisSysCtrlRestartAgentWithInvalidCommunity(self):
            """
            Negative SNMP Set Polatis System Control Restart Agent with Readonly Community
            """
            self.snmp_session.create_box('testSetPolatisSysCtrlRestartAgentWithInvalidCommunity')

            try:
                result = self.snmp_invalid_session.snmp_set('polatisSysCtrlRestartAgent.0', 2, 'INTEGER')
            except BaseException as err:
                raise err

            ##print self.snmp_invalid_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No Exception when restarting SNMP agent with Public Commnity')
            nose.tools.assert_equal(0, result, "Snmp Agent Restarted")

        def test_reboot_system_with_ro_community(self):
            """
            Negative SNMP Set Polatis System Control Restart Agent with Readonly Community
            """
            self.snmp_session.create_box('test_reboot_system_with_ro_community')
            try:
                output = self.snmp_ro_session.snmp_set('polatisSysCtrlRebootSys.0', 2, 'INTEGER')
            except BaseException as err:
                raise err
            ##print output
            while self.snmp_session.snmp_session.ErrorStr is not '':
                self.snmp_session.snmp_get('sysUpTime.0')
            nose.tools.assert_equal(0, output, 'Switch Reboot Action Successful with ReadOnly Community: %s ' % output)
            nose.tools.assert_equal('Timeout', self.snmp_ro_session.snmp_session.ErrorStr,
                                    'Wrong Error Message while rebooting the '
                                    'switch with Read Only Community: %s' % self.snmp_ro_session.snmp_session.ErrorStr)

        def test_reboot_system_with_invalid_community(self):
            """
            Negative SNMP Set Polatis System Control Restart Agent with Invalid Community
            """
            self.snmp_session.create_box('test_reboot_system_with_invalid_community')
            try:
                output = self.snmp_invalid_session.snmp_set('polatisSysCtrlRebootSys.0', 2, 'INTEGER')
            except BaseException as err:
                raise err
            ##print output
            while self.snmp_session.snmp_session.ErrorStr is not '':
                self.snmp_session.snmp_get('sysUpTime.0')
            nose.tools.assert_equal(0, output, 'Switch Reboot Action Successful with Invalid Community: %s ' % output)
            nose.tools.assert_equal('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                    'Wrong Error Message while rebooting the switch '
                                    'with Invalid Community: %s' % self.snmp_invalid_session.snmp_session.ErrorStr)

        def test_snmptable_netconfigtable_with_invalid_community(self):
            """
            Negative Query Polatis NetConfig Table through SnmpTable with Invalid Community
            """
            self.snmp_session.create_box('test_snmptable_netconfigtable_with_invalid_community')
            try:
                output = self.snmp_invalid_session.snmp_table('polatisNetConfigTable')
            except BaseException as err:
                raise err
            if output:
                raise Exception("Got output for snmp table with invalid community instead of empty dict: %s" % output)
            else:
                nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                        'Wrong or No exception for SNMP Table with Invalid Community:%s'
                                        % self.snmp_invalid_session.snmp_session.ErrorStr)

        def test_walk_netconfigtable_with_invalid_community(self):
            """
            Negative Query Polatis NetConfig Table through SnmpWalk with Invalid Community
            """
            self.snmp_session.create_box('test_walk_netconfigtable_with_invalid_community')
            try:
                output = self.snmp_invalid_session.snmp_walk('polatisNetConfigTable')
            except BaseException as err:
                raise err
            if output:
                raise Exception("Got output for snmp table with invalid community instead of empty dict: %s" % output)
            else:
                nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                        'Wrong or No exception for SNMP Walk with Invalid Community:%s'
                                        % self.snmp_invalid_session.snmp_session.ErrorStr)

        def testGetForNetConfigIpAddressWithInvalidIndex(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetForNetConfigIpAddressWithInvalidIndex')

            try:
                result = self.snmp_session.snmp_get('polatisNetConfigIpAddress.3')
            except BaseException as err:
                raise err

            ##print "Error : ", self.snmp_session.snmp_session.ErrorStr
            if not result['polatisNetConfigIpAddress.3']:
                if version == 1:
                    nose.tools.assert_in('(genError) A general failure occured',
                                         self.snmp_session.snmp_session.ErrorStr,
                                         'Wrong or No exception for SNMP Get with Invalid Index')
                if version == 2:
                    nose.tools.assert_in('(genError) A general failure occured', self.snmp_session.snmp_session.ErrorStr,
                                         'Wrong or No exception for SNMP Get with Invalid Index')
            else:
                raise Exception("Got Output for Netconfig IpAddress with Invalid Index instead of empty "
                                "dict:%s" % result['polatisNetConfigIpAddress.3'])

        def testGetForNetConfigGatewayWithInvalidIndex(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetForNetConfigGatewayWithInvalidIndex')

            try:
                result = self.snmp_session.snmp_get('polatisNetConfigGateway.3')
            except BaseException as err:
                raise err
            ##print "Error : ", self.snmp_session.snmp_session.ErrorStr
            if not result['polatisNetConfigGateway.3']:
                if version == 1:
                    nose.tools.assert_in('(genError) A general failure occured',
                                         self.snmp_session.snmp_session.ErrorStr,
                                         'Wrong or No exception for SNMP Get with Invalid Index')
                if version == 2:
                    nose.tools.assert_in('(genError) A general failure occured', self.snmp_session.snmp_session.ErrorStr,
                                         'Wrong or No exception for SNMP Get with Invalid Index')

            else:
                raise Exception("Got Output for Netconfig Gateway with Invalid Index instead of empty "
                                "dict:%s" % result['polatisNetConfigGateway.3'])

            ##print "Error : ", self.snmp_session.snmp_session.ErrorStr
#            nose.tools.assert_in('There is no such variable name in this MIB',
#                                 self.snmp_session.snmp_session.ErrorStr,
#                                 'Wrong or No exception for SNMP Get with Invalid Index')
#            nose.tools.assert_equal(0, len(result['polatisNetConfigGateway.3']),
#                                    'Result Obtained for Invalid Community SNMP Get')

        def testGetForNetConfigSubnetWithInvalidIndex(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetForNetConfigSubnetWithInvalidIndex')

            try:
                result = self.snmp_session.snmp_get('polatisNetConfigSubnet.3')
            except BaseException as err:
                raise err
            ###print "Error : ", self.snmp_session.snmp_session.ErrorStr
            if not result['polatisNetConfigSubnet.3']:
                if version == 1:
                    nose.tools.assert_in('(genError) A general failure occured',
                                         self.snmp_session.snmp_session.ErrorStr,
                                         'Wrong or No exception for SNMP Get with Invalid Index')
                if version == 2:
                    nose.tools.assert_in('(genError) A general failure occured', self.snmp_session.snmp_session.ErrorStr,
                                         'Wrong or No exception for SNMP Get with Invalid Index')

            else:
                raise Exception("Got Output for Netconfig Gateway with Invalid Index instead of empty "
                                "dict:%s" % result['polatisNetConfigSubnet.3'])


#            nose.tools.assert_in('There is no such variable name in this MIB',
#                                 self.snmp_session.snmp_session.ErrorStr,
#                                 'Wrong or No exception for SNMP Get with Invalid Index')
#            nose.tools.assert_equal(0, len(result['polatisNetConfigSubnet.3']),
#                                    'Result Obtained for Invalid Community SNMP Get')

        def testGetForNetConfigBroadcastWithInvalidIndex(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetForNetConfigBroadcastWithInvalidIndex')

            try:
                result = self.snmp_session.snmp_get('polatisNetConfigBroadcast.3')
            except BaseException as err:
                raise err
            ##print "Error : ", self.snmp_session.snmp_session.ErrorStr
            if not result['polatisNetConfigBroadcast.3']:
                if version == 1:
                    nose.tools.assert_in('(genError) A general failure occured',
                                         self.snmp_session.snmp_session.ErrorStr,
                                         'Wrong or No exception for SNMP Get with Invalid Index')
                if version == 2:
                    nose.tools.assert_in('(genError) A general failure occured', self.snmp_session.snmp_session.ErrorStr,
                                         'Wrong or No exception for SNMP Get with Invalid Index')

            else:
                raise Exception("Got Output for Netconfig Broadcast with Invalid Index instead of empty "
                                "dict:%s" % result['polatisNetConfigBroadcast.3'])
 
            ##print "Error : ", self.snmp_session.snmp_session.ErrorStr
#           nose.tools.assert_in('There is no such variable name in this MIB',
#                                 self.snmp_session.snmp_session.ErrorStr,
#                                 'Wrong or No exception for SNMP Get with Invalid Index')
#            nose.tools.assert_equal(0, len(result['polatisNetConfigBroadcast.3']),
#                                    'Result Obtained for Invalid Community SNMP Get')

        def testGetForNetConfigAutoAddrWithInvalidIndex(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetForNetConfigAutoAddrWithInvalidIndex')

            try:
                result = self.snmp_session.snmp_get('polatisNetConfigAutoAddr.3')
            except BaseException as err:
                raise err
            ##print "Error : ", self.snmp_session.snmp_session.ErrorStr
            if not result['polatisNetConfigAutoAddr.3']:
                if version == 1:
                    nose.tools.assert_in('(genError) A general failure occured',
                                         self.snmp_session.snmp_session.ErrorStr,
                                         'Wrong or No exception for SNMP Get with Invalid Index')
                if version == 2:
                    nose.tools.assert_in('(genError) A general failure occured', self.snmp_session.snmp_session.ErrorStr,
                                         'Wrong or No exception for SNMP Get with Invalid Index')

            else:
                raise Exception("Got Output for Netconfig Auto Addr with Invalid Index instead of empty "
                                "dict:%s" % result['polatisNetConfigAutoAddr.3'])

            ##print "Error : ", self.snmp_session.snmp_session.ErrorStr

#            nose.tools.assert_in('There is no such variable name in this MIB',
#                                 self.snmp_session.snmp_session.ErrorStr,
#                                 'Wrong or No exception for SNMP Get with Invalid Index')
#            nose.tools.assert_equal(0, len(result['polatisNetConfigAutoAddr.3']),
#                                    'Result Obtained for Invalid Community SNMP Get')

        def testGetForNetConfigStatusWithInvalidIndex(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetForNetConfigStatusWithInvalidIndex')

            try:
                result = self.snmp_session.snmp_get('polatisNetConfigStatus.3')
                #print "result : ", result
            except BaseException as err:
                raise err
            #print "ErrorStr : ", self.snmp_session.snmp_session.ErrorStr
            if not result['polatisNetConfigStatus.3']:
                if version == 1:
                    nose.tools.assert_in('There is no such variable name in this MIB',
                                         self.snmp_session.snmp_session.ErrorStr,
                                         'Wrong or No exception for SNMP Get with Invalid Index')
                if version == 2:
                    nose.tools.assert_in('',
                                         self.snmp_session.snmp_session.ErrorStr,
                                         'Wrong or No exception for SNMP Get with Invalid Index')

            else:
                raise Exception("Got Output for Netconfig Gateway with Invalid Index instead of empty "
                                "dict:%s" % result['polatisNetConfigStatus.3'])

            #print "ErrorStr : ", self.snmp_session.snmp_session.ErrorStr
            #print "ErrorNum : ", self.snmp_session.snmp_session.ErrorNum
            #print "ErrorInd : ", self.snmp_session.snmp_session.ErrorInd
#            nose.tools.assert_in('There is no such variable name in this MIB', self.snmp_session.snmp_session.ErrorStr,
#                                 'Wrong or No exception for SNMP Get with Invalid '
#                                 'Index: %s ' % self.snmp_session.snmp_session.ErrorStr)
#            nose.tools.assert_equal(0, len(result['polatisNetConfigStatus.3']),
#                                    'Result Obtained for Invalid Community SNMP Get')

        def test_snmptable_interfaceconfigtable_with_invalid_community(self):
            """
            Negative Query Polatis Interface Config Table through SnmpTable with Invalid Community
            """
            self.snmp_session.create_box('test_snmptable_interfaceconfigtable_with_invalid_community')
            try:
                output = self.snmp_invalid_session.snmp_table('polatisInterfaceConfigTable')
            except BaseException as err:
                raise err
            if output:
                raise Exception("Got output for snmp table with invalid community instead of empty dict: %s" % output)
            else:
                nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                        'Wrong or No exception for SNMP Table with Invalid Community:%s'
                                        % self.snmp_invalid_session.snmp_session.ErrorStr)

        def test_walk_interfaceconfigtable_with_invalid_community(self):
            """
            Negative Query Polatis Interface Config Table through SnmpWalk with Invalid Community
            """
            self.snmp_session.create_box('test_walk_interfaceconfigtable_with_invalid_community')
            try:
                output = self.snmp_invalid_session.snmp_walk('polatisInterfaceConfigTable')
            except BaseException as err:
                raise err
            if output:
                raise Exception("Got output for snmp table with invalid community instead of empty dict: %s" % output)
            else:
                nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                        'Wrong or No exception for SNMP Walk with Invalid Community:%s'
                                        % self.snmp_invalid_session.snmp_session.ErrorStr)

        def testGetForNetConfigIpAddressWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetForNetConfigIpAddressWithInvalidCommunity')
            try:
                result = self.snmp_invalid_session.snmp_get('polatisNetConfigIpAddress.1')
            except BaseException as err:
                raise err
            ##print self.snmp_invalid_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP Get with Invalid Community')
            nose.tools.assert_is_none(result['polatisNetConfigIpAddress.1'],
                                      'Result Obtained for Invalid Community Snmp Get')

        def testGetNextForNetConfigIpAddressWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetNextForNetConfigIpAddressWithInvalidCommunity')
            try:
                result = self.snmp_invalid_session.snmp_get_next('polatisNetConfigIpAddress')
            except BaseException as err:
                raise err
            #print self.snmp_invalid_session.snmp_session.ErrorStr
            if 'polatisNetConfigIpAddress.' in result:
                nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                        'No exception for SNMP GetNext with Invalid '
                                        'Community: %s' % self.snmp_invalid_session.snmp_session.ErrorStr)
            else:
                raise Exception('Result Obtained for Invalid Community Snmp GetNext: %s' % result)

        def testWalkForNetConfigIpAddressWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testWalkForNetConfigIpAddressWithInvalidCommunity')
            try:
                result = self.snmp_invalid_session.snmp_walk('polatisNetConfigIpAddress')
            except BaseException as err:
                raise err
            #print self.snmp_invalid_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP Walk with Invalid Community')
            nose.tools.assert_dict_equal({}, result, 'Result Obtained for Invalid Community Snmp Walk')

        def testGetForNetConfigGatewayWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetForNetConfigGatewayWithInvalidCommunity')
            try:
                result = self.snmp_invalid_session.snmp_get('polatisNetConfigGateway.1')
            except BaseException as err:
                raise err
            #print self.snmp_invalid_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP Get with Invalid Community')
            nose.tools.assert_is_none(result['polatisNetConfigGateway.1'],
                                      'Result Obtained for Invalid Community Snmp Get')

        def testGetNextForNetConfigGatewayWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetNextForNetConfigGatewayWithInvalidCommunity')
            try:
                result = self.snmp_invalid_session.snmp_get_next('polatisNetConfigGateway')
            except BaseException as err:
                raise err

            #print self.snmp_invalid_session.snmp_session.ErrorStr
            if 'polatisNetConfigGateway.' in result:
                nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                        'Wrong exception for SNMP GetNext with Invalid '
                                        'Community: %s' % self.snmp_invalid_session.snmp_session.ErrorStr)
            else:
                raise Exception('Result Obtained for Invalid Community Snmp GetNext: %s' % result)

        def testWalkForNetConfigGatewayWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testWalkForNetConfigGatewayWithInvalidCommunity')
            try:
                result = self.snmp_invalid_session.snmp_walk('polatisNetConfigGateway')
            except BaseException as err:
                raise err

            #print self.snmp_invalid_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP Walk with Invalid Community')
            nose.tools.assert_dict_equal({}, result, 'Result Obtained for Invalid Community Snmp Walk')

        def testGetForNetConfigSubnetWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetForNetConfigSubnetWithInvalidCommunity')
            try:
                result = self.snmp_invalid_session.snmp_get('polatisNetConfigSubnet.1')
            except BaseException as err:
                raise err

            #print self.snmp_invalid_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP Get with Invalid Community')
            nose.tools.assert_is_none(result['polatisNetConfigSubnet.1'],
                                      'Result Obtained for Invalid Community Snmp Get')

        def testGetNextForNetConfigSubnetWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetNextForNetConfigSubnetWithInvalidCommunity')
            try:
                result = self.snmp_invalid_session.snmp_get_next('polatisNetConfigSubnet')
            except BaseException as err:
                raise err

            #print self.snmp_invalid_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP GetNext with Invalid Community')
            nose.tools.assert_is_none(result['polatisNetConfigSubnet.'],
                                      'Result Obtained for Invalid Community Snmp GetNext')

        def testWalkForNetConfigSubnetWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testWalkForNetConfigSubnetWithInvalidCommunity')
            try:
                result = self.snmp_invalid_session.snmp_walk('polatisNetConfigSubnet')
            except BaseException as err:
                raise err

            #print self.snmp_invalid_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP Walk with Invalid Community')
            nose.tools.assert_dict_equal({}, result, 'Result Obtained for Invalid Community Snmp Walk')

        def testGetForNetconfigBroadcastWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetForNetconfigBroadcastWithInvalidCommunity')
            try:
                result = self.snmp_invalid_session.snmp_get('polatisNetConfigBroadcast.1')
            except BaseException as err:
                raise err

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP Get with Invalid Community')
            nose.tools.assert_is_none(result['polatisNetConfigBroadcast.1'],
                                      'Result Obtained for Invalid Community Snmp Get')

        def testGetNextForNetconfigBroadcastWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetNextForNetconfigBroadcastWithInvalidCommunity')
            try:
                result = self.snmp_invalid_session.snmp_get_next('polatisNetConfigBroadcast')
            except BaseException as err:
                raise err

            #print self.snmp_invalid_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP GetNext with Invalid Community')
            nose.tools.assert_is_none(result['polatisNetConfigBroadcast.'],
                                      'Result Obtained for Invalid Community Snmp GetNext')

        def testWalkForNetconfigBroadcastWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetNextForNetConfigSubnetWithInvalidCommunity')
            try:
                result = self.snmp_invalid_session.snmp_walk('polatisNetConfigBroadcast')
            except BaseException as err:
                raise err

            #print self.snmp_invalid_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP Walk with Invalid Community')
            nose.tools.assert_dict_equal({}, result, 'Result Obtained for Invalid Community Snmp Walk')

        def testGetForNetconfigAutoAddrWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetForNetconfigAutoAddrWithInvalidCommunity')
            try:
                result = self.snmp_invalid_session.snmp_get('polatisNetConfigAutoAddr.1')
            except BaseException as err:
                raise err

            #print self.snmp_invalid_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP Get with Invalid Community')
            nose.tools.assert_is_none(result['polatisNetConfigAutoAddr.1'],
                                      'Result Obtained for Invalid Community Snmp Get')

        def testGetNextForNetconfigAutoAddrWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetNextForNetconfigAutoAddrWithInvalidCommunity')
            try:
                result = self.snmp_invalid_session.snmp_get_next('polatisNetConfigAutoAddr')
            except BaseException as err:
                raise err

            #print self.snmp_invalid_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP GetNext with Invalid Community')
            nose.tools.assert_is_none(result['polatisNetConfigAutoAddr.'],
                                      'Result Obtained for Invalid Community Snmp GetNext')

        def testWalkForNetconfigAutoAddrWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testWalkForNetconfigAutoAddrWithInvalidCommunity')
            try:
                result = self.snmp_invalid_session.snmp_walk('polatisNetConfigAutoAddr')
            except BaseException as err:
                raise err

            #print self.snmp_invalid_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP Walk with Invalid Community')
            nose.tools.assert_dict_equal({}, result, 'Result Obtained for Invalid Community Snmp Walk')

        def testGetForNetconfigStatusWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetForNetconfigStatusWithInvalidCommunity')
            try:
                result = self.snmp_invalid_session.snmp_get('polatisNetConfigStatus.1')
            except BaseException as err:
                raise err

            #print self.snmp_invalid_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP Get with Invalid Community')
            nose.tools.assert_is_none(result['polatisNetConfigStatus.1'],
                                      'Result Obtained for Invalid Community Snmp Get')

        def testGetNextForNetconfigStatusWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetNextForNetconfigStatusWithInvalidCommunity')
            try:
                result = self.snmp_invalid_session.snmp_get_next('polatisNetConfigStatus')
            except BaseException as err:
                raise err

            #print self.snmp_invalid_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP GetNext with Invalid Community')
            nose.tools.assert_is_none(result['polatisNetConfigStatus.'],
                                      'Result Obtained for Invalid Community Snmp GetNext')

        def testWalkForNetconfigStatusWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testWalkForNetconfigStatusWithInvalidCommunity')
            try:
                result = self.snmp_invalid_session.snmp_walk('polatisNetConfigStatus')
                print "result : ", result
            except BaseException as err:
                raise err

            #print self.snmp_invalid_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP walk with Invalid Community')
            nose.tools.assert_dict_equal({}, result, 'Result Obtained for Invalid Community Snmp walk')

        def testGetForInterfaceConfigProtocolWithInvalidIndex(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetForInterfaceConfigProtocolWithInvalidIndex')

            try:
                result = self.snmp_session.snmp_get('polatisInterfaceConfigProtocol.13')
                print "result : \n", result
            except BaseException as err:
                raise err
            ##print "Error : ", self.snmp_session.snmp_session.ErrorStr
            if not result['polatisInterfaceConfigProtocol.13']:
                if version == 1:
                    nose.tools.assert_in('(genError) A general failure occured',
                                         self.snmp_session.snmp_session.ErrorStr,
                                         'Wrong or No exception for SNMP Get with Invalid Index')
                if version == 2:
                    nose.tools.assert_in('(genError) A general failure occured', self.snmp_session.snmp_session.ErrorStr,
                                         'Wrong or No exception for SNMP Get with Invalid Index')

            else:
                raise Exception("Got Output for Netconfig Gateway with Invalid Index instead of empty "
                                "dict:%s" % result['polatisInterfaceConfigProtocol.13'])

#            if result['polatisInterfaceConfigProtocol.13'] is not None:
#                nose.tools.assert_equal('(genError) A general failure occured', result['polatisInterfaceConfigProtocol.13'],
#                                        'Wrong value for GetPolatisNetConfigIpAddress')
#            else:
#                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)
            print "\n"
            ##print "Error : ", self.snmp_session.snmp_session.ErrorStr

            #nose.tools.assert_in('There is no such variable name in this MIB',
            #                     self.snmp_invalid_session.snmp_session.ErrorStr,
            #                     'Wrong or No exception for SNMP Get with Invalid Index')
            #nose.tools.assert_equal(0, len(result['polatisInterfaceConfigProtocol.13']),
                                    #'Result Obtained for Invalid Community SNMP Get')

        def testGetForInterfaceConfigDeviceWithInvalidIndex(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetForInterfaceConfigDeviceWithInvalidIndex')

            try:
                result = self.snmp_session.snmp_get('polatisInterfaceConfigDevice.13')
            except BaseException as err:
                raise err
            #print "Error : ", self.snmp_session.snmp_session.ErrorStr
            if not result['polatisInterfaceConfigDevice.13']:
                if version == 1:
                    nose.tools.assert_in('(genError) A general failure occured',
                                         self.snmp_session.snmp_session.ErrorStr,
                                         'Wrong or No exception for SNMP Get with Invalid Index')
                if version == 2:
                    nose.tools.assert_in('(genError) A general failure occured', self.snmp_session.snmp_session.ErrorStr,
                                         'Wrong or No exception for SNMP Get with Invalid Index')

            else:
                raise Exception("Got Output for Netconfig Gateway with Invalid Index instead of empty "
                                "dict:%s" % result['polatisInterfaceConfigDevice.13'])

            ##print "Error : ", self.snmp_session.snmp_session.ErrorStr

#            nose.tools.assert_in('There is no such variable name in this MIB',
#                                 self.snmp_invalid_session.snmp_session.ErrorStr,
#                                 'Wrong or No exception for SNMP Get with Invalid Index')
#            nose.tools.assert_equal(0, len(result['polatisInterfaceConfigDevice.13']),
#                                    'Result Obtained for Invalid Community SNMP Get')

        def testGetForInterfaceConfigStatusWithInvalidIndex(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetForInterfaceConfigStatusWithInvalidIndex')

            try:
                result = self.snmp_session.snmp_get('polatisInterfaceConfigStatus.13')
            except BaseException as err:
                raise err
            ##print "Error : ", self.snmp_session.snmp_session.ErrorStr
            if not result['polatisInterfaceConfigStatus.13']:
                if version == 1:
                    nose.tools.assert_in('(genError) A general failure occured',
                                         self.snmp_session.snmp_session.ErrorStr,
                                         'Wrong or No exception for SNMP Get with Invalid Index')
                if version == 2:
                    nose.tools.assert_in('(genError) A general failure occured', self.snmp_session.snmp_session.ErrorStr,
                                         'Wrong or No exception for SNMP Get with Invalid Index')

            else:
                raise Exception("Got Output for Netconfig Gateway with Invalid Index instead of empty "
                                "dict:%s" % result['polatisInterfaceConfigStatus.13'])




#            nose.tools.assert_in('There is no such variable name in this MIB',
#                                 self.snmp_invalid_session.snmp_session.ErrorStr,
#                                 'Wrong or No exception for SNMP Get with Invalid Index')
#            nose.tools.assert_equal(0, len(result['polatisInterfaceConfigStatus.13']),
#                                    'Result Obtained for Invalid Community SNMP Get')


        def testSetNonWritableInterfaceConfigProtocol(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testSetNonWritableInterfaceConfigProtocol')

            try:
                result = self.snmp_wr_session.snmp_set('polatisInterfaceConfigProtocol.3', 'Protocol', 'OCTET STRING')
            except BaseException as err:
                raise err
            #print self.snmp_wr_session.snmp_session.ErrorStr

            if version == 1:
                nose.tools.assert_in('There is no such variable name in this MIB',
                                     self.snmp_wr_session.snmp_session.ErrorStr,
                                     'No or Wrong Exception when setting a non-writable '
                                     'column(polatisInterfaceConfigProtocol)')
            elif version == 2:
                nose.tools.assert_in('notWritable', self.snmp_wr_session.snmp_session.ErrorStr,
                                     'No or Wrong Exception when setting a non-writable '
                                     'column(polatisInterfaceConfigProtocol)')

		nose.tools.assert_equal(0, result, "Able to Write the Non-Writable Polatis Interface Config Protocol")

        def testSetNonWritableInterfaceConfigDevice(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testSetNonWritableInterfaceConfigDevice')

            try:
                result = self.snmp_wr_session.snmp_set('polatisInterfaceConfigDevice.3', 'Device', 'OCTET STRING')
            except BaseException as err:
                raise err

            #print self.snmp_wr_session.snmp_session.ErrorStr

            if version == 1:
                nose.tools.assert_in('There is no such variable name in this MIB',
                                     self.snmp_wr_session.snmp_session.ErrorStr,
                                     'No or Wrong Exception when setting a non-writable '
                                     'column(polatisInterfaceConfigProtocol)')
            elif version == 2:
                nose.tools.assert_in('notWritable', self.snmp_wr_session.snmp_session.ErrorStr,
                                     'No or Wrong Exception when setting a non-writable '
                                     'column(polatisInterfaceConfigProtocol)')

            nose.tools.assert_equal(0, result, "Able to Write the Non-Writable Polatis Interface Config Device")

        def testGetForInterfaceConfigProtocolWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetForInterfaceConfigProtocolWithInvalidCommunity')

            try:
                result = self.snmp_invalid_session.snmp_get('polatisInterfaceConfigProtocol.1')
            except BaseException as err:
                raise err

            #print self.snmp_invalid_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP Get with Invalid Community')
            nose.tools.assert_is_none(result['polatisInterfaceConfigProtocol.1'],
                                      'Result Obtained for Invalid Community Snmp Get')

        def testGetNextForInterfaceConfigProtocolWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetForInterfaceConfigProtocolWithInvalidCommunity')

            try:
                result = self.snmp_invalid_session.snmp_get_next('polatisInterfaceConfigProtocol')
            except BaseException as err:
                raise err

            #print self.snmp_invalid_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP GetNext with Invalid Community')
            nose.tools.assert_is_none(result['polatisInterfaceConfigProtocol.'],
                                      'Result Obtained for Invalid Community Snmp GetNext')

        def testWalkForInterfaceConfigProtocolWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testWalkForInterfaceConfigProtocolWithInvalidCommunity')

            try:
                result = self.snmp_invalid_session.snmp_walk('polatisInterfaceConfigProtocol')
            except BaseException as err:
                raise err

            #print self.snmp_invalid_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP Walk with Invalid Community')
            nose.tools.assert_dict_equal({}, result, 'Result Obtained for Invalid Community Snmp Walk')

        def testGetForInterfaceConfigDeviceWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetForInterfaceConfigDeviceWithInvalidCommunity')

            try:
                result = self.snmp_invalid_session.snmp_get('polatisInterfaceConfigDevice.1')
            except BaseException as err:
                raise err

            #print self.snmp_invalid_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP Get with Invalid Community')
            nose.tools.assert_is_none(result['polatisInterfaceConfigDevice.1'],
                                      'Result Obtained for Invalid Community Snmp Get')

        def testGetNextForInterfaceConfigDeviceWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetNextForInterfaceConfigDeviceWithInvalidCommunity')

            try:
                result = self.snmp_invalid_session.snmp_get_next('polatisInterfaceConfigDevice')
            except BaseException as err:
                raise err

            #print self.snmp_invalid_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP GetNext with Invalid Community')
            nose.tools.assert_is_none(result['polatisInterfaceConfigDevice.'],
                                      'Result Obtained for Invalid Community Snmp GetNext')

        def testWalkForInterfaceConfigDeviceWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testWalkForInterfaceConfigDeviceWithInvalidCommunity')

            try:
                result = self.snmp_invalid_session.snmp_walk('polatisInterfaceConfigDevice')
            except BaseException as err:
                raise err

            #print self.snmp_invalid_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP Walk with Invalid Community')
            nose.tools.assert_dict_equal({}, result, 'Result Obtained for Invalid Community Snmp Walk')

        def testGetForInterfaceConfigStatusWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetForInterfaceConfigStatusWithInvalidCommunity')

            try:
                result = self.snmp_invalid_session.snmp_get('polatisInterfaceConfigStatus.1')
            except BaseException as err:
                raise err

            #print self.snmp_invalid_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP Get with Invalid Community')
            nose.tools.assert_is_none(result['polatisInterfaceConfigStatus.1'],
                                      'Result Obtained for Invalid Community Snmp Get')

        def testGetNextForInterfaceConfigStatusWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testGetNextForInterfaceConfigStatusWithInvalidCommunity')

            try:
                result = self.snmp_invalid_session.snmp_get_next('polatisInterfaceConfigStatus')
            except BaseException as err:
                raise err

            #print self.snmp_invalid_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP GetNext with Invalid Community')
            nose.tools.assert_is_none(result['polatisInterfaceConfigStatus.'],
                                      'Result Obtained for Invalid Community Snmp GetNext')

        def testWalkForInterfaceConfigStatusWithInvalidCommunity(self):
            """
            Negative Query Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('testWalkForInterfaceConfigStatusWithInvalidCommunity')

            try:
                result = self.snmp_invalid_session.snmp_walk('polatisInterfaceConfigStatus')
            except BaseException as err:
                raise err

            #print self.snmp_invalid_session.snmp_session.ErrorStr

            nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                    'No exception for SNMP Walk with Invalid Community')
            nose.tools.assert_dict_equal({}, result, 'Result Obtained for Invalid Community Snmp Walk')

    "SNMP v2 Specific Test Cases"

    if version == 2:

        def test_getbulk_polatisproductcode(self):
            """
            Query SNMP Getbulk for Polatis Product Code
            """
            self.snmp_session.create_box('test_getbulk_polatisproductcode')
            try:
                result = self.snmp_session.snmp_get_bulk('polatisSysInfoProductCode')
            except BaseException as err:
                raise err
            if None not in result.values():
                nose.tools.assert_equal(TABLE_DICT['polatisProductCode'], result['polatisSysInfoProductCode.0'],
                                        'Wrong value for GetBulkPolatisSysInfoProduct'
                                        'Code: %s' % result['polatisSysInfoProductCode.0'])
            else:
                raise Exception("None type value obtained,Error Message:%s" % self.snmp_session.snmp_session.ErrorStr)

        def test_getbulk_polatisserialnumber(self):
            """
            Query SNMP Getbulk for Polatis Serial Number
            """
            self.snmp_session.create_box('test_getbulk_polatisserialnumber')
            try:
                result = self.snmp_session.snmp_get_bulk('polatisSysInfoSerialNumber')
            except BaseException as err:
                raise err
            if None not in result.values():
                nose.tools.assert_equal(TABLE_DICT['polatisSerialNumber'], result['polatisSysInfoSerialNumber.0'],
                                        'Wrong value for GetBulkPolatisSysInfoSerial'
                                        'Number: %s' % result['polatisSysInfoSerialNumber.0'])
            else:
                raise Exception("None type value obtained,Error Message:%s" % self.snmp_session.snmp_session.ErrorStr)

        def test_getbulk_polatisfirmwareversion(self):
            """
            Query SNMP Getbulk for Polatis Firmware Version
            """
            self.snmp_session.create_box('test_getbulk_polatisfirmwareversion')
            try:
                result = self.snmp_session.snmp_get_bulk('polatisSysInfoFirmwareVersion')
            except BaseException as err:
                raise err
            if None not in result.values():
                nose.tools.assert_equal(TABLE_DICT['polatisFirmwareVersion'], result['polatisSysInfoFirmwareVersion.0'],
                                        'Wrong value for GetBulkPolatisSysInfoFirmware'
                                        'Version: %s' % result['polatisSysInfoFirmwareVersion.0'])
            else:
                raise Exception("None type value obtained,Error Message:%s" % self.snmp_session.snmp_session.ErrorStr)

        def test_bulkget_netconfigtable(self):
            """
            Query Polatis Netconfig Table through SnmpBulkGet
            """
            self.snmp_session.create_box('test_bulkget_netconfigtable')
            try:
                output = self.snmp_session.snmp_get_bulk('polatisNetConfigTable', 0, 6)
            except BaseException as err:
                raise err
            #print output
            if None in output.values():
                raise Exception("Timeout...Unable to bulk get for polatisNetConfigTable: %s " % output)
            else:
                for key, value in output.iteritems():
                    #strip_key = key[:-2]
                    nose.tools.assert_equal(TABLE_DICT[key], output[key],
                                            'Wrong Value for Get SnmpWalk against '
                                            'PolatisNetconfigTable:{%s:%s}' % (key, value))

        def test_getbulk_netconfigipaddress(self):
            """
            Query Polatis Netconfig IpAddress through Snmpgetbulk
            """
            self.snmp_session.create_box('test_getbulk_netconfigipaddress')
            try:
                result = self.snmp_session.snmp_get_bulk('polatisNetConfigIpAddress')
            except BaseException as err:
                raise err
            if None not in result.values():
                for key, value in result.iteritems():
                    #strip_key = key[:-2]
                    nose.tools.assert_equal(TABLE_DICT[key], result[key],
                                            'Wrong Value for Get SnmpWalk against '
                                            'polatisNetConfigIpAddress:{%s:%s}' % (key, value))
                #nose.tools.assert_equal(TABLE_DICT['polatisNetConfigIpAddress.1'], result['polatisNetConfigIpAddress.1'],
                #                        'Wrong value for GetBulkPolatisNetConfig'
                #                        'IpAddress: %s' % result['polatisNetConfigIpAddress.1'])
            else:
                raise Exception("None type value obtained,Error Message:%s" % self.snmp_session.snmp_session.ErrorStr)

        def test_getbulk_netconfigateway(self):
            """
            Query Polatis Netconfig Gateway through SnmpGetBulk
            """
            self.snmp_session.create_box('test_getbulk_netconfigateway')
            try:
                result = self.snmp_session.snmp_get_bulk('polatisNetConfigGateway')
            except BaseException as err:
                raise err
            if None not in result.values():
                for key, value in result.iteritems():
                    #strip_key = key[:-2]
                    nose.tools.assert_equal(TABLE_DICT[key], result[key],
                                            'Wrong Value for Get SnmpWalk against '
                                            'polatisNetConfigGateway:{%s:%s}' % (key, value))
                #nose.tools.assert_equal(TABLE_DICT['polatisNetConfigGateway.1'], result['polatisNetConfigGateway.1'],
                #                        'Wrong value for GetBulkPolatisNetConfig'
                #                        'Gateway: %s' % result['polatisNetConfigGateway.1'])
            else:
                raise Exception("None type value obtained,Error Message:%s" % self.snmp_session.snmp_session.ErrorStr)

        def test_getbulk_netconfigsubnet(self):
            """
            Query Polatis Netconfig Subnet through SnmpGetBulk
            """
            self.snmp_session.create_box('test_getbulk_netconfigsubnet')
            try:
                result = self.snmp_session.snmp_get_bulk('polatisNetConfigSubnet')
            except BaseException as err:
                raise err
            if None not in result.values():
                for key, value in result.iteritems():
                    nose.tools.assert_equal(TABLE_DICT['polatisNetConfigSubnet.1'], result['polatisNetConfigSubnet.1'],
                                        'Wrong value for GetBulkPolatisNetConfig'
                                        'Subnet: %s' % result['polatisNetConfigSubnet.1'])
            else:
                raise Exception("None type value obtained,Error Message:%s" % self.snmp_session.snmp_session.ErrorStr)

        def test_getbulk_netconfigbroadcast(self):
            """
            Query Polatis Netconfig Broadcast through SnmpGetBulk
            """
            self.snmp_session.create_box('test_getbulk_netconfigbroadcast')
            try:
                result = self.snmp_session.snmp_get_bulk('polatisNetConfigBroadcast')
            except BaseException as err:
                raise err
            if None not in result.values():
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigBroadcast.1'], result['polatisNetConfigBroadcast.1'],
                                        'Wrong value for GetBulkPolatisNetConfig'
                                        'Broadcast: %s' % result['polatisNetConfigBroadcast.1'])
            else:
                raise Exception("None type value obtained,Error Message:%s" % self.snmp_session.snmp_session.ErrorStr)

        def test_getbulk_netconfigautoaddr(self):
            """
            Query Polatis Netconfig Auto Addr through SnmpGetBulk
            """
            self.snmp_session.create_box('test_getbulk_netconfigautoaddr')
            try:
                result = self.snmp_session.snmp_get_bulk('polatisNetConfigAutoAddr')
            except BaseException as err:
                raise err
            if None not in result.values():
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigAutoAddr.1'], result['polatisNetConfigAutoAddr.1'],
                                        'Wrong value for GetBulkPolatisNetConfig'
                                        'AutoAddr: %s' % result['polatisNetConfigAutoAddr.1'])
            else:
                raise Exception("None type value obtained,Error Message:%s" % self.snmp_session.snmp_session.ErrorStr)

        def test_getbulk_netconfigstatus(self):
            """
            Query Polatis Netconfig Status through SnmpGetBulk
            """
            self.snmp_session.create_box('test_getbulk_netconfigstatus')
            try:
                result = self.snmp_session.snmp_get_bulk('polatisNetConfigStatus')
            except BaseException as err:
                raise err
            if None not in result.values():
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigStatus.1'], result['polatisNetConfigStatus.1'],
                                        'Wrong value for GetBulkPolatisNetConfig'
                                        'Status: %s' % result['polatisNetConfigStatus.1'])
            else:
                raise Exception("None type value obtained,Error Message:%s" % self.snmp_session.snmp_session.ErrorStr)

        def test_getbulk_interfaceconfigtable(self):
            """
            Query Polatis Interface Config Table through SnmpBulkGet
            """
            self.snmp_session.create_box('test_getbulk_interfaceconfigtable')
            try:
                e_index = len(TABLE_DICT['PolatisInterfaceConfigStatus'])
                output = self.snmp_session.snmp_get_bulk('polatisInterfaceConfigTable', 0, 3 * e_index)
            except BaseException as err:
                raise NameError(err)
            #print output
            for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigStatus'])) + 1):
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigStatus'][(value - 1)],
                                        output['polatisInterfaceConfigStatus.%s' % value],
                                        "Wrong Value for Get SnmpWalk against PolatisInterfaceConfig"
                                        "Table: {'%s':'%s'}" % ('polatisInterfaceConfigStatus.%s' % value,
                                                                output['polatisInterfaceConfigStatus.%s' % value]))
            for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigProtocol'])) + 1):
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigProtocol'][(value - 1)],
                                        output['polatisInterfaceConfigProtocol.%s' % value],
                                        "Wrong Value for Get SnmpWalk against PolatisInterfaceConfig"
                                        "Table: {'%s':'%s'}" % ('polatisInterfaceConfigProtocol.%s' % value,
                                                                output['polatisInterfaceConfigProtocol.%s' % value]))
            for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigDevice'])) + 1):
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigDevice'][(value - 1)],
                                        output['polatisInterfaceConfigDevice.%s' % value],
                                        "Wrong Value for Get SnmpWalk against PolatisInterfaceConfig"
                                        "Table:{'%s':'%s'}" % ('polatisInterfaceConfigDevice.%s' % value,
                                                               output['polatisInterfaceConfigDevice.%s' % value]))

        def test_getbulk_interfaceconfigprotocol(self):
            """
            Query Polatis Interface Config Protocol through SnmpBulkGet
            """
            self.snmp_session.create_box('test_getbulk_interfaceconfigprotocol')
            try:
                result = self.snmp_session.snmp_get_bulk('polatisInterfaceConfigProtocol')
            except BaseException as err:
                raise NameError(err)
            if None not in result.values():
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigProtocol'][0],
                                        result['polatisInterfaceConfigProtocol.1'],
                                        'Wrong value for GetBulkPolatisInterfaceConfig'
                                        'Protocol: %s' % result['polatisInterfaceConfigProtocol.1'])
            else:
                raise Exception("None type value obtained,Error Message:%s" % self.snmp_session.snmp_session.ErrorStr)

        def test_getbulk_interfaceconfigdevice(self):
            """
            Query Polatis Interface Config Device through SnmpBulkGet
            """
            self.snmp_session.create_box('test_getbulk_interfaceconfigdevice')
            try:
                result = self.snmp_session.snmp_get_bulk('polatisInterfaceConfigDevice')
            except BaseException as err:
                raise NameError(err)
            if None not in result.values():
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigDevice'][0],
                                        result['polatisInterfaceConfigDevice.1'],
                                        'Wrong value for GetBulkPolatisInterfaceConfig'
                                        'Device:%s' % result['polatisInterfaceConfigDevice.1'])
            else:
                raise Exception("None type value obtained,Error Message:%s" % self.snmp_session.snmp_session.ErrorStr)

        def test_getbulk_interfaceconfigstatus(self):
            """
            Query Polatis Interface Config Status through SnmpBulkGet
            """
            self.snmp_session.create_box('test_getbulk_interfaceconfigstatus')
            try:
                result = self.snmp_session.snmp_get_bulk('polatisInterfaceConfigStatus')
            except BaseException as err:
                raise NameError(err)
            if None not in result.values():
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigStatus'][0],
                                        result['polatisInterfaceConfigStatus.1'],
                                        'Wrong value for GetBulkPolatisInterfaceConfig'
                                        'Status:%s' % result['polatisInterfaceConfigStatus.1'])
            else:
                raise Exception("None type value obtained,Error Message:%s" % self.snmp_session.snmp_session.ErrorStr)

        def test_bulkget_vacmsecuritytogrouptable(self):
            """
            Query Vacm Security To Group Table through SnmpBulkGet
            """
            self.snmp_session.create_box('test_bulkget_vacmsecuritytogrouptable')
            try:
                output = self.snmp_session.snmp_get_bulk('vacmSecurityToGroupTable', 0, 6)
            except BaseException as err:
                raise err
            #print output
            if None in output.values():
                raise Exception("Timeout...Unable to bulk get for vacmSecurityToGroupTable: %s " % output)
            else:
                for key, value in output.iteritems():
                    #strip_key = key[:-2]
                    nose.tools.assert_equal(TABLE_DICT[key], output[key],
                                            'Wrong Value for Get Bulk against '
                                            'vacmSecurityToGroupTable:{%s:%s}' % (key, value))

        def test_bulkget_vacmgroupname(self):
            """
            Query Vacm Group Name through SnmpBulkGet
            """
            self.snmp_session.create_box('test_bulkget_vacmgroupname')
            try:
                output = self.snmp_session.snmp_get_bulk('vacmGroupName', 0, 6)
            except BaseException as err:
                raise err
            #print output
            if None in output.values():
                raise Exception("Timeout...Unable to bulk get for vacmGroupName: %s " % output)
            else:
                for key, value in output.iteritems():
                    #strip_key = key[:-2]
                    nose.tools.assert_equal(TABLE_DICT[key], output[key],
                                            'Wrong Value for Get Bulkt against '
                                            'vacmGroupName:{%s:%s}' % (key, value))

        def test_getbulk_productcode_with_invalidcommunity(self):
            """
            Negative SNMPv2 Getbulk Polatis ProductCode with Invalid Community
            """
            self.snmp_session.create_box('test_getbulk_productcode_with_invalidcommunity')
            try:
                result = self.snmp_invalid_session.snmp_get_bulk('polatisSysInfoProductCode')
            except BaseException as err:
                raise err
            if not result['polatisSysInfoProductCode.']:
                nose.tools.assert_in('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                     'Wrong or No exception for Getbulk with Invalid '
                                     'Community: % s' % self.snmp_invalid_session.snmp_session.ErrorStr)
            else:
                raise Exception('Got output for getbulk with invalid community instead of empty dict: %s' % result)

        def test_getbulk_serialnumber_with_invalidcommunity(self):
            """
            Negative SNMPv2 Getbulk Polatis Serial Number with Invalid Community
            """
            self.snmp_session.create_box('test_getbulk_serialnumber_with_invalidcommunity')
            try:
                result = self.snmp_invalid_session.snmp_get_bulk('polatisSysInfoSerialNumber')
            except BaseException as err:
                raise err
            if not result['polatisSysInfoSerialNumber.']:
                nose.tools.assert_in('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                     'Wrong or No exception for Getbulk with Invalid '
                                     'Community: % s' % self.snmp_invalid_session.snmp_session.ErrorStr)
            else:
                raise Exception('Got output for getbulk with invalid community instead of empty dict: %s' % result)

        def test_getbulk_firmwareversion_with_invalidcommunity(self):
            """
            Negative SNMPv2 Getbulk Polatis Firmware Version with Invalid Community
            """
            self.snmp_session.create_box('test_getbulk_firmwareversion_with_invalidcommunity')
            try:
                result = self.snmp_invalid_session.snmp_get_bulk('polatisSysInfoFirmwareVersion')
            except BaseException as err:
                raise err
            if not result['polatisSysInfoFirmwareVersion.']:
                nose.tools.assert_in('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                     'Wrong or No exception for Getbulk with Invalid '
                                     'Community: % s' % self.snmp_invalid_session.snmp_session.ErrorStr)
            else:
                raise Exception('Got output for getbulk with invalid community instead of empty dict: %s' % result)

        def test_getbulk_netconfigtable_with_invalid_community(self):
            """
            Negative Query Polatis NetConfig Table through SnmpBulkGet with Invalid Community
            """
            self.snmp_session.create_box('test_getbulk_netconfigtable_with_invalid_community')
            try:
                output = self.snmp_invalid_session.snmp_get_bulk('polatisNetConfigTable')
            except BaseException as err:
                raise err
            #print output
            if 'polatisNetConfigTable.' not in output:
                raise AssertionError("Got output for snmp bulkget with invalid community: %s" % output)
            else:
                nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                        'Wrong or No exception for SNMP BulkGet with Invalid Community:%s'
                                        % self.snmp_invalid_session.snmp_session.ErrorStr)

        def test_getbulk_netconfigipaddress_with_invalidcommunity(self):
            """
            Negative SNMPv2 Getbulk Polatis NetConfig Ip Address with Invalid Community
            """
            self.snmp_session.create_box('test_getbulk_netconfigipaddress_with_invalidcommunity')
            try:
                result = self.snmp_invalid_session.snmp_get_bulk('polatisNetConfigIpAddress')
            except BaseException as err:
                raise err
            if not result['polatisNetConfigIpAddress.']:
                nose.tools.assert_in('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                     'Wrong or No exception for Getbulk with Invalid '
                                     'Community: % s' % self.snmp_invalid_session.snmp_session.ErrorStr)
            else:
                raise Exception('Got output for getbulk with invalid community instead of empty dict: %s' % result)

        def test_getbulk_netconfigateway_with_invalidcommunity(self):
            """
            Negative SNMPv2 Getbulk Polatis NetConfig Gateway with Invalid Community
            """
            self.snmp_session.create_box('test_getbulk_netconfigateway_with_invalidcommunity')
            try:
                result = self.snmp_invalid_session.snmp_get_bulk('polatisNetConfigGateway')
            except BaseException as err:
                raise err
            if not result['polatisNetConfigGateway.']:
                nose.tools.assert_in('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                     'Wrong or No exception for Getbulk with Invalid '
                                     'Community: % s' % self.snmp_invalid_session.snmp_session.ErrorStr)
            else:
                raise Exception('Got output for getbulk with invalid community instead of empty dict: %s' % result)

        def test_getbulk_netconfigsubnet_with_invalidcommunity(self):
            """
            Negative SNMPv2 Getbulk Polatis NetConfig Subnet with Invalid Community
            """
            self.snmp_session.create_box('test_getbulk_netconfigsubnet_with_invalidcommunity')
            try:
                result = self.snmp_invalid_session.snmp_get_bulk('polatisNetConfigSubnet')
            except BaseException as err:
                raise err
            if not result['polatisNetConfigSubnet.']:
                nose.tools.assert_in('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                     'Wrong or No exception for Getbulk with Invalid '
                                     'Community: % s' % self.snmp_invalid_session.snmp_session.ErrorStr)
            else:
                raise Exception('Got output for getbulk with invalid community instead of empty dict: %s' % result)

        def test_getbulk_netconfigbroadcast_with_invalidcommunity(self):
            """
            Negative SNMPv2 Getbulk Polatis NetConfig Broadcast with Invalid Community
            """
            self.snmp_session.create_box('test_getbulk_netconfigbroadcast_with_invalidcommunity')
            try:
                result = self.snmp_invalid_session.snmp_get_bulk('polatisNetConfigBroadcast')
            except BaseException as err:
                raise err
            if not result['polatisNetConfigBroadcast.']:
                nose.tools.assert_in('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                     'Wrong or No exception for Getbulk with Invalid '
                                     'Community: % s' % self.snmp_invalid_session.snmp_session.ErrorStr)
            else:
                raise Exception('Got output for getbulk with invalid community instead of empty dict: %s' % result)

        def test_getbulk_netconfigautoaddr_with_invalidcommunity(self):
            """
            Negative SNMPv2 Getbulk Polatis NetConfig Auto Addr with Invalid Community
            """
            self.snmp_session.create_box('test_getbulk_netconfigautoaddr_with_invalidcommunity')
            try:
                result = self.snmp_invalid_session.snmp_get_bulk('polatisNetConfigAutoAddr')
            except BaseException as err:
                raise err
            if not result['polatisNetConfigAutoAddr.']:
                nose.tools.assert_in('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                     'Wrong or No exception for Getbulk with Invalid '
                                     'Community: % s' % self.snmp_invalid_session.snmp_session.ErrorStr)
            else:
                raise Exception('Got output for getbulk with invalid community instead of empty dict: %s' % result)

        def test_getbulk_netconfigstatus_with_invalidcommunity(self):
            """
            Negative SNMPv2 Getbulk Polatis NetConfig Status with Invalid Community
            """
            self.snmp_session.create_box('test_getbulk_netconfigstatus_with_invalidcommunity')
            try:
                result = self.snmp_invalid_session.snmp_get_bulk('polatisNetConfigStatus')
            except BaseException as err:
                raise err
            if not result['polatisNetConfigStatus.']:
                nose.tools.assert_in('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                     'Wrong or No exception for Getbulk with Invalid '
                                     'Community: % s' % self.snmp_invalid_session.snmp_session.ErrorStr)
            else:
                raise Exception('Got output for getbulk with invalid community instead of empty dict: %s' % result)

        def test_getbulk_interfaceconfigtable_with_invalid_community(self):
            """
            Negative Query Polatis Interface Config Table through SnmpBulkGet with Invalid Community
            """
            self.snmp_session.create_box('test_getbulk_interfaceconfigtable_with_invalid_community')
            try:
                output = self.snmp_invalid_session.snmp_get_bulk('polatisInterfaceConfigTable')
            except BaseException as err:
                raise err
            #print output
            if 'polatisInterfaceConfigTable.' not in output:
                raise AssertionError("Got output for snmp bulkget with invalid community: %s" % output)
            else:
                nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                        'Wrong or No exception for SNMP BulkGet with Invalid Community:%s'
                                        % self.snmp_invalid_session.snmp_session.ErrorStr)

        def test_getbulk_interfaceconfigprotocol_with_invalidcommunity(self):
            """
            Negative SNMPv2 Getbulk Polatis Interface Config Protocol with Invalid Community
            """
            self.snmp_session.create_box('test_getbulk_interfaceconfigprotocol_with_invalidcommunity')
            try:
                result = self.snmp_invalid_session.snmp_get_bulk('polatisInterfaceConfigProtocol')
            except BaseException as err:
                raise err
            if not result['polatisInterfaceConfigProtocol.']:
                nose.tools.assert_in('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                     'Wrong or No exception for Getbulk with Invalid '
                                     'Community: % s' % self.snmp_invalid_session.snmp_session.ErrorStr)
            else:
                raise Exception('Got output for getbulk with invalid community instead of empty dict: %s' % result)

        def test_getbulk_interfaceconfigdevice_with_invalidcommunity(self):
            """
            Negative SNMPv2 Getbulk Polatis Interface Config Device with Invalid Community
            """
            self.snmp_session.create_box('test_getbulk_interfaceconfigdevice_with_invalidcommunity')
            try:
                result = self.snmp_invalid_session.snmp_get_bulk('polatisInterfaceConfigDevice')
            except BaseException as err:
                raise err
            if not result['polatisInterfaceConfigDevice.']:
                nose.tools.assert_in('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                     'Wrong or No exception for Getbulk with Invalid '
                                     'Community: % s' % self.snmp_invalid_session.snmp_session.ErrorStr)
            else:
                raise Exception('Got output for getbulk with invalid community instead of empty dict: %s' % result)

        def test_getbulk_interfaceconfigstatus_with_invalidcommunity(self):
            """
            Negative SNMPv2 Getbulk Polatis Interface Config Status with Invalid Community
            """
            self.snmp_session.create_box('test_getbulk_interfaceconfigstatus_with_invalidcommunity')
            try:
                result = self.snmp_invalid_session.snmp_get_bulk('polatisInterfaceConfigStatus')
            except BaseException as err:
                raise err
            if not result['polatisInterfaceConfigStatus.']:
                nose.tools.assert_in('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                     'Wrong or No exception for Getbulk with Invalid '
                                     'Community: % s' % self.snmp_invalid_session.snmp_session.ErrorStr)
            else:
                raise Exception('Got output for getbulk with invalid community instead of empty dict: %s' % result)

    "SNMPv3 Test Cases"

    if version == 3:

        def test_v3_get_polatisproductcode(self):
            """
            SNMPv3 Get for Polatis System Info Product Code
            """
            self.snmp_session.create_box('test_v3_get_polatisproductcode')
            try:
                output = self.snmp_v3_session.snmp_get("polatisSysInfoProductCode.0")
            except BaseException as err:
                raise err
            if 'polatisSysInfoProductCode.0' not in output:
                raise KeyError("Incorrect output for PolatissysinfoproductCode SNMPv3 Get: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisProductCode'], output['polatisSysInfoProductCode.0'],
                                        "Wrong Value for GetPolatisSysInfoProductCode")

        def test_v3_getnext_polatisproductcode(self):
            """
            SNMPv3 GetNext for Polatis System Info Product Code
            """
            self.snmp_session.create_box('test_v3_getnext_polatisproductcode')
            try:
                output = self.snmp_v3_session.snmp_get_next("polatisSysInfoProductCode")
            except BaseException as err:
                raise err
            if 'polatisSysInfoProductCode.0' not in output:
                raise KeyError("Incorrect output for PolatissysinfoproductCode SNMPv3 GetNext: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisProductCode'], output['polatisSysInfoProductCode.0'],
                                        "Wrong Value for GetNextPolatisSysInfoProductCode")

        def test_v3_walk_polatisproductcode(self):
            """
            SNMPv3 Walk for Polatis System Info Product Code
            """
            self.snmp_session.create_box('test_v3_walk_polatisproductcode')
            try:
                output = self.snmp_v3_session.snmp_walk("polatisSysInfoProductCode")
            except BaseException as err:
                raise err
            if 'polatisSysInfoProductCode.0' not in output:
                raise KeyError("Incorrect output for PolatissysinfoproductCode SNMPv3 Walk: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisProductCode'], output['polatisSysInfoProductCode.0'],
                                        "Wrong Value for SnmpWalkPolatisSysInfoProductCode")

        def test_v3_getbulk_polatisproductcode(self):
            """
            SNMPv3 GetBulk for Polatis System Info Product Code
            """
            self.snmp_session.create_box('test_v3_getbulk_polatisproductcode')
            try:
                output = self.snmp_v3_session.snmp_get_bulk("polatisSysInfoProductCode")
            except BaseException as err:
                raise err
            if 'polatisSysInfoProductCode.0' not in output:
                raise KeyError("Incorrect output for PolatissysinfoproductCode SNMPv3 GetBulk: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisProductCode'], output['polatisSysInfoProductCode.0'],
                                        "Wrong Value for GetBulkPolatisSysInfoProductCode")

        def test_v3_get_polatisserialnumber(self):
            """
            SNMPv3 Get for Polatis System Info Serial Number
            """
            self.snmp_session.create_box('test_v3_get_polatisserialnumber')
            try:
                output = self.snmp_v3_session.snmp_get("polatisSysInfoSerialNumber.0")
            except BaseException as err:
                raise err
            if 'polatisSysInfoSerialNumber.0' not in output:
                raise KeyError("Incorrect output for polatissysinfoserialnumber SNMPv3 Get: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisSerialNumber'], output['polatisSysInfoSerialNumber.0'],
                                        "Wrong Value for GetPolatisSysInfoSerialNumber")

        def test_v3_getnext_polatisserialnumber(self):
            """
            SNMPv3 GetNext for Polatis System Info Serial Number
            """
            self.snmp_session.create_box('test_v3_getnext_polatisserialnumber')
            try:
                output = self.snmp_v3_session.snmp_get_next("polatisSysInfoSerialNumber")
            except BaseException as err:
                raise err
            if 'polatisSysInfoSerialNumber.0' not in output:
                raise KeyError("Incorrect output for polatissysinfoserialnumber SNMPv3 GetNext: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisSerialNumber'], output['polatisSysInfoSerialNumber.0'],
                                        "Wrong Value for GetNextPolatisSysInfoSerialNumber")
            time.sleep(10)

        def test_v3_walk_polatisserialnumber(self):
            """
            SNMPv3 Walk for Polatis System Info Serial Number
            """
            self.snmp_session.create_box('test_v3_walk_polatisserialnumber')
            try:
                output = self.snmp_v3_session.snmp_walk("polatisSysInfoSerialNumber")
            except BaseException as err:
                raise err
            if 'polatisSysInfoSerialNumber.0' not in output:
                raise KeyError("Incorrect output for polatissysinfoserialnumber SNMPv3 Walk: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisSerialNumber'], output['polatisSysInfoSerialNumber.0'],
                                        "Wrong Value for SnmpWalkPolatisSysInfoSerialNumber")
            time.sleep(10)

        def test_v3_getbulk_polatisserialnumber(self):
            """
            SNMPv3 GetBulk for Polatis System Info Serial Number
            """
            self.snmp_session.create_box('test_v3_getbulk_polatisserialnumber')
            try:
                output = self.snmp_v3_session.snmp_get_bulk("polatisSysInfoSerialNumber")
            except BaseException as err:
                raise err
            if 'polatisSysInfoSerialNumber.0' not in output:
                raise KeyError("Incorrect output for polatissysinfoserialnumber SNMPv3 GetBulk: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisSerialNumber'], output['polatisSysInfoSerialNumber.0'],
                                        "Wrong Value for GetBulkPolatisSysInfoSerialNumber")
            time.sleep(10)

        def test_v3_get_polatisfirmwareversion(self):
            """
            SNMPv3 Get for Polatis System Info Firmware Version
            """
            self.snmp_session.create_box('test_v3_get_polatisfirmwareversion')
            try:
                output = self.snmp_v3_session.snmp_get("polatisSysInfoFirmwareVersion.0")
            except BaseException as err:
                raise err
            if 'polatisSysInfoFirmwareVersion.0' not in output:
                raise KeyError("Incorrect output for polatissysinfofirmwareversion SNMPv3 Get: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisFirmwareVersion'], output['polatisSysInfoFirmwareVersion.0'],
                                        "Wrong Value for GetPolatisSysInfoFirmwareVersion")
            time.sleep(10)

        def test_v3_getnext_polatisfirmwareversion(self):
            """
            SNMPv3 GetNext for Polatis System Info Firmware Version
            """
            self.snmp_session.create_box('test_v3_getnext_polatisfirmwareversion')
            try:
                output = self.snmp_v3_session.snmp_get_next("polatisSysInfoFirmwareVersion")
            except BaseException as err:
                raise err
            if 'polatisSysInfoFirmwareVersion.0' not in output:
                raise KeyError("Incorrect output for polatissysinfofirmwareversion SNMPv3 GetNext: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisFirmwareVersion'], output['polatisSysInfoFirmwareVersion.0'],
                                        "Wrong Value for GetNextPolatisSysInfoFirmwareVersion")
            time.sleep(10)

        def test_v3_walk_polatisfirmwareversion(self):
            """
            SNMPv3 Walk for Polatis System Info Firmware Version
            """
            self.snmp_session.create_box('test_v3_walk_polatisfirmwareversion')
            try:
                output = self.snmp_v3_session.snmp_walk("polatisSysInfoFirmwareVersion")
            except BaseException as err:
                raise err
            if 'polatisSysInfoFirmwareVersion.0' not in output:
                raise KeyError("Incorrect output for polatissysinfofirmwareversion SNMPv3 Walk: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisFirmwareVersion'], output['polatisSysInfoFirmwareVersion.0'],
                                        "Wrong Value for SnmpWalkPolatisSysInfoFirmwareVersion")
            time.sleep(10)

        def test_v3_getbulk_polatisfirmwareversion(self):
            """
            SNMPv3 GetBulk for Polatis System Info Firmware Version
            """
            self.snmp_session.create_box('test_v3_getbulk_polatisfirmwareversion')
            try:
                output = self.snmp_v3_session.snmp_get_bulk("polatisSysInfoFirmwareVersion")
            except BaseException as err:
                raise err
            if 'polatisSysInfoFirmwareVersion.0' not in output:
                raise KeyError("Incorrect output for polatisSysInfoFirmwareVersion SNMPv3 GetBulk: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisFirmwareVersion'], output['polatisSysInfoFirmwareVersion.0'],
                                        "Wrong Value for GetBulkPolatisSysInfoFirmwareVersion")
            time.sleep(10)

        def test_v3_set_polatisrestartagent(self):
            """
            SNMPv3 Set Polatis System Control Restart Agent
            """
            self.snmp_session.create_box('test_v3_set_polatisrestartagent')
            try:
                uptime1 = self.snmp_v3_session.snmp_get("sysUpTime.0")
            except BaseException as err:
                raise err
            #print uptime1
            try:
                result = self.snmp_v3_session.snmp_set('polatisSysCtrlRestartAgent.0', 2, 'INTEGER')
                #print "result : ", result
            except BaseException as err:
                raise Exception("PolatisSysCtrlRestartAgentError:", err)
            self.snmp_v3_session.snmp_get('sysUpTime.0')
            print "t1:", self.snmp_v3_session.snmp_session.ErrorStr
            while self.snmp_v3_session.snmp_session.ErrorStr is not '':
                print "Agent Service Restarting..."
                self.snmp_v3_session.snmp_get('sysUpTime.0')
                print "t2:", self.snmp_v3_session.snmp_session.ErrorStr
            print "Agent is up now...!!!"
            uptime2 = self.snmp_v3_session.snmp_get('sysUpTime.0')
            #print uptime2
            nose.tools.assert_equal(1, result, "No Proper Output(0) for the command..Timeout exception "
                                               "thrown:%s" % result)
            nose.tools.assert_greater(int(uptime1['sysUpTimeInstance.']), int(uptime2['sysUpTimeInstance.']),
                                      "Snmp Agent Not restarted")

        def test_v3_get_eth0_netconfigipaddress(self):
            """
            SNMPv3 Get for Polatis NetConfig Ip Address
            """
            self.snmp_session.create_box('test_v3_get_eth0_netconfigipaddress')
            try:
                output = self.snmp_v3_session.snmp_get("polatisNetConfigIpAddress.1")
            except BaseException as err:
                raise err
            if 'polatisNetConfigIpAddress.1' not in output:
                raise KeyError("Incorrect output for polatisNetConfigIpAddress SNMPv3 Get: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigIpAddress.1'], output['polatisNetConfigIpAddress.1'],
                                        "Wrong Value for GetPolatisNetConfigIpAddress")
        def test_v3_get_eth1_netconfigipaddress(self):
            """
            SNMPv3 Get for Polatis NetConfig Ip Address
            """
            self.snmp_session.create_box('test_v3_get_eth1_netconfigipaddress')
            try:
                output = self.snmp_v3_session.snmp_get("polatisNetConfigIpAddress.2")
            except BaseException as err:
                raise err
            if 'polatisNetConfigIpAddress.2' not in output:
                raise KeyError("Incorrect output for polatisNetConfigIpAddress SNMPv3 Get: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigIpAddress.2'], output['polatisNetConfigIpAddress.2'],
                                        "Wrong Value for GetPolatisNetConfigIpAddress")

        def test_v3_getnext_eth0_netconfigipaddress(self):
            """
            SNMPv3 GetNext for Polatis NetConfig Ip Address
            """
            self.snmp_session.create_box('test_v3_getnext_eth0_netconfigipaddress')
            try:
                output = self.snmp_v3_session.snmp_get_next("polatisNetConfigIpAddress.1")
            except BaseException as err:
                raise err
            if 'polatisNetConfigIpAddress.2' not in output:
                raise KeyError("Incorrect output for polatisNetConfigIpAddress SNMPv3 GetNext: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigIpAddress.2'], output['polatisNetConfigIpAddress.2'],
                                        "Wrong Value for GetNextPolatisNetConfigIpAddress")

        def test_v3_getnext_eth1_netconfigipaddress(self):
            """
            SNMPv3 GetNext for Polatis NetConfig Ip Address
            """
            self.snmp_session.create_box('test_v3_getnext_eth1_netconfigipaddress')
            try:
                output = self.snmp_v3_session.snmp_get_next("polatisNetConfigIpAddress.2")
            except BaseException as err:
                raise err
            if 'polatisNetConfigGateway.1' not in output:
                raise KeyError("Incorrect output for polatisNetConfigIpAddress SNMPv3 GetNext: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigGateway.1'], output['polatisNetConfigGateway.1'],
                                        "Wrong Value for GetNextPolatisNetConfigIpAddress")

        def test_v3_walk_netconfigipaddress(self):
            """
            SNMPv3 Walk for Polatis NetConfig Ip Address
            """
            self.snmp_session.create_box('test_v3_walk_netconfigipaddress')
            try:
                output = self.snmp_v3_session.snmp_walk("polatisNetConfigIpAddress")
            except BaseException as err:
                raise err

            for key, value in output.iteritems():
                nose.tools.assert_equal(TABLE_DICT[key], output[key], 'Wrong value for WalkpolatisNetConfigIpAddress')

            #if 'polatisNetConfigIpAddress.1' not in output:
            #    raise KeyError("Incorrect output for polatisNetConfigIpAddress SNMPv3 Walk: %s" % output)
            #else:
            #    nose.tools.assert_equal(TABLE_DICT['polatisNetConfigIpAddress'], output['polatisNetConfigIpAddress.1'],
            #                            "Wrong Value for SnmpWalkPolatisNetConfigIpAddress")

        def test_v3_getbulk_netconfigipaddress(self):
            """
            SNMPv3 GetBulk for Polatis NetConfig Ip Address
            """
            self.snmp_session.create_box('test_v3_getbulk_netconfigipaddress')
            try:
                output = self.snmp_v3_session.snmp_get_bulk("polatisNetConfigIpAddress")
            except BaseException as err:
                raise err
            for key, value in output.iteritems():
                nose.tools.assert_equal(TABLE_DICT[key], output[key], 'Wrong value for GetBulkpolatisNetConfigIpAddress')
            time.sleep(10)
 
            #if 'polatisNetConfigIpAddress.1' not in output:
            #    raise KeyError("Incorrect output for polatisNetConfigIpAddress SNMPv3 GetBulk: %s" % output)
            #else:
            #    nose.tools.assert_equal(TABLE_DICT['polatisNetConfigIpAddress'], output['polatisNetConfigIpAddress.1'],
            #                            "Wrong Value for GetBulkPolatisNetConfigIpAddress")

        def test_v3_get_eth0_netconfigateway(self):
            """
            SNMPv3 Get for Polatis NetConfig Gateway
            """
            self.snmp_session.create_box('test_v3_get_eth0_netconfigateway')
            try:
                output = self.snmp_v3_session.snmp_get("polatisNetConfigGateway.1")
            except BaseException as err:
                raise err
            if 'polatisNetConfigGateway.1' not in output:
                raise KeyError("Incorrect output for polatisNetConfigGateway SNMPv3 Get: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigGateway.1'], output['polatisNetConfigGateway.1'],
                                        "Wrong Value for GetPolatisNetConfigGateway")
            time.sleep(10)

        def test_v3_get_eth1_netconfigateway(self):
            """
            SNMPv3 Get for Polatis NetConfig Gateway
            """
            self.snmp_session.create_box('test_v3_get_eth1_netconfigateway')
            try:
                output = self.snmp_v3_session.snmp_get("polatisNetConfigGateway.2")
            except BaseException as err:
                raise err
            if 'polatisNetConfigGateway.2' not in output:
                raise KeyError("Incorrect output for polatisNetConfigGateway SNMPv3 Get: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigGateway.2'], output['polatisNetConfigGateway.2'],
                                        "Wrong Value for GetPolatisNetConfigGateway")
            time.sleep(10)

        def test_v3_getnext_eth0_netconfigateway(self):
            """
            SNMPv3 GetNext for Polatis NetConfig Gateway
            """
            self.snmp_session.create_box('test_v3_getnext_eth0_netconfigateway')
            try:
                output = self.snmp_v3_session.snmp_get_next("polatisNetConfigGateway.1")
            except BaseException as err:
                raise err
            if 'polatisNetConfigGateway.2' not in output:
                raise KeyError("Incorrect output for polatisNetConfigGateway SNMPv3 GetNext: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigGateway.2'], output['polatisNetConfigGateway.2'],
                                        "Wrong Value for GetNextPolatisNetConfigGateway")
            time.sleep(10)

        def test_v3_getnext_eth1_netconfigateway(self):
            """
            SNMPv3 GetNext for Polatis NetConfig Gateway
            """
            self.snmp_session.create_box('test_v3_getnext_eth1_netconfigateway')
            try:
                output = self.snmp_v3_session.snmp_get_next("polatisNetConfigGateway.2")
            except BaseException as err:
                raise err
            if 'polatisNetConfigSubnet.1' not in output:
                raise KeyError("Incorrect output for polatisNetConfigGateway SNMPv3 GetNext: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigSubnet.1'], output['polatisNetConfigSubnet.1'],
                                        "Wrong Value for GetNextPolatisNetConfigGateway")
            time.sleep(10)

        def test_v3_walk_netconfigateway(self):
            """
            SNMPv3 Walk for Polatis NetConfig Gateway
            """
            self.snmp_session.create_box('test_v3_walk_netconfigateway')
            try:
                output = self.snmp_v3_session.snmp_walk("polatisNetConfigGateway")
            except BaseException as err:
                raise err
            for key, value in output.iteritems():
                nose.tools.assert_equal(TABLE_DICT[key], output[key], 'Wrong value for WalkpolatisNetConfigGateway')
            time.sleep(10)

            #if 'polatisNetConfigGateway.1' not in output:
            #    raise KeyError("Incorrect output for polatisNetConfigGateway SNMPv3 Walk: %s" % output)
            #else:
            #    nose.tools.assert_equal(TABLE_DICT['polatisNetConfigGateway'], output['polatisNetConfigGateway.1'],
            #                            "Wrong Value for SnmpWalkPolatisNetConfigGateway")

        def test_v3_getbulk_netconfigateway(self):
            """
            SNMPv3 GetBulk for Polatis NetConfig Gateway
            """
            self.snmp_session.create_box('test_v3_getbulk_netconfigateway')
            try:
                output = self.snmp_v3_session.snmp_get_bulk("polatisNetConfigGateway")
            except BaseException as err:
                raise err
 
            for key, value in output.iteritems():
                nose.tools.assert_equal(TABLE_DICT[key], output[key], 'Wrong value for GetBulkpolatisNetConfigGateway')
            time.sleep(10)

            #if 'polatisNetConfigGateway.1' not in output:
            #    raise KeyError("Incorrect output for polatisNetConfigGateway SNMPv3 GetBulk: %s" % output)
            #else:
            #    nose.tools.assert_equal(TABLE_DICT['polatisNetConfigGateway'], output['polatisNetConfigGateway.1'],
            #                            "Wrong Value for GetBulkPolatisNetConfigGateway")

        def test_v3_get_eth0_netconfigsubnet(self):
            """
            SNMPv3 Get for Polatis NetConfig Subnet
            """
            self.snmp_session.create_box('test_v3_get_eth0_netconfigsubnet')
            try:
                output = self.snmp_v3_session.snmp_get("polatisNetConfigSubnet.1")
            except BaseException as err:
                raise err
            if 'polatisNetConfigSubnet.1' not in output:
                raise KeyError("Incorrect output for polatisNetConfigSubnet SNMPv3 Get: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigSubnet.1'], output['polatisNetConfigSubnet.1'],
                                        "Wrong Value for GetPolatisNetConfigSubnet")
            time.sleep(10)

        def test_v3_get_eth1_netconfigsubnet(self):
            """
            SNMPv3 Get for Polatis NetConfig Subnet
            """
            self.snmp_session.create_box('test_v3_get_eth1_netconfigsubnet')
            try:
		#print "valid AuthPass: ", self.snmp_v3_session.snmp_session.AuthPass
                output = self.snmp_v3_session.snmp_get("polatisNetConfigSubnet.2")
            except BaseException as err:
                raise err
            if 'polatisNetConfigSubnet.2' not in output:
                raise KeyError("Incorrect output for polatisNetConfigSubnet SNMPv3 Get: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigSubnet.2'], output['polatisNetConfigSubnet.2'],
                                        "Wrong Value for GetPolatisNetConfigSubnet")
            time.sleep(10)

        def test_v3_getnext_eth0_netconfigsubnet(self):
            """
            SNMPv3 GetNext for Polatis NetConfig Subnet
            """
            self.snmp_session.create_box('test_v3_getnext_eth0_netconfigsubnet')
            try:
                output = self.snmp_v3_session.snmp_get_next("polatisNetConfigSubnet.1")
            except BaseException as err:
                raise err
            if 'polatisNetConfigSubnet.2' not in output:
                raise KeyError("Incorrect output for polatisNetConfigSubnet SNMPv3 GetNext: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigSubnet.2'], output['polatisNetConfigSubnet.2'],
                                        "Wrong Value for GetNextPolatisNetConfigSubnet")
            time.sleep(10)

        def test_v3_getnext_eth1_netconfigsubnet(self):
            """
            SNMPv3 GetNext for Polatis NetConfig Subnet
            """
            self.snmp_session.create_box('test_v3_getnext_eth1_netconfigsubnet')
            try:
                output = self.snmp_v3_session.snmp_get_next("polatisNetConfigSubnet.2")
            except BaseException as err:
                raise err
            if 'polatisNetConfigBroadcast.1' not in output:
                raise KeyError("Incorrect output for polatisNetConfigSubnet SNMPv3 GetNext: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigBroadcast.1'], output['polatisNetConfigBroadcast.1'],
                                        "Wrong Value for GetNextPolatisNetConfigSubnet")
            time.sleep(10)

        def test_v3_walk_netconfigsubnet(self):
            """
            SNMPv3 Walk for Polatis NetConfig Subnet
            """
            self.snmp_session.create_box('test_v3_walk_netconfigsubnet')
            try:
                output = self.snmp_v3_session.snmp_walk("polatisNetConfigSubnet")
            except BaseException as err:
                raise err
            for key, value in output.iteritems():
                nose.tools.assert_equal(TABLE_DICT[key], output[key], 'Wrong value for WalkpolatisNetConfigSubnet')
            time.sleep(10)
            #if 'polatisNetConfigSubnet.1' not in output:
            #    raise KeyError("Incorrect output for polatisNetConfigSubnet SNMPv3 Walk: %s" % output)
            #else:
            #    nose.tools.assert_equal(TABLE_DICT['polatisNetConfigSubnet'], output['polatisNetConfigSubnet.1'],
            #                            "Wrong Value for SnmpWalkPolatisNetConfigSubnet")

        def test_v3_getbulk_netconfigsubnet(self):
            """
            SNMPv3 GetBulk for Polatis NetConfig Subnet
            """
            self.snmp_session.create_box('test_v3_getbulk_netconfigsubnet')
            try:
                output = self.snmp_v3_session.snmp_get_bulk("polatisNetConfigSubnet")
            except BaseException as err:
                raise err
            #for key, value in output.iteritems():
            #    nose.tools.assert_equal(TABLE_DICT[key], output[key], 'Wrong value for GetBulkpolatisNetConfigSubnet')
            if 'polatisNetConfigSubnet.1' not in output:
                raise KeyError("Incorrect output for polatisNetConfigSubnet SNMPv3 GetBulk: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigSubnet.1'], output['polatisNetConfigSubnet.1'],
                                        "Wrong Value for GetBulkPolatisNetConfigSubnet")
            time.sleep(10)

        def test_v3_get_eth0_netconfigbroadcast(self):
            """
            SNMPv3 Get for Polatis NetConfig Broadcast
            """
            self.snmp_session.create_box('test_v3_get_eth0_netconfigbroadcast')
            try:
                output = self.snmp_v3_session.snmp_get("polatisNetConfigBroadcast.1")
            except BaseException as err:
                raise err
            if 'polatisNetConfigBroadcast.1' not in output:
                raise KeyError("Incorrect output for PolatisNetConfigBroadcast SNMPv3 Get: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigBroadcast.1'], output['polatisNetConfigBroadcast.1'],
                                        "Wrong Value for GetPolatisNetConfigBroadcast")
            time.sleep(10)

        def test_v3_get_eth1_netconfigbroadcast(self):
            """
            SNMPv3 Get for Polatis NetConfig Broadcast
            """
            self.snmp_session.create_box('test_v3_get_eth1_netconfigbroadcast')
            try:
                output = self.snmp_v3_session.snmp_get("polatisNetConfigBroadcast.2")
            except BaseException as err:
                raise err
            if 'polatisNetConfigBroadcast.2' not in output:
                raise KeyError("Incorrect output for PolatisNetConfigBroadcast SNMPv3 Get: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigBroadcast.2'], output['polatisNetConfigBroadcast.2'],
                                        "Wrong Value for GetPolatisNetConfigBroadcast")
            time.sleep(10)

        def test_v3_getnext_eth0_netconfigbroadcast(self):
            """
            SNMPv3 GetNext for Polatis NetConfig Broadcast
            """
            self.snmp_session.create_box('test_v3_getnext_eth0_netconfigbroadcast')
            try:
                output = self.snmp_v3_session.snmp_get_next("polatisNetConfigBroadcast.1")
            except BaseException as err:
                raise err
            if 'polatisNetConfigBroadcast.2' not in output:
                raise KeyError("Incorrect output for PolatisNetConfigBroadcast SNMPv3 GetNext: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigBroadcast.2'], output['polatisNetConfigBroadcast.2'],
                                        "Wrong Value for GetNextPolatisNetConfigBroadcast")
            time.sleep(10)

        def test_v3_getnext_eth1_netconfigbroadcast(self):
            """
            SNMPv3 GetNext for Polatis NetConfig Broadcast
            """
            self.snmp_session.create_box('test_v3_getnext_eth1_netconfigbroadcast')
            try:
                output = self.snmp_v3_session.snmp_get_next("polatisNetConfigBroadcast.2")
            except BaseException as err:
                raise err
            if 'polatisNetConfigAutoAddr.1' not in output:
                raise KeyError("Incorrect output for PolatisNetConfigBroadcast SNMPv3 GetNext: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigAutoAddr.1'], output['polatisNetConfigAutoAddr.1'],
                                        "Wrong Value for GetNextPolatisNetConfigBroadcast")
            time.sleep(10)

        def test_v3_walk_netconfigbroadcast(self):
            """
            SNMPv3 Walk for Polatis NetConfig Broadcast
            """
            self.snmp_session.create_box('test_v3_walk_netconfigbroadcast')
            try:
                output = self.snmp_v3_session.snmp_walk("polatisNetConfigBroadcast")
            except BaseException as err:
                raise err
            for key, value in output.iteritems():
                nose.tools.assert_equal(TABLE_DICT[key], output[key], 'Wrong value for WalkpolatisNetConfigBroadcast')
            time.sleep(10)
            #if 'polatisNetConfigBroadcast.1' not in output:
            #    raise KeyError("Incorrect output for PolatisNetConfigBroadcast SNMPv3 Walk: %s" % output)
            #else:
            #    nose.tools.assert_equal(TABLE_DICT['polatisNetConfigBroadcast'], output['polatisNetConfigBroadcast.1'],
            #                            "Wrong Value for SnmpWalkPolatisNetConfigBroadcast")

        def test_v3_getbulk_netconfigbroadcast(self):
            """
            SNMPv3 GetBulk for Polatis NetConfig Broadcast
            """
            self.snmp_session.create_box('test_v3_getbulk_netconfigbroadcast')
            try:
                output = self.snmp_v3_session.snmp_get_bulk("polatisNetConfigBroadcast")
            except BaseException as err:
                raise err
            #for key, value in output.iteritems():
            #    nose.tools.assert_equal(TABLE_DICT[key], output[key], 'Wrong value for GteBulkpolatisNetConfigBroadcast')
            if 'polatisNetConfigBroadcast.1' not in output:
                raise KeyError("Incorrect output for PolatisNetConfigBroadcast SNMPv3 GetBulk: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigBroadcast.1'], output['polatisNetConfigBroadcast.1'],
                                        "Wrong Value for GetBulkPolatisNetConfigBroadcast")
            time.sleep(10)

        def test_v3_get_eth0_netconfigautoaddr(self):
            """
            SNMPv3 Get for Polatis NetConfig AutoAddr
            """
            self.snmp_session.create_box('test_v3_get_eth0_netconfigautoaddr')
            try:
                output = self.snmp_v3_session.snmp_get("polatisNetConfigAutoAddr.1")
            except BaseException as err:
                raise err
            if 'polatisNetConfigAutoAddr.1' not in output:
                raise KeyError("Incorrect output for PolatisNetConfigAutoAddr SNMPv3 Get: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigAutoAddr.1'], output['polatisNetConfigAutoAddr.1'],
                                        "Wrong Value for GetPolatisNetConfigAutoAddr")
            time.sleep(10)

        def test_v3_get_eth1_netconfigautoaddr(self):
            """
            SNMPv3 Get for Polatis NetConfig AutoAddr
            """
            self.snmp_session.create_box('test_v3_get_eth1_netconfigautoaddr')
            try:
                output = self.snmp_v3_session.snmp_get("polatisNetConfigAutoAddr.2")
            except BaseException as err:
                raise err
            if 'polatisNetConfigAutoAddr.2' not in output:
                raise KeyError("Incorrect output for PolatisNetConfigAutoAddr SNMPv3 Get: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigAutoAddr.2'], output['polatisNetConfigAutoAddr.2'],
                                        "Wrong Value for GetPolatisNetConfigAutoAddr")
            time.sleep(10)

        def test_v3_getnext_eth0_netconfigautoaddr(self):
            """
            SNMPv3 GetNext for Polatis NetConfig AutoAddr
            """
            self.snmp_session.create_box('test_v3_getnext_eth0_netconfigautoaddr')
            try:
                output = self.snmp_v3_session.snmp_get_next("polatisNetConfigAutoAddr.1")
            except BaseException as err:
                raise err
            if 'polatisNetConfigAutoAddr.2' not in output:
                raise KeyError("Incorrect output for PolatisNetConfigAutoAddr SNMPv3 GetNext: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigAutoAddr.2'], output['polatisNetConfigAutoAddr.2'],
                                        "Wrong Value for GetNextPolatisNetConfigAutoAddr")
            time.sleep(10)

        def test_v3_getnext_eth1_netconfigautoaddr(self):
            """
            SNMPv3 GetNext for Polatis NetConfig AutoAddr
            """
            self.snmp_session.create_box('test_v3_getnext_eth1_netconfigautoaddr')
            try:
                output = self.snmp_v3_session.snmp_get_next("polatisNetConfigAutoAddr.2")
            except BaseException as err:
                raise err
            if 'polatisNetConfigStatus.1' not in output:
                raise KeyError("Incorrect output for PolatisNetConfigAutoAddr SNMPv3 GetNext: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigStatus.1'], output['polatisNetConfigStatus.1'],
                                        "Wrong Value for GetNextPolatisNetConfigAutoAddr")
            time.sleep(10)

        def test_v3_walk_netconfigautoaddr(self):
            """
            SNMPv3 Walk for Polatis NetConfig AutoAddr
            """
            self.snmp_session.create_box('test_v3_walk_netconfigautoaddr')
            try:
                output = self.snmp_v3_session.snmp_walk("polatisNetConfigAutoAddr")
            except BaseException as err:
                raise err
            for key, value in output.iteritems():
                nose.tools.assert_equal(TABLE_DICT[key], output[key], 'Wrong value for WalkpolatisNetConfigAutoAddr')
            time.sleep(10)
            #if 'polatisNetConfigAutoAddr.1' not in output:
            #    raise KeyError("Incorrect output for PolatisNetConfigAutoAddr SNMPv3 Walk: %s" % output)
            #else:
            #    nose.tools.assert_equal(TABLE_DICT['polatisNetConfigAutoAddr'], output['polatisNetConfigAutoAddr.1'],
            #                            "Wrong Value for SnmpWalkPolatisNetConfigAutoAddr")

        def test_v3_getbulk_netconfigautoaddr(self):
            """
            SNMPv3 GetBulk for Polatis NetConfig AutoAddr
            """
            self.snmp_session.create_box('test_v3_getbulk_netconfigautoaddr')
            try:
                output = self.snmp_v3_session.snmp_get_bulk("polatisNetConfigAutoAddr")
            except BaseException as err:
                raise err
            #for key, value in output.iteritems():
            #    nose.tools.assert_equal(TABLE_DICT[key], output[key], 'Wrong value for GetBulkpolatisNetConfigAutoAddr')
            if 'polatisNetConfigAutoAddr.1' not in output:
                raise KeyError("Incorrect output for PolatisNetConfigAutoAddr SNMPv3 GetBulk: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigAutoAddr.1'], output['polatisNetConfigAutoAddr.1'],
                                        "Wrong Value for GetBulkPolatisNetConfigAutoAddr")
            time.sleep(10)

        def test_v3_get_eth0_netconfigstatus(self):
            """
            SNMPv3 Get for Polatis NetConfig Status
            """
            self.snmp_session.create_box('test_v3_get_eth0_netconfigstatus')
            try:
                output = self.snmp_v3_session.snmp_get("polatisNetConfigStatus.1")
            except BaseException as err:
                raise err
            if 'polatisNetConfigStatus.1' not in output:
                raise KeyError("Incorrect output for PolatisNetConfigStatus SNMPv3 Get: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigStatus.1'], output['polatisNetConfigStatus.1'],
                                        "Wrong Value for GetPolatisNetConfigStatus")
            time.sleep(10)

        def test_v3_get_eth1_netconfigstatus(self):
            """
            SNMPv3 Get for Polatis NetConfig Status
            """
            self.snmp_session.create_box('test_v3_get_eth1_netconfigstatus')
            try:
                output = self.snmp_v3_session.snmp_get("polatisNetConfigStatus.2")
            except BaseException as er:
                raise err
            if 'polatisNetConfigStatus.2' not in output:
                raise KeyError("Incorrect output for PolatisNetConfigStatus SNMPv3 Get: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigStatus.2'], output['polatisNetConfigStatus.2'],
                                        "Wrong Value for GetPolatisNetConfigStatus")
            time.sleep(10)

        def test_v3_getnext_eth0_netconfigstatus(self):
            """
            SNMPv3 GetNext for Polatis NetConfig Status
            """
            self.snmp_session.create_box('test_v3_getnext_eth0_netconfigstatus')
            try:
                output = self.snmp_v3_session.snmp_get_next("polatisNetConfigStatus.1")
            except BaseException as err:
                raise err
            if 'polatisNetConfigStatus.2' not in output:
                raise KeyError("Incorrect output for PolatisNetConfigStatus SNMPv3 GetNext: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigStatus.2'], output['polatisNetConfigStatus.2'],
                                        "Wrong Value for GetNextPolatisNetConfigStatus")
            time.sleep(10)

        def test_v3_getnext_eth1_netconfigstatus(self):
            """
            SNMPv3 GetNext for Polatis NetConfig Status
            """
            self.snmp_session.create_box('test_v3_getnext_eth1_netconfigstatus')
            try:
                output = self.snmp_v3_session.snmp_get_next("polatisNetConfigStatus")
            except BaseException as err:
                raise err
            if 'polatisNetConfigStatus.1' not in output:
                raise KeyError("Incorrect output for PolatisNetConfigStatus SNMPv3 GetNext: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigStatus.1'], output['polatisNetConfigStatus.1'],
                                        "Wrong Value for GetNextPolatisNetConfigStatus")
            time.sleep(10)

        def test_v3_walk_netconfigstatus(self):
            """
            SNMPv3 Walk for Polatis NetConfig Status
            """
            self.snmp_session.create_box('test_v3_walk_netconfigstatus')
            try:
                output = self.snmp_v3_session.snmp_walk("polatisNetConfigStatus")
            except BaseException as err:
                raise err
            for key, value in output.iteritems():
                nose.tools.assert_equal(TABLE_DICT[key], output[key], 'Wrong value for WalkpolatisNetConfigStatus')
            time.sleep(10)
            #if 'polatisNetConfigStatus.1' not in output:
            #    raise KeyError("Incorrect output for PolatisNetConfigStatus SNMPv3 Walk: %s" % output)
            #else:
            #    nose.tools.assert_equal(TABLE_DICT['polatisNetConfigStatus'], output['polatisNetConfigStatus.1'],
            #                            "Wrong Value for SnmpWalkPolatisNetConfigStatus")

        def test_v3_getbulk_netconfigstatus(self):
            """
            SNMPv3 GetBulk for Polatis NetConfig Status
            """
            self.snmp_session.create_box('test_v3_getbulk_netconfigstatus')
            try:
                output = self.snmp_v3_session.snmp_get_bulk("polatisNetConfigStatus")
            except BaseException as err:
                raise err
            #for key, value in output.iteritems():
            #    nose.tools.assert_equal(TABLE_DICT[key], output[key], 'Wrong value for GetBulkpolatisNetConfigStatus')
            if 'polatisNetConfigStatus.1' not in output:
                raise KeyError("Incorrect output for PolatisNetConfigStatus SNMPv3 GetBulk: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['polatisNetConfigStatus.1'], output['polatisNetConfigStatus.1'],
                                        "Wrong Value for GetBulkPolatisNetConfigStatus")
            time.sleep(10)

        def test_v3_get_interfaceconfigprotocol(self):
            """
            SNMPv3 Get for Polatis Interface Config Protocol
            """
            self.snmp_session.create_box('test_v3_get_interfaceconfigprotocol')
            try:
                output = self.snmp_v3_session.snmp_get("polatisInterfaceConfigProtocol.1")
            except BaseException as err:
                raise err
            if 'polatisInterfaceConfigProtocol.1' not in output:
                raise KeyError("Incorrect output for PolatisInterfaceConfigProtocol SNMPv3 Get: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigProtocol'][0],
                                        output['polatisInterfaceConfigProtocol.1'],
                                        "Wrong Value for GetPolatisInterfaceConfigProtocol")
            time.sleep(10)

        def test_v3_getnext_interfaceconfigprotocol(self):
            """
            SNMPv3 GetNext for Polatis Interface Config Protocol
            """
            self.snmp_session.create_box('test_v3_getnext_interfaceconfigprotocol')
            try:
                output = self.snmp_v3_session.snmp_get_next("polatisInterfaceConfigProtocol")
            except BaseException as err:
                raise err
            if 'polatisInterfaceConfigProtocol.1' not in output:
                raise KeyError("Incorrect output for PolatisInterfaceConfigProtocol SNMPv3 GetNext: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigProtocol'][0],
                                        output['polatisInterfaceConfigProtocol.1'],
                                        "Wrong Value for GetNextPolatisInterfaceConfigProtocol")
            time.sleep(10)

        def test_v3_walk_interfaceconfigprotocol(self):
            """
            SNMPv3 Walk for Polatis Interface Config Protocol
            """
            self.snmp_session.create_box('test_v3_walk_interfaceconfigprotocol')
            try:
                output = self.snmp_v3_session.snmp_walk("polatisInterfaceConfigProtocol")
            except BaseException as err:
                raise err
            for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigProtocol'])) + 1):
                if 'polatisInterfaceConfigProtocol.%s' % value not in output:
                    raise KeyError("Incorrect output for PolatisInterfaceConfigProtocol SNMPv3 Walk: %s" % output)
            else:
                for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigProtocol'])) + 1):
                    nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigProtocol'][(value - 1)],
                                            output['polatisInterfaceConfigProtocol.%s' % value],
                                            "Wrong Value for SnmpWalkPolatisInterfaceConfigProtocol")
            time.sleep(10)

        def test_v3_getbulk_interfaceconfigprotocol(self):
            """
            SNMPv3 GetBulk for Polatis Interface Config Protocol
            """
            self.snmp_session.create_box('test_v3_getbulk_interfaceconfigprotocol')
            try:
                output = self.snmp_v3_session.snmp_get_bulk("polatisInterfaceConfigProtocol")
            except BaseException as err:
                raise err
            for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigProtocol'])) + 1):
                if 'polatisInterfaceConfigProtocol.%s' % value not in output:
                    raise KeyError("Incorrect output for PolatisInterfaceConfigProtocol SNMPv3 GetBulk: %s" % output)
            else:
                for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigProtocol'])) + 1):
                    nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigProtocol'][(value - 1)],
                                            output['polatisInterfaceConfigProtocol.%s' % value],
                                            "Wrong Value for GetBulkPolatisInterfaceConfigProtocol")
            time.sleep(10)

        def test_v3_get_interfaceconfigdevice(self):
            """
            SNMPv3 Get for Polatis Interface Config Device
            """
            self.snmp_session.create_box('test_v3_get_interfaceconfigdevice')
            try:
                output = self.snmp_v3_session.snmp_get("polatisInterfaceConfigDevice.1")
            except BaseException as err:
                raise err
            if 'polatisInterfaceConfigDevice.1' not in output:
                raise KeyError("Incorrect output for PolatisInterfaceConfigDevice SNMPv3 Get: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigDevice'][0],
                                        output['polatisInterfaceConfigDevice.1'],
                                        "Wrong Value for GetPolatisInterfaceConfigDevice")
            time.sleep(10)

        def test_v3_getnext_interfaceconfigdevice(self):
            """
            SNMPv3 GetNext for Polatis Interface Config Device
            """
            self.snmp_session.create_box('test_v3_getnext_interfaceconfigdevice')
            try:
                output = self.snmp_v3_session.snmp_get_next("polatisInterfaceConfigDevice.1")
            except BaseException as err:
                raise err
            if 'polatisInterfaceConfigDevice.2' not in output:
                raise KeyError("Incorrect output for PolatisInterfaceConfigDevice SNMPv3 GetNext: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigDevice'][1],
                                        output['polatisInterfaceConfigDevice.2'],
                                        "Wrong Value for GetNextPolatisInterfaceConfigDevice")
            time.sleep(10)

        def test_v3_walk_interfaceconfigdevice(self):
            """
            SNMPv3 Walk for Polatis Interface Config Device
            """
            self.snmp_session.create_box('test_v3_walk_interfaceconfigdevice')
            try:
                output = self.snmp_v3_session.snmp_walk("polatisInterfaceConfigDevice")
            except BaseException as err:
                raise err
            for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigDevice'])) + 1):
                if 'polatisInterfaceConfigDevice.%s' % value not in output:
                    raise KeyError("Incorrect output for PolatisInterfaceConfigDevice SNMPv3 Walk: %s" % output)
            else:
                for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigDevice'])) + 1):
                    nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigDevice'][(value - 1)],
                                            output['polatisInterfaceConfigDevice.%s' % value],
                                            "Wrong Value for SnmpWalkPolatisInterfaceConfigDevice")

            time.sleep(10)
        def test_v3_getbulk_interfaceconfigdevice(self):
            """
            SNMPv3 GetBulk for Polatis Interface Config Device
            """
            self.snmp_session.create_box('test_v3_getbulk_interfaceconfigdevice')
            try:
                output = self.snmp_v3_session.snmp_get_bulk("polatisInterfaceConfigDevice")
            except BaseException as err:
                raise err
            for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigDevice'])) + 1):
                if 'polatisInterfaceConfigDevice.%s' % value not in output:
                    raise KeyError("Incorrect output for PolatisInterfaceConfigDevice SNMPv3 GetBulk: %s" % output)
            else:
                for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigDevice'])) + 1):
                    nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigDevice'][(value - 1)],
                                            output['polatisInterfaceConfigDevice.%s' % value],
                                            "Wrong Value for GetBulkPolatisInterfaceConfigDevice")
            time.sleep(10)

        def test_v3_get_interfaceconfigstatus(self):
            """
            SNMPv3 Get for Polatis Interface Config Status
            """
            self.snmp_session.create_box('test_v3_get_interfaceconfigstatus')
            try:
                output = self.snmp_v3_session.snmp_get("polatisInterfaceConfigStatus.1")
                #print "output : ", output
            except BaseException as err:
                raise err
            if 'polatisInterfaceConfigStatus.1' not in output:
                raise KeyError("Incorrect output for PolatisInterfaceConfigStatus SNMPv3 Get: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigStatus'][0],
                                        output['polatisInterfaceConfigStatus.1'],
                                        "Wrong Value for GetPolatisInterfaceConfigStatus")

            time.sleep(10)
        def test_v3_getnext_interfaceconfigstatus(self):
            """
            SNMPv3 GetNext for Polatis Interface Config Status
            """
            self.snmp_session.create_box('test_v3_getnext_interfaceconfigstatus')
            try:
                output = self.snmp_v3_session.snmp_get_next("polatisInterfaceConfigStatus.1")
                #print "output : ", output
            except BaseException as err:
                raise err
            if 'polatisInterfaceConfigStatus.2' not in output:
                raise KeyError("Incorrect output for PolatisInterfaceConfigStatus SNMPv3 GetNext: %s" % output)
            else:
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigStatus'][0],
                                        output['polatisInterfaceConfigStatus.2'],
                                        "Wrong Value for GetNextPolatisInterfaceConfigStatus")

            time.sleep(10)
        def test_v3_walk_interfaceconfigstatus(self):
            """
            SNMPv3 Walk for Polatis Interface Config Status
            """
            self.snmp_session.create_box('test_v3_walk_interfaceconfigstatus')
            try:
                output = self.snmp_v3_session.snmp_walk("polatisInterfaceConfigStatus")
            except BaseException as err:
                raise err
            for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigStatus'])) + 1):
                if 'polatisInterfaceConfigStatus.%s' % value not in output:
                    raise KeyError("Incorrect output for PolatisInterfaceConfigStatus SNMPv3 Walk: %s" % output)
            else:
                for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigStatus'])) + 1):
                    nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigStatus'][(value - 1)],
                                            output['polatisInterfaceConfigStatus.%s' % value],
                                            "Wrong Value for SnmpWalkPolatisInterfaceConfigStatus")

            time.sleep(10)
        def test_v3_bulkget_interfaceconfigstatus(self):
            """
            SNMPv3 GetBulk for Polatis Interface Config Status
            """
            self.snmp_session.create_box('test_v3_bulkget_interfaceconfigstatus')
            try:
                output = self.snmp_v3_session.snmp_get_bulk("polatisInterfaceConfigStatus")
            except BaseException as err:
                raise err
            for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigStatus'])) + 1):
                if 'polatisInterfaceConfigStatus.%s' % value not in output:
                    raise KeyError("Incorrect output for PolatisInterfaceConfigStatus SNMPv3 GetBulk: %s" % output)
            else:
                for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigStatus'])) + 1):
                    nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigStatus'][(value - 1)],
                                            output['polatisInterfaceConfigStatus.%s' % value],
                                            "Wrong Value for GetBulkPolatisInterfaceConfigStatus")
            time.sleep(10)

        "Negative SNMPv3 Test Cases"


        def test_v3_get_netconfigipaddress_with_invalid_index(self):
            """
            Negative SNMPv3 Get Polatis NetConfig Ip Address with Invalid Index
            """
            self.snmp_session.create_box('test_v3_get_netconfigipaddress_with_invalid_index')
            try:
                output = self.snmp_v3_session.snmp_get('polatisNetConfigIpAddress.3')
            except BaseException as err:
                raise err
            if output['polatisNetConfigIpAddress.3']:
                raise Exception("Got output for Snmp Get with Invalid Index instead of empty dict: %s" % output)
            else:
                nose.tools.assert_equal('(genError) A general failure occured', self.snmp_v3_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP Get with Invalid '
                                        'Index: %s' % self.snmp_v3_session.snmp_session.ErrorStr)
            time.sleep(10)

        def test_v3_get_netconfigateway_with_invalid_index(self):
            """
            Negative SNMPv3 Get Polatis NetConfig Gateway with Invalid Index
            """
            self.snmp_session.create_box('test_v3_get_netconfigateway_with_invalid_index')
            try:
                output = self.snmp_v3_session.snmp_get('polatisNetConfigGateway.3')
            except BaseException as err:
                raise err

	    ##print "Error : ", self.snmp_v3_session.snmp_session.ErrorStr

            if output['polatisNetConfigGateway.3']:
                raise Exception("Got output for Snmp Get with Invalid Index instead of empty dict: %s" % output)
            else:
                nose.tools.assert_equal('(genError) A general failure occured', self.snmp_v3_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP Get with Invalid '
                                        'Index: %s' % self.snmp_v3_session.snmp_session.ErrorStr)
            time.sleep(10)

        def test_v3_get_netconfigsubnet_with_invalid_index(self):
            """
            Negative SNMPv3 Get Polatis NetConfig Subnet with Invalid Index
            """
            self.snmp_session.create_box('test_v3_get_netconfigsubnet_with_invalid_index')
            try:
                output = self.snmp_v3_session.snmp_get('polatisNetConfigSubnet.3')
            except BaseException as err:
                raise err
            if output['polatisNetConfigSubnet.3']:
                raise Exception("Got output for Snmp Get with Invalid Index instead of empty dict: %s" % output)
            else:
                nose.tools.assert_equal('(genError) A general failure occured', self.snmp_v3_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP Get with Invalid '
                                        'Index: %s' % self.snmp_v3_session.snmp_session.ErrorStr)
            time.sleep(10)

        def test_v3_get_netconfigbroadcast_with_invalid_index(self):
            """
            Negative SNMPv3 Get Polatis NetConfig Broadcast with Invalid Index
            """
            self.snmp_session.create_box('test_v3_get_netconfigbroadcast_with_invalid_index')
            try:
                output = self.snmp_v3_session.snmp_get('polatisNetConfigBroadcast.3')
            except BaseException as err:
                raise err
            if output['polatisNetConfigBroadcast.3']:
                raise Exception("Got output for Snmp Get with Invalid Index instead of empty dict: %s" % output)
            else:
                nose.tools.assert_equal('(genError) A general failure occured', self.snmp_v3_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP Get with Invalid '
                                        'Index: %s' % self.snmp_v3_session.snmp_session.ErrorStr)
            time.sleep(10)

        def test_v3_get_netconfigautoaddr_with_invalid_index(self):
            """
            Negative SNMPv3 Get Polatis NetConfig Auto Addr with Invalid Index
            """
            self.snmp_session.create_box('test_v3_get_netconfigautoaddr_with_invalid_index')
            try:
                output = self.snmp_v3_session.snmp_get('polatisNetConfigAutoAddr.3')
            except BaseException as err:
                raise err
            if output['polatisNetConfigAutoAddr.3']:
                raise Exception("Got output for Snmp Get with Invalid Index instead of empty dict: %s" % output)
            else:
                nose.tools.assert_equal('(genError) A general failure occured', self.snmp_v3_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP Get with Invalid '
                                        'Index: %s ' % self.snmp_v3_session.snmp_session.ErrorStr)
            time.sleep(10)

        def test_v3_get_netconfigstatus_with_invalid_index(self):
            """
            Negative SNMPv3 Get Polatis NetConfig Status with Invalid Index
            """
            self.snmp_session.create_box('test_v3_get_netconfigstatus_with_invalid_index')
            try:
                output = self.snmp_v3_session.snmp_get('polatisNetConfigStatus.3')
            except BaseException as err:
                raise err
            if output['polatisNetConfigStatus.3']:
                raise Exception("Got output for Snmp Get with Invalid Index instead of empty dict: %s" % output)
            else:
                nose.tools.assert_equal('', self.snmp_v3_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP Get with Invalid '
                                        'Index : %s ' % self.snmp_v3_session.snmp_session.ErrorStr)
            time.sleep(10)



        def test_v3_get_interfaceconfigprotocol_with_invalid_index(self):
            """
            Negative SNMPv3 Get Polatis Interface Config Protocol with Invalid Index
            """
            self.snmp_session.create_box('test_v3_get_interfaceconfigprotocol_with_invalid_index')
            try:
                output = self.snmp_v3_session.snmp_get('polatisInterfaceConfigProtocol.11')
            except BaseException as err:
                raise err
            if output['polatisInterfaceConfigProtocol.11']:
                raise Exception("Got output for Snmp Get with Invalid Index instead of empty dict: %s" % output)
            else:
                nose.tools.assert_equal('(genError) A general failure occured', self.snmp_v3_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP Get with Invalid '
                                        'Index: %s ' % self.snmp_v3_session.snmp_session.ErrorStr)
            time.sleep(10)

        def test_v3_get_interfaceconfigdevice_with_invalid_index(self):
            """
            Negative SNMPv3 Get Polatis Interface Config Device with Invalid Index
            """
            self.snmp_session.create_box('test_v3_get_interfaceconfigdevice_with_invalid_index')
            try:
                output = self.snmp_v3_session.snmp_get('polatisInterfaceConfigDevice.11')
            except BaseException as err:
                raise err
            if output['polatisInterfaceConfigDevice.11']:
                raise Exception("Got output for Snmp Get with Invalid Index instead of empty dict: %s" % output)
            else:
                nose.tools.assert_equal('(genError) A general failure occured', self.snmp_v3_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP Get with Invalid '
                                        'Index: %s ' % self.snmp_v3_session.snmp_session.ErrorStr)
            time.sleep(10)

        def test_v3_get_interfaceconfigstatus_with_invalid_index(self):
            """
            Negative SNMPv3 Get Polatis Interface Config Status with Invalid Index
            """
            self.snmp_session.create_box('test_v3_get_interfaceconfigstatus_with_invalid_index')
            try:
                output = self.snmp_v3_session.snmp_get('polatisInterfaceConfigStatus.11')
            except BaseException as err:
                raise err
            if output['polatisInterfaceConfigStatus.11']:
                raise Exception("Got output for Snmp Get with Invalid Index instead of empty dict: %s" % output)
            else:
                nose.tools.assert_equal('(genError) A general failure occured', self.snmp_v3_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP Get with Invalid '
                                        'Index: %s ' % self.snmp_v3_session.snmp_session.ErrorStr)
            time.sleep(10)

        def test_v3_set_nonwritable_interfaceconfigprotocol(self):
            """
            SNMPv3 Set Non-Writable Polatis Interface Config Protocol
            """
            self.snmp_session.create_box('test_v3_set_nonwritable_interfaceconfigprotocol')
            try:
                result = self.snmp_v3_session.snmp_set('polatisInterfaceConfigProtocol.3', 'Protocol', 'OCTET STRING')
            except BaseException as err:
                raise err
            if result is not 0:
                raise Exception(
                    "Able to set the nonwritable column, SNMPSet value should be 0 for non-writable columns "
                    "instead the value is %s" % result)
            else:
                nose.tools.assert_in('notWritable', self.snmp_v3_session.snmp_session.ErrorStr,
                                     'No or Wrong Exception when setting a non-writable column'
                                     '(polatisInterfaceConfigProtocol):%s' % self.snmp_v3_session.snmp_session.ErrorStr)
            time.sleep(10)

        def test_v3_set_nonwritable_interfaceconfigdevice(self):
            """
            SNMPv3 Set Non-Writable Polatis Interface Config Device
            """
            self.snmp_session.create_box('test_v3_set_nonwritable_interfaceconfigdevice')
            try:
                result = self.snmp_v3_session.snmp_set('polatisInterfaceConfigDevice.3', 'Device', 'OCTET STRING')
            except BaseException as err:
                raise err
            if result is not 0:
                raise Exception(
                    "Able to set the nonwritable column, SNMPSet value should be 0 for non-writable columns "
                    "instead the value is %s" % result)
            else:
                nose.tools.assert_in('notWritable', self.snmp_v3_session.snmp_session.ErrorStr,
                                     'No or Wrong Exception when setting a non-writable column'
                                     '(polatisInterfaceConfigDevice): %s' % self.snmp_v3_session.snmp_session.ErrorStr)
            time.sleep(10)


        def test_v3_snmptable_netconfigtable(self):
            """
            SNMPv3 Query Polatis Netconfig Table through SnmpTable
            """
            self.snmp_session.create_box('test_v3_snmptable_netconfigtable')
            try:
                output = self.snmp_v3_session.snmp_table('polatisNetConfigTable')
            except BaseException as err:
                raise NameError(err)
            for key, value in output.iteritems():
                strip_key = key[:-2]
                nose.tools.assert_equal(TABLE_DICT[key], output[key], 'Wrong Value for Get SnmpTable against '
                                                                            'PolatisNetconfigTable:{%s:%s}' % (
                                        key, value))
            time.sleep(10)

        def test_v3_walk_netconfigtable(self):
            """
            SNMPv3 Query Polatis NetConfig Table through SnmpWalk
            """
            self.snmp_session.create_box('test_v3_walk_netconfigtable')
            try:
                output = self.snmp_v3_session.snmp_walk('polatisNetConfigTable')
            except BaseException as err:
                raise NameError(err)
            for key, value in output.iteritems():
                strip_key = key[:-2]
                nose.tools.assert_equal(TABLE_DICT[key], output[key], 'Wrong Value for Get SnmpTable against '
                                                                            'PolatisNetconfigTable:{%s:%s}' % (
                                        key, value))
            time.sleep(10)

        def test_v3_bulkget_netconfigtable(self):
            """
            SNMPv3 Query Polatis Netconfig Table through SnmpBulkGet
            """
            self.snmp_session.create_box('test_v3_bulkget_netconfigtable')
            try:
                output = self.snmp_v3_session.snmp_get_bulk('polatisNetConfigTable', 0, 6)
                #print "output : ", output
            except BaseException as err:
                raise err
            time.sleep(10)
            if None in output.values():
                raise Exception("Timeout...Unable to bulkget for polatisNetConfigTable: %s " % output)
            else:
                for key, value in output.iteritems():
                    #strip_key = key[:-2]
                    #print "strip_key :", strip_key
                    #print "TABLE_DICT[strip_key] \n", TABLE_DICT[strip_key]
                    #print "output[key], \n", output[key]
                    nose.tools.assert_equal(TABLE_DICT[key], output[key],
                                            'Wrong Value for Get SnmpWalk against Polatis'
                                            'NetconfigTable:{%s:%s}' % (key, value))

        def test_v3_snmptable_interfaceconfigtable(self):
            """
            SNMPv3 Query Polatis Interface Config Table through SnmpTable
            """
            self.snmp_session.create_box('test_v3_snmptable_interfaceconfigtable')
            try:
                output = self.snmp_v3_session.snmp_table('polatisInterfaceConfigTable')
            except BaseException as err:
                raise NameError(err)
            #print output
            for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigStatus'])) + 1):
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigStatus'][(value - 1)],
                                        output['polatisInterfaceConfigStatus.%s' % value],
                                        "Wrong Value for Get SnmpWalk against PolatisInterfaceConfig"
                                        "Table: {'%s':'%s'}" % ('polatisInterfaceConfigStatus.%s' % value,
                                                                output['polatisInterfaceConfigStatus.%s' % value]))
            for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigProtocol'])) + 1):
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigProtocol'][(value - 1)],
                                        output['polatisInterfaceConfigProtocol.%s' % value],
                                        "Wrong Value for Get SnmpWalk against PolatisInterfaceConfig"
                                        "Table: {'%s':'%s'}" % ('polatisInterfaceConfigProtocol.%s' % value,
                                                                output['polatisInterfaceConfigProtocol.%s' % value]))
            for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigDevice'])) + 1):
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigDevice'][(value - 1)],
                                        output['polatisInterfaceConfigDevice.%s' % value],
                                        "Wrong Value for Get SnmpWalk against PolatisInterfaceConfig"
                                        "Table:{'%s':'%s'}" % ('polatisInterfaceConfigDevice.%s' % value,
                                                               output['polatisInterfaceConfigDevice.%s' % value]))
            time.sleep(10)

        def test_v3_getbulk_interfaceconfigtable(self):
            """
            SNMPv3 Query Interface Config Table through SnmpBulkGet
            """
            self.snmp_session.create_box('test_v3_getbulk_interfaceconfigtable')
            try:
                e_index = len(TABLE_DICT['PolatisInterfaceConfigStatus'])
                output = self.snmp_v3_session.snmp_get_bulk('polatisInterfaceConfigTable', 0, 3 * e_index)
            except BaseException as err:
                raise NameError(err)
            #print output
            for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigStatus'])) + 1):
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigStatus'][(value - 1)],
                                        output['polatisInterfaceConfigStatus.%s' % value],
                                        "Wrong Value for Get SnmpWalk against PolatisInterfaceConfig"
                                        "Table: {'%s':'%s'}" % ('polatisInterfaceConfigStatus.%s' % value,
                                                                output['polatisInterfaceConfigStatus.%s' % value]))
            for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigProtocol'])) + 1):
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigProtocol'][(value - 1)],
                                        output['polatisInterfaceConfigProtocol.%s' % value],
                                        "Wrong Value for Get SnmpWalk against PolatisInterfaceConfig"
                                        "Table: {'%s':'%s'}" % ('polatisInterfaceConfigProtocol.%s' % value,
                                                                output['polatisInterfaceConfigProtocol.%s' % value]))
            for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigDevice'])) + 1):
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigDevice'][(value - 1)],
                                        output['polatisInterfaceConfigDevice.%s' % value],
                                        "Wrong Value for Get SnmpWalk against PolatisInterfaceConfig"
                                        "Table:{'%s':'%s'}" % ('polatisInterfaceConfigDevice.%s' % value,
                                                               output['polatisInterfaceConfigDevice.%s' % value]))
            time.sleep(10)

        def test_v3_walk_interfaceconfigtable(self):
            """
            SNMPv3 Query Polatis Interface Config Table through SnmpWalk
            """
            self.snmp_session.create_box('test_v3_walk_interfaceconfigtable')
            try:
                output = self.snmp_v3_session.snmp_walk('polatisInterfaceConfigTable')
            except BaseException as err:
                raise NameError(err)
            #print output
            for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigStatus'])) + 1):
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigStatus'][(value - 1)],
                                        output['polatisInterfaceConfigStatus.%s' % value],
                                        "Wrong Value for Get SnmpWalk against PolatisInterfaceConfig"
                                        "Table: {'%s':'%s'}" % ('polatisInterfaceConfigStatus.%s' % value,
                                                                output['polatisInterfaceConfigStatus.%s' % value]))
            for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigProtocol'])) + 1):
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigProtocol'][(value - 1)],
                                        output['polatisInterfaceConfigProtocol.%s' % value],
                                        "Wrong Value for Get SnmpWalk against PolatisInterfaceConfig"
                                        "Table: {'%s':'%s'}" % ('polatisInterfaceConfigProtocol.%s' % value,
                                                                output['polatisInterfaceConfigProtocol.%s' % value]))
            for value in range(1, (len(TABLE_DICT['PolatisInterfaceConfigDevice'])) + 1):
                nose.tools.assert_equal(TABLE_DICT['PolatisInterfaceConfigDevice'][(value - 1)],
                                        output['polatisInterfaceConfigDevice.%s' % value],
                                        "Wrong Value for Get SnmpWalk against PolatisInterfaceConfig"
                                        "Table:{'%s':'%s'}" % ('polatisInterfaceConfigDevice.%s' % value,
                                                               output['polatisInterfaceConfigDevice.%s' % value]))
            time.sleep(10)




        def test_v3_reboot_polatiscontrolsystem(self):
            """
            SNMPv3 Set Polatis System Control Restart Agent
            """
            self.snmp_session.create_box('test_v3_reboot_polatiscontrolsystem')
            try:
                output = self.snmp_v3_session.snmp_set('polatisSysCtrlRebootSys.0', 2, 'INTEGER')
            except BaseException as err:
                raise err
            #print output
            #print "result : ", output
            #print "AuthPass : ", self.snmp_v3_session.snmp_session.AuthPass
            #print "secuser : ", self.snmp_v3_session.snmp_session.SecName
            #print "Err : ", self.snmp_v3_session.snmp_session.ErrorStr
            time.sleep(20)
            nose.tools.assert_equal(1, output, 'Switch Reboot Action Not Successful: %s ' % output)
            nose.tools.assert_equal('', self.snmp_v3_session.snmp_session.ErrorStr,
                                    'Wrong Message while rebooting the '
                                    'switch: %s' % self.snmp_v3_session.snmp_session.ErrorStr)
	    tme = 0.2
            while self.snmp_v3_session.snmp_session.ErrorStr is not '':
                if tme < 100:
                    print "Switch Rebooting...Completed: %s" % tme
                else:
                    print "Loading Configuration..."
                self.snmp_v3_session.snmp_get('sysUpTime.0')
                tme += 33.1
            print "Switch is up now...!!!"
            time.sleep(10)



    
    if version == 1 or version == 2:
        "POLATIS OXC MIB"
       
        def test_get_polatisoxcsize(self):
            """
            Query Polatis Oxc Size through Snmp Get
            """
            self.snmp_session.create_box('test_get_polatisoxcsize')

            result = self.snmp_session.snmp_get('polatisOxcSize.0')

            #print result
            if result['polatisOxcSize.0'] is not None:
                nose.tools.assert_equal(pol_dict['polatisOxcSize'], result['polatisOxcSize.0'],
                                        'Wrong value for GetPolatisOxcSize: %s' % result['polatisOxcSize.0'])
            else:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)

        def test_getnext_polatisoxcsize(self):
            """
            Query Polatis Oxc Size through Snmp GetNext
            """
            self.snmp_session.create_box('test_getnext_polatisoxcsize')
            try:
                result = self.snmp_session.snmp_get_next('polatisOxcSize')
            except BaseException as err:
                raise err
            #print result
            if 'polatisOxcSize.0' not in result:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)
            else:
                nose.tools.assert_equal(pol_dict['polatisOxcSize'], result['polatisOxcSize.0'],
                                        'Wrong value for GetNextPolatisOxcSize: %s' % result['polatisOxcSize.0'])

        def test_walk_polatisoxcsize(self):
            """
            Query Polatis Oxc Size through Snmp Walk
            """
            self.snmp_session.create_box('test_walk_polatisoxcsize')
            try:
                result = self.snmp_session.snmp_walk('polatisOxcSize')
            except BaseException as err:
                raise err
            #print result
            if not result:
                raise Exception("None Type value returned,Error Message: %s" % self.snmp_session.snmp_session.ErrorStr)
            else:
                nose.tools.assert_equal(pol_dict['polatisOxcSize'], result['polatisOxcSize.0'],
                                        'Wrong value for SnmpWalkPolatisOxcSize: %s' % result['polatisOxcSize.0'])

        #def test_snmptable_oxcporttable(self):
        #    """
        #    Query Polatis Oxc Port Table with Snmp Table
        #    """
        #    self.snmp_session.create_box('test_snmptable_oxcporttable')
        #    sze = map(int, pol_dict['polatisOxcSize'].split('x'))
        #    egress_port = sze[0] + 1
        #    for ingress_port in range(1, sze[0] + 1):
        #        if ingress_port <= sze[1]:
        #            self.snmp_session.snmp_set('polatisOxcPortPatch.%s' % ingress_port, egress_port, 'GAUGE32')
        #            egress_port += 1
        #    for index in range(1, (sze[0] + sze[1]) + 1):
        #        self.snmp_session.snmp_set('polatisOxcPortDesiredState.%s' % index, 2, 'INTEGER')
        #    time.sleep(10)
        #    output = self.snmp_session.snmp_table('polatisOxcPortTable')
        #    for ingress_port in range(1, sze[0] + 1):
        #        if ingress_port <= sze[1]:
        #            nose.tools.assert_equal(output['polatisOxcPortPatch.%s' % ingress_port], str(egress_port),
        #                                    'err: %s ' % output['polatisOxcPortPatch.%s' % ingress_port])
        #            egress_port += 1
        #        else:
        #            nose.tools.assert_equal(output['polatisOxcPortPatch.%s' % ingress_port], '0',
        #                                    'err: %s ' % output['polatisOxcPortPatch.%s' % ingress_port])
        #    for index in range(1, (sze[0] + sze[1]) + 1):
        #        nose.tools.assert_equal(output['polatisOxcPortDesiredState.%s' % ingress_port], '2',
        #                                'err: %s' % output['polatisOxcPortDesiredState.%s' % ingress_port])
        #        nose.tools.assert_in(output['polatisOxcPortCurrentState.%s' % ingress_port], ['1', '2'],
        #                             'err: %s' % output['polatisOxcPortCurrentState.%s' % ingress_port])

        def test_get_polatisoxcportpatch(self):
            """
            Query Polatis Oxc Port Patch through Snmpget
            """
            self.snmp_session.create_box('test_get_polatisoxcportpatch')
            output = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), int(prtlst[0])+int(prtlst[0]), 'GAUGE32')
            nose.tools.assert_equal(1, output, 'SNMP Set Error: %s' % self.snmp_wr_session.snmp_session.ErrorStr)

            result = self.snmp_session.snmp_get('polatisOxcPortPatch.%s' % int(prtlst[0]))
            if 'polatisOxcPortPatch.%s' % int(prtlst[0]) in result:
                nose.tools.assert_equal(str(int(prtlst[0])+int(prtlst[0])), result['polatisOxcPortPatch.%s' % int(prtlst[0])],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result)
            else:
                raise Exception(
                    "Incorrect Output:%s, Error Message:%s" % (result, self.snmp_session.snmp_session.ErrorStr))

            self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'GAUGE32')

        def test_getnext_polatisoxcportpatch(self):
            """
            Query Polatis Oxc Port Patch through Snmpgetnext
            """
            output = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.1', int(prtlst[0])+int(prtlst[0]), 'GAUGE32')
            nose.tools.assert_equal(1, output, 'SNMP Set Error: %s' % self.snmp_wr_session.snmp_session.ErrorStr)
            try:
                result = self.snmp_session.snmp_get_next('polatisOxcPortPatch')
            except BaseException as err:
                raise err
            if 'polatisOxcPortPatch.1' in result:
                nose.tools.assert_equal(str(int(prtlst[0])+int(prtlst[0])), result['polatisOxcPortPatch.1'],
                                        'Wrong value received for getnext PolatisOxcPortPatch: %s' % result)
            else:
                raise Exception(
                    "Incorrect Output:%s, Error Message:%s" % (result, self.snmp_session.snmp_session.ErrorStr))

            self.snmp_wr_session.snmp_set('polatisOxcPortPatch.1', 0, 'GAUGE32')

        def test_walk_polatisoxcportpatch(self):
            """
            Query Polatis Oxc Port Patch through Snmpwalk
            """
            self.snmp_session.create_box('test_walk_polatisoxcportpatch')
            output = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), int(prtlst[0])+int(prtlst[0]), 'GAUGE32')
	    time.sleep(10)
            nose.tools.assert_equal(1, output, 'SNMP Set Error: %s' % self.snmp_wr_session.snmp_session.ErrorStr)
            try:
                result = self.snmp_session.snmp_walk('polatisOxcPortPatch')
            except BaseException as err:
                raise err
            if 'polatisOxcPortPatch.%s' % int(prtlst[0]) in result:
                nose.tools.assert_equal(str(int(prtlst[0])+int(prtlst[0])), result['polatisOxcPortPatch.%s' % int(prtlst[0])],
                                        'Wrong value received for walk PolatisOxcPortPatch: %s' % result)
                nose.tools.assert_equal(str(int(prtlst[0])), result['polatisOxcPortPatch.%s' % str(int(prtlst[0])+int(prtlst[0]))],
                                        'Wrong value received for walk PolatisOxcPortPatch: %s' % result)
            else:
                raise Exception(
                    "Incorrect Output:%s, Error Message:%s" % (result, self.snmp_session.snmp_session.ErrorStr))

            self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'GAUGE32')
	    time.sleep(10)
	
        def test_get_polatisoxcportdesiredstate(self):
            """
            Query Polatis Oxc Port Desired State through Snmpget
            """
            self.snmp_session.create_box('test_get_polatisoxcportdesiredstate')
            output = self.snmp_wr_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 1, 'INTEGER')
            nose.tools.assert_equal(1, output, 'SNMP Set Error: %s' % self.snmp_wr_session.snmp_session.ErrorStr)
            time.sleep(10)
            try:
                result = self.snmp_session.snmp_get('polatisOxcPortDesiredState.%s' % int(prtlst[0]))
            except BaseException as err:
                raise err
            if 'polatisOxcPortDesiredState.%s' % int(prtlst[0]) in result:
                nose.tools.assert_equal('1', result['polatisOxcPortDesiredState.%s' % int(prtlst[0])],
                                        'Wrong value received for get PolatisOxcPortDesiredState: %s' % result)
            else:
                raise Exception(
                    "Incorrect Output:%s, Error Message:%s" % (result, self.snmp_session.snmp_session.ErrorStr))

        def test_getnext_polatisoxcportdesiredstate(self):
            """
            Query Polatis Oxc Port Desired State through Snmpgetnext
            """
            self.snmp_session.create_box('test_getnext_polatisoxcportdesiredstate')
            output = self.snmp_wr_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 2, 'INTEGER')
            nose.tools.assert_equal(1, output, 'SNMP Set Error: %s' % self.snmp_wr_session.snmp_session.ErrorStr)
            time.sleep(10)
            try:
                result = self.snmp_session.snmp_get_next('polatisOxcPortDesiredState.%s' % (int(prtlst[0])-1))
            except BaseException as err:
                raise err
            if 'polatisOxcPortDesiredState.%s' % int(prtlst[0]) in result:
                nose.tools.assert_equal('2', result['polatisOxcPortDesiredState.%s' % int(prtlst[0])],
                                        'Wrong value received for getnext PolatisOxcPortDesiredState: %s' % result)
            else:
                raise Exception(
                    "Incorrect Output:%s, Error Message:%s" % (result, self.snmp_session.snmp_session.ErrorStr))

        def test_walk_polatisoxcportdesiredstate(self):
            """
            Query Polatis Oxc Port Desired State through Snmpwalk
            """
            self.snmp_session.create_box('test_walk_polatisoxcportdesiredstate')
            output = self.snmp_wr_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 1, 'INTEGER')
            nose.tools.assert_equal(1, output, 'SNMP Set Error: %s' % self.snmp_wr_session.snmp_session.ErrorStr)
            time.sleep(10)
            try:
                result = self.snmp_session.snmp_walk('polatisOxcPortDesiredState')
            except BaseException as err:
                raise err
            if 'polatisOxcPortDesiredState.%s' % int(prtlst[0]) in result:
                nose.tools.assert_equal('1', result['polatisOxcPortDesiredState.%s' % int(prtlst[0])],
                                        'Wrong value received for walk PolatisOxcPortDesiredState: %s' % result)
            else:
                raise Exception(
                    "Incorrect Output:%s, Error Message:%s" % (result, self.snmp_session.snmp_session.ErrorStr))

        def test_get_polatisoxcportcurrentstate(self):
            """
            Query Polatis Oxc Port Current State through Snmpget
            """
            self.snmp_session.create_box('test_get_polatisoxcportcurrentstate')
            try:
                result = self.snmp_session.snmp_get('polatisOxcPortCurrentState.%s' % int(prtlst[0]))
            except BaseException as err:
                raise err
            if 'polatisOxcPortCurrentState.%s' % int(prtlst[0]) in result:
                nose.tools.assert_in(result['polatisOxcPortCurrentState.%s' % int(prtlst[0])], ['1', '2'],
                                     'Wrong value received for get PolatisOxcPortCurrentState: %s' % result)
            else:
                raise Exception(
                    "Incorrect Output:%s, Error Message:%s" % (result, self.snmp_session.snmp_session.ErrorStr))

        def test_getnext_polatisoxcportcurrentstate(self):
            """
            Query Polatis Oxc Port Current State through Snmpgetnext
            """
            self.snmp_session.create_box('test_getnext_polatisoxcportcurrentstate')
            try:
                result = self.snmp_session.snmp_get_next('polatisOxcPortCurrentState.%s' % int(prtlst[0]))
            except BaseException as err:
                raise err
            if 'polatisOxcPortCurrentState.%s' % (int(prtlst[0])+1) in result:
                nose.tools.assert_in(result['polatisOxcPortCurrentState.%s' % (int(prtlst[0])+1)], ['1', '2'],
                                     'Wrong value received for getnext PolatisOxcPortCurrentState: %s' % result)
            else:
                raise Exception(
                    "Incorrect Output:%s, Error Message:%s" % (result, self.snmp_session.snmp_session.ErrorStr))

        def test_walk_polatisoxcportcurrentstate(self):
            """
            Query Polatis Oxc Port Current State through Snmpwalk
            """
            self.snmp_session.create_box('test_walk_polatisoxcportcurrentstate')
            try:
                result = self.snmp_session.snmp_walk('polatisOxcPortCurrentState')
            except BaseException as err:
                raise err
            if 'polatisOxcPortCurrentState.%s' % int(prtlst[0]) in result:
                nose.tools.assert_in(result['polatisOxcPortCurrentState.%s' % int(prtlst[0])], ['1', '2'],
                                     'Wrong value received for walk PolatisOxcPortDesiredState: %s' % result)
            else:
                raise Exception(
                    "Incorrect Output:%s, Error Message:%s" % (result, self.snmp_session.snmp_session.ErrorStr))

        def test_set_disable_ideal_port(self):
            """
            Disable Ideal ports through SnmpSet
            """
            self.snmp_session.create_box('test_set_disable_ideal_port')
            output1 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output1,
                                    'SNMP Set Port Patch Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)

            output2 = self.snmp_wr_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 2, 'INTEGER')
            nose.tools.assert_equal(1, output2, 'SNMP Set Port DesiredState '
                                                'Error: %s' % self.snmp_wr_session.snmp_session.ErrorStr)
	    time.sleep(10)
            result = self.snmp_session.snmp_get('polatisOxcPortDesiredState.%s' % int(prtlst[0]))
            if 'polatisOxcPortDesiredState.%s' % int(prtlst[0]) in result:
                nose.tools.assert_equal('2', result['polatisOxcPortDesiredState.%s' % int(prtlst[0])],
                                        'Wrong value received for get PolatisOxcPortDesiredState: %s' % result)
            else:
                raise Exception(
                    "Incorrect Output:%s, Error Message:%s" % (result, self.snmp_session.snmp_session.ErrorStr))

        def test_set_disable_crossconnected_port(self):
            """
            Disable CrossConnected Ports through Snmpset
            """
            self.snmp_session.create_box('test_set_disable_crossconnected_port')
            output1 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), int(prtlst[0])+int(prtlst[0]), 'UINTEGER')
            nose.tools.assert_equal(1, output1,
                                    'SNMP Set Port Patch Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)

            output2 = self.snmp_wr_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 2, 'INTEGER')
            nose.tools.assert_equal(1, output2, 'SNMP Set Port DesiredState '
                                                'Error: %s' % self.snmp_wr_session.snmp_session.ErrorStr)
            time.sleep(10)
            result = self.snmp_session.snmp_get('polatisOxcPortDesiredState.%s' % int(prtlst[0]))
            if 'polatisOxcPortDesiredState.%s' % int(prtlst[0]) in result:
                nose.tools.assert_equal('2', result['polatisOxcPortDesiredState.%s' % int(prtlst[0])],
                                        'Wrong value received for get PolatisOxcPortDesiredState: %s' % result)
            else:
                raise Exception(
                    "Incorrect Output:%s, Error Message:%s" % (result, self.snmp_session.snmp_session.ErrorStr))

            self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            time.sleep(10)

        def test_set_enable_ideal_port(self):
            """
            Enable Ideal ports through SnmpSet
            """
            self.snmp_session.create_box('test_set_enable_ideal_port')
            output1 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output1,
                                    'SNMP Set Port Patch Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)

            output2 = self.snmp_wr_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 1, 'INTEGER')
            nose.tools.assert_equal(1, output2, 'SNMP Set Port DesiredState '
                                                'Error: %s' % self.snmp_wr_session.snmp_session.ErrorStr)
            time.sleep(10)
            result = self.snmp_session.snmp_get('polatisOxcPortDesiredState.%s' % int(prtlst[0]))
            if 'polatisOxcPortDesiredState.%s' % int(prtlst[0]) in result:
                nose.tools.assert_equal('1', result['polatisOxcPortDesiredState.%s' % int(prtlst[0])],
                                        'Wrong value received for get PolatisOxcPortDesiredState: %s' % result)
            else:
                raise Exception(
                    "Incorrect Output:%s, Error Message:%s" % (result, self.snmp_session.snmp_session.ErrorStr))
            

        def test_set_enable_crossconnected_port(self):
            """
            Enable CrossConnected Ports through Snmpset
            """
            self.snmp_session.create_box('test_set_enable_crossconnected_port')
            output1 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), int(prtlst[0])+int(prtlst[0]), 'UINTEGER')
            nose.tools.assert_equal(1, output1,
                                    'SNMP Set Port Patch Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)

            output2 = self.snmp_wr_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 1, 'INTEGER')
            nose.tools.assert_equal(1, output2, 'SNMP Set Port DesiredState '
                                                'Error: %s' % self.snmp_wr_session.snmp_session.ErrorStr)

            time.sleep(10)
            result = self.snmp_session.snmp_get('polatisOxcPortDesiredState.%s' % int(prtlst[0]))
            if 'polatisOxcPortDesiredState.%s' % int(prtlst[0]) in result:
                nose.tools.assert_equal('1', result['polatisOxcPortDesiredState.%s' % int(prtlst[0])],
                                        'Wrong value received for get PolatisOxcPortDesiredState: %s' % result)
            else:
                raise Exception(
                    "Incorrect Output:%s, Error Message:%s" % (result, self.snmp_session.snmp_session.ErrorStr))

            self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            time.sleep(10)        

        def test_set_create_crossconnect_with_ingress_port(self):
            """
            Create CrossConnect with Ingress port through Snmpset
            """
            self.snmp_session.create_box('test_set_create_crossconnect_with_ingress_port')
            output1 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output1, 'SNMPSet disconnect port '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)

            output2 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output2, 'SNMPSet disconnect port '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)

            output3 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), int(prtlst[0])+1, 'UINTEGER')
            nose.tools.assert_equal(1, output3, 'SNMPSet create crossconnect '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)
  
            time.sleep(10)
            result1 = self.snmp_session.snmp_get('polatisOxcPortPatch.%s' % int(prtlst[0]))
            result2 = self.snmp_session.snmp_get('polatisOxcPortPatch.%s' % (int(prtlst[0])+1))
            if 'polatisOxcPortPatch.%s' % int(prtlst[0]) in result1:
                nose.tools.assert_equal(str(int(prtlst[0])+1), result1['polatisOxcPortPatch.%s' % int(prtlst[0])],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result1)
            elif 'polatisOxcPortPatch.%s' % (int(prtlst[0])+1) in result2:
                nose.tools.assert_equal(str(int(prtlst[0])), result2['polatisOxcPortPatch.%s' % (int(prtlst[0])+1)],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result2)
            else:
                raise Exception(
                    "Incorrect Output:%s,Error Message:%s" % (result1, self.snmp_session.snmp_session.ErrorStr))

            self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            time.sleep(10)
        def test_set_create_crossconnect_with_egress_port(self):
            """
            Create CrossConnect with Egress port through Snmpset
            """
            self.snmp_session.create_box('test_set_create_crossconnect_with_egress_port')
            output1 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output1, 'SNMPSet disconnectport '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)

            output2 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output2, 'SNMPSet disconnectport '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)

            output3 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), int(prtlst[0]), 'UINTEGER')
            nose.tools.assert_equal(1, output3, 'SNMPSet create crossconnect '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)
            time.sleep(10)
            result1 = self.snmp_session.snmp_get('polatisOxcPortPatch.%s' % (int(prtlst[0])+1))
            result2 = self.snmp_session.snmp_get('polatisOxcPortPatch.%s' % int(prtlst[0]))
            if 'polatisOxcPortPatch.%s' % (int(prtlst[0])+1) in result1:
                nose.tools.assert_equal(str(int(prtlst[0])), result1['polatisOxcPortPatch.%s' % (int(prtlst[0])+1)],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result1)
            elif 'polatisOxcPortPatch.%s' % int(prtlst[0]) in result2:
                nose.tools.assert_equal(str(int(prtlst[0])+1), result2['polatisOxcPortPatch.%s' % int(prtlst[0])],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result2)
            else:
                raise Exception(
                    "Incorrect Output:%s,Error Message:%s" % (result1, self.snmp_session.snmp_session.ErrorStr))

            self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), 0, 'UINTEGER')
            time.sleep(10)
        def test_set_update_crossconnect_with_ingress_port(self):
            """
            Update CrossConnect with Ingress port through Snmpset
            """
            self.snmp_session.create_box('test_set_update_crossconnect_with_ingress_port')
            output1 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), int(prtlst[0])+int(prtlst[0]), 'UINTEGER')
            nose.tools.assert_equal(1, output1, 'SNMPSet crossconnectPort '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)

            output2 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), int(prtlst[0])+1, 'UINTEGER')
            nose.tools.assert_equal(1, output2, 'SNMPSet crossconnectPort '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)
            time.sleep(10)
            result1 = self.snmp_session.snmp_get('polatisOxcPortPatch.%s' % int(prtlst[0]))

            if 'polatisOxcPortPatch.%s' % int(prtlst[0]) in result1:
                nose.tools.assert_equal(str(int(prtlst[0])+1), result1['polatisOxcPortPatch.%s' % int(prtlst[0])],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result1)
            else:
                raise Exception(
                    "Incorrect Output:%s,Error Message:%s" % (result1, self.snmp_session.snmp_session.ErrorStr))

            self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            time.sleep(10)
        def test_set_update_crossconnect_with_egress_port(self):
            """
            Update CrossConnect with Egress port through Snmpset
            """
            self.snmp_session.create_box('test_set_update_crossconnect_with_egress_port')
            output1 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), int(prtlst[0]), 'UINTEGER')
            nose.tools.assert_equal(1, output1, 'SNMPSet crossconnectPort '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)

            output2 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), int(prtlst[0])-1, 'UINTEGER')
            nose.tools.assert_equal(1, output2, 'SNMPSet crossconnectPort '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)
            time.sleep(10)
            result1 = self.snmp_session.snmp_get('polatisOxcPortPatch.%s' % (int(prtlst[0])+1))
            if 'polatisOxcPortPatch.%s' % (int(prtlst[0])+1) in result1:
                nose.tools.assert_equal(str(int(prtlst[0])-1), result1['polatisOxcPortPatch.%s' % (int(prtlst[0])+1)],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result1)
            else:
                raise Exception(
                    "Incorrect Output:%s,Error Message:%s" % (result1, self.snmp_session.snmp_session.ErrorStr))

            self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), 0, 'UINTEGER')
            time.sleep(10)
 
        def test_set_delete_crossconnect_with_ingress_port(self):
            """
            Delete CrossConnect with Ingress port through Snmpset
            """
            self.snmp_session.create_box('test_set_delete_crossconnect_with_ingress_port')
            output1 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), int(prtlst[0])+int(prtlst[0]), 'UINTEGER')
            nose.tools.assert_equal(1, output1, 'SNMPSet crossconnectPort '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)

            output2 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output2, 'SNMPSet disconnectPort '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)
            time.sleep(10)
            result1 = self.snmp_session.snmp_get('polatisOxcPortPatch.%s' % int(prtlst[0]))
            if 'polatisOxcPortPatch.%s' % int(prtlst[0]) in result1:
                nose.tools.assert_equal('0', result1['polatisOxcPortPatch.%s' % int(prtlst[0])],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result1)
            else:
                raise Exception(
                    "Incorrect Output:%s,Error Message:%s" % (result1, self.snmp_session.snmp_session.ErrorStr))

            self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            time.sleep(10)
 
        def test_set_delete_crossconnect_with_egress_port(self):
            """
            Delete CrossConnect with Egress port through Snmpset
            """
            self.snmp_session.create_box('test_set_delete_crossconnect_with_egress_port')
            output1 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), int(prtlst[0]), 'UINTEGER')
            nose.tools.assert_equal(1, output1, 'SNMPSet crossconnectPort '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)

            output2 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output2, 'SNMPSet disconnectPort '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)
            time.sleep(10)
            result1 = self.snmp_session.snmp_get('polatisOxcPortPatch.%s' % (int(prtlst[0])+1))
            if 'polatisOxcPortPatch.%s' % (int(prtlst[0])+1) in result1:
                nose.tools.assert_equal('0', result1['polatisOxcPortPatch.%s' % (int(prtlst[0])+1)],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result1)
            else:
                raise Exception(
                    "Incorrect Output:%s,Error Message:%s" % (result1, self.snmp_session.snmp_session.ErrorStr))

            self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), 0, 'UINTEGER')
            time.sleep(10)         

        def test_set_create_crossconnect_with_disabled_ingress_port(self):
            """
            Create CrossConnect with Disabled Ingress port through Snmpset
            """
            self.snmp_session.create_box('test_set_create_crossconnect_with_disabled_ingress_port')
            output1 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output1, 'SNMPSet disconnect port '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)

            output2 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output2, 'SNMPSet disconnect port '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)

            output3 = self.snmp_wr_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 2, 'UINTEGER')
            nose.tools.assert_equal(1, output3, 'SNMPSet Disable Ingress Port '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)

            output4 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), int(prtlst[0])+1, 'UINTEGER')
            nose.tools.assert_equal(1, output4, 'SNMPSet create crossconnect '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)
            time.sleep(10)
            result1 = self.snmp_session.snmp_get('polatisOxcPortPatch.%s' % int(prtlst[0]))
            result2 = self.snmp_session.snmp_get('polatisOxcPortPatch.%s' % (int(prtlst[0])+1))
            if 'polatisOxcPortPatch.%s' % int(prtlst[0]) in result1:
                nose.tools.assert_equal(str(int(prtlst[0])+1), result1['polatisOxcPortPatch.%s' % int(prtlst[0])],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result1)
            elif 'polatisOxcPortPatch..%s' % (int(prtlst[0])+1) in result2:
                nose.tools.assert_equal(str(int(prtlst[0])), result2['polatisOxcPortPatch..%s' % (int(prtlst[0])+1)],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result2)
            else:
                raise Exception(
                    "Incorrect Output:%s,Error Message:%s" % (result1, self.snmp_session.snmp_session.ErrorStr))

            self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            self.snmp_wr_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 1, 'UINTEGER')
            time.sleep(10)

        def test_set_create_crossconnect_with_disabled_egress_port(self):
            """
            Create CrossConnect with Disabled Egress port through Snmpset
            """
            self.snmp_session.create_box('test_set_create_crossconnect_with_disabled_egress_port')
            output1 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output1, 'SNMPSet disconnect port '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)

            output2 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output2, 'SNMPSet disconnect port '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)

            output3 = self.snmp_wr_session.snmp_set('polatisOxcPortDesiredState.%s' % (int(prtlst[0])+1), 2, 'UINTEGER')
            nose.tools.assert_equal(1, output3, 'SNMPSet Disable Ingress Port '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)

            output4 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), int(prtlst[0]), 'UINTEGER')
            nose.tools.assert_equal(1, output4, 'SNMPSet create crossconnect '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)
            time.sleep(10)
            result1 = self.snmp_session.snmp_get('polatisOxcPortPatch.%s' % (int(prtlst[0])+1))
            result2 = self.snmp_session.snmp_get('polatisOxcPortPatch.%s' % int(prtlst[0]))
            if 'polatisOxcPortPatch.%s' % (int(prtlst[0])+1) in result1:
                nose.tools.assert_equal(str(int(prtlst[0])), result1['polatisOxcPortPatch.%s' % (int(prtlst[0])+1)],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result1)
            elif 'polatisOxcPortPatch.%s' % int(prtlst[0]) in result2:
                nose.tools.assert_equal(str(int(prtlst[0])+1), result2['polatisOxcPortPatch.%s' % int(prtlst[0])],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result2)
            else:
                raise Exception(
                    "Incorrect Output:%s,Error Message:%s" % (result1, self.snmp_session.snmp_session.ErrorStr))

            self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), 0, 'UINTEGER')
            self.snmp_wr_session.snmp_set('polatisOxcPortDesiredState.%s' % (int(prtlst[0])+1), 1, 'UINTEGER')
            time.sleep(10)  
  
        def test_set_delete_crossconnect_with_disabled_ingress_port(self):
            """
            Delete CrossConnect with Disabled Ingress port through Snmpset
            """
            self.snmp_session.create_box('test_set_delete_crossconnect_with_disabled_ingress_port')
            output1 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), int(prtlst[0])+int(prtlst[0]), 'UINTEGER')
            nose.tools.assert_equal(1, output1, 'SNMPSet crossconnectPort '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)

            output2 = self.snmp_wr_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 2, 'UINTEGER')
            nose.tools.assert_equal(1, output2, 'SNMPSet Disable Ingress Port '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)

            output3 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output3, 'SNMPSet disconnectPort '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)
	    time.sleep(10)
            result1 = self.snmp_session.snmp_get('polatisOxcPortPatch.%s' % int(prtlst[0]))
            if 'polatisOxcPortPatch.%s' % int(prtlst[0]) in result1:
                nose.tools.assert_equal('0', result1['polatisOxcPortPatch.%s' % int(prtlst[0])],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result1)
            else:
                raise Exception(
                    "Incorrect Output:%s,Error Message:%s" % (result1, self.snmp_session.snmp_session.ErrorStr))

            self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            self.snmp_wr_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 1, 'UINTEGER')
            time.sleep(10)             

        def test_set_delete_crossconnect_with_disabled_egress_port(self):
            """
            Delete CrossConnect with Disabled Egress port through Snmpset
            """
            self.snmp_session.create_box('test_set_delete_crossconnect_with_disabled_egress_port')
            output1 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), int(prtlst[0]), 'UINTEGER')
            nose.tools.assert_equal(1, output1, 'SNMPSet crossconnectPort '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)

            output2 = self.snmp_wr_session.snmp_set('polatisOxcPortDesiredState.%s' % (int(prtlst[0])+1), 2, 'UINTEGER')
            nose.tools.assert_equal(1, output2, 'SNMPSet Disable Ingress Port '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)

            output3 = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output3, 'SNMPSet disconnectPort '
                                                'Error:%s' % self.snmp_wr_session.snmp_session.ErrorStr)
 	    time.sleep(10)
            result1 = self.snmp_session.snmp_get('polatisOxcPortPatch.%s' % (int(prtlst[0])+1))
            #print "result :" , result1
            if 'polatisOxcPortPatch.%s' % (int(prtlst[0])+1) in result1:
                nose.tools.assert_equal('0', result1['polatisOxcPortPatch.%s' % (int(prtlst[0])+1)],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result1)
            else:
                raise Exception(
                    "Incorrect Output:%s,Error Message:%s" % (result1, self.snmp_session.snmp_session.ErrorStr))

  	    self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), 0, 'UINTEGER')	   
            self.snmp_wr_session.snmp_set('polatisOxcPortDesiredState.%s' % (int(prtlst[0])+1), 1, 'UINTEGER')
	    time.sleep(10)

        "Negative SNMPv1 & SNMPv2 Cases"

        def test_get_oxcsize_with_invalid_community(self):
            """
            Negative: Query Polatis Oxc Size through Snmp Get with Invalid Community
            """
            self.snmp_session.create_box('test_get_oxcsize_with_invalid_community')
            result = self.snmp_invalid_session.snmp_get('polatisOxcSize.0')
            #print result
            if 'polatisOxcSize.0' in result:
                nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                        'Wrong or No exception for SNMP Get with Invalid '
                                        'Community: %s' % self.snmp_invalid_session.snmp_session.ErrorStr)
                nose.tools.assert_is_none(result['polatisOxcSize.0'],
                                          'Result Obtained is Not None for Invalid Community '
                                          'Snmp Get: %s' % result['polatisOxcSize.0'])
            else:
                raise Exception("Incorrect Output for Snmp Get using Invalid Community: %s" % result)

        def test_getnext_oxcsize_with_invalid_community(self):
            """
            Negative: Query Polatis Oxc Size through Snmp GetNext with Invalid Community
            """
            self.snmp_session.create_box('test_getnext_oxcsize_with_invalid_community')
            result = self.snmp_invalid_session.snmp_get_next('polatisOxcSize')
            #print result
            if 'polatisOxcSize.' in result:
                nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                        'Wrong or No exception for SNMP GetNext with Invalid '
                                        'Community: %s' % self.snmp_invalid_session.snmp_session.ErrorStr)
            else:
                raise Exception('Result Obtained for Invalid Community Snmp Get Next: %s' % result)

        def test_walk_oxcsize_with_invalid_community(self):
            """
            Negative: Query Polatis Oxc Size through Snmp Walk with Invalid Community
            """
            self.snmp_session.create_box('test_walk_oxcsize_with_invalid_community')
            result = self.snmp_invalid_session.snmp_walk('polatisOxcSize')
            #print result
            if not result:
                nose.tools.assert_equal(self.snmp_invalid_session.snmp_session.ErrorStr, 'Timeout',
                                        'Wrong or No exception for SNMP walk with Invalid '
                                        'Community: %s' % self.snmp_invalid_session.snmp_session.ErrorStr)
            else:
                raise Exception('Result Obtained for Invalid Community Snmp Walk: %s' % result)

        def test_get_oxcportpatch_with_invalid_index(self):
            """
            Negative: Query Polatis Oxc Port Patch through Snmp Get with Invalid Index
            """
            self.snmp_session.create_box('test_get_oxcportpatch_with_invalid_index')
            result = self.snmp_session.snmp_get('polatisOxcPortPatch.3000')
            #print result
            #print "Error : ", self.snmp_session.snmp_session.ErrorStr
            if 'polatisOxcPortPatch.3000' in result:
                if version == 1:
                    ##print "Error : ", self.snmp_session.snmp_session.ErrorStr
                    nose.tools.assert_in('(genError) A general failure occured',
                                         self.snmp_session.snmp_session.ErrorStr,
                                         'Wrong or No exception for SNMP Get with Invalid '
                                         'Index: %s' % self.snmp_session.snmp_session.ErrorStr)
                if version == 2:
                    ##print "Error : ", self.snmp_session.snmp_session.ErrorStr
                    nose.tools.assert_equal('(genError) A general failure occured', self.snmp_session.snmp_session.ErrorStr,
                                            'Wrong or No exception for SNMP Get with Invalid '
                                            'Index: %s' % self.snmp_session.snmp_session.ErrorStr)
            else:
                raise Exception("Got Output for Oxc Port Patch with Invalid Index instead of empty "
                                "dict:%s" % result)

        def test_get_oxcportcurrentstate_with_invalid_index(self):
            """
            Negative: Query Polatis Oxc Port Current State through Snmp Get with Invalid Index
            """
            self.snmp_session.create_box('test_get_oxcportcurrentstate_with_invalid_index')
            result = self.snmp_session.snmp_get('polatisOxcPortCurrentState.3000')
            #print result
            ##print "Error : ", self.snmp_session.snmp_session.ErrorStr
            if 'polatisOxcPortCurrentState.3000' in result:
                if version == 1:
                    ##print "Error : ", self.snmp_session.snmp_session.ErrorStr
                    nose.tools.assert_in('(genError) A general failure occured',
                                         self.snmp_session.snmp_session.ErrorStr,
                                         'Wrong or No exception for SNMP Get with Invalid '
                                         'Index: %s' % self.snmp_session.snmp_session.ErrorStr)
                if version == 2:
                    ##print "Error : ", self.snmp_session.snmp_session.ErrorStr
                    nose.tools.assert_equal('(genError) A general failure occured', self.snmp_session.snmp_session.ErrorStr,
                                            'Wrong or No exception for SNMP Get with Invalid '
                                            'Index: %s' % self.snmp_session.snmp_session.ErrorStr)
            else:
                raise Exception("Got Output for Oxc Port Patch with Invalid Index instead of empty "
                                "dict:%s" % result)

        def test_get_oxcportdesiredstate_with_invalid_index(self):
            """
            Negative: Query Polatis Oxc Port Desired State through Snmp Get with Invalid Index
            """
            self.snmp_session.create_box('test_get_oxcportdesiredstate_with_invalid_index')
            result = self.snmp_session.snmp_get('polatisOxcPortDesiredState.3000')
            #print "result", result
            #print "Error : ", self.snmp_session.snmp_session.ErrorStr
            if 'polatisOxcPortDesiredState.3000' in result:
                if version == 1:
                    ##print "Error : ", self.snmp_session.snmp_session.ErrorStr
                    nose.tools.assert_in('(genError) A general failure occured',
                                         self.snmp_session.snmp_session.ErrorStr,
                                         'Wrong or No exception for SNMP Get with Invalid '
                                         'Index: %s' % self.snmp_session.snmp_session.ErrorStr)
                if version == 2:
                    ##print "Error : ", self.snmp_session.snmp_session.ErrorStr
                    nose.tools.assert_equal('(genError) A general failure occured', self.snmp_session.snmp_session.ErrorStr,
                                            'Wrong or No exception for SNMP Get with Invalid '
                                            'Index: %s' % self.snmp_session.snmp_session.ErrorStr)
            else:
                raise Exception("Got Output for Oxc Port Patch with Invalid Index instead of empty "
                                "dict:%s" % result)

        def test_set_oxcportpatch_with_invalid_index(self):
            """
            Negative: Create Polatis Oxc Port Crossconnect through Snmp Set with Invalid Index
            """
            self.snmp_session.create_box('test_set_oxcportpatch_with_invalid_index')
            result = self.snmp_session.snmp_set('polatisOxcPortPatch.3000', int(prtlst[0]), 'GAUGE32')
            #print result
            ##print "Error : ", self.snmp_session.snmp_session.ErrorStr
            if result is 0:
                if version == 1 or version == 2:
               	    if community == community_ro:
                        nose.tools.assert_equal('Timeout', self.snmp_session.snmp_session.ErrorStr,
                                                'Wrong or No exception for SNMP Set with Invalid '
                                                'Index: %s' % self.snmp_session.snmp_session.ErrorStr)
                    if community == community_rw:
                        nose.tools.assert_equal('(genError) A general failure occured', self.snmp_session.snmp_session.ErrorStr,
                                                'Wrong or No exception for SNMP Set with Invalid '
                                                'Index: %s' % self.snmp_session.snmp_session.ErrorStr)
		else:
                    raise Exception("Incorrect Output, should be zero : %s " % result) 

        def test_set_oxcportdesiredstate_with_invalid_index(self):
            """
            Negative: Set Oxc Port Desired State through Snmp Set with Invalid Index
            """
            self.snmp_session.create_box('test_set_oxcportdesiredstate_with_invalid_index')
            result = self.snmp_session.snmp_set('polatisOxcPortDesiredState.3000', 1, 'INTEGER')
            #print result
            ##print "Error : ", self.snmp_session.snmp_session.ErrorStr
            if result is 0:
                if version == 1:
                    nose.tools.assert_in('',
                                         self.snmp_session.snmp_session.ErrorStr,
                                         'Wrong or No exception for SNMP Set with Invalid '
                                         'Index: %s' % self.snmp_session.snmp_session.ErrorStr)
                if version == 2:
			if community == community_ro:
                    		nose.tools.assert_equal('Timeout', self.snmp_session.snmp_session.ErrorStr,
                                            		'Wrong or No exception for SNMP Set with Invalid '
                                            		'Index: %s' % self.snmp_session.snmp_session.ErrorStr)
			if community == community_rw:
				nose.tools.assert_equal('(genError) A general failure occured', self.snmp_session.snmp_session.ErrorStr,
                                                        'Wrong or No exception for SNMP Set with Invalid '
                                                        'Index: %s' % self.snmp_session.snmp_session.ErrorStr)

            else:
                raise Exception("Incorrect Output, should be zero : %s " % result)

        def test_get_oxcportpatch_with_invalid_community(self):
            """
            Negative SNMP Get Polatis Oxc Port Patch with Invalid Community
            """
            self.snmp_session.create_box('test_get_oxcportpatch_with_invalid_community')
            result = self.snmp_invalid_session.snmp_get('polatisOxcPortPatch.11')
            #print "self.snmp_invalid_session.snmp_session.ErrorStr", self.snmp_invalid_session.snmp_session.ErrorStr
            if 'polatisOxcPortPatch.11' not in result:
                raise Exception("Got output for Snmp Get with Invalid Index instead of empty dict: %s" % result)
            else:
                nose.tools.assert_equal('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP Get with Invalid '
                                        'Community: %s ' % self.snmp_invalid_session.snmp_session.ErrorStr)

        def test_getnext_oxcportpatch_with_invalid_community(self):
            """
            Negative SNMP GetNext Polatis Oxc Port Patch with Invalid Community
            """
            self.snmp_session.create_box('test_getnext_oxcportpatch_with_invalid_community')
            result = self.snmp_invalid_session.snmp_get_next('polatisOxcPortPatch.11')
            if 'polatisOxcPortPatch.11' not in result:
                raise Exception("Got output for Snmp GetNext with Invalid Index instead of empty dict: %s" % result)
            else:
                nose.tools.assert_equal('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP GetNext with Invalid '
                                        'Community: %s ' % self.snmp_invalid_session.snmp_session.ErrorStr)

        def test_walk_oxcportpatch_with_invalid_community(self):
            """
            Negative SNMP Walk Polatis Oxc Port Patch with Invalid Community
            """
            self.snmp_session.create_box('test_walk_oxcportpatch_with_invalid_community')
            result = self.snmp_invalid_session.snmp_walk('polatisOxcPortPatch.12')
            if result:
                raise Exception("Got output for Snmp Walk with Invalid Index instead of empty dict: %s" % result)
            else:
                nose.tools.assert_equal('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP Walk with Invalid '
                                        'Community: %s ' % self.snmp_invalid_session.snmp_session.ErrorStr)

        def test_get_oxcportcurrentstate_with_invalid_community(self):
            """
            Negative SNMP Get Polatis Oxc Port Current State with Invalid Community
            """
            self.snmp_session.create_box('test_get_oxcportcurrentstate_with_invalid_community')
            result = self.snmp_invalid_session.snmp_get('polatisOxcPortCurrentState.1')
            if 'polatisOxcPortCurrentState.1' not in result:
                raise Exception("Got output for Snmp Get with Invalid Index instead of empty dict: %s" % result)
            else:
                nose.tools.assert_equal('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP Get with Invalid '
                                        'Community: %s ' % self.snmp_invalid_session.snmp_session.ErrorStr)

        def test_getnext_oxcportcurrentstate_with_invalid_community(self):
            """
            Negative SNMP GetNext Polatis Oxc Port Current State with Invalid Community
            """
            self.snmp_session.create_box('test_getnext_oxcportcurrentstate_with_invalid_community')
            result = self.snmp_invalid_session.snmp_get_next('polatisOxcPortCurrentState')
            if 'polatisOxcPortCurrentState.' not in result:
                raise Exception("Got output for Snmp GetNext with Invalid Index instead of empty dict: %s" % result)
            else:
                nose.tools.assert_equal('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP GetNext with Invalid '
                                        'Community: %s ' % self.snmp_invalid_session.snmp_session.ErrorStr)

        def test_walk_oxcportcurrentstate_with_invalid_community(self):
            """
            Negative SNMP Walk Polatis Oxc Port Current State with Invalid Community
            """
            self.snmp_session.create_box('test_walk_oxcportcurrentstate_with_invalid_community')
            result = self.snmp_invalid_session.snmp_walk('polatisOxcPortCurrentState.12')
            if result:
                raise Exception("Got output for Snmp Walk with Invalid Index instead of empty dict: %s" % result)
            else:
                nose.tools.assert_equal('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP Walk with Invalid '
                                        'Community: %s ' % self.snmp_invalid_session.snmp_session.ErrorStr)

        def test_get_oxcportdesiredstate_with_invalid_community(self):
            """
            Negative SNMP Get Polatis Oxc Port Desired State with Invalid Community
            """
            self.snmp_session.create_box('test_get_oxcportdesiredstate_with_invalid_community')
            result = self.snmp_invalid_session.snmp_get('polatisOxcPortDesiredState.1')
            if 'polatisOxcPortDesiredState.1' not in result:
                raise Exception("Got output for Snmp Get with Invalid Index instead of empty dict: %s" % result)
            else:
                nose.tools.assert_equal('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP Get with Invalid '
                                        'Community: %s ' % self.snmp_invalid_session.snmp_session.ErrorStr)

        def test_getnext_oxcportdesiredstate_with_invalid_community(self):
            """
            Negative SNMP GetNext Polatis Oxc Port Desired State with Invalid Community
            """
            self.snmp_session.create_box('test_getnext_oxcportdesiredstate_with_invalid_community')
            result = self.snmp_invalid_session.snmp_get_next('polatisOxcPortDesiredState')
            if 'polatisOxcPortDesiredState.' not in result:
                raise Exception("Got output for Snmp GetNext with Invalid Index instead of empty dict: %s" % result)
            else:
                nose.tools.assert_equal('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP GetNext with Invalid '
                                        'Community: %s ' % self.snmp_invalid_session.snmp_session.ErrorStr)

        def test_walk_oxcportdesiredstate_with_invalid_community(self):
            """
            Negative SNMP Walk Polatis Oxc Port Desired State with Invalid Community
            """
            self.snmp_session.create_box('test_walk_oxcportdesiredstate_with_invalid_community')
            result = self.snmp_invalid_session.snmp_walk('polatisOxcPortDesiredState.12')
            if result:
                raise Exception("Got output for Snmp Walk with Invalid Index instead of empty dict: %s" % result)
            else:
                nose.tools.assert_equal('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP Walk with Invalid '
                                        'Community: %s ' % self.snmp_invalid_session.snmp_session.ErrorStr)

        def test_set_nonwritable_oxcportcurrentstate(self):
            """
            Negative: Set Non Writable Polatis Oxc Port Current State
            """
            self.snmp_session.create_box('test_set_nonwritable_oxcportcurrentstate')
            result = self.snmp_wr_session.snmp_set('polatisOxcPortCurrentState.1', '1', 'INTEGER')
            if result is not 0:
                raise Exception("There is no such variable name in this MIB  %s" % result)
            else:
                nose.tools.assert_in('', self.snmp_wr_session.snmp_session.ErrorStr,
                                     'No or Wrong Exception when setting a non-writable column'
                                     '(polatisOxcPortCurrentState.1):%s' % self.snmp_wr_session.snmp_session.ErrorStr)

        def test_set_invalid_value_oxcdesiredstate(self):
            """
            Negative: Set Invalid Value for Polatis Oxc Port Desired State
            """
            self.snmp_session.create_box('test_set_invalid_value_oxcdesiredstate')
            result = self.snmp_wr_session.snmp_set('polatisOxcPortDesiredState.1', '10', 'INTEGER')
            if result is 0:
                if version == 1:
                    nose.tools.assert_in('badValue', self.snmp_wr_session.snmp_session.ErrorStr,
                                         'No or Wrong Exception while setting Oxc Port Desired State with invalid '
                                         'value: %s' % self.snmp_wr_session.snmp_session.ErrorStr)
                if version == 2:
                    nose.tools.assert_in('wrongValue', self.snmp_wr_session.snmp_session.ErrorStr,
                                         'No or Wrong Exception while setting Oxc Port Desired State with invalid '
                                         'value: %s' % self.snmp_wr_session.snmp_session.ErrorStr)
            else:
                raise Exception(
                    "Able to Set Oxc Port Desired State with value other than 1, 2. SnmpSet output should be 0 "
                    "but the value is: %s" % result)

        def test_set_create_crossconnect_with_invalid_port(self):
            """
            Negative: Create Crossconnect with Invalid Port
            """
            self.snmp_session.create_box('test_set_create_crossconnect_with_invalid_port')
            result = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.2000', '23', 'GAUGE32')
            #print result
            #print self.snmp_wr_session.snmp_session.ErrorStr
            if result is 0:
                nose.tools.assert_in('(genError) A general failure occured', self.snmp_wr_session.snmp_session.ErrorStr,
                                     'No or Wrong Exception while setting Oxc Port Desired State with invalid '
                                     'value: %s' % self.snmp_wr_session.snmp_session.ErrorStr)
            else:
                raise Exception(
                    "Able to create crossconnect with Invalid ports. SnmpSet output should be 0 but the value "
                    "is: %s" % result)

        def test_delete_crossconnect_with_invalid_port(self):
            """
            Negative: Delete Crossconnect with Invalid Port
            """
            self.snmp_session.create_box('test_delete_crossconnect_with_invalid_port')
            result = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.2000', '0', 'GAUGE32')
            #print result
            #print self.snmp_wr_session.snmp_session.ErrorStr
            if result is 0:
                nose.tools.assert_in('(genError) A general failure occured', self.snmp_wr_session.snmp_session.ErrorStr,
                                     'No or Wrong Exception while setting Oxc Port Desired State with invalid '
                                     'value: %s' % self.snmp_wr_session.snmp_session.ErrorStr)
            else:
                raise Exception(
                    "Able to Delete crossconnect with Invalid ports. SnmpSet output should be 0 but the value "
                    "is: %s" % result)

        def test_set_create_crossconnect_between_ingress_port(self):
            """
            Negative: Create Crossconnect between Ingress Ports
            """
            self.snmp_session.create_box('test_set_create_crossconnect_between_ingress_port')
            result = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]),  int(prtlst[0])-1, 'GAUGE32')
            #print result
            #print self.snmp_wr_session.snmp_session.ErrorStr
            if result is 0:
                nose.tools.assert_in('(genError) A general failure occured', self.snmp_wr_session.snmp_session.ErrorStr,
                                     'No or Wrong Exception while setting Oxc Port Desired State with invalid '
                                     'value: %s' % self.snmp_wr_session.snmp_session.ErrorStr)
            else:
                raise Exception("Able to create crossconnect between Ingress Ports. SnmpSet output should be 0 but "
                                "the value is: %s" % result)

        def test_set_create_crossconnect_between_egress_port(self):
            """
            Negative: Create Crossconnect between Egress Ports
            """
            self.snmp_session.create_box('test_set_create_crossconnect_between_egress_port')
            result = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), int(prtlst[0])+int(prtlst[0]), 'GAUGE32')
            #print result
            #print self.snmp_wr_session.snmp_session.ErrorStr
            if result is 0:
                nose.tools.assert_in('(genError) A general failure occured', self.snmp_wr_session.snmp_session.ErrorStr,
                                     'No or Wrong Exception while setting Oxc Port Desired State with invalid '
                                     'value: %s' % self.snmp_wr_session.snmp_session.ErrorStr)
            else:
                raise Exception("Able to create crossconnect between Egress Ports. SnmpSet output should be 0 but "
                                "the value is: %s" % result)

    if version == 2:
        "SNMPv2c Specific TestCases"

        def test_getbulk_polatisoxcsize(self):
            """
            Query Polatis oxc size through Snmp getbulk
            """
            self.snmp_session.create_box('test_getbulk_polatisoxcsize')
            result = self.snmp_session.snmp_get_bulk('polatisOxcSize')

            if 'polatisOxcSize.0' in result and result['polatisOxcSize.0'] is not None:
                nose.tools.assert_equal(pol_dict['polatisOxcSize'], result['polatisOxcSize.0'],
                                        'Wrong value for GetBulk PolatisOxcSize: %s' % result['polatisOxcSize.0'])
            else:
                raise Exception("Incorrect Output for polatis Oxc Size through get bulk: %s,Error Message: %s"
                                % (result, self.snmp_session.snmp_session.ErrorStr))

        def test_getbulk_polatisoxcportpatch(self):
            """
            Query Polatis oxc port patch through Snmp getbulk
            """
            self.snmp_session.create_box('test_getbulk_polatisoxcportpatch')
            output = self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), int(prtlst[0])+int(prtlst[0]), 'GAUGE32')
            nose.tools.assert_equal(1, output, 'SNMP Set Error: %s' % self.snmp_wr_session.snmp_session.ErrorStr)

            result = self.snmp_session.snmp_get_bulk('polatisOxcPortPatch.%s' % (int(prtlst[0])-1))
            #print result
            if 'polatisOxcPortPatch.%s' % int(prtlst[0]) in result and result['polatisOxcPortPatch.%s' % int(prtlst[0])] is not None:
                nose.tools.assert_equal(str(int(prtlst[0])+int(prtlst[0])), result['polatisOxcPortPatch.%s' % int(prtlst[0])],
                                        'Wrong value for GetBulk PolatisOxcPortPatch: %s' % result[
                                            'polatisOxcPortPatch.%s' % int(prtlst[0])])
            else:
                raise Exception("Incorrect Output for polatis Oxc port Patch through get bulk: %s,Error Message: %s"
                                % (result, self.snmp_session.snmp_session.ErrorStr))

            self.snmp_wr_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')

        def test_getbulk_polatisoxcportcurrentstate(self):
            """
            Query Polatis oxc port current state through Snmp getbulk
            """
            self.snmp_session.create_box('test_getbulk_polatisoxcportcurrentstate')
            result = self.snmp_session.snmp_get_bulk('polatisOxcPortCurrentState.%s' % (int(prtlst[0])-1))
            #print result
            if 'polatisOxcPortCurrentState.%s' % int(prtlst[0]) in result and result['polatisOxcPortCurrentState.%s' % int(prtlst[0])] is not None:
                nose.tools.assert_in(result['polatisOxcPortCurrentState.%s' % int(prtlst[0])], ['1', '2'],
                                     'Wrong value for GetBulk PolatisOxcPortCurrent'
                                     'State: %s' % result['polatisOxcPortCurrentState.%s' % int(prtlst[0])])
            else:
                raise Exception(
                    "Incorrect Output for polatis Oxc port Current State through get bulk: %s,Error Message: %s"
                    % (result, self.snmp_session.snmp_session.ErrorStr))

        def test_getbulk_polatisoxcportdesiredstate(self):
            """
            Query Polatis oxc port Desired state through Snmp getbulk
            """
            self.snmp_session.create_box('test_getbulk_polatisoxcportdesiredstate')
            output = self.snmp_wr_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 2, 'INTEGER')
            # #print output
            #print self.snmp_wr_session.snmp_session.ErrorStr
            nose.tools.assert_equal(1, output, 'SNMP Set Error: %s' % self.snmp_wr_session.snmp_session.ErrorStr)
            time.sleep(10)
            result = self.snmp_session.snmp_get_bulk('polatisOxcPortDesiredState.%s' % (int(prtlst[0])-1))
            #print result
            ##print "Error : ", self.snmp_session.snmp_session.ErrorStr
            if 'polatisOxcPortDesiredState.%s' % int(prtlst[0]) in result and result['polatisOxcPortDesiredState.%s' % int(prtlst[0])] is not None:
                nose.tools.assert_equal('2', result['polatisOxcPortDesiredState.%s' % int(prtlst[0])],
                                        'Wrong value for GetBulk PolatisOxcPortDesired'
                                        'State: %s' % result['polatisOxcPortDesiredState.%s' % int(prtlst[0])])
            else:
                raise Exception(
                    "Incorrect Output for polatis Oxc port Desired State through get bulk: %s,Error Message: %s"
                    % (result, self.snmp_session.snmp_session.ErrorStr))

        def test_getbulk_oxcsize_with_invalid_community(self):
            """
            Negative: Query Polatis oxc size through Snmp bulkget with Invalid community
            """
            self.snmp_session.create_box('test_getbulk_oxcsize_with_invalid_community')
            result = self.snmp_invalid_session.snmp_get_bulk('polatisOxcPortDesiredState')
            if 'polatisOxcPortDesiredState.' not in result:
                raise Exception("Got output for Snmp Getbulk with Invalid Community instead of empty dict: %s" % result)
            else:
                nose.tools.assert_equal('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP getbulk with Invalid '
                                        'Community: %s ' % self.snmp_invalid_session.snmp_session.ErrorStr)

        def test_getbulk_oxcportpatch_with_invalid_community(self):
            """
            Negative: Query Polatis oxc port patch through Snmp bulkget with Invalid community
            """
            self.snmp_session.create_box('test_getbulk_oxcportpatch_with_invalid_community')
            result = self.snmp_invalid_session.snmp_get_bulk('polatisOxcPortPatch')
            if 'polatisOxcPortPatch.' not in result:
                raise Exception("Got output for Snmp Getbulk with Invalid Community instead of empty dict: %s" % result)
            else:
                nose.tools.assert_equal('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP getbulk with Invalid '
                                        'Community: %s ' % self.snmp_invalid_session.snmp_session.ErrorStr)

        def test_getbulk_oxcportcurrentstate_with_invalid_community(self):
            """
            Negative: Query Polatis oxc port current state through Snmp bulkget with Invalid community
            """
            self.snmp_session.create_box('test_getbulk_oxcportcurrentstate_with_invalid_community')
            result = self.snmp_invalid_session.snmp_get_bulk('polatisOxcPortCurrentState')
            if 'polatisOxcPortCurrentState.' not in result:
                raise Exception("Got output for Snmp Getbulk with Invalid community instead of empty dict: %s" % result)
            else:
                nose.tools.assert_equal('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP getbulk with Invalid '
                                        'Community: %s ' % self.snmp_invalid_session.snmp_session.ErrorStr)

        def test_getbulk_oxcportdesiredstate_with_invalid_community(self):
            """
            Negative: Query Polatis oxc port desired state through Snmp bulkget with Invalid community
            """
            self.snmp_session.create_box('test_getbulk_oxcportdesiredstate_with_invalid_community')
            result = self.snmp_invalid_session.snmp_get_bulk('polatisOxcPortDesiredState')
            if 'polatisOxcPortDesiredState.' not in result:
                raise Exception("Got output for Snmp Getbulk with Invalid community instead of empty dict: %s" % result)
            else:
                nose.tools.assert_equal('Timeout', self.snmp_invalid_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP getbulk with Invalid '
                                        'Community: %s ' % self.snmp_invalid_session.snmp_session.ErrorStr)

    if version == 3:
        "SNMPv3 Test Cases"

        def test_v3_get_polatisoxcsize(self):
            """
            SNMPv3 Query Polatis Oxc Size through Snmp Get
            """
            self.snmp_session.create_box('test_v3_get_polatisoxcsize')
            output = self.snmp_v3_session.snmp_get("polatisOxcSize.0")
            # #print output
            if 'polatisOxcSize.0' not in output:
                raise KeyError("Incorrect output for Get on polatisOxcSize: %s" % output)
            else:
                nose.tools.assert_equal(pol_dict['polatisOxcSize'], output['polatisOxcSize.0'],
                                        "Wrong Value for Get on PolatisOxcSize: %s" % output['polatisOxcSize.0'])

        def test_v3_getnext_polatisoxcsize(self):
            """
            SNMPv3 Query Polatis Oxc Size through Snmp GetNext
            """
            self.snmp_session.create_box('test_v3_getnext_polatisoxcsize')
            output = self.snmp_v3_session.snmp_get_next("polatisOxcSize")
            # #print output
            if 'polatisOxcSize.0' not in output:
                raise KeyError("Incorrect output for GetNext on  polatisOxcSize: %s" % output)
            else:
                nose.tools.assert_equal(pol_dict['polatisOxcSize'], output['polatisOxcSize.0'],
                                        "Wrong Value for GetNext on PolatisOxcSize: %s" % output['polatisOxcSize.0'])

        def test_v3_walk_polatisoxcsize(self):
            """
            SNMPv3 Query Polatis Oxc Size through Snmp Walk
            """
            self.snmp_session.create_box('test_v3_walk_polatisoxcsize')
            output = self.snmp_v3_session.snmp_walk("polatisOxcSize")
            # #print output
            if 'polatisOxcSize.0' not in output:
                raise KeyError("Incorrect output for Snmp Walk on  polatisOxcSize: %s" % output)
            else:
                nose.tools.assert_equal(pol_dict['polatisOxcSize'], output['polatisOxcSize.0'],
                                        "Wrong Value for Snmp Walk on PolatisOxcSize: %s" % output['polatisOxcSize.0'])

        def test_v3_getbulk_polatisoxcsize(self):
            """
            SNMPv3 Query Polatis Oxc Size through Snmp GetBulk
            """
            self.snmp_session.create_box('test_v3_getbulk_polatisoxcsize')
            output = self.snmp_v3_session.snmp_get_bulk("polatisOxcSize")
            # #print output
            if 'polatisOxcSize.0' not in output:
                raise KeyError("Incorrect output for Snmp getbulk on  polatisOxcSize: %s" % output)
            else:
                nose.tools.assert_equal(pol_dict['polatisOxcSize'], output['polatisOxcSize.0'],
                                        "Wrong Value for Snmp getbulk on PolatisOxcSize: %s" % output[
                                            'polatisOxcSize.0'])

        def test_v3_get_polatisoxcportpatch(self):
            """
            SNMPv3 Query Polatis Oxc Port Patch through Snmp Get
            """
            self.snmp_session.create_box('test_v3_get_polatisoxcportpatch')
            output = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), int(prtlst[0])+int(prtlst[0]), 'GAUGE32')
            # #print output
            nose.tools.assert_equal(1, output, '(genError) A general failure occured : %s' % self.snmp_v3_session.snmp_session.ErrorStr)
            result = self.snmp_v3_session.snmp_get("polatisOxcPortPatch.%s" % int(prtlst[0]))
            #print result
            time.sleep(10)
            if 'polatisOxcPortPatch.%s' % int(prtlst[0]) not in result:
                raise KeyError("Incorrect output for Get on polatisOxcPortPatch: %s" % result)
            else:
                nose.tools.assert_equal(str(int(prtlst[0])+int(prtlst[0])), result['polatisOxcPortPatch.%s' % int(prtlst[0])],
                                        "Wrong Value for Get on polatisOxcPortPatch: %s" % result[
                                            'polatisOxcPortPatch.%s' % int(prtlst[0])])

            self.snmp_v3_session.snmp_set('polatisOxcPortPatch.1', 0, 'UINTEGER')
            time.sleep(10)

        def test_v3_getnext_polatisoxcportpatch(self):
            """
            SNMPv3 Query Polatis Oxc Port Patch through Snmp GetNext
            """
            self.snmp_session.create_box('test_v3_getnext_polatisoxcportpatch')
            output = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.1', int(prtlst[0])+int(prtlst[0]), 'GAUGE32')
            # #print output
            nose.tools.assert_equal(1, output, 'SNMP Set Error: %s' % self.snmp_v3_session.snmp_session.ErrorStr)
            result = self.snmp_v3_session.snmp_get_next("polatisOxcPortPatch")
            #print result
            time.sleep(10)
            if 'polatisOxcPortPatch.1' not in result:
                raise KeyError("Incorrect output for GetNext on polatisOxcPortPatch: %s" % result)
            else:
                nose.tools.assert_equal(str(int(prtlst[0])+int(prtlst[0])), result['polatisOxcPortPatch.1'],
                                        "Wrong Value for GetNext polatisOxcPortPatch: %s" % result[
                                            'polatisOxcPortPatch.1'])

            self.snmp_v3_session.snmp_set('polatisOxcPortPatch.1', 0, 'UINTEGER')
            time.sleep(10)

        def test_v3_walk_polatisoxcportpatch(self):
            """
            SNMPv3 Query Polatis Oxc Port Patch through Snmp Walk
            """
            self.snmp_session.create_box('test_v3_walk_polatisoxcportpatch')
            output = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), int(prtlst[0])+int(prtlst[0]), 'GAUGE32')
            # #print output
            nose.tools.assert_equal(1, output, 'SNMP Set Error: %s' % self.snmp_v3_session.snmp_session.ErrorStr)
            result = self.snmp_v3_session.snmp_walk("polatisOxcPortPatch")
            #print result
            time.sleep(10)
            if 'polatisOxcPortPatch.%s' % int(prtlst[0]) not in result:
                raise KeyError("Incorrect output for Walk on polatisOxcPortPatch: %s" % result)
            else:
                nose.tools.assert_equal(str(int(prtlst[0])+int(prtlst[0])), result['polatisOxcPortPatch.%s' % int(prtlst[0])],
                                        "Wrong Value for Walk on polatisOxcPortPatch: %s" % result[
                                            'polatisOxcPortPatch.%s' % int(prtlst[0])])

            self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            time.sleep(10)

        def test_v3_bulkget_polatisoxcportpatch(self):
            """
            SNMPv3 Query Polatis Oxc Port Patch through Snmp Bulkget
            """
            self.snmp_session.create_box('test_v3_bulkget_polatisoxcportpatch')
            output = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), int(prtlst[0])+int(prtlst[0]), 'GAUGE32')
            # #print output
            nose.tools.assert_equal(1, output, 'SNMP Set Error: %s' % self.snmp_v3_session.snmp_session.ErrorStr)
            time.sleep(10)
	    result = self.snmp_v3_session.snmp_get_bulk("polatisOxcPortPatch.%s" % (int(prtlst[0])-1))
            #print result
	    time.sleep(10)
            if 'polatisOxcPortPatch.%s' % int(prtlst[0]) not in result:
                raise KeyError("Incorrect output for Getbulk on polatisOxcPortPatch: %s" % result)
            else:
                nose.tools.assert_equal(str(int(prtlst[0])+int(prtlst[0])), result['polatisOxcPortPatch.%s' % int(prtlst[0])],
                                        "Wrong Value for Getbulk polatisOxcPortPatch: %s" % result[
                                            'polatisOxcPortPatch.%s' % int(prtlst[0])])

            self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
	    time.sleep(10)

        def test_v3_get_polatisoxcportdesiredstate(self):
            """
            SNMPv3 Query Polatis Oxc Port Desired State through Snmp Get
            """
            self.snmp_session.create_box('test_v3_get_polatisoxcportdesiredstate')
            output = self.snmp_v3_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 1, 'UINTEGER')
            # #print output
            time.sleep(10)
            nose.tools.assert_equal(1, output, 'SNMP Set Error: %s' % self.snmp_v3_session.snmp_session.ErrorStr)
            result = self.snmp_v3_session.snmp_get("polatisOxcPortDesiredState.%s" % int(prtlst[0]))
            #print result
            time.sleep(10)
            if 'polatisOxcPortDesiredState.%s' % int(prtlst[0]) not in result:
                raise KeyError("Incorrect output for Get on polatisOxcPortDesiredState: %s" % result)
            else:
                nose.tools.assert_equal('1', result['polatisOxcPortDesiredState.%s' % int(prtlst[0])],
                                        "Wrong Value for Get on polatisOxcPortDesired"
                                        "State: %s" % result['polatisOxcPortDesiredState.%s' % int(prtlst[0])])

        def test_v3_getnext_polatisoxcportdesiredstate(self):
            """
            SNMPv3 Query Polatis Oxc Port Desired State through Snmp GetNext
            """
            self.snmp_session.create_box('test_v3_getnext_polatisoxcportdesiredstate')
            output = self.snmp_v3_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 2, 'INTEGER')
            # #print output
            time.sleep(10)
            nose.tools.assert_equal(1, output, 'SNMP Set Error: %s' % self.snmp_v3_session.snmp_session.ErrorStr)
            result = self.snmp_v3_session.snmp_get_next("polatisOxcPortDesiredState.%s" % (int(prtlst[0])-1))
            #print result
	    time.sleep(10)
            if 'polatisOxcPortDesiredState.%s' % int(prtlst[0]) not in result:
                raise KeyError("Incorrect output for GetNext on polatisOxcPortDesiredState: %s" % result)
            else:
                nose.tools.assert_equal('2', result['polatisOxcPortDesiredState.%s' % int(prtlst[0])],
                                        "Wrong Value for GetNext on polatisOxcPortDesired"
                                        "State: %s" % result['polatisOxcPortDesiredState.%s' % int(prtlst[0])])
            

        def test_v3_walk_polatisoxcportdesiredstate(self):
            """
            SNMPv3 Query Polatis Oxc Port Desired State through Snmp Walk
            """
            self.snmp_session.create_box('test_v3_walk_polatisoxcportdesiredstate')
            output = self.snmp_v3_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 2, 'INTEGER')
            #print output
	    time.sleep(10)
            nose.tools.assert_equal(1, output, 'SNMP Set Error: %s' % self.snmp_v3_session.snmp_session.ErrorStr)
	    result = self.snmp_v3_session.snmp_walk('polatisOxcPortDesiredState')
            time.sleep(10)
	    #print result
            if 'polatisOxcPortDesiredState.%s' % int(prtlst[0]) not in result:
                raise KeyError("Incorrect output for Walk on polatisOxcPortDesiredState: %s" % result)
            else:
                nose.tools.assert_equal('2', result['polatisOxcPortDesiredState.%s' % int(prtlst[0])],
                                        "Wrong Value for Walk on polatisOxcPortDesired"
                                        "State: %s" % result['polatisOxcPortDesiredState.%s' % int(prtlst[0])])
            self.snmp_v3_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 1, 'INTEGER')

        def test_v3_getbulk_polatisoxcportdesiredstate(self):
            """
            SNMPv3 Query Polatis Oxc Port Desired State through Snmp GetBulk
            """
            self.snmp_session.create_box('test_v3_getbulk_polatisoxcportdesiredstate')
            output = self.snmp_v3_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 1, 'INTEGER')
            # #print output
            time.sleep(10)
            nose.tools.assert_equal(1, output, 'SNMP Set Error: %s' % self.snmp_v3_session.snmp_session.ErrorStr)
            result = self.snmp_v3_session.snmp_get_bulk("polatisOxcPortDesiredState.%s" % (int(prtlst[0])-1))
            #print result
            time.sleep(10)
            if 'polatisOxcPortDesiredState.%s' % int(prtlst[0]) not in result:
                raise KeyError("Incorrect output for getbulk on polatisOxcPortDesiredState: %s" % result)
            else:
                nose.tools.assert_equal('1', result['polatisOxcPortDesiredState.%s' % int(prtlst[0])],
                                        "Wrong Value for getbulk on polatisOxcPortDesired"
                                        "State: %s" % result['polatisOxcPortDesiredState.%s' % int(prtlst[0])])

        def test_v3_get_polatisoxcportcurrentstate(self):
            """
            SNMPv3 Query Polatis Oxc Port Current State through Snmp Get
            """
            self.snmp_session.create_box('test_v3_get_polatisoxcportcurrentstate')
            result = self.snmp_v3_session.snmp_get("polatisOxcPortCurrentState.%s" % int(prtlst[0]))
            #print result
            time.sleep(10)
            if 'polatisOxcPortCurrentState.%s' % int(prtlst[0]) not in result:
                raise KeyError("Incorrect output for Get on polatisOxcPortCurrentState: %s" % result)
            else:
                nose.tools.assert_in(result['polatisOxcPortCurrentState.%s' % int(prtlst[0])], ['1', '2'],
                                     "Wrong Value for Get on polatisOxcPortCurrent"
                                     "State: %s" % result['polatisOxcPortCurrentState.%s' % int(prtlst[0])])

        def test_v3_getnext_polatisoxcportcurrentstate(self):
            """
            SNMPv3 Query Polatis Oxc Port Current State through Snmp GetNext
            """
            self.snmp_session.create_box('test_v3_getnext_polatisoxcportcurrentstate')
            result = self.snmp_v3_session.snmp_get_next("polatisOxcPortCurrentState.%s" % int(prtlst[0]))
            #print result
            if 'polatisOxcPortCurrentState.%s' % (int(prtlst[0])+1) not in result:
                raise KeyError("Incorrect output for GetNext on polatisOxcPortCurrentState: %s" % result)
            else:
                nose.tools.assert_in(result['polatisOxcPortCurrentState.%s' % (int(prtlst[0])+1)], ['1', '2'],
                                     "Wrong Value for GetNext on polatisOxcPortCurrent"
                                     "State: %s" % result['polatisOxcPortCurrentState.%s' % (int(prtlst[0])+1)])

        def test_v3_walk_polatisoxcportcurrentstate(self):
            """
            SNMPv3 Query Polatis Oxc Port Current State through Snmp Walk
            """
            self.snmp_session.create_box('test_v3_walk_polatisoxcportcurrentstate')
            result = self.snmp_v3_session.snmp_walk("polatisOxcPortCurrentState")
            #print result
            if 'polatisOxcPortCurrentState.%s' % int(prtlst[0]) not in result:
                raise KeyError("Incorrect output for Walk on polatisOxcPortCurrentState: %s" % result)
            else:
                nose.tools.assert_in(result['polatisOxcPortCurrentState.%s' % int(prtlst[0])], ['1', '2'],
                                     "Wrong Value for Walk on polatisOxcPortCurrent"
                                     "State: %s" % result['polatisOxcPortCurrentState.%s' % int(prtlst[0])])

        def test_v3_getbulk_polatisoxcportcurrentstate(self):
            """
            SNMPv3 Query Polatis Oxc Port Current State through Snmp GetBulk
            """
            self.snmp_session.create_box('test_v3_getbulk_polatisoxcportcurrentstate')
            result = self.snmp_v3_session.snmp_get_bulk("polatisOxcPortCurrentState.%s" % (int(prtlst[0])-1))
            #print result
            if 'polatisOxcPortCurrentState.%s' % int(prtlst[0]) not in result:
                raise KeyError("Incorrect output for Getbulk on polatisOxcPortCurrentState: %s" % result)
            else:
                nose.tools.assert_in(result['polatisOxcPortCurrentState.%s' % int(prtlst[0])], ['1', '2'],
                                     "Wrong Value for Getbulk on polatisOxcPortCurrent"
                                     "State: %s" % result['polatisOxcPortCurrentState.%s' % int(prtlst[0])])

        def test_v3_set_disable_ideal_port(self):
            """
            SNMPv3 Disable Ideal ports through SnmpSet
            """
            self.snmp_session.create_box('test_v3_set_disable_ideal_port')
            output1 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output1,
                                    'SNMP Set Port Patch Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)

            output2 = self.snmp_v3_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 2, 'INTEGER')
            nose.tools.assert_equal(1, output2, 'SNMP Set Port DesiredState '
                                                'Error: %s' % self.snmp_v3_session.snmp_session.ErrorStr)
            time.sleep(10)
            result = self.snmp_v3_session.snmp_get('polatisOxcPortDesiredState.%s' % int(prtlst[0]))
            time.sleep(10)
            if 'polatisOxcPortDesiredState.%s' % int(prtlst[0]) in result:
                nose.tools.assert_equal('2', result['polatisOxcPortDesiredState.%s' % int(prtlst[0])],
                                        'Wrong value received for get PolatisOxcPortDesiredState: %s' % result)
            else:
                raise Exception(
                    "Incorrect Output:%s, Error Message:%s" % (result, self.snmp_v3_session.snmp_session.ErrorStr))

        def test_v3_set_disable_crossconnected_port(self):
            """
            SNMPv3 Disable CrossConnected Ports through Snmpset
            """
            self.snmp_session.create_box('test_v3_set_disable_crossconnected_port')
            output1 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), int(prtlst[0])+int(prtlst[0]), 'UINTEGER')
            nose.tools.assert_equal(1, output1,
                                    'SNMP Set Port Patch Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)
            output2 = self.snmp_v3_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 2, 'INTEGER')
            time.sleep(10)
            nose.tools.assert_equal(1, output2, 'SNMP Set Port DesiredState '
                                                'Error: %s' % self.snmp_v3_session.snmp_session.ErrorStr)
           
            result = self.snmp_v3_session.snmp_get('polatisOxcPortDesiredState.%s' % int(prtlst[0]))
            time.sleep(10)
	    if 'polatisOxcPortDesiredState.%s' % int(prtlst[0]) in result:
                nose.tools.assert_equal('2', result['polatisOxcPortDesiredState.%s' % int(prtlst[0])],
                                        'Wrong value received for get PolatisOxcPortDesiredState: %s' % result)
            else:
                raise Exception(
                    "Incorrect Output:%s, Error Message:%s" % (result, self.snmp_v3_session.snmp_session.ErrorStr))

            self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            self.snmp_v3_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 1, 'INTEGER')
            time.sleep(10)

        def test_v3_set_enable_ideal_port(self):
            """
            SNMPv3 Enable Ideal ports through SnmpSet
            """
            self.snmp_session.create_box('test_v3_set_enable_ideal_port')
            output1 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output1,
                                    'SNMP Set Port Patch Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)

            output2 = self.snmp_v3_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 1, 'INTEGER')
            nose.tools.assert_equal(1, output2, 'SNMP Set Port DesiredState '
                                                'Error: %s' % self.snmp_v3_session.snmp_session.ErrorStr)
            time.sleep(10)
            result = self.snmp_v3_session.snmp_get('polatisOxcPortDesiredState.%s' % int(prtlst[0]))
            if 'polatisOxcPortDesiredState.%s' % int(prtlst[0]) in result:
                nose.tools.assert_equal('1', result['polatisOxcPortDesiredState.%s' % int(prtlst[0])],
                                        'Wrong value received for get PolatisOxcPortDesiredState: %s' % result)
            else:
                raise Exception(
                    "Incorrect Output:%s, Error Message:%s" % (result, self.snmp_v3_session.snmp_session.ErrorStr))

        def test_v3_set_enable_crossconnected_port(self):
            """
            SNMPv3 Enable CrossConnected Ports through Snmpset
            """
            self.snmp_session.create_box('test_v3_set_enable_crossconnected_port')
            output1 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), int(prtlst[0])+int(prtlst[0]), 'UINTEGER')
            nose.tools.assert_equal(1, output1,
                                    'SNMP Set Port Patch Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)

            output2 = self.snmp_v3_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 1, 'INTEGER')
            nose.tools.assert_equal(1, output2, 'SNMP Set Port DesiredState '
                                                'Error: %s' % self.snmp_v3_session.snmp_session.ErrorStr)
            time.sleep(10)
            result = self.snmp_v3_session.snmp_get('polatisOxcPortDesiredState.%s' % int(prtlst[0]))
            if 'polatisOxcPortDesiredState.%s' % int(prtlst[0]) in result:
                nose.tools.assert_equal('1', result['polatisOxcPortDesiredState.%s' % int(prtlst[0])],
                                        'Wrong value received for get PolatisOxcPortDesiredState: %s' % result)
            else:
                raise Exception(
                    "Incorrect Output:%s, Error Message:%s" % (result, self.snmp_v3_session.snmp_session.ErrorStr))

            self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            time.sleep(10)

        def test_v3_set_create_crossconnect_with_ingress_port(self):
            """
            SNMPv3 Create CrossConnect with Ingress port through Snmpset
            """
            self.snmp_session.create_box('test_v3_set_create_crossconnect_with_ingress_port')
            output1 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output1, 'SNMPSet disconnect port '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)

            output2 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output2, 'SNMPSet disconnect port '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)

            output3 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), int(prtlst[0])+1, 'UINTEGER')
            nose.tools.assert_equal(1, output3, 'SNMPSet create crossconnect '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)
            time.sleep(10)
            result1 = self.snmp_v3_session.snmp_get('polatisOxcPortPatch.%s' % int(prtlst[0]))
            result2 = self.snmp_v3_session.snmp_get('polatisOxcPortPatch.%s' % (int(prtlst[0])+1))
            time.sleep(10)
            if 'polatisOxcPortPatch.%s' % int(prtlst[0]) in result1:
                nose.tools.assert_equal(str(int(prtlst[0])+1), result1['polatisOxcPortPatch.%s' % int(prtlst[0])],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result1)
            elif 'polatisOxcPortPatch.%s' % (int(prtlst[0])+1) in result2:
                nose.tools.assert_equal(str(int(prtlst[0])), result2['polatisOxcPortPatch.%s' % (int(prtlst[0])+1)],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result2)
            else:
                raise Exception("Incorrect Output:%s,Error Message:%s" % (
                    (result1, result2), self.snmp_v3_session.snmp_session.ErrorStr))

            self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            time.sleep(10)
   
        def test_v3_set_create_crossconnect_with_egress_port(self):
            """
            SNMPv3 Create CrossConnect with Egress port through Snmpset
            """
            self.snmp_session.create_box('test_v3_set_create_crossconnect_with_egress_port')
            output1 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output1, 'SNMPSet disconnectport '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)

            output2 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output2, 'SNMPSet disconnectport '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)

            output3 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), int(prtlst[0]), 'UINTEGER')
            nose.tools.assert_equal(1, output3, 'SNMPSet create crossconnect '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)
            time.sleep(10)
            result1 = self.snmp_v3_session.snmp_get('polatisOxcPortPatch.%s' % (int(prtlst[0])+1))
            result2 = self.snmp_v3_session.snmp_get('polatisOxcPortPatch.%s' % int(prtlst[0]))
            time.sleep(10)
            if 'polatisOxcPortPatch.%s' % (int(prtlst[0])+1) in result1 and 'polatisOxcPortPatch.%s' % int(prtlst[0]) in result2:
                nose.tools.assert_equal(str(int(prtlst[0])), result1['polatisOxcPortPatch.%s' % (int(prtlst[0])+1)],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result1)
                nose.tools.assert_equal(str(int(prtlst[0])+1), result2['polatisOxcPortPatch.%s' % int(prtlst[0])],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result2)
            else:
                raise Exception("Incorrect Output:%s,Error Message:%s" % (
                    (result1, result2), self.snmp_v3_session.snmp_session.ErrorStr))

            self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            time.sleep(10)
              
        def test_v3_set_update_crossconnect_with_ingress_port(self):
            """
            SNMPv3 Update CrossConnect with Ingress port through Snmpset
            """
            self.snmp_session.create_box('test_v3_set_update_crossconnect_with_ingress_port')
            output1 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), int(prtlst[0])+int(prtlst[0]), 'UINTEGER')
            nose.tools.assert_equal(1, output1, 'SNMPSet crossconnectPort '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)

            output2 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), int(prtlst[0])+1, 'UINTEGER')
            nose.tools.assert_equal(1, output2, 'SNMPSet crossconnectPort '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)
            time.sleep(10)
            result1 = self.snmp_v3_session.snmp_get('polatisOxcPortPatch.%s' % int(prtlst[0]))
            result2 = self.snmp_v3_session.snmp_get('polatisOxcPortPatch.%s' % (int(prtlst[0])+int(prtlst[0])))
            #print result1
            #print result2
            time.sleep(10)
            if 'polatisOxcPortPatch.%s' % int(prtlst[0]) in result1 and 'polatisOxcPortPatch.%s' %(int(prtlst[0])+int(prtlst[0])) in result2:
                nose.tools.assert_equal(str(int(prtlst[0])+1), result1['polatisOxcPortPatch.%s' % int(prtlst[0])],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result1)
                nose.tools.assert_equal('0', result2['polatisOxcPortPatch.%s' % (int(prtlst[0])+int(prtlst[0]))],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result2)
            else:
                raise Exception("Incorrect Output:%s,Error Message:%s" % (
                    (result1, result2), self.snmp_v3_session.snmp_session.ErrorStr))

            self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            time.sleep(10)
        def test_v3_set_update_crossconnect_with_egress_port(self):
            """
            SNMPv3 Update CrossConnect with Egress port through Snmpset
            """
            self.snmp_session.create_box('test_v3_set_update_crossconnect_with_egress_port')
            output1 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+int(prtlst[0])), int(prtlst[0]), 'UINTEGER')
            nose.tools.assert_equal(1, output1, 'SNMPSet crossconnectPort '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)

            output2 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+int(prtlst[0])), int(prtlst[0])-1, 'UINTEGER')
            nose.tools.assert_equal(1, output2, 'SNMPSet crossconnectPort '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)
            time.sleep(10)
            result1 = self.snmp_v3_session.snmp_get('polatisOxcPortPatch.%s' % (int(prtlst[0])+int(prtlst[0])))
            result2 = self.snmp_v3_session.snmp_get('polatisOxcPortPatch.%s' % int(prtlst[0]))
            time.sleep(10)
            if 'polatisOxcPortPatch.%s' % (int(prtlst[0])+int(prtlst[0])) in result1 and 'polatisOxcPortPatch.%s' % int(prtlst[0]) in result2:
                nose.tools.assert_equal(str(int(prtlst[0])-1), result1['polatisOxcPortPatch.%s' % (int(prtlst[0])+int(prtlst[0]))],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result1)
                nose.tools.assert_equal('0', result2['polatisOxcPortPatch.%s' % int(prtlst[0])],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result2)
            else:
                raise Exception("Incorrect Output:%s,Error Message:%s" % (
                    (result1, result2), self.snmp_v3_session.snmp_session.ErrorStr))

            self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+int(prtlst[0])), 0, 'UINTEGER')
            time.sleep(10)
       
        def test_v3_set_delete_crossconnect_with_ingress_port(self):
            """
            SNMPv3 Delete CrossConnect with Ingress port through Snmpset
            """
            self.snmp_session.create_box('test_v3_set_delete_crossconnect_with_ingress_port')
            output1 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), int(prtlst[0])+int(prtlst[0]), 'UINTEGER')
            nose.tools.assert_equal(1, output1, 'SNMPSet crossconnectPort '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)

            output2 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output2, 'SNMPSet disconnectPort '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)

            result1 = self.snmp_v3_session.snmp_get('polatisOxcPortPatch.%s' % int(prtlst[0]))
            time.sleep(10)
            if 'polatisOxcPortPatch.%s' % int(prtlst[0]) in result1:
                nose.tools.assert_equal('0', result1['polatisOxcPortPatch.%s' % int(prtlst[0])],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result1)
            else:
                raise Exception(
                    "Incorrect Output:%s,Error Message:%s" % (result1, self.snmp_v3_session.snmp_session.ErrorStr))

            self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            time.sleep(10)
      
        def test_v3_set_delete_crossconnect_with_egress_port(self):
            """
            SNMPv3 Delete CrossConnect with Egress port through Snmpset
            """
            self.snmp_session.create_box('test_v3_set_delete_crossconnect_with_egress_port')
            output1 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), int(prtlst[0]), 'UINTEGER')
            nose.tools.assert_equal(1, output1, 'SNMPSet crossconnectPort '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)

            output2 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output2, 'SNMPSet disconnectPort '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)
            time.sleep(10)
            result1 = self.snmp_v3_session.snmp_get('polatisOxcPortPatch.%s' % (int(prtlst[0])+1))
            if 'polatisOxcPortPatch.%s' % (int(prtlst[0])+1) in result1:
                nose.tools.assert_equal('0', result1['polatisOxcPortPatch.%s' % (int(prtlst[0])+1)],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result1)
            else:
                raise Exception(
                    "Incorrect Output:%s,Error Message:%s" % (result1, self.snmp_v3_session.snmp_session.ErrorStr))

            self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), 0, 'UINTEGER')
            time.sleep(10)
 
        def test_v3_set_create_crossconnect_with_disabled_ingress_port(self):
            """
            SNMPv3 Create CrossConnect with Disabled Ingress port through Snmpset
            """
            self.snmp_session.create_box('test_v3_set_create_crossconnect_with_disabled_ingress_port')
            output1 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output1, 'SNMPSet disconnect port '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)

            output2 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output2, 'SNMPSet disconnect port '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)

            output3 = self.snmp_v3_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 2, 'UINTEGER')
            nose.tools.assert_equal(1, output3, 'SNMPSet Disable Ingress Port '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)

            output4 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), int(prtlst[0])+1, 'UINTEGER')
            nose.tools.assert_equal(1, output4, 'SNMPSet create crossconnect '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)
            time.sleep(10)
            result1 = self.snmp_v3_session.snmp_get('polatisOxcPortPatch.%s' % int(prtlst[0]))
            result2 = self.snmp_v3_session.snmp_get('polatisOxcPortPatch.%s' % (int(prtlst[0])+1))
            time.sleep(10)
            if 'polatisOxcPortPatch.%s' % int(prtlst[0]) in result1 and 'polatisOxcPortPatch.%s' % (int(prtlst[0])+1) in result2:
                nose.tools.assert_equal(str(int(prtlst[0])+1), result1['polatisOxcPortPatch.%s' % int(prtlst[0])],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result1)
                nose.tools.assert_equal(str(int(prtlst[0])), result2['polatisOxcPortPatch.%s' % (int(prtlst[0])+1)],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result2)
            else:
                raise Exception(
                    "Incorrect Output:%s,Error Message:%s" % (result1, self.snmp_v3_session.snmp_session.ErrorStr))

            self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            self.snmp_v3_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 1, 'UINTEGER')
            time.sleep(10)
 
        def test_v3_set_create_crossconnect_with_disabled_egress_port(self):
            """
            SNMPv3 Create CrossConnect with Disabled Egress port through Snmpset
            """
            self.snmp_session.create_box('test_v3_set_create_crossconnect_with_disabled_egress_port')
            output1 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output1, 'SNMPSet disconnect port '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)

            output2 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output2, 'SNMPSet disconnect port '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)

            output3 = self.snmp_v3_session.snmp_set('polatisOxcPortDesiredState.%s' % (int(prtlst[0])+1), 2, 'UINTEGER')
            nose.tools.assert_equal(1, output3, 'SNMPSet Disable Ingress Port '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)

            output4 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), int(prtlst[0]), 'UINTEGER')
            nose.tools.assert_equal(1, output4, 'SNMPSet create crossconnect '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)
            time.sleep(10)
            result1 = self.snmp_v3_session.snmp_get('polatisOxcPortPatch.%s' % (int(prtlst[0])+1))
            result2 = self.snmp_v3_session.snmp_get('polatisOxcPortPatch.%s' % int(prtlst[0]))
            time.sleep(10)
            if 'polatisOxcPortPatch.%s' % (int(prtlst[0])+1) in result1 and 'polatisOxcPortPatch.%s' % int(prtlst[0]) in result2:
                nose.tools.assert_equal(str(int(prtlst[0])), result1['polatisOxcPortPatch.%s' % (int(prtlst[0])+1)],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result1)
                nose.tools.assert_equal(str(int(prtlst[0])+1), result2['polatisOxcPortPatch.%s' % int(prtlst[0])],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result2)
            else:
                raise Exception(
                    "Incorrect Output:%s,Error Message:%s" % (result1, self.snmp_v3_session.snmp_session.ErrorStr))

            self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), 0, 'UINTEGER')
            self.snmp_v3_session.snmp_set('polatisOxcPortDesiredState.%s' % (int(prtlst[0])+1), 1, 'UINTEGER')
            time.sleep(10)
 
        def test_v3_set_delete_crossconnect_with_disabled_ingress_port(self):
            """
            SNMPv3 Delete CrossConnect with Disabled Ingress port through Snmpset
            """
            self.snmp_session.create_box('test_v3_set_delete_crossconnect_with_disabled_ingress_port')
            output1 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), int(prtlst[0])+int(prtlst[0]), 'UINTEGER')
            nose.tools.assert_equal(1, output1, 'SNMPSet crossconnectPort '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)

            output2 = self.snmp_v3_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 2, 'UINTEGER')
            nose.tools.assert_equal(1, output2, 'SNMPSet Disable Ingress Port '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)

            output3 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output3, 'SNMPSet disconnectPort '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)
            time.sleep(10)
            result1 = self.snmp_v3_session.snmp_get('polatisOxcPortPatch.%s' % int(prtlst[0]))
            if 'polatisOxcPortPatch.%s' % int(prtlst[0]) in result1:
                nose.tools.assert_equal('0', result1['polatisOxcPortPatch.%s' % int(prtlst[0])],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result1)
            else:
                raise Exception(
                    "Incorrect Output:%s,Error Message:%s" % (result1, self.snmp_v3_session.snmp_session.ErrorStr))
            self.snmp_v3_session.snmp_set('polatisOxcPortDesiredState.%s' % int(prtlst[0]), 1, 'UINTEGER')

        def test_v3_set_delete_crossconnect_with_disabled_egress_port(self):
            """
            SNMPv3 Delete CrossConnect with Disabled Egress port through Snmpset
            """
            self.snmp_session.create_box('test_v3_set_delete_crossconnect_with_disabled_egress_port')
            output1 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), int(prtlst[0])+int(prtlst[0]), 'UINTEGER')
            nose.tools.assert_equal(1, output1, 'SNMPSet crossconnectPort '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)

            output2 = self.snmp_v3_session.snmp_set('polatisOxcPortDesiredState.%s' % (int(prtlst[0])+int(prtlst[0])), 2, 'UINTEGER')
            nose.tools.assert_equal(1, output2, 'SNMPSet Disable Ingress Port test_v3_get_polatisproductcode'
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)

            output3 = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+int(prtlst[0])), 0, 'UINTEGER')
            nose.tools.assert_equal(1, output3, 'SNMPSet disconnectPort '
                                                'Error:%s' % self.snmp_v3_session.snmp_session.ErrorStr)
            time.sleep(10)
            result1 = self.snmp_v3_session.snmp_get('polatisOxcPortPatch.%s' % (int(prtlst[0])+int(prtlst[0])))
            if 'polatisOxcPortPatch.%s' % (int(prtlst[0])+int(prtlst[0])) in result1:
                nose.tools.assert_equal('0', result1['polatisOxcPortPatch.%s' % (int(prtlst[0])+int(prtlst[0]))],
                                        'Wrong value received for get PolatisOxcPortPatch: %s' % result1)
            else:
                raise Exception(
                    "Incorrect Output:%s,Error Message:%s" % (result1, self.snmp_v3_session.snmp_session.ErrorStr))

        "Negative SNMPv3 Test cases"



        def test_v3_get_oxcportpatch_with_invalid_index(self):
            """
            Negative SNMPv3 Get Polatis Oxc Port Patch with Invalid Index
            """
            self.snmp_session.create_box('test_v3_get_oxcportpatch_with_invalid_index')
            output = self.snmp_v3_session.snmp_get('polatisOxcPortPatch.3000')
            if 'polatisOxcPortPatch.3000' not in output and output['polatisOxcPortPatch.3000']:
                raise Exception("Got output for Snmp Get with Invalid Index, Instead of empty dict: %s" % output)
            else:
                nose.tools.assert_equal('(genError) A general failure occured', self.snmp_v3_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP Get with Invalid '
                                        'Index: %s' % self.snmp_v3_session.snmp_session.ErrorStr)

        def test_v3_get_oxccurrentstate_with_invalid_index(self):
            """
            Negative SNMPv3 Get Polatis Oxc Port Current State with Invalid Index
            """
            time.sleep(10)
            self.snmp_session.create_box('test_v3_get_oxccurrentstate_with_invalid_index')
            output = self.snmp_v3_session.snmp_get('polatisOxcPortCurrentState.3000')
            if 'polatisOxcPortCurrentState.3000' not in output and output['polatisOxcPortCurrentState.3000']:
                raise Exception("Got output for Snmp Get with Invalid Index, Instead of empty dict: %s" % output)
            else:
                nose.tools.assert_equal('(genError) A general failure occured', self.snmp_v3_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP Get with Invalid '
                                        'Index: %s' % self.snmp_v3_session.snmp_session.ErrorStr)

        def test_v3_get_oxcdesiredstate_with_invalid_index(self):
            """
            Negative SNMPv3 Get Polatis Oxc Port Desired State with Invalid Index
            """
            self.snmp_session.create_box('test_v3_get_oxcdesiredstate_with_invalid_index')
            output = self.snmp_v3_session.snmp_get('polatisOxcPortDesiredState.3000')
            if 'polatisOxcPortDesiredState.3000' not in output and output['polatisOxcPortDesiredState.3000']:
                raise Exception("Got output for Snmp Get with Invalid Index, Instead of empty dict: %s" % output)
            else:
                nose.tools.assert_equal('(genError) A general failure occured', self.snmp_v3_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP Get with Invalid '
                                        'Index: %s' % self.snmp_v3_session.snmp_session.ErrorStr)

        def test_v3_set_oxcportpatch_with_invalid_index(self):
            """
            Negative: SNMPv3 Create Polatis Oxc Port Crossconnect through Snmp Set with Invalid Index
            """
            self.snmp_session.create_box('test_v3_set_oxcportpatch_with_invalid_index')
            result = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.3000', 2, 'GAUGE32')
            #print result
            #print self.snmp_v3_session.snmp_session.ErrorStr
            if result is 0:
                nose.tools.assert_equal('(genError) A general failure occured', self.snmp_v3_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP Set with Invalid '
                                        'Index: %s' % self.snmp_v3_session.snmp_session.ErrorStr)
            else:
                raise Exception("Incorrect Output, should be zero : %s " % result)

        def test_v3_set_oxcportdesiredstate_with_invalid_index(self):
            """
            Negative: SNMPv3 Set Oxc Port Desired State through Snmp Set with Invalid Index
            """
            self.snmp_session.create_box('test_v3_set_oxcportdesiredstate_with_invalid_index')
            result = self.snmp_v3_session.snmp_set('polatisOxcPortDesiredState.3000', 1, 'INTEGER')
            #print result
            #print self.snmp_v3_session.snmp_session.ErrorStr
            if result is 0:
                nose.tools.assert_equal('(genError) A general failure occured', self.snmp_v3_session.snmp_session.ErrorStr,
                                        'Wrong or No exception for SNMP Set with Invalid '
                                        'Index: %s' % self.snmp_v3_session.snmp_session.ErrorStr)
            else:
                raise Exception("Incorrect Output, should be zero : %s " % result)


        def test_v3_set_nonwritable_oxcportcurrentstate(self):
            """
            Negative: SNMPv3 Set Non Writable Polatis Oxc Port Current State
            """
            self.snmp_session.create_box('test_v3_set_nonwritable_oxcportcurrentstate')
            result = self.snmp_v3_session.snmp_set('polatisOxcPortCurrentState.1', '1', 'INTEGER')
            if result is not 0:
                raise Exception(
                    "Able to set the nonwritable column, SNMPSet value should be 0 for non-writable columns "
                    "instead the value is %s" % result)
            else:
                nose.tools.assert_in('notWritable', self.snmp_v3_session.snmp_session.ErrorStr,
                                     'No or Wrong Exception when setting a non-writable column'
                                     '(polatisOxcPortCurrentState):%s' % self.snmp_v3_session.snmp_session.ErrorStr)

        def test_v3_set_invalid_value_oxcdesiredstate(self):
            """
            Negative: SNMPv3 Set Invalid Value for Polatis Oxc Port Desired State
            """
            self.snmp_session.create_box('test_v3_set_invalid_value_oxcdesiredstate')
            result = self.snmp_v3_session.snmp_set('polatisOxcPortDesiredState.1', '10', 'INTEGER')

            if result is 0:
                nose.tools.assert_in('wrongValue', self.snmp_v3_session.snmp_session.ErrorStr,
                                     'No or Wrong Exception while setting Oxc Port Desired State with invalid '
                                     'value: %s' % self.snmp_v3_session.snmp_session.ErrorStr)
            else:
                raise Exception(
                    "Able to Set Oxc Port Desired State with value other than 1, 2. SnmpSet output should be 0 "
                    "but the value is: %s" % result)

        def test_v3_set_create_crossconnect_with_invalid_port(self):
            """
            Negative: SNMPv3 Create Crossconnect with Invalid Port
            """
            self.snmp_session.create_box('test_v3_set_create_crossconnect_with_invalid_port')
            result = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.2000', '1', 'GAUGE32')

            if result is 0:
                nose.tools.assert_in('(genError) A general failure occured', self.snmp_v3_session.snmp_session.ErrorStr,
                                     'No or Wrong Exception while setting Oxc Port Desired State with invalid '
                                     'value: %s' % self.snmp_v3_session.snmp_session.ErrorStr)
            else:
                raise Exception(
                    "Able to create crossconnect with Invalid ports. SnmpSet output should be 0 but the value "
                    "is: %s" % result)

        def test_v3_set_delete_crossconnect_with_invalid_port(self):
            """
            Negative: SNMPv3 Delete Crossconnect with Invalid Port
            """
            self.snmp_session.create_box('test_v3_set_delete_crossconnect_with_invalid_port')
            result = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.2000', '0', 'GAUGE32')

            if result is 0:
                nose.tools.assert_in('(genError) A general failure occured', self.snmp_v3_session.snmp_session.ErrorStr,
                                     'No or Wrong Exception while setting Oxc Port Desired State with invalid '
                                     'value: %s' % self.snmp_v3_session.snmp_session.ErrorStr)
            else:
                raise Exception(
                    "Able to Delete crossconnect with Invalid ports. SnmpSet output should be 0 but the value "
                    "is: %s" % result)

        def test_v3_set_create_crossconnect_between_ingress_port(self):
            """
            Negative: SNMPv3 Create Crossconnect between Ingress Ports
            """
            self.snmp_session.create_box('test_v3_set_create_crossconnect_between_ingress_port')
            result = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % int(prtlst[0]), int(prtlst[0])-1, 'GAUGE32')
            #print "result : ", result
            #print "AuthPass : ", self.snmp_v3_session.snmp_session.AuthPass
            #print "secuser : ", self.snmp_v3_session.snmp_session.SecName
            #print "Err : ", self.snmp_v3_session.snmp_session.ErrorStr

            if result is 0:
                nose.tools.assert_in('(genError) A general failure occured', self.snmp_v3_session.snmp_session.ErrorStr,
                                     'No or Wrong Exception while setting Oxc Port Desired State with invalid '
                                     'value: %s' % self.snmp_v3_session.snmp_session.ErrorStr)
            else:
                raise Exception("Able to create crossconnect between Ingress Ports. SnmpSet output should be 0 but "
                                "the value is: %s" % result)

        time.sleep(30)         
        def test_v3_set_create_crossconnect_between_egress_port(self):
            """
            Negative: SNMPv3 Create Crossconnect between Egress Ports
            """
            self.snmp_session.create_box('test_v3_set_create_crossconnect_between_egress_port')
            time.sleep(10)
            result = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.%s' % (int(prtlst[0])+1), int(prtlst[0])+int(prtlst[0]), 'GAUGE32')
	    #result = self.snmp_v3_session.snmp_set('polatisOxcPortPatch.49', '50', 'GAUGE32')
            #print "result : ", result
            #print "AuthPass : ", self.snmp_v3_session.snmp_session.AuthPass
            #print "secuser : ", self.snmp_v3_session.snmp_session.SecName
            #print "Err : ", self.snmp_v3_session.snmp_session.ErrorStr
            if result is 0:
                nose.tools.assert_in('(genError) A general failure occured', self.snmp_v3_session.snmp_session.ErrorStr,
                                     'No or Wrong Exception while setting Oxc Port Desired State with invalid '
                                     'value: %s' % self.snmp_v3_session.snmp_session.ErrorStr)
            else:
                raise Exception("Able to create crossconnect between Egress Ports. SnmpSet output should be 0 but "
                                "the value is: %s" % result)


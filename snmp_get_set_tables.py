""" Python File that handles the SNMP (SET, GET, GETNEXT, WALK and GETBULK) 
Operations on:

- polatisOxcPortTable
- polatisNetConfigTable
- polatisInterfaceConfigTable
"""
import netsnmp
import logging

logger = logging.getLogger('SnmpAgent')
#logger.setLevel(logging.INFO)
#ch = logging.StreamHandler()
#ch.setLevel(logging.DEBUG)
#formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
#ch.setFormatter(formatter)
#logger.addHandler(ch)

POL_DICT = eval(open("snmp_config.txt").read())
TABLE_DICT = {
    'polatisProductCode': POL_DICT['polatisProductCode'],
    'polatisSerialNumber': POL_DICT['polatisSerialNumber'],
    'polatisFirmwareVersion': POL_DICT['polatisFirmwareVersion'],
    'polatisNetConfigIpAddress.1': POL_DICT['polatisNetConfigIpAddress.1'],
    'polatisNetConfigIpAddress.2': POL_DICT['polatisNetConfigIpAddress.2'],
    'polatisNetConfigGateway.1': POL_DICT['polatisNetConfigGateway.1'],
    'polatisNetConfigGateway.2': POL_DICT['polatisNetConfigGateway.2'],
    'polatisNetConfigSubnet.1': POL_DICT['polatisNetConfigSubnet.1'],
    'polatisNetConfigSubnet.2': POL_DICT['polatisNetConfigSubnet.2'],
    'polatisNetConfigBroadcast.1': POL_DICT['polatisNetConfigBroadcast.1'],
    'polatisNetConfigBroadcast.2': POL_DICT['polatisNetConfigBroadcast.2'],
    'polatisNetConfigAutoAddr.1': POL_DICT['polatisNetConfigAutoAddr.1'],
    'polatisNetConfigAutoAddr.2': POL_DICT['polatisNetConfigAutoAddr.2'],
    'polatisNetConfigStatus.1': '1',
    'polatisNetConfigStatus.2': '1',
    'PolatisInterfaceConfigProtocol': ['scpi', 'scpi', 'scpi', 'tl1', 'tl1'],
    'PolatisInterfaceConfigDevice': ['console', 'tcp:333', 'tcp:5025',
                                     'usbserial', 'tcp:3082'],
    'PolatisInterfaceConfigStatus': ['1', '1', '1', '1', '1'],
    'vacmGroupName.1.6.112.117.98.108.105.99': POL_DICT['vacmGroupName.1.6.112.117.98.108.105.99'], #vacmGroupName.1.\"public\"
    'vacmGroupName.1.7.112.114.105.118.97.116.101': POL_DICT['vacmGroupName.1.7.112.114.105.118.97.116.101'], #vacmGroupName.1.\"private\"
    'vacmGroupName.2.6.112.117.98.108.105.99': POL_DICT['vacmGroupName.2.6.112.117.98.108.105.99'], #vacmGroupName.2.\"public\"
    'vacmGroupName.2.7.112.114.105.118.97.116.101': POL_DICT['vacmGroupName.2.7.112.114.105.118.97.116.101'], # vacmGroupName.2.\"private\"
    'vacmGroupName.3.4.114.111.111.116': POL_DICT['vacmGroupName.3.4.114.111.111.116'], #vacmGroupName.3.\"root\"
    'vacmGroupName.3.8.112.114.105.118.114.111.111.116': POL_DICT['vacmGroupName.3.8.112.114.105.118.114.111.111.116'], #vacmGroupName.3.\"privroot\"

    'vacmSecurityToGroupStorageType.1.6.112.117.98.108.105.99': POL_DICT['vacmSecurityToGroupStorageType.1.6.112.117.98.108.105.99'], #.1.\"public\"
    'vacmSecurityToGroupStorageType.1.7.112.114.105.118.97.116.101': POL_DICT['vacmSecurityToGroupStorageType.1.7.112.114.105.118.97.116.101'], #.1.\"private\"
    'vacmSecurityToGroupStorageType.2.6.112.117.98.108.105.99': POL_DICT['vacmSecurityToGroupStorageType.2.6.112.117.98.108.105.99'], #.2.\"public\"
    'vacmSecurityToGroupStorageType.2.7.112.114.105.118.97.116.101': POL_DICT['vacmSecurityToGroupStorageType.2.7.112.114.105.118.97.116.101'], #2.\"private\"
    'vacmSecurityToGroupStorageType.3.4.114.111.111.116': POL_DICT['vacmSecurityToGroupStorageType.3.4.114.111.111.116'], #.3.\"root\"
    'vacmSecurityToGroupStorageType.3.8.112.114.105.118.114.111.111.116': POL_DICT['vacmSecurityToGroupStorageType.3.8.112.114.105.118.114.111.111.116'], #.3.\"privroot\"
    'vacmSecurityToGroupStatus.1.6.112.117.98.108.105.99': POL_DICT['vacmSecurityToGroupStatus.1.6.112.117.98.108.105.99'], #.1.\"public\"
    'vacmSecurityToGroupStatus.1.7.112.114.105.118.97.116.101': POL_DICT['vacmSecurityToGroupStatus.1.7.112.114.105.118.97.116.101'],#.1.\"private\"
    'vacmSecurityToGroupStatus.2.6.112.117.98.108.105.99': POL_DICT['vacmSecurityToGroupStatus.2.6.112.117.98.108.105.99'], #.2.\"public\"
    'vacmSecurityToGroupStatus.2.7.112.114.105.118.97.116.101': POL_DICT['vacmSecurityToGroupStatus.2.7.112.114.105.118.97.116.101'], #.2.\"private\"
    'vacmSecurityToGroupStatus.3.4.114.111.111.116': POL_DICT['vacmSecurityToGroupStatus.3.4.114.111.111.116'], #.3.\"root\"
    'vacmSecurityToGroupStatus.3.8.112.114.105.118.114.111.111.116': POL_DICT['vacmSecurityToGroupStatus.3.8.112.114.105.118.114.111.111.116']#.3.\"privroot\"
    }


class PolatisMibTables:
    """
    Performs SNMP Table Operation for Polatis Mib Tables
    """
    def __init__(self, host_addr, version=2, community='public', **kwargs):
        self.snmp_session = netsnmp.Session(DestHost=host_addr, Version=version,
                                            Community=community, **kwargs)

    netConfigTable = {
        'polatisNetConfigTable': {
            'polatisNetConfigIpAddress':
                '.1.3.6.1.4.1.26592.2.1.2.3.1.1.1.2',  # UNSIGNED32
            'polatisNetConfigGateway':
                '.1.3.6.1.4.1.26592.2.1.2.3.1.1.1.3',  # UNSIGNED32
            'polatisNetConfigSubnet':
                '.1.3.6.1.4.1.26592.2.1.2.3.1.1.1.4',  # UNSIGNED32
            'polatisNetConfigBroadcast':
                '.1.3.6.1.4.1.26592.2.1.2.3.1.1.1.5',  # UNSIGNED32
            'polatisNetConfigAutoAddr':
                '.1.3.6.1.4.1.26592.2.1.2.3.1.1.1.6',  # INTEGER-enable(1),
                                                       # disable(2)
            'polatisNetConfigStatus':
                '.1.3.6.1.4.1.26592.2.1.2.3.1.1.1.7'   # INTEGER-enable(1),
                                                       # disable(2)
                }
        }

    interfaceConfigTable = {
        'polatisInterfaceConfigTable': {
            'polatisInterfaceConfigProtocol':
                '.1.3.6.1.4.1.26592.2.1.2.3.2.1.1.2',  # UNSIGNED32
            'polatisInterfaceConfigDevice':
                '.1.3.6.1.4.1.26592.2.1.2.3.2.1.1.3',  # UNSIGNED32
            'polatisInterfaceConfigStatus':
                '.1.3.6.1.4.1.26592.2.1.2.3.2.1.1.4'  # INTEGER -enable(1),
                                                      # disable(2)
                }
        }

    oxcPortTable = {
        'polatisOxcPortTable': {
            'polatisOxcPortPatch':
                '.1.3.6.1.4.1.26592.2.2.2.1.2.1.2',  # UNSIGNED32
            'polatisOxcPortCurrentState':
                '.1.3.6.1.4.1.26592.2.2.2.1.2.1.3',  # INTEGER-enable(1),
                                                     # disable(2),failed(3)

            'polatisOxcPortDesiredState':
                '.1.3.6.1.4.1.26592.2.2.2.1.2.1.4'  # INTEGER-enabled(1),
                                                    # disabled(2)
            }
        }

    vacmSecToGrpTble = { 
        'vacmSecurityToGroupTable': {
            'vacmGroupName':
                '.1.3.6.1.6.3.16.1.2.1.3',
            'vacmSecurityToGroupStorageType':
                '.1.3.6.1.6.3.16.1.2.1.4',
            'vacmSecurityToGroupStatus':
                '.1.3.6.1.6.3.16.1.2.1.5'
            }
        }

    usmUsrTble = { 
        'usmUserTable': {
            'usmUserSecurityName' :
                '.1.3.6.1.6.3.15.1.2.2.2.2',
            'usmUserCloneFrom' : 
                '.1.3.6.1.6.3.15.1.2.2.1.4',
            'usmUserAuthProtocol' :
                '.1.3.6.1.6.3.15.1.2.2.1.5',
            'usmUserAuthKeyChange' :
                '.1.3.6.1.6.3.15.1.2.2.1.7',
            'usmUserOwnAuthKeyChange' :
                '.1.3.6.1.6.3.15.1.2.2.1.7',
            'usmUserPrivProtocol' :
                '.1.3.6.1.6.3.15.1.2.2.1.8',
            'usmUserPrivKeyChange' :
                '.1.3.6.1.6.3.15.1.2.2.1.9',
            'usmUserOwnPrivKeyChange' :
                '.1.3.6.1.6.3.15.1.2.2.1.10',
            'usmUserPublic' :
                '.1.3.6.1.6.3.15.1.2.2.1.11',
            'usmUserStorageType' :
                '.1.3.6.1.6.3.15.1.2.2.1.12',
            'usmUserStatus' :
                '.1.3.6.1.6.3.15.1.2.2.1.13',

                }
            }

    def snmp_table(self, oid_name):
        """ Performs the SNMP Retrieve Operation on the OID specified.
            Arguments:
                oid_name : OID to Perform SNMP Retrieve Operation.
        """
        polatisconfigdict = {}
        try:
            val = self.netConfigTable[oid_name]
        except KeyError:
            try:
                val = self.interfaceConfigTable[oid_name]
            except KeyError:
                try:
                    val = self.oxcPortTable[oid_name]
                except KeyError:
                    try:
                        val = self.vacmSecToGrpTble[oid_name]
                    except KeyError:
                        try:
                            val = self.usmUsrTble[oid_name]
                        except:
                            raise NameError("No Such OID Name Exist: %s " % oid_name)


        #print "val : ", val
        #print "length : ", len(val)
        for oid_key in val:
            #print "val : ", val
            oid = val[oid_key]
            oid = netsnmp.VarList(netsnmp.Varbind(oid))
            self.snmp_session.walk(oid)
            results = {}
            for result in oid:
                results['%s.%s' % (result.tag, result.iid)] = result.val
                #print "results : ", results
            polatisconfigdict.update(results)
        logger.info('snmp_table ...')

        logger.info('Output for snmp_table : %s \n' % polatisconfigdict)
        return polatisconfigdict


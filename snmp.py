""" SNMP Script that performs SNMP Get, SNMP GetNext, SNMP Walk, SNMP GetBulk
and SNMP Set Operations. Currently supports SNMPv1 and SNMPv2. 

"""
import logging

import netsnmp
import time
from snmp_get_set_tables import PolatisMibTables

pol_dict = eval(open("snmp_config.txt").read())

host_addr = pol_dict['destinationHost']
firmware_version = pol_dict['polatisFirmwareVersion']
community = pol_dict['community']
ver = pol_dict['version']
security_level = pol_dict['security_level']

logger = logging.getLogger('SnmpAgent')
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

logger.info('DestinationHostIpAddress : %s' % host_addr)
logger.info('FirmwareVersion : %s' % firmware_version)
logger.info('SnmpVersion : %s' % ver)
logger.info('Community : %s' % community)
logger.info('Testing Snmp Agent test cases...\n')

class Snmp(PolatisMibTables):
    """
    Snmp Class Performs Snmp Operations like get, getnext, walk, getbulk
    """
    def __init__(self, host_addr, version=2, community='public', **kwargs):
        """ Arguments 
            host_addr : IpAddress of the box to query.
            community : SNMP Community String.
            version   : SNMP Version.
        """
        PolatisMibTables.__init__(self, host_addr, version, community, **kwargs)
        self.snmp_session = netsnmp.Session(DestHost=host_addr, Version=version,
                                            Community=community, **kwargs)
        if ver == 3:
            logger.info('security_level : %s' % security_level)
	    #print "AuthPass: ", kwargs['AuthPass']
		
    def create_box(self, testcase_name):
        """create box for test case name.
        Arguments:
        testcase_name   :       valid testcase name
        """

        print "\n"
        l = len(testcase_name) + 7
        start_end_session = '       +' + (l * '-') + '+       '
        middle = '| ' + '   ' + str(testcase_name) + '  ' + ' |'

        #print '%s\n       %s\n%s\n\n' % (start_end_session, middle, start_end_session)
        logger.info('\n%s\n       %s\n%s\n\n' % (start_end_session, middle, start_end_session))

    def get_snmp_session(self):
        """
        Returns the Snmp Session
        """
        #logger.info("self.snmp_session", self.snmp_session)
        return self.snmp_session

    def snmp_walk(self, oid_to_get):
        """
        Performs SNMP Walk on the OID Specified.
        :param oid_to_get: OID
        :rtype: dict
        """
        try:
            logger.info('Performing SNMP WALK for %s' % oid_to_get)
            oid = netsnmp.VarList(netsnmp.Varbind(oid_to_get))
            #logger.info('oid : %s' % oid)
            self.snmp_session.walk(oid)
            results = {}
            for result in oid:
                #logger.info('result : %s' % result)
                results['%s.%s' % (result.tag, result.iid)] = result.val
                #logger.info(result.tag)
                #logger.info(result.iid)
                #logger.info(result.val)
            logger.info('Output for SNMP WALK: %s' % results)
            return results
        except BaseException as err:
            logger.info("Snmp Walk Error: %s\n" % err)
            raise Exception("Snmp Walk Error: %s\n" % err)

    def snmp_get(self, oid_to_get):
        """
        Performs SNMP Get on the OID Specified.
        :param oid_to_get: OID
        :rtype: dict
        """
        try:
            logger.info('Performing SNMP GET for %s' % oid_to_get)
            oid = netsnmp.VarList(netsnmp.Varbind(oid_to_get))
            self.snmp_session.get(oid)
            results = {}
            for result in oid:
                results['%s.%s' % (result.tag, result.iid)] = result.val
            logger.info('Output for SNMP GET : %s\n' % results)
            return results
        except Exception as err:
            logger.info("Snmp Get Error: %s\n" % err)
            raise Exception("Snmp Get Error: %s" % err)

    def snmp_get_next(self, oid_to_get):
        """
        Performs SNMP Get Next on the OID Specified.
        :param oid_to_get: OID
        :rtype: dict
        """
        try:
            logger.info('Performing SNMP GET NEXT for %s' % oid_to_get)
            oid = netsnmp.VarList(netsnmp.Varbind(oid_to_get))
            self.snmp_session.getnext(oid)
            results = {}
            for result in oid:
                results['%s.%s' % (result.tag, result.iid)] = result.val
            logger.info('Output for SNMP GET NEXT : %s\n' % results)
            return results
        except BaseException as err:
            logger.info("Snmp GetNext Error: %s\n" % err)
            raise Exception("Snmp GetNext Error: %s" % err)

    def snmp_get_bulk(self, oid_to_get, start_index=0, stop_index=10):
        """
        Performs SNMP Get Bulk Operation.
        :param start_index: Index to Start With
        :param stop_index: Index to End
        :param oid_to_get: OID
        :rtype: dict
        """
        try:
            logger.info('Performing SNMP GET BULK for %s' % oid_to_get)
            oid = netsnmp.VarList(netsnmp.Varbind(oid_to_get))
            self.snmp_session.getbulk(start_index, stop_index, oid)
            results = {}
            for result in oid:
                results['%s.%s' % (result.tag, result.iid)] = result.val
            logger.info('Output for SNMP GET BULK: %s\n' % results)
            return results
        except BaseException as err:
            logger.info("Snmp GetBulk Error: %s\n" % err)
            raise Exception("Snmp GetBulk Error: %s" % err)

    def snmp_set(self, oid_to_set, value_to_set, datatype):
        """
        Performs SNMP Set Operation on the OID specified
        :param datatype: Data type of value
        :param value_to_set: value
        :param oid_to_set: OID
        :rtype: dict
        """
        try:
            logger.info('Performing SNMP SET for %s' % oid_to_set)
            logger.info('value_to_set %s' % value_to_set)
            logger.info('datatype %s' % datatype)
            oid_value = oid_to_set.split('.')
            oid = netsnmp.VarList(netsnmp.Varbind(oid_value[0], oid_value[1],
                                                  value_to_set, datatype))
            value = self.snmp_session.set(oid)
            time.sleep(2)
            logger.info('Output for SNMP SET : %s\n' % value)
            return value
        except BaseException as err:
            logger.info("Snmp Set Error: %s\n" % err)
            raise Exception("Snmp Set Error: %s" % err)

    def do_snmp_operations(self, oid_to_get, action):
        """
        Performs SNMP Get, SNMP Walk and SNMP GetNext Operations on the OID Specified.
        :param oid_to_get: OID
        :type action: Action to be carried out. Valid actions are get,walk and getnext.
        """

        oid = netsnmp.VarList(netsnmp.Varbind(oid_to_get))
        snmp_action = {
            'get': self.snmp_session.get,
            'walk': self.snmp_session.walk,
            'getnext': self.snmp_session.getnext
        }
        snmp_action[action](oid)
        results = {}
        for result in oid:
            results['%s.%s' % (result.tag, result.iid)] = result.val
        logger.info('Output for DO SNMP OPERATIONS: %s\n' % results)
        return results


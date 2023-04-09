from pyzabbix import ZabbixAPI, ZabbixAPIException
import sys
import click
import ast

@click.command()
@click.option('--url', '-u', required=True, type=str, help='Zabbix JSON API url')
@click.option('--user', required=True, type=str, help='Zabbix username')
@click.option('--passw', required=True, type=str, help='Zabbix password')
@click.option('--host', required=True, type=str, help='Hostname')
@click.option('--command', required=True, type=str, help='Command to execute')
def main(url, user, passw, host, command):
    try:
        zapi = ZabbixAPI(url)
        zapi.login(user, passw)
        hosts = zapi.host.get(filter={"host": host}, selectInterfaces=["interfaceid"])
        if hosts:
            host_id = hosts[0]["hostid"]
            interfaceid, = hosts[0]["interfaces"][0]['interfaceid'],
            item = zapi.item.create(
                hostid=host_id,
                name='zaebbix',
                key_='system.run[{0},nowait]'.format(command),
                type=0,
                value_type=3,
                interfaceid=interfaceid,
                delay=30
            )
            print("Added item with itemid {0} to host: {1}".format(item["itemids"][0], host))
        else:
            print("No such host")
    except Exception as e:
        print(e)

if __name__ == '__main__':
    main()

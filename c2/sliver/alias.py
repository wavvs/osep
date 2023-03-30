import click
import os
import json
import shutil

config = {
    "name": "",
    "version": "0.0.0",
    "command_name": "",
    "original_author": "",
    "repo_url": "",
    "help": "",

    "entrypoint": "Main",
    "allow_args": True,
    "default_args": "",
    "is_reflective": False,
    "is_assembly": True,
    "files": [
    ]
}

@click.command()
@click.option('--input', '-i', type=click.Path(exists=True), help="Input directory with artifacts")
@click.option('--output', '-o', type=click.Path(exists=False), help="Output directory")
@click.option('--arch', '-a', type=click.Choice(['64', '86', 'any']))
@click.option('--suffix', '-s', default=None, type=str)
def cli(input, output, arch, suffix):
    """Generate JSON configuration for sliver alias"""
    if not os.path.exists(output):
        os.mkdir(output)

    for path in os.listdir(input):
        if os.path.isfile(os.path.join(input, path)):
            name = os.path.splitext(path)[0].lower() + '-' + arch
            if suffix is not None:
                name = name + '-' + suffix
            config['name'] = name
            config['command_name'] = name
            config['original_author'] = name
            config['repo_url'] = name
            config['help'] = name
            if arch == 'any':
                config['files'] = [
                    {
                        "os": "windows",
                        "arch": "amd64",
                        "path": path
                    },
                    {
                        "os": "windows",
                        "arch": "386",
                        "path": path
                    }
                ]
            elif arch == '64':
                config['files'] = [
                    {
                        "os": "windows",
                        "arch": "amd64",
                        "path": path
                    }
                ]
            elif arch == '86':
                config['files'] = [
                    {
                        "os": "windows",
                        "arch": "386",
                        "path": path
                    }
                ]

            config_json = json.dumps(config)
            artifact_dir = os.path.join(output, name) 
            os.mkdir(artifact_dir)
            with open(os.path.join(artifact_dir, 'alias.json'), 'w') as f:
                f.write(config_json)
            
            shutil.copyfile(os.path.join(input, path), os.path.join(artifact_dir, path))


if __name__ == '__main__':
    cli()
import os
import sys

if __name__ == '__main__':
    project_name = sys.argv[1]
    dir_path = sys.argv[2]
    if os.path.isdir(dir_path):
        project_path = os.path.join(dir_path, project_name)
        os.makedirs(project_path)
        paths = ['admin', 'recon', 'targets', 'screenshots', 'payloads', 'logs']
        for path in paths:
            os.makedirs(os.path.join(project_path, path))
        readme = os.path.join(project_path, 'README.md')
        open(readme, 'w').close()
    else:
        sys.exit('Not a directory')
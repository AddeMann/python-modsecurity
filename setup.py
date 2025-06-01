from typing import Any

from Cython.Build import cythonize
from Cython.Compiler.AutoDocTransforms import EmbedSignature
from setuptools import Extension, find_packages, setup

import os, sys, shutil, re
import platform

__version__ = '1.0'

msc_dir = 'modsecurity'

from setuptools import Command

_NO_EXECUTABLE = 0

class Commands(Command):
    def run(self) -> None:
        global _NO_EXECUTABLE
        _NO_EXECUTABLE += 1
def _copy_libraries(library_dir: str):
    if not os.path.exists('modsecurity/lib'):
        os.mkdir('modsecurity/lib')
    _library_dir = 'modsecurity/lib'
    if not os.path.exists(_library_dir):
        os.mkdir(_library_dir)
        
    for file in os.listdir(library_dir):
        if file.startswith('libModSecurity'):
            shutil.copy2(os.path.join(library_dir, file), _library_dir)
            
    return _library_dir
def _get_executable(library_dir: str) -> dict[str, str]:
    executable = {}
    if sys.platform == 'win32':
        type = '.exe'
    else:
        type = ''
    for file in os.listdir(library_dir):
        print(file)
        if file.endswith(type):
            executable[file.split('.')[0] if '.' in file else file] = os.path.join(library_dir, file)
    return executable
    
class CompilerDirectories(dict[str, Any]):
    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)
    def __setattr__(self, name, value) -> None:
        self[name] = value
        
    def append_to_dir(self, name: str, value: Any) -> None:
        if name in self:
            assert isinstance(self[name], list)
            self[name].append(value)
if sys.platform == 'win32':

    def _get_compiler_dirs():
        def iter_envs():
            for environ in os.environ:
                for path in os.environ[environ].split(os.pathsep):
                    yield path
        def find_env_library():
            pattern = r'build\\win32\\build\\Release'
            for path in iter_envs():
                path = os.path.join(path, 'build', 'win32', 'build', 'Release')
                print(path)
                if os.path.exists(path) and 'libModSecurity.dll' in os.listdir(path):
                    
                    if _NO_EXECUTABLE == 1:
                        executable = {}
                    else:
                        executable = _get_executable(path)
                    path = _copy_libraries(path)
                    return [path], executable
                else:
                    continue
            return [], {}
                    
        def find_env_include_dir() -> list[str]:
            for path in iter_envs():
                path = os.path.join(path, 'headers')
                if os.path.exists(path) and os.path.isfile(os.path.join(path, 'modsecurity', 'modsecurity.h')):
                    return [path]
                else:
                    continue
            return []
        library_dirs, executable = find_env_library()
        include_dirs = find_env_include_dir()
        assert len(library_dirs) != 0 and len(include_dirs) != 0
        library = 'libmodsecurity'
        return dict(
            include_dirs=include_dirs, 
            library_dirs=library_dirs,
            library=library, 
            executable=executable
        )
    compiler_dirs = CompilerDirectories(_get_compiler_dirs())
else:
    def _get_compiler_dirs():
        _compiler_dirs = dict()
        root_path = '/usr/local/modsecurity'
        library = 'libmodsecurity'
        if os.path.exists(root_path):
            library_dir = os.path.join(root_path, 'lib')
            include_dir = os.path.join(root_path, 'include')
            executable = os.path.join(root_path, 'bin')
            
            if os.path.exists(library_dir) and os.path.islink(os.path.join(library_dir, library + '.so')):
                library_dirs = [library_dir]
                _compiler_dirs.update(library_dirs=library_dirs, library=library)
            else:
                raise OSError(f'Could not find library: {library_dirs}/libmodsecurity.so')
            
            if os.path.exists(include_dir) and os.path.isfile(os.path.join(include_dir, 'modsecurity/modsecurity.h')):
                include_dirs = [include_dir]
                _compiler_dirs.update(include_dirs=include_dirs)
            else:
                raise OSError(f'Could not find include directory: {include_dirs}')
            
            if os.path.exists(executable) and os.path.isfile(os.path.join(executable, 'modsec-rules-check')):
                _compiler_dirs.update(executable=_get_executable(executable))
            else:
                raise OSError(f'Could not find bin directory: {executable}')
        return _compiler_dirs
    
    compiler_dirs = CompilerDirectories(_get_compiler_dirs())
    
compiler_dirs.append_to_dir('include_dirs', 'modsecurity/include')
sources = ['modsecurity/modsecurity.pyx']

_cython_source_file = Extension(
        'modsecurity.modsecurity', sources=sources, 
        include_dirs=compiler_dirs.include_dirs, 
        library_dirs=compiler_dirs.library_dirs,
        libraries=[compiler_dirs.library],
        language="c++"
    )

cython_ext_modules = cythonize(
    _cython_source_file,
    build_dir="build",
    compiler_directives={
        "c_string_type": "str",
        "c_string_encoding": "ascii",
        'language_level': 3,
    },
    include_path=["modsecurity/include"]
)

packages = [msc_dir, os.path.join(msc_dir, 'lib')]
package_data = {
    msc_dir: ['*.pyi', '*.typed'],
    os.path.join(msc_dir, 'lib'): ['*.dll' if platform.system() == 'Windows' else '*.so']
}

def _copy_executable_files(executable: dict[str, str]):
    _executable = 'modsecurity/bin'
    if not os.path.exists(_executable):
        os.mkdir(_executable)
        
    for fname, file in executable.items():
        shutil.copy2(file, os.path.join(_executable, fname + '.exe'))
        
    packages.append(_executable)
    package_data[_executable] = ['*.exe'] if sys.platform == 'win32' else ['*']

if _NO_EXECUTABLE == 0:
    _copy_executable_files(compiler_dirs.executable)

setup(
    name='python-modsecurity',
    version=__version__,
    description='Python bindings for libModSecurity C++ Library.',
    #long_description=open('README.md', 'r').read(),
    packages=packages,
    package_data=package_data,
    include_package_data=True,
    zip_safe=False,
    ext_modules=cython_ext_modules,
    cmdclass={'executable': Commands}
)
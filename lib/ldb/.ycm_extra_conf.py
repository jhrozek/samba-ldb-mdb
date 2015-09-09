# This file is NOT licensed under the GPLv3, which is the license for the rest
# of Samba.
#
# Here's the license text for this file:
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
# For more information, please refer to <http://unlicense.org/>

import os
import ycm_core

flags = [
'-Wall',
'-Wextra',
'-Werror',
'-Wno-unused-parameter',
# This is a C project
'-x', 'c',
# Defines
'-DCONFIG_H_IS_FROM_SAMBA=1',
'-DHAVE_CONFIG_H=1',
'-D_SAMBA_BUILD_=4',
'-DAD_DC_BUILD_IS_ENABLED=1',
'-D_GNU_SOURCE=1',
'-DHAVE_IPV6=1',
# Includes
'-I.',
'-Iauth',
'-Iauth/gensec',
'-Iauth/credentials',
'-Iauth/kerberos',
'-Iauth/ntlmssp',
'-Idfs_server',
'-Idynconfig',
'-Iinclude',
'-Iinclude/public',
'-Ilib/addns',
'-Ilib/ccan',
'-Ilib/async_req',
'-Ilib/compression',
'-Ilib/crypto',
'-Ilib/dbwrap',
'-Isource3',
'-Isource3/auth',
'-Isource3/include',
'-Isource3/lib',
'-Isource3/lib/asys',
'-Isource3/lib/pthreadpool',
'-Isource3/librpc',
'-Isource3/modules',
'-Isource3/passdb',
'-Isource3/rpc_server',
'-Ilib/ldb/include',
'-Ilib/ldb-samba',
'-Ilib/ldb',
'-Ilib/krb5_wrap',
'-Ilib/param',
'-Ilib/replace',
'-Ilib/smbconf',
'-Ilib/socket',
'-Ilib/talloc',
'-Ilib/tdb',
'-Ilib/tdb/include',
'-Ilib/tdb_compat',
'-Ilib/tevent',
'-Ilib/tsocket',
'-Ilib/util/charset',
'-Ilibcli/auth',
'-Ilibcli/cldap',
'-Ilibcli/dns',
'-Ilibcli/drsuapi',
'-Ilibcli/ldap',
'-Ilibcli/lsarpc',
'-Ilibcli/named_pipe_auth',
'-Ilibcli/nbt',
'-Ilibcli/netlogon',
# Generated headers
'-Ibin/default',
'-Ibin/default/auth',
'-Ibin/default/auth/credentials',
'-Ibin/default/auth/gensec',
'-Ibin/default/auth/kerberos',
'-Ibin/default/auth/ntlmssp',
'-Ibin/default/include',
'-Ibin/default/dfs_server',
'-Ibin/default/dynconfig',
'-Ibin/default/include/public',
'-Ibin/default/lib',
'-Ibin/default/lib/crypto',
'-Ibin/default/lib/ldb/include',
'-Ibin/default/lib/param',
'-Ibin/default/lib/replace',
'-Ibin/default/lib/smbconf',
'-Ibin/default/lib/socket',
'-Ibin/default/lib/talloc',
'-Ibin/default/lib/tdb',
'-Ibin/default/lib/tdb/include',
'-Ibin/default/lib/tdb_compat',
'-Ibin/default/lib/tevent',
'-Ibin/default/lib/tsocket',
'-Ibin/default/lib/util/charset',
'-Ibin/default/libcli/auth',
'-Ibin/default/libcli/cldap',
'-Ibin/default/libcli/dns',
'-Ibin/default/libcli/drsuapi',
'-Ibin/default/libcli/ldap',
'-Ibin/default/libcli/lsarpc',
'-Ibin/default/libcli/named_pipe_auth',
'-Ibin/default/libcli/nbt',
'-Ibin/default/libcli/netlogon', '-Ilibcli/netlogon',
'-Ibin/default/libcli/registry', '-Ilibcli/registry',
'-Ibin/default/libcli/security', '-Ilibcli/security',
'-Ibin/default/libcli/smb', '-Ilibcli/smb',
'-Ibin/default/libcli/util', '-Ilibcli/util',
'-Ibin/default/libds/common', '-Ilibds/common',
'-Ibin/default/librpc', '-Ilibrpc',
'-Ibin/default/nsswitch', '-Insswitch',
'-Ibin/default/nsswitch/libwbclient', '-Insswitch/libwbclient',
'-Ibin/default/source3',
'-Ibin/default/source3/auth',
'-Ibin/default/source3/include',
'-Ibin/default/source3/lib',
'-Ibin/default/source3/lib/asys',
'-Ibin/default/source3/lib/pthreadpool',
'-Ibin/default/source3/librpc',
'-Ibin/default/source3/modules',
'-Ibin/default/source3/passdb',
'-Ibin/default/source3/rpc_server',
'-Ibin/default/source4',
'-Isource4',
'-Isource4/auth',
'-Isource4/auth/gensec',
'-Isource4/auth/kerberos',
'-Isource4/dsdb',
'-Isource4/heimdal/base',
'-Isource4/heimdal/include',
'-Isource4/heimdal/lib',
'-Ibin/default/source4/auth',
'-Ibin/default/source4/auth/gensec',
'-Ibin/default/source4/heimdal/base',
'-Ibin/default/source4/heimdal/include',
'-Ibin/default/source4/heimdal/lib',
'-Ibin/default/source4/dsdb',
'-Ibin/default/source4/auth/kerberos',
'-Ibin/default/source4/heimdal/lib/asn1',
'-Ibin/default/source4/heimdal/lib/asn1', '-Isource4/heimdal/lib/asn1',
'-Ibin/default/source4/heimdal/lib/com_err', '-Isource4/heimdal/lib/com_err',
'-Ibin/default/source4/heimdal/lib/gssapi', '-Isource4/heimdal/lib/gssapi',
'-Ibin/default/source4/heimdal/lib/gssapi/gssapi', '-Isource4/heimdal/lib/gssapi/gssapi',
'-Ibin/default/source4/heimdal/lib/gssapi/krb5', '-Isource4/heimdal/lib/gssapi/krb5',
'-Ibin/default/source4/heimdal/lib/gssapi/mech', '-Isource4/heimdal/lib/gssapi/mech',
'-Ibin/default/source4/heimdal/lib/gssapi/spnego', '-Isource4/heimdal/lib/gssapi/spnego',
'-Ibin/default/source4/heimdal/lib/hcrypto', '-Isource4/heimdal/lib/hcrypto',
'-Ibin/default/source4/heimdal/lib/hcrypto/libtommath', '-Isource4/heimdal/lib/hcrypto/libtommath',
'-Ibin/default/source4/heimdal/lib/hx509', '-Isource4/heimdal/lib/hx509',
'-Ibin/default/source4/heimdal/lib/krb5', '-Isource4/heimdal/lib/krb5',
'-Ibin/default/source4/heimdal/lib/roken', '-Isource4/heimdal/lib/roken',
'-Ibin/default/source4/heimdal/lib/wind', '-Isource4/heimdal/lib/wind',
'-Ibin/default/source4/heimdal_build', '-Isource4/heimdal_build',
'-Ibin/default/source4/include', '-Isource4/include',
'-Ibin/default/source4/lib', '-Isource4/lib',
'-Ibin/default/source4/lib/events', '-Isource4/lib/events',
'-Ibin/default/source4/lib/socket', '-Isource4/lib/socket',
'-Ibin/default/source4/lib/stream', '-Isource4/lib/stream',
'-Ibin/default/source4/lib/tls', '-Isource4/lib/tls',
'-Ibin/default/source4/libcli', '-Isource4/libcli',
'-Ibin/default/source4/libcli/ldap', '-Isource4/libcli/ldap',
'-Ibin/default/source4/param', '-Isource4/param',
'-Ibin/default/source4/winbind', '-Isource4/winbind',
]

# Set this to the absolute path to the folder (NOT the file!) containing the
# compile_commands.json file to use that instead of 'flags'. See here for
# more details: http://clang.llvm.org/docs/JSONCompilationDatabase.html
#
# Most projects will NOT need to set this to anything; you can just change the
# 'flags' list of compilation flags. Notice that YCM itself uses that approach.
compilation_database_folder = ''

if os.path.exists( compilation_database_folder ):
  database = ycm_core.CompilationDatabase( compilation_database_folder )
else:
  database = None

SOURCE_EXTENSIONS = [ '.cpp', '.cxx', '.cc', '.c', '.m', '.mm' ]

def DirectoryOfThisScript():
  return os.path.dirname( os.path.abspath( __file__ ) )


def MakeRelativePathsInFlagsAbsolute( flags, working_directory ):
  if not working_directory:
    return list( flags )
  new_flags = []
  make_next_absolute = False
  path_flags = [ '-isystem', '-I', '-iquote', '--sysroot=' ]
  for flag in flags:
    new_flag = flag

    if make_next_absolute:
      make_next_absolute = False
      if not flag.startswith( '/' ):
        new_flag = os.path.join( working_directory, flag )

    for path_flag in path_flags:
      if flag == path_flag:
        make_next_absolute = True
        break

      if flag.startswith( path_flag ):
        path = flag[ len( path_flag ): ]
        new_flag = path_flag + os.path.join( working_directory, path )
        break

    if new_flag:
      new_flags.append( new_flag )
  return new_flags


def IsHeaderFile( filename ):
  extension = os.path.splitext( filename )[ 1 ]
  return extension in [ '.h', '.hxx', '.hpp', '.hh' ]


def GetCompilationInfoForFile( filename ):
  # The compilation_commands.json file generated by CMake does not have entries
  # for header files. So we do our best by asking the db for flags for a
  # corresponding source file, if any. If one exists, the flags for that file
  # should be good enough.
  if IsHeaderFile( filename ):
    basename = os.path.splitext( filename )[ 0 ]
    for extension in SOURCE_EXTENSIONS:
      replacement_file = basename + extension
      if os.path.exists( replacement_file ):
        compilation_info = database.GetCompilationInfoForFile(
          replacement_file )
        if compilation_info.compiler_flags_:
          return compilation_info
    return None
  return database.GetCompilationInfoForFile( filename )


def FlagsForFile( filename, **kwargs ):
  if database:
    # Bear in mind that compilation_info.compiler_flags_ does NOT return a
    # python list, but a "list-like" StringVec object
    compilation_info = GetCompilationInfoForFile( filename )
    if not compilation_info:
      return None

    final_flags = MakeRelativePathsInFlagsAbsolute(
      compilation_info.compiler_flags_,
      compilation_info.compiler_working_dir_ )
  else:
    relative_to = DirectoryOfThisScript()
    final_flags = MakeRelativePathsInFlagsAbsolute( flags, relative_to )

  return {
    'flags': final_flags,
    'do_cache': True
  }

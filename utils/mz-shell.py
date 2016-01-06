#!/usr/bin/env python
#coding: utf8

# (c) 2014, Nandor Sivok <dominis@haxor.hu>
#
# ansible-shell is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ansible-shell is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#
#
# ansible-shell is an interactive shell for ansible
# with built-in tab completion for all the documented modules
#
# Available commands:
#  cd - change host/group (you can use host patterns eg.: app*.dc*:!app01*)
#  list - list available hosts in the current path
#  forks - change fork
#  become - become
#  ! - forces shell module instead of the ansible module (!yum update -y)
#
# Configuration:
# create a [ansible-shell] section in your ansbile.cfg
#  cwd=app-servers - you can set your default host pattern
#  forks=100 - default forks

import sys
try:
    import ansible 
except Exception as e:
    sys.exit("please install ansible \n pip install ansible")

try:
    import urllib2 
except Exception as e:
    sys.exit("please install urllib2 \n pip install urllib2")

try:
    import simplejson as json
except Exception as e:
    sys.exit("please install simplejson \n pip install simplejson")

#import simplejson as json
#import urllib2
#import ansible

import cmd
import ansible.runner
from ansible.color import stringc, codeCodes
import ansible.constants as C
from ansible import utils
from ansible import callbacks
from ansible.inventory import Inventory, Host
import ansible.utils.module_docs as module_docs
import os
import readline
import atexit
import re
import signal
import time

def log(args):
    user = os.getlogin()
    now = time.strftime('%Y-%m-%d %T',time.localtime(time.time()))
    historyfile = '/var/log/record.log'
    output = open(historyfile,'a+')
    log = '%s ##### %s pts/0 (sl.meizu.mz)  #### uid=%s(%s) #### %s %s /usr/sbin/mz-shell args %s\n'% \
          (now,user,os.getuid(),user,now,user,args)
    output.write(log)
    output.close()

class colorizer(object):
    def __init__(self, color):
        self.color = color

    def __enter__(self):
        sys.stdout.write("\033[")
        sys.stdout.write(codeCodes[self.color])
        sys.stdout.write("m")

    def __exit__(self, *args):
        sys.stdout.write("\033[0m")


class AnsibleShell(cmd.Cmd):

    modules = []

    def __init__(self, options, args):
        self.options = options
        self.options.cwd = '*'
        self.ssh_password, self.become_password, self.vault_password = self.load_passwords()

        self.user = os.getlogin()
        self.homedir = '/home/' + self.user
        #create .hosts
        self.options.inventory = self.get_user_host_from_cmdb()
        self.options.private_key_file = self.get_private_key_file()

        self.ansible = ansible.runner.Runner(
            inventory=Inventory(self.options.inventory,
                                vault_password=self.vault_password),
            vault_pass=self.vault_password,
        )
        self.groups = self.ansible.inventory.groups_list().keys()
        self.hosts = self.ansible.inventory.groups_list()['all']
        self.callbacks = callbacks.CliRunnerCallbacks()
        self.read_config_file()
        self.intro = '''
                     Welcome to the mz-shell.\n
                     查看能管理的机器组列表 \n
                     \t\t list groups \n
                     查看某组的ip列表 list 组名 \n
                     \t\t list GZ-YG)\n
                     选中某批机器 以便批量执行 \n
                     \t\t cd 组名(例如 cd GZ-YG)\n
                     \t\t 支持正则处理 \n
                     \t\t\t例如选择广州的sync业务的jetty (cd *GZ&*sync&*jetty)\n
                     执行shell命令 \n
                     \t\t ps aux | grep java | wc -l
                     '''
        self.set_prompt()
        self.modules = set(['shell','raw'])#self.list_modules()
        #self.modules.remove('shell')
        for module in self.modules:
            setattr(self, 'do_' + module, lambda arg, module=module: self.default(module + ' ' + arg))
            setattr(self, 'help_' + module, lambda module=module: self.helpdefault(module))
        cmd.Cmd.__init__(self)

    def get_user_host_from_cmdb(self):
        hostfile = self.homedir + '/.hosts'
        if not os.path.exists(hostfile):
            output = open(hostfile,'w')
            output.close()
        host_url = 'http://***.***.***.***/get_hosts_by_user'
        req = urllib2.Request(host_url + '/' + self.user)
        response_stream = urllib2.urlopen(req)
        res = response_stream.read()
        if not res:
            return hostfile
        res = json.loads(res)
        result = {}
        for i in res.get('values'):
            datacenter_dict = res.get('values').get(i)
            key1 = i+':children'
            for j in datacenter_dict:
                if key1 in result:
                    result[key1].append(i+'->'+j)
                else:
                    result[key1]=[i+'->'+j]
                business_dict = datacenter_dict.get(j)
                key2 = i+'->'+j+':children'
                for k in business_dict:
                    if key2 in result:
                        result[key2].append(i+'->'+j+'->'+k)
                    else:
                        result[key2]=[i+'->'+j+'->'+k]
                    container_dict = business_dict.get(k)
                    key3 = i+'->'+j+'->'+k+':children'
                    for l in container_dict:
                        l.replace(u'[','')
                        l.replace(u']','')
                        if container_dict.get(l) == []:
                                continue
                        if key3 in result:
                            result[key3].append(i+'->'+j+'->'+k+'->'+l)
                        else:
                            result[key3]=[i+'->'+j+'->'+k+'->'+l]
                        result[i+'->'+j+'->'+k+'->'+l] = container_dict.get(l)
	    output = open(hostfile,'w')
        try:
            for i in result:
                output.write('['+i+']\n')
                output.write('\n'.join(result[i]))
                output.write('\n\n')
        except Exception as e:
            print e
        finally:
            output.close()
        os.system("chmod 644 %s"%hostfile)
        return hostfile

    def get_private_key_file(self):
        return self.homedir + "/.ssh/id_rsa_new"

    def load_passwords(self):
        return utils.ask_passwords(
                self.options.ask_pass,
                self.options.become_ask_pass,
                self.options.ask_vault_pass
                )

    def read_config_file(self):
        allowed_items = {
            # name: type
            'cwd': 'str',
            'forks': 'int',
        }
        config = C.load_config_file()
        if config is not None and config.has_section('ansible-shell'):
            for item in config.items('ansible-shell'):
                if item[0] in allowed_items.keys():
                    value = vars(__builtins__)[allowed_items[item[0]]](item[1])
                    setattr(self.options, item[0], value)

    @staticmethod
    def parse_opts():
        parser = utils.base_parser(
            constants=C,
            runas_opts=True,
            subset_opts=True,
            async_opts=True,
            output_opts=True,
            connect_opts=True,
            check_opts=True,
            diff_opts=False,
            usage='%prog <host-pattern> [options]'
        )

        parser.add_option('-p', '--step', default=False, action="store_true",
                          dest='step',
                          help='one-step-at-a-time: confirm each task before running')

        return parser.parse_args()

    def get_names(self):
        return dir(self)

    def cmdloop(self):
        try:
            cmd.Cmd.cmdloop(self)
        except KeyboardInterrupt:
            self.do_exit(self)

    def set_prompt(self):
        self.selected = self.ansible.inventory.list_hosts(self.options.cwd)
        self.prompt = '\033[0;32;1m%s\033[0m @ \033[0;31;1m(%s)\033[0m (%d machines)$' % (self.options.remote_user, self.options.cwd, len(self.selected))

    def list_modules(self):
        modules = set()
        module_paths = ansible.utils.plugins.module_finder._get_paths()
        for path in module_paths:
            if path is not None:
                modules.update(self._find_modules_in_path(path))

        return modules

    def _find_modules_in_path(self, path):
        """Generate a list of potential modules in a given path"""
        for root, dirs, files in os.walk(path):
            for basename in files:
                module_name = basename.split('.')[0]
                ext = basename.split('.')[-1] if '.' in basename else None
                if not module_name.startswith('_') and \
                   ext in ('py', 'ps1', None) and \
                   module_name in utils.plugins.module_finder:
                    yield module_name

    def confirm(self, module, module_args):
        if not self.options.step:
            return True

        # print hosts
        callbacks.display("HOSTS:","bright blue")
        for host in self.selected:
            hostname = host.name if isinstance(host, Host) else host
            callbacks.display("\t%s" % hostname,"green")

        callbacks.display("\nSUMMARY: host_num[%d] module[%s] module_args[%s] options[%s]\n" % (len(self.selected), module, module_args, self.options),"bright blue")

        answer=False
        try:
            print "Do you confirm to execute?[y/N]:(default=No) ",
            # cmd module use raw_input to read user command by default, to avoid our answer here 'logged' into history,
            # use sys.stdin.readline instead of raw_input, see more at http://docs.python.org/2/library/cmd.html#cmd.Cmd.use_rawinput
            answer = sys.stdin.readline()[:-1]
        except:
            answer = False
        return utils.boolean(answer)

    def default(self, arg, forceshell=True):
        if arg.startswith("#"):
            return False

        if not self.options.cwd:
            print u'没有匹配到机器 请重新选择\n'
            return False

        if arg.split()[0] in self.modules:
            module = arg.split()[0]
            module_args = ' '.join(arg.split()[1:])
        else:
            module = 'shell'
            module_args = arg

        if forceshell is True:
            module = 'shell'
            module_args = arg

            log(arg)

        if not self.confirm(module, module_args):
            callbacks.display("Command canceled by user")
            return

        self.options.module_name = module
        self.callbacks.options = self.options

        try:
            results = ansible.runner.Runner(
                pattern=self.options.cwd,
                module_name=module,
                module_args=module_args,
                remote_user=self.options.remote_user,
                timeout=self.options.timeout,
                private_key_file=self.options.private_key_file,
                forks=self.options.forks,
                become=self.options.become,
                become_user=self.options.become_user,
                become_pass=self.become_password,
                become_method=self.options.become_method,
                transport=self.options.connection,
                subset=self.options.subset,
                check=self.options.check,
                diff=self.options.check,
                callbacks=self.callbacks,
                inventory=self.ansible.inventory,
                vault_pass=self.vault_password,
            ).run()
            if results is None:
                print "No hosts found"
                return False
        except Exception as e:
            print unicode(e)
            return False

    def emptyline(self):
        return

    def do_shell(self, arg):
        """
        You can run shell commands through the shell module.

        eg.:
        shell ps uax | grep java | wc -l
        shell killall python
        shell halt -n

        You can use the ! to force the shell module. eg.:
        !ps aux | grep java | wc -l
        """
        self.default(arg, True)

    def do_forks(self, arg):
        """Set the number of forks"""
        if not arg:
            print 'Usage: forks <number>'
            return
        self.options.forks = int(arg)
        self.set_prompt()

    #do_serial = do_forks

    def do_cd(self, arg):
        """
            Change active host/group. You can use hosts patterns as well eg.:
            cd webservers
            cd webservers:dbservers
            cd webservers:!phoenix
            cd webservers:&staging
            cd webservers:dbservers:&staging:!phoenix
        """
        if not arg:
            self.options.cwd = '*'
        elif arg == '..':
            try:
                self.options.cwd = self.ansible.inventory.groups_for_host(self.options.cwd)[1].name
            except Exception:
                self.options.cwd = ''
        elif arg == '/':
            self.options.cwd = 'all'
        elif self.ansible.inventory.get_hosts(arg):
            """如果是ip 直接ssh登录到对应机器
            """
            # if checkip(arg):
            #     res = os.popen('ssh -i %s %s -p 16120' %(self.get_private_key_file(),arg)).read()
            #     print res
            # else:
            #     self.options.cwd = arg
            self.options.cwd = arg
        else:
            print "no host matched"
        log(arg)
        self.set_prompt()

    def do_list(self, arg):
        """List the hosts in the current group"""
        if arg == 'groups':
            items = self.ansible.inventory.list_groups()
        else:
            items = self.selected
        for item in items:
            print item
        log(arg)
    # def do_become(self, arg):
    #     """Toggle whether plays run with become"""
    #     self.options.become = not self.options.become
    #     print "become changed to %s" % self.options.become

    # def do_remote_user(self, arg):
    #     """Given a username, set the remote user plays are run by"""
    #     if arg:
    #         self.options.remote_user = arg
    #         self.set_prompt()
    #     else:
    #         print "Please specify a remote user, e.g. `remote_user root`"

    # def do_become_user(self, arg):
    #     """Given a username, set the user that plays are run by when using become"""
    #     if arg:
    #         self.options.become_user = arg
    #     else:
    #         print "Please specify a user, e.g. `become_user jenkins`"
    #         print "Current user is %s" % self.options.become_user

    def do_exit(self, args):
        """Exits from the console"""
        sys.stdout.write('\n')
        log(args)
        return -1

    # do_EOF = do_exit

    def helpdefault(self, module_name):
        if module_name in self.modules:
            in_path = utils.plugins.module_finder.find_plugin(module_name)
            oc, a, _ = ansible.utils.module_docs.get_docstring(in_path)
            print stringc(oc['short_description'], 'bright gray')
            print 'Parameters:'
            for opt in oc['options'].keys():
                print '  ' + stringc(opt, 'white') + ' ' + oc['options'][opt]['description'][0]

    def complete_cd(self, text, line, begidx, endidx):
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)

        if self.options.cwd == '*':
            completions = self.hosts + self.groups
        else:
            completions = self.ansible.inventory.list_hosts(self.options.cwd)

        return [s[offs:] for s in completions if s.startswith(mline)]

    def completedefault(self, text, line, begidx, endidx):
        if line.split()[0] in self.modules:
            mline = line.split(' ')[-1]
            offs = len(mline) - len(text)
            completions = self.module_args(line.split()[0])

            return [s[offs:] + '=' for s in completions if s.startswith(mline)]

    def module_args(self, module_name):
        in_path = utils.plugins.module_finder.find_plugin(module_name)
        oc, a, _ = ansible.utils.module_docs.get_docstring(in_path)
        print oc['options'].keys()
        return oc['options'].keys()


def main():
    if 'libedit' in readline.__doc__:
        readline.parse_and_bind("bind ^I rl_complete")
    else:
        readline.parse_and_bind("tab: complete")
    histfile = os.path.join(os.path.expanduser("~"), ".mz-shell_history")
    try:
        readline.read_history_file(histfile)
    except IOError:
        pass
    atexit.register(readline.write_history_file, histfile)

    (options, args) = AnsibleShell.parse_opts()
    AnsibleShell(options, args).cmdloop()

def checkip(ip):
    p = re.compile("^((?:(2[0-4]\d)|(25[0-5])|([01]?\d\d?))\.){3}(?:(2[0-4]\d)|(255[0-5])|([01]?\d\d?))$")
    if p.match(ip):
        return True
    else:
        return False

if __name__ == '__main__':
    # This hack is to work around readline issues on a mac:
    #  http://stackoverflow.com/a/7116997/541202
    try:
        main()
    except Exception, e:
        pass
    # def sigint_handler(signum, frame):
    #     global is_sigint_up
    #     is_sigint_up = True
    # signal.signal(signal.SIGINT, sigint_handler)
    # signal.signal(signal.SIGHUP, sigint_handler)
    # signal.signal(signal.SIGTERM, sigint_handler)
    # is_sigint_up = False
    # # 循环
    # while True:
    #     try:
    #         main()
    #         if cd_shell:
    #             sys.exit(1)
    #         elif is_sigint_up:
    #             print "Not Allow Exit"
    #             break
    #     except Exception, e:
    #         print e
    #         break



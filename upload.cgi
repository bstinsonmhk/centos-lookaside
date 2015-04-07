#!/usr/bin/python
#
# CGI script to handle file updates for the rpms CVS repository. There
# is nothing really complex here other than tedious checking of our
# every step along the way...
#
# Written for Fedora, modified to suit CentOS Infrastructure.
# Modified by Howard Johnson <merlin@merlinthp.org> 2014
#
# License: GPL

#
# centos' lookaside is a bit differently laid out to fedora's.
# centos uses a <package>/<branch>/<sha1sum> scheme.
#
# The upload.cgi gets called with the following arguments:
#   name - package (git repo) name
#   branch - branch name
#   sha1sum - SHA1 checksum of the file
#   file - the file to upload (optional)
#
# With only the first three args, the script runs in check mode.
# With the fourth too, it operates in upload mode.
#

import os
import sys
import cgi
import tempfile
import syslog
import smtplib
import re
import fnmatch
from ConfigParser import SafeConfigParser

from email import Header, Utils
try:
    from email.mime.text import MIMEText
except ImportError:
    from email.MIMEText import MIMEText

import hashlib
sha1_constructor = hashlib.sha1

# Config file with all our settings
CONFIG = '/etc/lookaside.cfg'
conf = SafeConfigParser()
conf.read(CONFIG)

# Reading buffer size
BUFFER_SIZE = 4096

# Gitblit config file regexes
SECTION = re.compile(r'\[(?P<sectiontype>.+?)\s+?(?P<sectionname>.+)\]')
OPTION = re.compile(r'(.+)=(.+)')
REPO = re.compile(r'([^/]+).git$')

def merge_gitblit_section(repoacl, repos, users):
    for repo in repos:
        if repo not in repoacl:
            repoacl[repo] = []
        for user in users:
            if user not in repoacl[repo]:
                repoacl[repo].append(user)

def stripwithquotes(thestring):
    return thestring.strip('\" \n')


# Parse the authtags in the form "Gitblit Team Name":branch_or_branch_regex
def gitblit_branch_to_team(filename):
    branches = {}

    with open(filename, 'r') as authtagfile:
        for line in authtagfile:
            # Ignore comments
            if line.strip() == '' or line[0] == '#':
                continue

            try:
                team, branch = map(stripwithquotes, line.split(':'))
            except ValueError:
                # There was trouble splitting the lines, meaning something in
                # the config is wrong, ignore this line
                continue
            branches.setdefault(branch,[]).append(team)

    return branches

# Parse the gitblit user/team definitions (and other things) and stuff it into a
# dictionary
def parse_gitblit_config(filename):
    config = {}
    with open(filename, 'r') as configfile:
        for line in configfile:
            # Ignore comments
            if line.strip() == '' or line[0] == '#':
                continue

            section = SECTION.match(line.strip())
            if section:
                section_type,section_name = section.groupdict().values()
                section_name = stripwithquotes(section_name)
                config.setdefault(section_type,{}).setdefault(section_name,{})
                continue

            option = OPTION.match(line.strip())
            if option:
                key = option.group(1).strip()
                value = option.group(2).strip()
                config[section_type][section_name].setdefault(key, []).append(value)
    return config


def send_error(text):
    print text
    sys.exit(1)

def check_auth(username, pkgname, branchname):
    config = parse_gitblit_config(conf.get('acl', 'gitblit_config'))

    auth_tags = gitblit_branch_to_team(conf.get('acl', 'auth_tag_config'))

    branchacl = []
    # The ACL might be defined by a glob, search for the right entry here
    matching_acls = [acl_match for acl_match in auth_tags if fnmatch.fnmatch(branchname, acl_match)]
    print >> sys.stderr, matching_acls

    possible_groups = []
    for acl in matching_acls:
        # If _any_ of the protected-branch ACLs match our branch name bail
        # out quickly
        if 'None' in auth_tags[acl]:
            return False
        possible_groups.extend(auth_tags[acl])

    for group in possible_groups:
        try:
            if username in config['team'][group]['user']:
                return True
        except KeyError:
            print >> sys.stderr, '[group={0}] group or user entries do not exist'.format(group)
    return False

def check_form(form, var):
    ret = form.getvalue(var, None)
    if ret is None:
        send_error('Required field "%s" is not present.' % var)
    if isinstance(ret, list):
        send_error('Multiple values given for "%s". Aborting.' % var)
    return ret

def send_email(pkg, sha1, filename, username):
    text = """A file has been added to the lookaside cache for %(pkg)s:

%(sha1)s  %(filename)s""" % locals()
    msg = MIMEText(text)
    sender_name = conf.get('mail', 'sender_name')
    sender_email = conf.get('mail', 'sender_email')
    sender = Utils.formataddr((sender_name, sender_email))
    recipient = conf.get('mail', 'recipient')
    msg['Subject'] = 'File %s uploaded to lookaside cache by %s' % (
            filename, username)
    msg['From'] = sender
    msg['To'] = recipient
    try:
        s = smtplib.SMTP(conf.get('mail', 'smtp_server'))
        s.sendmail(sender, recipient, msg.as_string())
    except:
        errstr = 'sending mail for upload of %s failed!' % filename
        print >> sys.stderr, errstr
        syslog.syslog(errstr)

def main():
    os.umask(002)

    username = os.environ.get('SSL_CLIENT_S_DN_CN', None)

    print 'Content-Type: text/plain'
    print

    assert os.environ['REQUEST_URI'].split('/')[1] == 'lookaside'

    form = cgi.FieldStorage()
    name = check_form(form, 'name')
    branch = check_form(form, 'branch')
    sha1sum = check_form(form, 'sha1sum')

    action = None
    upload_file = None
    filename = None

    # Is this a submission or a test?
    # in a test, we don't get a file.
    if not form.has_key('file'):
        action = 'check'
        print >> sys.stderr, '[username=%s] Checking file status: NAME=%s BRANCH=%s SHA1SUM=%s' % (username, name, branch, sha1sum)
    else:
        action = 'upload'
        upload_file = form['file']
        if not upload_file.file:
            send_error('No file given for upload. Aborting.')
        filename = os.path.basename(upload_file.filename)
        print >> sys.stderr, '[username=%s] Processing upload request: NAME=%s BRANCH=%s SHA1SUM=%s' % (username, name, branch, sha1sum)

    module_dir = os.path.join(conf.get('lookaside', 'cache_dir'), name, branch)
    dest_file =  os.path.join(module_dir, sha1sum)

    # try to see if we already have this file...
    if os.path.exists(dest_file):
        if action == 'check':
            print 'Available'
        else:
            upload_file.file.close()
            dest_file_stat = os.stat(dest_file)
            print 'File %s already exists' % filename
            print 'File: %s Size: %d' % (dest_file, dest_file_stat.st_size)
        sys.exit(0)
    elif action == 'check':
        print 'Missing'
        sys.exit(0)

    # if desired, make sure the user has permission to write to this branch
    if conf.getboolean('acl', 'do_acl'):
        if not check_auth(username, branch):
            print 'Status: 403 Forbidden'
            print 'Content-type: text/plain'
            print
            print 'You must connect with a valid certificate and have permissions on the appropriate branch to upload'
            sys.exit(0)

    # check that all directories are in place
    if not os.path.isdir(module_dir):
        os.makedirs(module_dir, 02775)

    # grab a temporary filename and dump our file in there
    tempfile.tempdir = module_dir
    tmpfile = tempfile.mkstemp(sha1sum)[1]
    tmpfd = open(tmpfile, 'w')

    # now read the whole file in
    m = sha1_constructor()
    filesize = 0
    while True:
        data = upload_file.file.read(BUFFER_SIZE)
        if not data:
            break
        tmpfd.write(data)
        m.update(data)
        filesize += len(data)

    # now we're done reading, check the MD5 sum of what we got
    tmpfd.close()
    check_sha1sum = m.hexdigest()
    if sha1sum != check_sha1sum:
        os.unlink(tmpfile)
        send_error("SHA1 check failed. Received %s instead of %s." % (check_sha1sum, sha1sum))

    # rename it its final name
    os.rename(tmpfile, dest_file)
    os.chmod(dest_file, 0644)

    print >> sys.stderr, '[username=%s] Stored %s (%d bytes)' % (username, dest_file, filesize)
    print 'File %s size %d SHA1 %s stored OK' % (filename, filesize, sha1sum)
    if conf.getboolean('mail', 'send_mail'):
        send_email(name, sha1sum, filename, username)

if __name__ == '__main__':
    main()

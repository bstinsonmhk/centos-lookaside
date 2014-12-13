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
SECTION = re.compile(r'\[(.+)\]')
OPTION = re.compile(r'(.+)=(.+)')
REPO = re.compile(r'([^/]+).git$')

def merge_gitblit_section(repoacl, repos, users):
    for repo in repos:
        if repo not in repoacl:
            repoacl[repo] = []
        for user in users:
            if user not in repoacl[repo]:
                repoacl[repo].append(user)

# turns the gitblit config file into a dict of package name to permitted users
def parse_gitblit_config(filename):
    insection = False
    repoacl = {}
    sectrepos = []
    sectusers = []

    f = open(filename)
    for line in f:
        if line.strip() == '' or line[0] == '#':
            continue
        secth = SECTION.match(line)
        if secth:
            if insection:
                merge_gitblit_section(repoacl, sectrepos, sectusers)

                sectrepos = []
                sectusers = []
            else:
                insection = True
            continue
        opt = OPTION.match(line)
        if opt:
            if not insection:
                continue
            key = opt.group(1).strip()
            value = opt.group(2).strip()

            if key == "repository":
                pack = REPO.search(value)
                if pack:
                    sectrepos.append(pack.group(1))
            elif key == "user":
                sectusers.append(value)
    if insection:
        merge_gitblit_section(repoacl, sectrepos, sectusers)
    f.close()
    return repoacl

def send_error(text):
    print text
    sys.exit(1)

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
        # load in the gitblit config
        repoacl = parse_gitblit_config(conf.get('acl', 'gitblit_config'))

        # if the package isn't in the gitblit config, we can't give upload perms
        if name not in repoacl:
            send_error("Unknown package %s" % name)

        # now check the perms
        if username not in repoacl[name]:
            send_error("Write access package %s rejected for user %s" % (name, username))

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

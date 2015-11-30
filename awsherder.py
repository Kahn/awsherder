from flask import Flask, request, redirect, session, json, g, render_template, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_openid import OpenID
from flask_sslify import SSLify
from wtforms import Form, BooleanField, TextField, PasswordField, validators, SelectField
import urllib2
import werkzeug
import re
import logging
from logging.handlers import RotatingFileHandler
import boto.ec2
import boto.cloudformation
import time
import os

app = Flask(__name__)
app.config.from_pyfile('settings.cfg')
app.debug = app.config['DEBUG']
boto_logger = logging.getLogger('boto')
handler = RotatingFileHandler(app.config['LOG_DIR'] + '/' + __name__ + '.log', maxBytes=10000, backupCount=1)
if app.config['DEBUG'] == 'True':
    handler.setLevel(logging.DEBUG)
    boto_logger.setLevel(logging.DEBUG)
else:
    # Force TLS and HSTS only in production
    sslify = SSLify(app, permanent=True)
    handler.setLevel(logging.INFO)
app.logger.addHandler(handler)
db = SQLAlchemy(app)
oid = OpenID(app)

app.logger.info('App started with debug mode: {0}\nApp running with Flask: {1}'.format(app.config['DEBUG'],app.config['USE_FLASK']))

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role = db.relationship('User', backref='user')
    name = db.Column(db.String(40))

    @staticmethod
    def get_or_create(role_name):
        rv = Role.query.filter_by(name=role_name).first()
        if rv is None:
            rv = Role()
            rv.name = role_name
            db.session.add(rv)
        return rv

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    steam_id = db.Column(db.String(40))
    nickname = db.Column(db.String(80))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))

    @staticmethod
    def get_or_create(steam_id):
        rv = User.query.filter_by(steam_id=steam_id).first()
        if rv is None:
            rv = User()
            rv.steam_id = steam_id
            db.session.add(rv)
        return rv

    @staticmethod
    def create_user(steam_id,nickname,role_id):
        rv = User.query.filter_by(steam_id=steam_id).first()
        if rv is None:
            rv = User()
            rv.steam_id = steam_id
            rv.nickname = nickname
            rv.role_id = role_id
            app.logger.info('Created user - steam_id: "{0}" nickname: "{1}"'.format(steam_id,nickname))
            db.session.add(rv)
        else:
            app.logger.debug('Existing user - steam_id: "{0}" nickname: "{1}"'.format(steam_id,nickname))
        return rv

class Instance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    instance_id = db.Column(db.String(80))
    ark_process_status = db.Column(db.String(80))
    ark_server_status = db.Column(db.String(80))
    ark_version = db.Column(db.String(80))

    @staticmethod
    def get_or_create(instance_id):
        rv = Instance.query.filter_by(instance_id=instance_id).first()
        if rv is None:
            rv = Instance()
            rv.instance_id = instance_id
            db.session.add(rv)
        return rv

if app.config['DEBUG'] == 'True':
    app.logger.debug('Dropping database')
    db.drop_all()

db.create_all()
Role.get_or_create('Admin')
Role.get_or_create('User')
User.create_user(app.config['ADMIN_USER_STEAM_ID'],app.config['ADMIN_USER_STEAM_NICK'],1)
db.session.commit()

_steam_id_re = re.compile('steamcommunity.com/openid/id/(.*?)$')

class UserAdminForm(Form):
    roles = []
    for role in Role.query.all():
        app.logger.debug('name: "{0}" id: "{1}"'.format(role.name,role.id))
        r = role.id, role.name
        roles.append(r)
        app.logger.debug('Roles: {0}'.format(roles))

    role = SelectField(u'User Role', choices=roles)

def authenticated_user():
    if g.user is None:
        return False
    return True

def user_has_role(role_id):
    authenticated_user()
    app.logger.debug('g.user: "{0}"'.format(g.user.id))
    user = User.query.filter_by(id=g.user.id).first()
    if not user.role_id == role_id:
        app.logger.debug('user_id "{0}" rejected by user_has_role() check rid {1} != {2}'.format(g.user.nickname,user.role_id,role_id))
        return False
    return True

def get_users(user_id):
    if user_id:
        users = User.query.filter_by(id=user_id).first()
    elif user_id == False:
        users = User.query.all()
    else:
        abort(500)
    return users

def get_steam_userinfo(steam_id):
    options = {
        'key': app.config['STEAM_API_KEY'],
        'steamids': steam_id
    }
    url = 'http://api.steampowered.com/ISteamUser/' \
          'GetPlayerSummaries/v0001/?%s' % werkzeug.urls.url_encode(options)
    rv = json.load(urllib2.urlopen(url))
    return rv['response']['players']['player'][0] or {}

def get_ark_serverinfo(ipaddress):
    app.logger.info('Checking remote ARK server status: {0}'.format(ipaddress))

    ark_serverinfo = {}
    # TODO - Really get some stats
    ark_serverinfo['server_address'] = ipaddress
    ark_serverinfo['process_status'] = "Offline"
    ark_serverinfo['server_status'] = "Offline"
    ark_serverinfo['current_version'] = "000000"
    return ark_serverinfo

def get_aws_instances(instance_id):
    statuses = False
    conn = boto.ec2.connect_to_region(app.config['AWS_DEFAULT_REGION'],aws_access_key_id=app.config['AWS_ACCESS_KEY_ID'],aws_secret_access_key=app.config['AWS_SECRET_ACCESS_KEY'])
    if instance_id:
        f = {}
        f['instance-id'] = instance_id
        f['instance-state-name'] = 'running'
        f['instance-state-name'] = 'running'
        instance = conn.get_only_instances(filters=f)
        app.logger.debug('aws statuses {0}'.format(statuses))
        if len(instance) >= 1:
            ip_address = instance[0].ip_address
            return ip_address
        else:
            return False
    elif instance_id == False:
        f = {}
        f['instance-state-name'] = 'running'
        statuses = conn.get_only_instances(filters=f)
        app.logger.debug('running aws statuses {0}'.format(statuses))
        instace_ids = []
        for instance in statuses:
            instace_ids.append(instance.id)
        return instace_ids
    else:
        return False

def get_stack():
    conn = boto.cloudformation.connect_to_region(app.config['AWS_DEFAULT_REGION'],aws_access_key_id=app.config['AWS_ACCESS_KEY_ID'],aws_secret_access_key=app.config['AWS_SECRET_ACCESS_KEY'])

    try:
        stacks = conn.describe_stacks(app.config['APP_UUID'])
    except:
        stacks = []
    if len(stacks) == 1:
        stack = stacks[0]
        app.logger.debug('Existing stack: {0}'.format(stack.stack_id))
        return stack
    else:
        return False

def create_stack(parameters):
    conn = boto.cloudformation.connect_to_region(app.config['AWS_DEFAULT_REGION'],aws_access_key_id=app.config['AWS_ACCESS_KEY_ID'],aws_secret_access_key=app.config['AWS_SECRET_ACCESS_KEY'])

    try:
        stacks = conn.describe_stacks(app.config['APP_UUID'])
    except:
        stacks = []
    if len(stacks) == 1:
        stack = stacks[0]
        instance_id = stack.outputs[0].value
        app.logger.debug('Existing stack: {0} stack instace {1}'.format(stack.stack_id,instance_id))
        app.logger.debug('Existing stack instance: {0}'.format(stack.outputs[0].value))
        return instance_id
    else:
        # Create stack after all
        tpl_file = open(os.path.join(os.path.dirname(__file__),'lib/cloudformation.json'))
        cfn_template_body = tpl_file.read()
        tpl_file.close()
        stack = conn.create_stack(app.config['APP_UUID'],template_body=cfn_template_body,parameters=parameters)
        app.logger.debug('cloudformation stack create: {0}'.format(stack))
        return stack

def delete_stack():
    conn = boto.cloudformation.connect_to_region(app.config['AWS_DEFAULT_REGION'],aws_access_key_id=app.config['AWS_ACCESS_KEY_ID'],aws_secret_access_key=app.config['AWS_SECRET_ACCESS_KEY'])

    try:
        stacks = conn.describe_stacks(app.config['APP_UUID'])
    except:
        stacks = []
    if len(stacks) == 1:
        stack = stacks[0]
        instance_id = stack.outputs[0].value
        app.logger.info('Deleting stack: {0}'.format(stack.stack_id))
        delete = stack.delete()
        app.logger.debug('Delete: {0}'.format(delete))
        return True
    else:
        abort(500)

def wait_for_snapshot_complete(snapshot_id):
    conn = boto.ec2.connect_to_region(app.config['AWS_DEFAULT_REGION'],aws_access_key_id=app.config['AWS_ACCESS_KEY_ID'],aws_secret_access_key=app.config['AWS_SECRET_ACCESS_KEY'])
    inprogress_snapshot = conn.get_all_snapshots(snapshot_id)
    app.logger.debug('waiting for snap {0} status {1}'.format(inprogress_snapshot[0].id, inprogress_snapshot[0].status))
    if 'completed' in inprogress_snapshot[0].status:
        return True
    else:
        return False

def image_from_instance(instance_id):
    conn = boto.ec2.connect_to_region(app.config['AWS_DEFAULT_REGION'],aws_access_key_id=app.config['AWS_ACCESS_KEY_ID'],aws_secret_access_key=app.config['AWS_SECRET_ACCESS_KEY'])

    f = {}
    f['name'] = app.config['APP_UUID']
    amis = conn.get_all_images(filters=f)
    if len(amis) == 1:
        for ami in amis:
            app.logger.debug('deleting ami: {0}'.format(ami.id))
            try:
                delete_ami = conn.deregister_image(ami.id)
            except:
                app.logger.error('deleting ami failed: {0}'.format(delete_ami))

    f = {}
    f['description'] = app.config['APP_UUID']
    snapshots = conn.get_all_snapshots(filters=f)
    if len(snapshots) == 1:
        for snapshot in snapshots:
            app.logger.debug('deleting snapshot: {0}'.format(snapshot.id))
            conn.delete_snapshot(snapshot.id)

    vols = conn.get_all_volumes(filters={'attachment.instance-id': instance_id})
    volume = vols[0]
    snap = volume.create_snapshot(app.config['APP_UUID'])
    app.logger.debug('snap: {0}'.format(snap.id))

    while True:
        # conn = boto.ec2.connect_to_region(app.config['AWS_DEFAULT_REGION'],aws_access_key_id=app.config['AWS_ACCESS_KEY_ID'],aws_secret_access_key=app.config['AWS_SECRET_ACCESS_KEY'])
        app.logger.debug('waiting for snap {0} status {1}'.format(snap.id, snap.status))
        if 'completed' in snap.status:
            break
        else:
            time.sleep(10)
            snap.update()

    app.logger.debug('completed snap: {0}'.format(snap.id))

    ami = conn.register_image(name=app.config['APP_UUID'],snapshot_id=snap.id,root_device_name='/dev/sda1',virtualization_type='hvm',architecture='x86_64')
    app.logger.debug('ami: {0}'.format(ami))

    return ami

@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = User.query.get(session['user_id'])
        try:
            steamdata = get_steam_userinfo(g.user.steam_id)
        except AttributeError:
            app.logger.warning('Invalidated session missing steam data - user_id: {0}'.format(session['user_id']))
            session.pop('user_id', None)
            return redirect(oid.get_next_url())
        g.user.nickname = steamdata['personaname']
        g.user.avatar_url = steamdata['avatar']
        app.logger.debug('steam_id: {0} steam_nickname: {1}'.format(g.user.steam_id, g.user.nickname))
        app.logger.debug('steam_avatar_url: {0}'.format(g.user.avatar_url))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(oid.get_next_url())

@app.route('/login')
@oid.loginhandler
def login():
    if g.user is not None:
        return redirect(oid.get_next_url())
    return oid.try_login('http://steamcommunity.com/openid')

@oid.after_login
def create_or_login(resp):
    match = _steam_id_re.search(resp.identity_url)
    g.user = User.get_or_create(match.group(1))
    steamdata = get_steam_userinfo(g.user.steam_id)
    g.user.nickname = steamdata['personaname']
    db.session.commit()
    session['user_id'] = g.user.id
    flash('You are logged in as %s' % g.user.nickname)
    return redirect(oid.get_next_url())

@app.route('/users')
def users():
    if user_has_role(1) or user_has_role(2):
        return render_template('users.html', users=get_users(False))
    else:
        abort(401)

@app.route('/user/<user_id>', methods=['POST', 'GET'])
def user(user_id):
    if user_has_role(1):
        error = None

        user = User.query.get(user_id)
        form = UserAdminForm(obj=user)
        app.logger.debug('form POST data {0}'.format(request.form))

        # if request.method == 'POST' and form.validate():
        if request.method == 'POST':
            app.logger.debug('editing user {0}'.format(user.nickname))
            user.role_id = request.form['role']
            db.session.commit()
            flash('Updated user_id {0} permissions'.format(user_id))

        return render_template('user.html', user=get_users(user_id),form=form)
    else:
        abort(401)

@app.route('/')
def landingpage():
    if g.user is None:
        return render_template('login.html')
    else:
        return render_template('index.html')

@app.route('/instance_console')
def console():
    if user_has_role(1) or user_has_role(2):
        # app.logger.debug('starting aws instances: {0}'.format(start_aws_instances(False)))
        stack = get_stack()
        if stack == False:
            return render_template('console.html')
        elif stack.stack_status == 'CREATE_IN_PROGRESS':
            flash('Stack is creating - please wait ... ')
            return render_template('console.html', stack='error')
        elif stack.stack_status == 'CREATE_COMPLETE':
            flash('Stack is created!')
            return render_template('console.html', aws_instances=get_aws_instances(False))
        else:
            error = 'Stack {0} status {1} invalid'.format(stack.stack_id,stack.stack_status)
            return render_template('console.html',error=error,stack='error')
    else:
        abort(401)

@app.route('/instance/create')
def instance_create():
    if user_has_role(1) or user_has_role(2):
        authenticated_user()
        stack = get_stack()
        if stack == False:
            conn = boto.ec2.connect_to_region(app.config['AWS_DEFAULT_REGION'],aws_access_key_id=app.config['AWS_ACCESS_KEY_ID'],aws_secret_access_key=app.config['AWS_SECRET_ACCESS_KEY'])

            try:
                f = {}
                f['name'] = app.config['APP_UUID']
                amis = conn.get_all_images(filters=f)
                if len(amis) == 1:
                    for ami in amis:
                        boot_ami = ami.id
                        app.logger.debug('booting with ami {0}'.format(boot_ami))
                else:
                    boot_ami = 'ami-9c1a42ff'
            except:
                boot_ami = 'ami-9c1a42ff'

            p = [
            ('InstanceType','m4.large'),
            ('KeyName','yubikey'),
            ('AMI',boot_ami),
            ('SubnetId','subnet-760e6713 '),
            ('SecurityGroup','sg-fba5849e'),
            ('ElasticIpAllocationId','eipalloc-784a841d'),
            ]
            stack = create_stack(p)
            if 'arn' in stack:
                flash('Creating new cloudformation stack '+stack)
                return render_template('console.html', stack='error')

            if 'i-' in stack:
                return render_template('console.html', stack=stack)
        else:
            return render_template('console.html', stack=stack)
    else:
        abort(401)

@app.route('/instance/<instance_id>')
def instance_console(instance_id):
    if user_has_role(1) or user_has_role(2):
        authenticated_user()
        serveraddress = get_aws_instances(instance_id)
        instance = Instance.query.filter_by(instance_id=instance_id).first()
        app.logger.debug('instance db {0}'.format(instance))
        return render_template('instance.html', instance_id=instance_id, serveraddress=serveraddress, ark_serverinfo=instance)
    else:
        abort(401)

@app.route('/instance/<instance_id>/shutdown')
def instance_shutdown(instance_id):
    if user_has_role(1) or user_has_role(2):
        authenticated_user()
        flash('AMI deleted: '+image_from_instance(instance_id))
        stack = delete_stack()
        if stack:
            flash('Cloudformation stack deleted')
        return render_template('index.html')
    else:
        abort(401)

@app.route('/instance/<instance_id>/update', methods=['PUT'])
def instance_update(instance_id):
    instance = Instance.get_or_create(instance_id)
    instance.ark_process_status = request.form['ark_process_status']
    instance.ark_server_status = request.form['ark_server_status']
    instance.ark_version = request.form['ark_version']
    db.session.commit()
    return 'OK'

if app.config['USE_FLASK'] == 'True':
    if __name__ == '__main__':
        app.run(debug=app.config['DEBUG'])

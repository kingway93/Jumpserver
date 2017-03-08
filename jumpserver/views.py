# coding: utf-8

from __future__ import division
import uuid
import json
import urllib
import socket
import subprocess

from django.db.models import Count
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.http import HttpResponseNotFound
from django.http import HttpResponse
# from jperm.models import Apply
import paramiko
from jumpserver.api import *
from jumpserver.models import Setting, HostLog
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from jlog.models import Log, FileLog
from juser.models import User
from jperm.perm_api import get_group_user_perm, gen_resource
from jasset.models import Asset, IDC
from jperm.ansible_api import MyRunner
import zipfile


def getDaysByNum(num):
    """
    输出格式:([datetime.date(2015, 11, 6),  datetime.date(2015, 11, 8)], ['11-06', '11-08'])
    """

    today = datetime.date.today()
    oneday = datetime.timedelta(days=1)
    date_li, date_str = [], []
    for i in range(0, num):
        today = today-oneday
        date_li.append(today)
        date_str.append(str(today)[5:10])
    date_li.reverse()
    date_str.reverse()
    return date_li, date_str


def get_data(x, y, z):
    pass


def get_data_by_day(date_li, item):
    data_li = []
    for d in date_li:
        logs = Log.objects.filter(start_time__year=d.year,
                                  start_time__month=d.month,
                                  start_time__day=d.day)
        if item == 'user':
            data_li.append(set([log.user for log in logs]))
        elif item == 'asset':
            data_li.append(set([log.host for log in logs]))
        elif item == 'login':
            data_li.append(logs)
        else:
            pass
    return data_li


def get_count_by_day(date_li, item):
    data_li = get_data_by_day(date_li, item)
    data_count_li = []
    for data in data_li:
        data_count_li.append(len(data))
    return data_count_li


def get_count_by_date(date_li, item):
    data_li = get_data_by_day(date_li, item)
    data_count_tmp = []
    for data in data_li:
        data_count_tmp.extend(list(data))

    return len(set(data_count_tmp))


@require_role(role='user')
def index_cu(request):
    username = request.user.username
    return HttpResponseRedirect(reverse('user_detail'))


@require_role(role='user')
def index(request):
    li_date, li_str = getDaysByNum(7)
    today = datetime.datetime.now().day
    from_week = datetime.datetime.now() - datetime.timedelta(days=7)

    if is_role_request(request, 'user'):
        return index_cu(request)

    elif is_role_request(request, 'super'):
        # dashboard 显示汇总
        users = User.objects.all()
        hosts = Asset.objects.all()
        online = Log.objects.filter(is_finished=0)
        online_host = online.values('host').distinct()
        online_user = online.values('user').distinct()
        active_users = User.objects.filter(is_active=1)
        active_hosts = Asset.objects.filter(is_active=1)

        # 一个月历史汇总
        date_li, date_str = getDaysByNum(30)
        date_month = repr(date_str)
        active_user_per_month = str(get_count_by_day(date_li, 'user'))
        active_asset_per_month = str(get_count_by_day(date_li, 'asset'))
        active_login_per_month = str(get_count_by_day(date_li, 'login'))

        # 活跃用户资产图
        active_user_month = get_count_by_date(date_li, 'user')
        disabled_user_count = len(users.filter(is_active=False))
        inactive_user_month = len(users) - active_user_month
        active_asset_month = get_count_by_date(date_li, 'asset')
        disabled_asset_count = len(hosts.filter(is_active=False)) if hosts.filter(is_active=False) else 0
        inactive_asset_month = len(hosts) - active_asset_month if len(hosts) > active_asset_month else 0

        # 一周top10用户和主机
        week_data = Log.objects.filter(start_time__range=[from_week, datetime.datetime.now()])
        user_top_ten = week_data.values('user').annotate(times=Count('user')).order_by('-times')[:10]
        host_top_ten = week_data.values('host').annotate(times=Count('host')).order_by('-times')[:10]

        for user_info in user_top_ten:
            username = user_info.get('user')
            last = Log.objects.filter(user=username).latest('start_time')
            user_info['last'] = last

        for host_info in host_top_ten:
            host = host_info.get('host')
            last = Log.objects.filter(host=host).latest('start_time')
            host_info['last'] = last

        # 一周top5
        week_users = week_data.values('user').distinct().count()
        week_hosts = week_data.count()

        user_top_five = week_data.values('user').annotate(times=Count('user')).order_by('-times')[:5]
        color = ['label-success', 'label-info', 'label-primary', 'label-default', 'label-warnning']

        # 最后10次权限申请
        # perm apply latest 10
        # perm_apply_10 = Apply.objects.order_by('-date_add')[:10]

        # 最后10次登陆
        login_10 = Log.objects.order_by('-start_time')[:10]
        login_more_10 = Log.objects.order_by('-start_time')[10:21]

    return render_to_response('index.html', locals(), context_instance=RequestContext(request))


def skin_config(request):
    return render_to_response('skin_config.html')


def is_latest():
    node = uuid.getnode()
    jsn = uuid.UUID(int=node).hex[-12:]
    with open(os.path.join(BASE_DIR, 'version')) as f:
        current_version = f.read()
    lastest_version = urllib.urlopen('http://www.jumpserver.org/lastest_version.html?jsn=%s' % jsn).read().strip()

    if current_version != lastest_version:
        pass


@defend_attack
def Login(request):
    """登录界面"""
    error = ''
    if request.user.is_authenticated():
        return HttpResponseRedirect(reverse('index'))
    if request.method == 'GET':
        return render_to_response('login.html')
    else:
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = get_object(User, username=username)
        if username and password and user:
            is_ldap = int(user.is_ldap)
            if is_ldap:
                ldapaddr = user.ldapaddr
                ou = user.ou
                dc = user.dc
                ldap_auth = ldap_login_auth(username=username, password=password, ldapaddr=ldapaddr, ou=ou, dc=dc)
                if ldap_auth:
                    password = '123456'
                else:
                    password = ''
            user = authenticate(username=username, password=password)
            if user is not None:
                if user.is_active:
                    login(request, user)
                    # c = {}
                    # c.update(csrf(request))
                    # request.session['csrf_token'] = str(c.get('csrf_token'))
        # user_filter = User.objects.filter(username=username)
        # if user_filter:
        #     user = user_filter[0]
        #     if PyCrypt.md5_crypt(password) == user.password:
        #         request.session['user_id'] = user.id
        #         user_filter.update(last_login=datetime.datetime.now())
                    if user.role == 'SU':
                        request.session['role_id'] = 2
                    elif user.role == 'GA':
                        request.session['role_id'] = 1
                    else:
                        request.session['role_id'] = 0
                    return HttpResponseRedirect(request.session.get('pre_url', '/'))
                # response.set_cookie('username', username, expires=604800)
                # response.set_cookie('seed', PyCrypt.md5_crypt(password), expires=604800)
                # return response
                else:
                    error = '用户未激活'
            else:
                error = '用户名或密码错误'
        else:
            error = '用户名或密码错误'
    return render_to_response('login.html', {'error': error})


@require_role('user')
def Logout(request):
    logout(request)
    return HttpResponseRedirect(reverse('index'))


@require_role('admin')
def setting(request):
    header_title, path1 = '项目设置', '设置'
    setting_default = get_object(Setting, name='default')

    if request.method == "POST":
        try:
            setting_raw = request.POST.get('setting', '')
            if setting_raw == 'default':
                username = request.POST.get('username', '')
                port = request.POST.get('port', '')
                password = request.POST.get('password', '')
                private_key = request.POST.get('key', '')

                if len(password) > 30:
                    raise ServerError(u'秘密长度不能超过30位!')

                if '' in [username, port]:
                    return ServerError(u'所填内容不能为空, 且密码和私钥填一个')
                else:
                    private_key_dir = os.path.join(BASE_DIR, 'keys', 'default')
                    private_key_path = os.path.join(private_key_dir, 'admin_user.pem')
                    mkdir(private_key_dir)

                    if private_key:
                        with open(private_key_path, 'w') as f:
                                f.write(private_key)
                        os.chmod(private_key_path, 0600)

                    if setting_default:
                        if password:
                            password_encode = CRYPTOR.encrypt(password)
                        else:
                            password_encode = password
                        Setting.objects.filter(name='default').update(field1=username, field2=port,
                                                                      field3=password_encode,
                                                                      field4=private_key_path)

                    else:
                        password_encode = CRYPTOR.encrypt(password)
                        setting_r = Setting(name='default', field1=username, field2=port,
                                            field3=password_encode,
                                            field4=private_key_path).save()
                        msg = "设置成功"
        except ServerError as e:
            error = e.message
    return my_render('setting.html', locals(), request)


@login_required(login_url='/login')
def upload(request):
    user = request.user
    assets = get_group_user_perm(user).get('asset').keys()
    asset_select = []
    if request.method == 'POST':
        remote_ip = request.META.get('REMOTE_ADDR')
        asset_ids = request.POST.getlist('asset_ids', '')
        upload_files = request.FILES.getlist('file[]', None)
        date_now = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        upload_dir = get_tmp_dir()
        # file_dict = {}
        for asset_id in asset_ids:
            asset_select.append(get_object(Asset, id=asset_id))

        if not set(asset_select).issubset(set(assets)):
            illegal_asset = set(asset_select).issubset(set(assets))
            return HttpResponse('没有权限的服务器 %s' % ','.join([asset.hostname for asset in illegal_asset]))

        for upload_file in upload_files:
            file_path = '%s/%s' % (upload_dir, upload_file.name)
            with open(file_path, 'w') as f:
                for chunk in upload_file.chunks():
                    f.write(chunk)

        res = gen_resource({'user': user, 'asset': asset_select})
        runner = MyRunner(res)
        runner.run('copy', module_args='src=%s dest=%s directory_mode'
                                        % (upload_dir, '/tmp'), pattern='*')
        ret = runner.results
        logger.debug(ret)
        FileLog(user=request.user.username, host=' '.join([asset.hostname for asset in asset_select]),
                filename=' '.join([f.name for f in upload_files]), type='upload', remote_ip=remote_ip,
                result=ret).save()
        if ret.get('failed'):
            error = u'上传目录: %s <br> 上传失败: [ %s ] <br>上传成功 [ %s ]' % (upload_dir,
                                                                             ', '.join(ret.get('failed').keys()),
                                                                             ', '.join(ret.get('ok').keys()))
            return HttpResponse(error, status=500)
        msg = u'上传目录: %s <br> 传送成功 [ %s ]' % (upload_dir, ', '.join(ret.get('ok').keys()))
        return HttpResponse(msg)
    return my_render('upload.html', locals(), request)


@login_required(login_url='/login')
def download(request):
    user = request.user
    assets = get_group_user_perm(user).get('asset').keys()
    asset_select = []
    if request.method == 'POST':
        remote_ip = request.META.get('REMOTE_ADDR')
        asset_ids = request.POST.getlist('asset_ids', '')
        file_path = request.POST.get('file_path')
        date_now = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        upload_dir = get_tmp_dir()
        for asset_id in asset_ids:
            asset_select.append(get_object(Asset, id=asset_id))

        if not set(asset_select).issubset(set(assets)):
            illegal_asset = set(asset_select).issubset(set(assets))
            return HttpResponse(u'没有权限的服务器 %s' % ','.join([asset.hostname for asset in illegal_asset]))

        res = gen_resource({'user': user, 'asset': asset_select})
        runner = MyRunner(res)
        runner.run('fetch', module_args='src=%s dest=%s' % (file_path, upload_dir), pattern='*')
        FileLog(user=request.user.username, host=' '.join([asset.hostname for asset in asset_select]),
                filename=file_path, type='download', remote_ip=remote_ip, result=runner.results).save()
        logger.debug(runner.results)
        tmp_dir_name = os.path.basename(upload_dir)
        file_zip = '/tmp/'+tmp_dir_name+'.zip'
        zf = zipfile.ZipFile(file_zip, "w", zipfile.ZIP_DEFLATED)
        for dirname, subdirs, files in os.walk(upload_dir):
            zf.write(dirname)
            for filename in files:
                zf.write(os.path.join(dirname, filename))
        zf.close()
        f = open(file_zip)
        data = f.read()
        f.close()
        response = HttpResponse(data, content_type='application/octet-stream')
        response['Content-Disposition'] = 'attachment; filename=%s.zip' % tmp_dir_name
        return response

    return render_to_response('download.html', locals(), context_instance=RequestContext(request))


@login_required(login_url='/login')
def exec_cmd(request):
    role = request.GET.get('role')
    check_assets = request.GET.get('check_assets', '')
    web_terminal_uri = '/ws/exec?role=%s' % (role)
    return my_render('exec_cmd.html', locals(), request)


@require_role('user')
def web_terminal(request):
    asset_id = request.GET.get('id')
    role_name = request.GET.get('role')
    asset = get_object(Asset, id=asset_id)
    if asset:
        hostname = asset.hostname
    return render_to_response('jlog/web_terminal.html', locals())


@login_required(login_url='/login')
def look_log(request):
    if request.method == 'POST':
        web_data = json.loads(request.body)
        offset = int(web_data.get("offset"))
        host_id = int(web_data.get("host_id", ""))
        log_id = int(web_data.get("log_id", ""))
        port = 11311
        if not host_id or not log_id:
            return HttpResponse(json.dumps({"status": "failed", "msg": "获取表单数据失败，请刷新后重试"}))
        host = Asset.objects.get(id=host_id)
        log = HostLog.objects.get(id=log_id)
        ip = host.ip
        log_path = log.path
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        msg = ''
        try:
            sock.connect((ip, port)) 
        except socket.error, e:
            msg = "请检查目标主机是否启动客户端程序"
            logger.error(e)
            sock.close()
            return HttpResponse(json.dumps({"status": "failed", "msg": msg}))
        data = {"file_path": log_path, "type": "log", "offset": offset}
        sock.sendall(json.dumps(data))
        while True:
            sock.recv(1024)
            sock.sendall("next")
            result = sock.recv(1024)
            result = json.loads(result)
            code = int(result.get("code"))
            if code == 200:
                length = int(result.get("length"))
                recv = 0
                sock.sendall("Start")
                while recv < length:
                    data = sock.recv(1024)
                    msg += data
                    recv += len(data)
            elif code == 300:
                offset = int(result.get("offset"))
                break
            else:
                msg = result.get("data")
                sock.close()
                return HttpResponse(json.dumps({"status": "failed", "msg": msg}))
        return HttpResponse(json.dumps({"status": "successed", "msg": msg, "offset": offset}))
    asset_list = Asset.objects.all()
    error = ''
    msg = ''
    header_title, path1 = '日志查看', '日志查看'
    return my_render('func/look_log.html', locals(), request)


@require_role('admin')
def manage_log(request):
    asset_list = Asset.objects.all()
    header_title, path1 = '日志查看', '日志管理'
    return my_render('func/manage_log.html', locals(), request)


@login_required(login_url='/login')
def get_loglist(request):
    log_list = []
    if request.method == 'POST':
        web_data = json.loads(request.body)
        host_id = int(web_data.get("host_id"))
        if host_id:
            host = Asset.objects.get(id=host_id)
            log_all = host.hostlog_set.all()
            try:
                for log in log_all:
                    log_dict = {}
                    log_dict['id'] = log.id
                    log_dict['path'] = log.path
                    log_list.append(log_dict)
            except Exception, e:
                logger.debug(e)
    return HttpResponse(json.dumps({"status": "successed", "log_list": log_list}))


@require_role('admin')
def add_log(request):
    if request.method == "POST":
        web_data = json.loads(request.body)
        host_id = int(web_data.get("host_id", ""))
        log_path = web_data.get("log_path", "")
        if not host_id or not log_path:
            return HttpResponse(json.dumps({"status": "failed", "msg": "获取表单数据失败，请刷新后重试"}))
        else:
            try:
                log_obj = HostLog.objects.filter(path=log_path)
                host = Asset.objects.get(id=host_id)
                if not log_obj:
                    log_obj = HostLog.objects.create(path=log_path)
                    log_obj.host.add(host)
                    log_obj.save()
                    return HttpResponse(json.dumps({"status": "successed"}))
                else:
                    log_obj = HostLog.objects.get(path=log_path)
                    if host in log_obj.host.all():
                        return HttpResponse(json.dumps({"status": "failed", "msg": "该记录已存在"}))
                    else:
                        log_obj.host.add(host)
                        log_obj.save()
                        return HttpResponse(json.dumps({"status": "successed"}))
            except Exception, e:
                logger.warn(e)


@require_role('admin')
def del_log(request):
    if request.method == "POST":
        web_data = json.loads(request.body)
        host_id = int(web_data.get("host_id", ""))
        log_id = int(web_data.get("log_id", ""))
        if not host_id or not log_id:
            return HttpResponse(json.dumps({"status": "failed", "msg": "获取表单数据失败，请刷新后重试"}))
        else:
            try:
                log_obj = HostLog.objects.get(id=log_id)
                host = Asset.objects.get(id=host_id)
                if host in log_obj.host.all():
                    log_obj.host.remove(host)
                    log_obj.save()
                    if not log_obj.host.all():
                        log_obj.delete()
                    return HttpResponse(json.dumps({"status": "successed"}))
                else:
                    return HttpResponse(json.dumps({"status": "failed", "msg": "该记录在数据库中不存在"}))
            except Exception, e:
                logger.warn(e)

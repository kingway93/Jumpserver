from django.conf.urls import patterns, include, url


urlpatterns = patterns('jumpserver.views',
    # Examples:
    url(r'^$', 'index', name='index'),
    # url(r'^api/user/$', 'api_user'),
    url(r'^skin_config/$', 'skin_config', name='skin_config'),
    url(r'^login/$', 'Login', name='login'),
    url(r'^logout/$', 'Logout', name='logout'),
    url(r'^exec_cmd/$', 'exec_cmd', name='exec_cmd'),
    url(r'^file/upload/$', 'upload', name='file_upload'),
    url(r'^file/download/$', 'download', name='file_download'),
    url(r'^func/look_log/$', 'look_log', name='look_log'),
    url(r'^func/manage_log/$', 'manage_log', name='manage_log'),
    url(r'^func/add_log/$', 'add_log', name='add_log'),
    url(r'^func/del_log/$', 'del_log', name='del_log'),
    url(r'^func/get_loglist/$', 'get_loglist', name='get_loglist'),
    url(r'^setting', 'setting', name='setting'),
    url(r'^terminal/$', 'web_terminal', name='terminal'),
    url(r'^juser/', include('juser.urls')),
    url(r'^jasset/', include('jasset.urls')),
    url(r'^jlog/', include('jlog.urls')),
    url(r'^jperm/', include('jperm.urls')),
)

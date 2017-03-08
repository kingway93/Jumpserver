# coding: utf-8

from django.db import models
from jasset.models import Asset


class Setting(models.Model):
    name = models.CharField(max_length=100)
    field1 = models.CharField(max_length=100, null=True, blank=True)
    field2 = models.CharField(max_length=100, null=True, blank=True)
    field3 = models.CharField(max_length=256, null=True, blank=True)
    field4 = models.CharField(max_length=100, null=True, blank=True)
    field5 = models.CharField(max_length=100, null=True, blank=True)

    class Meta:
        db_table = u'setting'

    def __unicode__(self):
        return self.name


class HostLog(models.Model):
    path = models.CharField(max_length=200, verbose_name=u'日志路径')
    host = models.ManyToManyField(Asset, verbose_name=u'日志关联主机')

    def __unicode__(self):
        return self.path

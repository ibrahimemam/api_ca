# Generated by Django 4.0.3 on 2023-06-17 01:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0017_rename_is_seen_mymodel_alarm_seen_delete_notificat'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='mymodel',
            name='alarm_seen',
        ),
        migrations.AddField(
            model_name='mymodel',
            name='alrm_at',
            field=models.DateTimeField(auto_now_add=True, default='2013-05-08 09:05:25.85'),
            preserve_default=False,
        ),
    ]
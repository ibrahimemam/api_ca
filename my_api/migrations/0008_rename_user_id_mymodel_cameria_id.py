# Generated by Django 4.0.3 on 2023-05-08 14:27

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0007_alter_mymodel_user_id'),
    ]

    operations = [
        migrations.RenameField(
            model_name='mymodel',
            old_name='User_id',
            new_name='cameria_id',
        ),
    ]

# Generated by Django 4.0.3 on 2023-06-14 09:43

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0009_notfication'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='notfication',
            name='owner',
        ),
    ]

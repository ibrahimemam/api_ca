# Generated by Django 4.0.3 on 2023-05-08 14:25

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0006_camira_reservation'),
    ]

    operations = [
        migrations.AlterField(
            model_name='mymodel',
            name='User_id',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='listings', to='api.camira'),
        ),
    ]
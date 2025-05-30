# Generated by Django 5.1.6 on 2025-05-17 13:24

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('voting', '0016_customuser_voted_candidates_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='CancellationRequest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('pool_id', models.IntegerField(help_text='ID of the pool requested to be cancelled.')),
                ('reason', models.TextField(help_text='Reason provided for cancellation.')),
                ('created_at', models.DateTimeField(auto_now_add=True, help_text='When the cancellation was requested.')),
                ('is_executed', models.BooleanField(default=False, help_text='Whether the cancellation has been executed on the blockchain.')),
                ('transaction_hash', models.CharField(blank=True, help_text='Blockchain transaction hash if executed.', max_length=66, null=True)),
                ('requested_by', models.ForeignKey(help_text='Admin who requested the cancellation.', on_delete=django.db.models.deletion.CASCADE, related_name='cancellation_requests', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Cancellation Request',
                'verbose_name_plural': 'Cancellation Requests',
                'ordering': ['-created_at'],
            },
        ),
    ]

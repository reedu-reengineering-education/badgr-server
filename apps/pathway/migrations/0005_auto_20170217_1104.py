# -*- coding: utf-8 -*-


from django.db import models, migrations
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('pathway', '0004_pathway_is_active'),
    ]

    operations = [
        migrations.AlterField(
            model_name='pathwayelement',
            name='completion_badgeclass',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='completion_elements', blank=True, to='issuer.BadgeClass', null=True),
            preserve_default=True,
        ),
    ]

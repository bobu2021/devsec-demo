from django.db import migrations, models

import philemon_mutabazi.models


class Migration(migrations.Migration):
    dependencies = [
        ("philemon_mutabazi", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="profile",
            name="avatar",
            field=models.FileField(
                blank=True,
                upload_to=philemon_mutabazi.models.avatar_upload_path,
            ),
        ),
        migrations.AddField(
            model_name="profile",
            name="document",
            field=models.FileField(
                blank=True,
                upload_to=philemon_mutabazi.models.document_upload_path,
            ),
        ),
    ]

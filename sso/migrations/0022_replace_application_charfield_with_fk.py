# Manual migration to replace application CharField with ForeignKey
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("sso", "0021_migrate_application_data"),
    ]

    operations = [
        # Step 1: Remove unique_together constraint (references old application field)
        migrations.AlterUniqueTogether(
            name="applicationrole",
            unique_together=set(),
        ),
        # Step 2: Remove old application CharField
        migrations.RemoveField(
            model_name="applicationrole",
            name="application",
        ),
        # Step 3: Rename application_new to application
        migrations.RenameField(
            model_name="applicationrole",
            old_name="application_new",
            new_name="application",
        ),
        # Step 4: Make application non-nullable
        migrations.AlterField(
            model_name="applicationrole",
            name="application",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="roles",
                to="sso.application",
            ),
        ),
        # Step 5: Re-add unique_together constraint with new FK field
        migrations.AlterUniqueTogether(
            name="applicationrole",
            unique_together={("user", "application")},
        ),
    ]

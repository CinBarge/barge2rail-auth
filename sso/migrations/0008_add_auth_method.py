from django.db import migrations, models


def classify_existing_users(apps, schema_editor):
    """Classify existing users by auth method"""
    User = apps.get_model('sso', 'User')

    for user in User.objects.all():
        if user.email and user.email.endswith('@barge2rail.com'):
            user.auth_method = 'google'
        elif hasattr(user, 'google_id') and user.google_id:
            user.auth_method = 'google'
        else:
            user.auth_method = 'password'
        user.save()


class Migration(migrations.Migration):

    dependencies = [
        ('sso', '0007_authorizationcode'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='auth_method',
            field=models.CharField(
                choices=[('google', 'Google OAuth'), ('password', 'Password Authentication')],
                default='password',
                help_text='How this user authenticates',
                max_length=20
            ),
        ),
        migrations.RunPython(classify_existing_users, reverse_code=migrations.RunPython.noop),
    ]

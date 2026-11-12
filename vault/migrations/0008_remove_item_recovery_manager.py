from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [("vault", "0007_user_auth_revision")]
    operations = [migrations.RemoveField(model_name="item", name="recovery_manager")]

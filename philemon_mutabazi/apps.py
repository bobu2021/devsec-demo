from django.apps import AppConfig


class PhilemonMutabaziConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "philemon_mutabazi"

    def ready(self):
        import philemon_mutabazi.signals

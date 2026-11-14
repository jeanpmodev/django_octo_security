import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")
django.setup()


def before_all(context):
    from django.test.utils import setup_test_environment, setup_databases

    setup_test_environment()
    context.old_config = setup_databases(verbosity=0, interactive=False)


def after_all(context):
    from django.test.utils import teardown_databases, teardown_test_environment

    teardown_databases(context.old_config, verbosity=0)
    teardown_test_environment()

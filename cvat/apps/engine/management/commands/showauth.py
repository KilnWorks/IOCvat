from django.core.management.base import BaseCommand
from django.conf import settings

class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        print("AUTHENTICATION_BACKENDS:")
        for b in settings.AUTHENTICATION_BACKENDS:
            print(f" - {b}")
        print("\nINSTALLED_APPS:")
        for app in settings.INSTALLED_APPS:
            if 'social' in app:
                print(f" - {app}")
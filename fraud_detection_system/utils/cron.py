from authenticate.models import User, Alerts
from userstats.views import send_alerts


class CronJob:
    users = list(User.objects.all())

    @staticmethod
    def weekly_alerts():
        for user in users:
            user_alerts = Alerts.objects.filter(user=user)
            if user_alerts.weekly_alerts == False:
                continue
            prepare_alerts(user, "week")

    @staticmethod
    def monthly_alerts():

        for user in users:
            user_alerts = Alerts.objects.filter(user=user)
            if user_alerts.monthly_alerts == False:
                continue
            prepare_alerts(user, "month")

    @staticmethod
    def year_alerts():

        for user in users:
            user_alerts = Alerts.objects.filter(user=user)
            if user_alerts.year_alerts == False:
                continue
            prepare_alerts(user, "year")
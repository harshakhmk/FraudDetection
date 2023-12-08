from notifications.signals import notify


class Notifications:
    @staticmethod
    def send_notification(sender, recipient, message):
        try:
            notify.send(
                actor=sender, recipient=recipient, verb="Message", description=message
            )
            return {"status": "success", "message": " Notification sent"}
        except Exception as e:
            return {
                "status": "error",
                "message": "unable to send notification",
                "details": f"{e} has occured",
            }
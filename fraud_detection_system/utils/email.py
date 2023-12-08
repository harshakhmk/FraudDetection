from django.core.mail import EmailMessage


class Util:
    @staticmethod
    def send_email(email_data):
        try:
            email = EmailMessage(
                subject=email_data["subject"],
                body=email_data["body"],
                to=[email_data["to_email"]],
            )
            email.send()
            return {"status": "success", "message": "email sent successfully"}
        except Exception as e:
            return {
                "status": "error",
                "message": "unable to send email",
                "details": f"{e} has occured",
            }
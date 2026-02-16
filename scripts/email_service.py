import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from icalendar import Calendar, Event, Alarm
from datetime import datetime, timedelta
import pytz
import sys

def create_ics_invitation(summary, start_time, duration_minutes, location, attendee_email, organizer_email):
    """
    Creates an .ics calendar invitation file content.
    """
    cal = Calendar()
    cal.add('prodid', '-//Programari Oftalmologie//dr-eye-david//RO')
    cal.add('version', '2.0')
    cal.add('method', 'REQUEST')

    event = Event()
    event.add('summary', summary)
    event.add('dtstart', start_time)
    event.add('dtend', start_time + timedelta(minutes=duration_minutes))
    event.add('dtstamp', datetime.now(pytz.UTC))
    event.add('location', location)
    event.add('organizer', organizer_email)
    event.add('status', 'confirmed')
    event.add('priority', 5)

    # Add Alarm (Reminder) 60 minutes before
    alarm = Alarm()
    alarm.add('action', 'DISPLAY')
    alarm.add('description', f'Reminder: {summary}')
    alarm.add('trigger', timedelta(minutes=-60))
    event.add_component(alarm)

    cal.add_component(event)
    return cal.to_ical()

def send_confirmation_email(patient_name, patient_email, appointment_type, start_time_str, location):
    """
    Sends a confirmation email with a calendar invitation.
    """
    # Configuration
    sender_email = "dr.eye.david@gmail.com"
    # SENDER_PASSWORD should be the 16-character App Password provided by the user
    # In a real scenario, this would be an environment variable or input
    sender_password = "brujheiuqtmxwmyo" 

    # Parse start time (Expected format: YYYY-MM-DD HH:MM)
    # Note: Adjust format based on your application's data
    try:
        start_time = datetime.strptime(start_time_str, "%Y-%m-%d %H:%M")
        start_time = pytz.timezone('Europe/Bucharest').localize(start_time)
    except ValueError:
        print(f"Error: Invalid date format {start_time_str}. Expected YYYY-MM-DD HH:MM")
        sys.exit(1)

    summary = f"Programare Prof. Dr. Balta Florian - [{appointment_type}]"
    
    # Create the email container
    msg = MIMEMultipart('mixed')
    msg['Subject'] = f"Confirmare Programare: {summary}"
    msg['From'] = sender_email
    msg['To'] = patient_email

    # HTML Body
    html_body = f"""
    <html>
    <body style="font-family: Arial, sans-serif;">
        <h2 style="color: #2c3e50;">Bună ziua, {patient_name}!</h2>
        <p>Programarea dumneavoastră a fost confirmată cu succes.</p>
        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 5px solid #007bff;">
            <p><strong>Detalii programare:</strong></p>
            <ul>
                <li><strong>Tip:</strong> {appointment_type}</li>
                <li><strong>Data și ora:</strong> {start_time.strftime('%d.%m.%Y %H:%M')}</li>
                <li><strong>Locație:</strong> {location}</li>
            </ul>
        </div>
        <p>Detaliile se află în invitația de calendar atașată. Vă rugăm să confirmați prezența folosind butoanele din e-mail.</p>
        <p>Vă mulțumim!</p>
        <p><em>Echipa Prof. Dr. Florian Balta</em></p>
    </body>
    </html>
    """
    msg.attach(MIMEText(html_body, 'html'))

    # Create .ics content
    ics_content = create_ics_invitation(
        summary=summary,
        start_time=start_time,
        duration_minutes=30,
        location=location,
        attendee_email=patient_email,
        organizer_email=sender_email
    )

    # Attach .ics file
    part = MIMEBase('text', 'calendar', method='REQUEST', name='invite.ics')
    part.set_payload(ics_content)
    encoders.encode_base64(part)
    part.add_header('Content-Description', 'Calendar Invitation')
    part.add_header('Content-Class', 'urn:content-classes:calendarmessage')
    part.add_header('Filename', 'invite.ics')
    part.add_header('Path', 'invite.ics')
    msg.attach(part)

    # SMTP Transmission
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        print(f"Email sent successfully to {patient_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")
        sys.exit(1)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        # Expected arguments: patient_name, patient_email, appointment_type, start_time_str, location
        try:
            p_name = sys.argv[1]
            p_email = sys.argv[2]
            p_type = sys.argv[3]
            p_time = sys.argv[4]
            p_loc = sys.argv[5]
            
            send_confirmation_email(p_name, p_email, p_type, p_time, p_loc)
        except IndexError:
            print("Error: Missing arguments.")
            print("Usage: python email_service.py 'Name' 'email@test.com' 'Type' 'YYYY-MM-DD HH:MM' 'Location'")
    else:
        # Example usage:
        # send_confirmation_email(
        #     patient_name="Alexandru",
        #     patient_email="alexynho2009@gmail.com",
        #     appointment_type="Consultație Oftalmologică",
        #     start_time_str="2026-02-25 10:00",
        #     location="Piața Alexandru Lahovari nr. 1, Sector 1, București"
        # )
        print("Email service script ready. Use command line arguments to send emails.")

from datetime import datetime


activities = []



def add_activity(
    title,
    description,
    activity_type="info",
    icon="activity"
):

    event = {

        "title": title,

        "description": description,

        "type": activity_type,

        "icon": icon,

        "time":
        datetime.now().strftime("%H:%M")

    }


    activities.insert(
        0,
        event
    )


    # نخلي آخر 50 حدث فقط
    if len(activities) > 50:
        activities.pop()



def get_activities():

    return {
        "activities": activities
    }

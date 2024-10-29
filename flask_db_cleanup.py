from datetime import datetime, timedelta
from app_generate_config import app, db, DeviceInfo

# Define the criteria for stale entries
days_old = 30
cutoff_date = datetime.utcnow() - timedelta(days=days_old)

with app.app_context():
    # Query for stale entries
    stale_devices = DeviceInfo.query.filter(DeviceInfo.last_updated < cutoff_date).all()

    # Print the stale entries for review
    print(f"Found {len(stale_devices)} stale devices:")
    for device in stale_devices:
        print(f"Device ID: {device.id}, Hostname: {device.hostname}, Last Updated: {device.last_updated}")

    # Confirm deletion
    confirm = input(f"Do you want to delete these {len(stale_devices)} devices? (y/n): ")
    if confirm.lower() == 'y':
        # Delete stale entries
        for device in stale_devices:
            db.session.delete(device)
        db.session.commit()
        print("Stale devices deleted successfully.")
    else:
        print("Deletion aborted.")

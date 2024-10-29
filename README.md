Author: surajsharma@juniper.net

# Project Name
easy_configuration

## Setup Instructions

### Prerequisites
Ensure you have Python 3.8+ installed.

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/surajnsharma/easy_configuration.git
   cd easy_configuration

2. Set up a virtual environment (optional but recommended):
python3 -m venv venv
source venv/bin/activate

3. Install the required packages:
pip install -r requirements.txt

## Running the Application
1. Initialize the Flask application:

export FLASK_APP="app:create_app('development')" or export FLASK_APP="app:create_app('production')"
./start_app.sh

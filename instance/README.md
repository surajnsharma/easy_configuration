surajsharma@surajsharma-mbp instance % sqlite3 app_database.db ".schema"
CREATE TABLE user (
	id INTEGER NOT NULL, 
	username VARCHAR(150) NOT NULL, 
	password_hash VARCHAR(150) NOT NULL, 
	role VARCHAR(50) NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (username)
);
CREATE TABLE device_info (
	id INTEGER NOT NULL, 
	user_id INTEGER NOT NULL, 
	hostname VARCHAR(150) NOT NULL, 
	ip VARCHAR(150) NOT NULL, 
	username VARCHAR(150) NOT NULL, 
	password VARCHAR(150) NOT NULL, 
	last_updated DATETIME, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES user (id), 
	UNIQUE (ip)
);
CREATE TABLE topology (
	id INTEGER NOT NULL, 
	user_id INTEGER NOT NULL, 
	csv_data TEXT NOT NULL, 
	timestamp DATETIME, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES user (id)
);


CREATE TABLE users (
	id VARCHAR NOT NULL, 
	label VARCHAR NOT NULL, 
	ssh_public_key VARCHAR NOT NULL, 
	ssh_key_fingerprint VARCHAR NOT NULL, 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (id)
);
CREATE UNIQUE INDEX ix_users_label ON users (label);
CREATE UNIQUE INDEX ix_users_ssh_key_fingerprint ON users (ssh_key_fingerprint);
CREATE TABLE enroll_challenges (
	id VARCHAR NOT NULL, 
	fingerprint VARCHAR NOT NULL, 
	challenge VARCHAR NOT NULL, 
	created_at DATETIME NOT NULL, 
	expires_at DATETIME NOT NULL, 
	used_at DATETIME, 
	PRIMARY KEY (id)
);
CREATE INDEX ix_enroll_challenges_fingerprint ON enroll_challenges (fingerprint);
CREATE TABLE server_secrets (
	name VARCHAR NOT NULL, 
	value VARCHAR NOT NULL, 
	PRIMARY KEY (name)
);
CREATE TABLE devices (
	id VARCHAR NOT NULL, 
	name VARCHAR NOT NULL, 
	owner_user_id VARCHAR NOT NULL, 
	cert_serial VARCHAR NOT NULL, 
	api_token_hash VARCHAR NOT NULL, 
	enrolled_at DATETIME NOT NULL, 
	last_seen_at DATETIME, 
	agent_version VARCHAR, 
	enabled BOOLEAN NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_devices_owner_name UNIQUE (owner_user_id, name), 
	FOREIGN KEY(owner_user_id) REFERENCES users (id)
);
CREATE INDEX ix_devices_name ON devices (name);
CREATE UNIQUE INDEX ix_devices_api_token_hash ON devices (api_token_hash);
CREATE INDEX ix_devices_owner_user_id ON devices (owner_user_id);
CREATE TABLE enroll_tokens (
	id VARCHAR NOT NULL, 
	token_hash VARCHAR NOT NULL, 
	device_name_hint VARCHAR, 
	created_by VARCHAR NOT NULL, 
	created_at DATETIME NOT NULL, 
	expires_at DATETIME NOT NULL, 
	used_at DATETIME, 
	revoked_at DATETIME, 
	PRIMARY KEY (id), 
	FOREIGN KEY(created_by) REFERENCES users (id)
);
CREATE UNIQUE INDEX ix_enroll_tokens_token_hash ON enroll_tokens (token_hash);
CREATE TABLE key_rotation_challenges (
	id VARCHAR NOT NULL, 
	device_id VARCHAR NOT NULL, 
	public_key VARCHAR NOT NULL, 
	challenge VARCHAR NOT NULL, 
	created_at DATETIME NOT NULL, 
	expires_at DATETIME NOT NULL, 
	used_at DATETIME, 
	PRIMARY KEY (id), 
	FOREIGN KEY(device_id) REFERENCES devices (id)
);
CREATE INDEX ix_key_rotation_challenges_device_id ON key_rotation_challenges (device_id);
CREATE TABLE services (
	id VARCHAR NOT NULL, 
	device_id VARCHAR NOT NULL, 
	name VARCHAR NOT NULL, 
	protocol VARCHAR(3) NOT NULL, 
	target_port INTEGER NOT NULL, 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(device_id) REFERENCES devices (id)
);
CREATE UNIQUE INDEX ix_services_name ON services (name);
CREATE INDEX ix_services_device_id ON services (device_id);
CREATE TABLE grants (
	id VARCHAR NOT NULL, 
	service_id VARCHAR NOT NULL, 
	consumer_device_id VARCHAR NOT NULL, 
	secret VARCHAR NOT NULL, 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(service_id) REFERENCES services (id), 
	FOREIGN KEY(consumer_device_id) REFERENCES devices (id)
);
CREATE INDEX ix_grants_consumer_device_id ON grants (consumer_device_id);
CREATE INDEX ix_grants_service_id ON grants (service_id);

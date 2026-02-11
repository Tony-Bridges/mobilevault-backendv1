-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    encrypted_master_key BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    subscription_tier VARCHAR(50) DEFAULT 'free',
    metadata JSONB DEFAULT '{}'
);

-- User sessions (for auth)
CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(512) UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    ip_address INET,
    user_agent TEXT
);

-- Virtual devices
CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    model VARCHAR(100) NOT NULL DEFAULT 'Pixel 6',
    android_version VARCHAR(20) NOT NULL DEFAULT '13',
    cpu_cores INT DEFAULT 4,
    ram_mb INT DEFAULT 8192,
    storage_gb INT DEFAULT 128,
    gpu_enabled BOOLEAN DEFAULT false,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}'
);

-- Snapshots (immutable)
CREATE TABLE snapshots (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID REFERENCES devices(id),
    parent_snapshot_id UUID REFERENCES snapshots(id),
    name VARCHAR(100) NOT NULL,
    storage_path VARCHAR(500) NOT NULL,
    size_bytes BIGINT NOT NULL,
    is_base BOOLEAN DEFAULT false,
    is_auto BOOLEAN DEFAULT false,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Indexes for performance
    INDEX idx_snapshots_user (user_id, created_at DESC),
    INDEX idx_snapshots_device (device_id)
);

-- Active sessions (cloud VM sessions)
CREATE TABLE vm_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID REFERENCES devices(id),
    snapshot_id UUID REFERENCES snapshots(id),
    vm_host_id VARCHAR(100) NOT NULL,
    overlay_path VARCHAR(500) NOT NULL,
    streaming_url VARCHAR(500),
    webrtc_offer TEXT,
    status VARCHAR(50) DEFAULT 'creating',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP WITH TIME ZONE,
    ended_at TIMESTAMP WITH TIME ZONE,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Performance indexes
    INDEX idx_vm_sessions_active (status, last_activity),
    INDEX idx_vm_sessions_user (user_id)
);

-- VM Hosts (edge nodes)
CREATE TABLE vm_hosts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hostname VARCHAR(100) UNIQUE NOT NULL,
    region VARCHAR(50) NOT NULL,
    ip_address INET NOT NULL,
    capacity_cpu INT NOT NULL,
    capacity_ram_mb INT NOT NULL,
    capacity_gpu BOOLEAN DEFAULT false,
    available_cpu INT DEFAULT 0,
    available_ram_mb INT DEFAULT 0,
    current_sessions INT DEFAULT 0,
    max_sessions INT DEFAULT 10,
    is_active BOOLEAN DEFAULT true,
    last_heartbeat TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}'
);

-- User preferences/settings
CREATE TABLE user_settings (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    streaming_quality VARCHAR(20) DEFAULT 'adaptive',
    auto_snapshot BOOLEAN DEFAULT true,
    snapshot_interval_hours INT DEFAULT 3,
    default_region VARCHAR(50) DEFAULT 'us-east-1',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create function to update timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger for user_settings
CREATE TRIGGER update_user_settings_updated_at 
    BEFORE UPDATE ON user_settings 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
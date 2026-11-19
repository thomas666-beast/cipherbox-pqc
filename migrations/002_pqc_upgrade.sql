ALTER TABLE users ADD COLUMN IF NOT EXISTS pqc_nonce_expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_messages_room_id_desc ON messages (room_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_room_members_user_room ON room_members (user_id, room_id);

-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (token, created_at, updated_at, expires_at, revoked_at, user_id)
VALUES (
    $1,
    NOW(),
    NOW(),
    NOW() + INTERVAL '60 days',
    NULL,
    $2
)
RETURNING *;

-- name: GetSingleRefreshToken :one
SELECT * FROM refresh_tokens
WHERE token = $1;

-- name: RevokeRefreshToken :one
UPDATE refresh_tokens
SET revoked_at = NOW(), updated_at = NOW()
WHERE token = $1
RETURNING *;
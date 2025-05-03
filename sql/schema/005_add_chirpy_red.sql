-- +goose Up
ALTER TABLE users
ADD COLUMN is_chirpy_red BOOLEAN DEFAULT false;

ALTER TABLE users
ALTER COLUMN is_chirpy_red SET NOT NULL;

-- +goose Down
ALTER TABLE users
DROP COLUMN is_chirpy_red;

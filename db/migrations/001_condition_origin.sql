-- Existing rows remain unknown until their source format has been verified.
ALTER TABLE policy ADD COLUMN IF NOT EXISTS condition_origin text;

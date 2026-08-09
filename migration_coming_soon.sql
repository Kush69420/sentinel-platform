-- Mobile OSINT (mobile_lookup) is the only module live for Day 1 go-live.
-- Mark every other catalog service "upcoming" so the dashboard shows a
-- "COMING SOON" badge instead of letting users click into a dead tool.
-- To bring a module live later: UPDATE services SET status='enabled' WHERE code='<code>';
UPDATE services SET status='upcoming' WHERE code <> 'mobile_lookup';
UPDATE services SET status='enabled', is_enabled=1 WHERE code='mobile_lookup';

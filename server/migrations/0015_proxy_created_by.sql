-- Who added a proxy.
--
-- Until now only owners and admins could add one, and they may change any
-- proxy, so nobody needed to know. From here a person holding edit_proxy on a
-- project may add proxies too, and change or retire the ones they added -- not
-- a colleague's, which other profiles may be going out through. That rule needs
-- this column. NULL is every proxy that existed before it, and those stay with
-- the owners and admins who added them.
ALTER TABLE proxies ADD COLUMN created_by UUID REFERENCES users(id) ON DELETE SET NULL;

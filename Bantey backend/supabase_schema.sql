-- ============================================================================
-- supabase_schema.sql - creates/configures EVERY table the rewritten backend
-- (api/app.py) needs. Idempotent: safe to re-run.
--
-- HOW TO RUN: Supabase dashboard -> SQL editor -> paste whole file -> Run.
-- Service-role key only: Row Level Security is intentionally LEFT OFF on
-- every table, because the backend talks to Supabase with the service-role
-- key which bypasses RLS anyway. Do NOT expose these tables through the
-- public PostgREST API (anon key) - keep the anon key out of the client.
-- ============================================================================

-- ============================================================================
-- AUTH / IDENTITY
-- ============================================================================

-- device_players: THE device-key lock. One device key = one PlayFab account
-- + one PERMANENT MothershipID, assigned on first login, never rotated.
CREATE TABLE IF NOT EXISTS public.device_players (
    device_key   text PRIMARY KEY,
    playfabid    text NOT NULL,
    mothershipid uuid NOT NULL UNIQUE,
    platform     text DEFAULT 'Steam',
    created_at   timestamptz DEFAULT now(),
    last_login   timestamptz DEFAULT now()
);

-- players: PlayFab-side identity + display name + cosmetics bookkeeping
CREATE TABLE IF NOT EXISTS public.players (
    playfabid     text PRIMARY KEY,
    oculusid      text,
    displayname   text,
    platform      text DEFAULT 'Steam',
    sessionticket text,
    entitytoken   text,
    entityid      text,
    entitytype    text,
    last_daily    text,
    createdat     timestamptz DEFAULT now(),
    lastlogin     timestamptz DEFAULT now()
);

-- mothershipplayers: MothershipID <-> external id, plus the cached ES256
-- player token so repeat logins reuse it until it nears expiry.
CREATE TABLE IF NOT EXISTS public.mothershipplayers (
    mothershipid    uuid PRIMARY KEY,
    userid          text,
    platform        text DEFAULT 'STEAM',
    token           text,
    expirationtime  bigint DEFAULT 0,
    lastlogin       timestamptz DEFAULT now()
);

-- ============================================================================
-- TITLE DATA / USER DATA
-- ============================================================================

-- mothershiptitledata: key/value store. datakey examples: MOTD,
-- AllActiveQuests (JSON string), progression_tree (official {'Results': [...]}
-- JSON string - required for the SI gadget trees).
CREATE TABLE IF NOT EXISTS public.mothershiptitledata (
    datakey   text PRIMARY KEY,
    datavalue text NOT NULL DEFAULT ''
);

-- mothershipuserdata: per-player key/value blobs (map saves, cosmetics list)
CREATE TABLE IF NOT EXISTS public.mothershipuserdata (
    mothershipid uuid NOT NULL,
    keyname      text NOT NULL,
    datavalue    text NOT NULL DEFAULT '',
    updatedat    timestamptz DEFAULT now(),
    PRIMARY KEY (mothershipid, keyname)
);

-- sharedgroupdata: self-hosted PlayFab shared groups (room actor data,
-- BroadcastMyRoomV2 room pointers)
CREATE TABLE IF NOT EXISTS public.sharedgroupdata (
    groupid   text NOT NULL,
    datakey   text NOT NULL,
    value     text NOT NULL DEFAULT '',
    updatedat timestamptz DEFAULT now(),
    PRIMARY KEY (groupid, datakey)
);

-- player_readonlydata: Client/GetUserReadOnlyData backing store
CREATE TABLE IF NOT EXISTS public.player_readonlydata (
    playfabid text   NOT NULL,
    datakey   text   NOT NULL,
    datavalue text   NOT NULL DEFAULT '',
    updatedat timestamptz DEFAULT now(),
    PRIMARY KEY (playfabid, datakey)
);

-- ============================================================================
-- FRIENDS / PRIVACY / PRESENCE
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.friendlinks (
    playerid  text NOT NULL,
    friendid  text NOT NULL,
    createdat timestamptz DEFAULT now(),
    PRIMARY KEY (playerid, friendid)
);

CREATE TABLE IF NOT EXISTS public.friendpresence (
    playfabid text PRIMARY KEY,
    roomid    text NOT NULL DEFAULT '',
    zone      text NOT NULL DEFAULT '',
    region    text NOT NULL DEFAULT '',
    nickname  text NOT NULL DEFAULT '',
    updatedat timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.privacystates (
    playfabid text PRIMARY KEY,
    state     text NOT NULL DEFAULT 'VISIBLE'  -- VISIBLE | PUBLIC_ONLY | HIDDEN
);

-- ============================================================================
-- RANKED / MATCHES
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.rankeddata (
    playfabid    text NOT NULL,
    platform     text NOT NULL,              -- PC | Quest
    elo          double precision NOT NULL DEFAULT 1000,
    majortier    integer NOT NULL DEFAULT 2,
    minortier    integer NOT NULL DEFAULT 0,
    rankprogress double precision NOT NULL DEFAULT 0,
    PRIMARY KEY (playfabid, platform)
);

CREATE TABLE IF NOT EXISTS public.matchids (
    matchid    text PRIMARY KEY,
    createdby  text,
    platform   text DEFAULT 'PC',
    isactive   smallint NOT NULL DEFAULT 1,
    lastping   timestamptz
);

CREATE TABLE IF NOT EXISTS public.matchparticipants (
    matchid   text NOT NULL,
    playfabid text NOT NULL,
    PRIMARY KEY (matchid, playfabid)
);

-- ============================================================================
-- QUESTS (daily/weekly points ledger)
-- ============================================================================

-- Official point keys: dailyPoints = 'MM/DD/YYYY', weeklyPoints = ISO week
CREATE TABLE IF NOT EXISTS public.queststatus (
    playfabid       text PRIMARY KEY,
    dailypoints     text NOT NULL DEFAULT '{}',
    weeklypoints    text NOT NULL DEFAULT '{}',
    userpointstotal integer NOT NULL DEFAULT 0,
    updatedat       timestamptz DEFAULT now()
);

-- ============================================================================
-- SUPER INFECTION
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.si_player_resources (
    mothershipid     uuid PRIMARY KEY,
    tech_points      integer NOT NULL DEFAULT 0,
    strange_wood     integer NOT NULL DEFAULT 0,
    weird_gear       integer NOT NULL DEFAULT 0,
    vibrating_spring integer NOT NULL DEFAULT 0,
    bouncy_sand      integer NOT NULL DEFAULT 0,
    floppy_metal     integer NOT NULL DEFAULT 0,
    updated_at       timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.si_player_quest_status (
    mothershipid           uuid PRIMARY KEY,
    stashed_quests         integer NOT NULL DEFAULT 3,
    stashed_bonus_points   integer NOT NULL DEFAULT 1,
    bonus_progress         integer NOT NULL DEFAULT 0,
    daily_limited_turned_in boolean NOT NULL DEFAULT false,
    last_reset_date        date,
    updated_at             timestamptz DEFAULT now()
);

-- ============================================================================
-- PROGRESSION
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.progression (
    mothershipid uuid NOT NULL,
    trackid      text NOT NULL,
    progress     integer NOT NULL DEFAULT 0,
    PRIMARY KEY (mothershipid, trackid)
);

CREATE TABLE IF NOT EXISTS public.progressionnodes (
    mothershipid uuid NOT NULL,
    treeid       text NOT NULL,
    nodeid       text NOT NULL,
    unlockedat   timestamptz DEFAULT now(),
    PRIMARY KEY (mothershipid, treeid, nodeid)
);

-- ============================================================================
-- GHOST REACTOR ECONOMY (shift credits, juicer, dock wrist, shifts)
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.shiftcredits (
    mothershipid uuid PRIMARY KEY,
    currentcredits integer NOT NULL DEFAULT 100,
    capincreases   integer NOT NULL DEFAULT 0,
    capincreasesmax integer NOT NULL DEFAULT 25
);

CREATE TABLE IF NOT EXISTS public.juicerstatus (
    mothershipid       uuid PRIMARY KEY,
    corecount          integer NOT NULL DEFAULT 0,
    processingpercent  integer NOT NULL DEFAULT 0,
    overdrivesupply    integer NOT NULL DEFAULT 0,
    overdrivecap       integer NOT NULL DEFAULT 5,
    coresbyoverdrive   integer NOT NULL DEFAULT 0,
    refreshjuice       smallint NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS public.dockwrist (
    mothershipid  uuid PRIMARY KEY,
    upgrade1level integer NOT NULL DEFAULT 0,
    upgrade2level integer NOT NULL DEFAULT 0,
    upgrade3level integer NOT NULL DEFAULT 0,
    upgrade1max   integer NOT NULL DEFAULT 10,
    upgrade2max   integer NOT NULL DEFAULT 10,
    upgrade3max   integer NOT NULL DEFAULT 10
);

CREATE TABLE IF NOT EXISTS public.shifts (
    shiftid        text PRIMARY KEY,
    mothershipid   uuid,
    coresrequired  integer NOT NULL DEFAULT 0,
    numberofplayers integer NOT NULL DEFAULT 0,
    depth          integer NOT NULL DEFAULT 0,
    startedat      timestamptz DEFAULT now(),
    completed      smallint NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS public.reactorstats (
    mothershipid    uuid PRIMARY KEY,
    maxdepthreached integer NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS public.reactorinventory (
    mothershipid  uuid PRIMARY KEY,
    inventoryjson text NOT NULL DEFAULT '{}'
);

-- ============================================================================
-- SHARED MAPS (Destinations / Virtual Stump)
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.sharedmaps (
    mapid               text PRIMARY KEY,
    mothershipid        uuid,
    userdatametadatakey text NOT NULL DEFAULT '',
    nickname            text NOT NULL DEFAULT '',
    mapdata             text NOT NULL DEFAULT '',
    votecount           integer NOT NULL DEFAULT 0,
    isactive            smallint NOT NULL DEFAULT 1,
    createdat           timestamptz DEFAULT now(),
    updatedat           timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.mapvotes (
    mapid        text NOT NULL,
    mothershipid uuid NOT NULL,
    vote         integer NOT NULL DEFAULT 0,   -- 1 | 0 | -1
    PRIMARY KEY (mapid, mothershipid)
);

-- ============================================================================
-- POLLS
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.polls (
    id          bigserial PRIMARY KEY,
    question    text NOT NULL,
    options_json text NOT NULL DEFAULT '[]',
    created_at  timestamptz DEFAULT now(),
    expires_at  timestamptz
);

CREATE TABLE IF NOT EXISTS public.poll_votes (
    id           bigserial PRIMARY KEY,
    poll_id      bigint NOT NULL REFERENCES public.polls(id) ON DELETE CASCADE,
    playfabid    text NOT NULL,
    option_index integer NOT NULL,
    is_prediction smallint NOT NULL DEFAULT 0,
    created_at   timestamptz DEFAULT now(),
    UNIQUE (poll_id, playfabid, is_prediction)
);

-- ============================================================================
-- CODES / LINKS / AGREEMENTS
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.redeemable_codes (
    id               bigserial PRIMARY KEY,
    code             text NOT NULL UNIQUE,
    active           smallint NOT NULL DEFAULT 1,
    type             text,                       -- e.g. discord_link | item
    item_id          text,
    playfab_item_name text,
    discord_id       text,
    start_time       timestamptz,
    end_time         timestamptz,
    max_uses         integer NOT NULL DEFAULT -1, -- -1 = unlimited
    use_count        integer NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS public.code_redemptions (
    id           bigserial PRIMARY KEY,
    code_id      bigint,
    code         text NOT NULL,
    mothershipid uuid,
    playfabid    text,
    createdat    timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.discord_links (
    discord_id   text PRIMARY KEY,
    playfabid    text,
    mothershipid uuid,
    linked_at    timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.acceptedagreements (
    playfabid    text NOT NULL,
    agreementkey text NOT NULL,                 -- TOS | PrivacyPolicy
    version      text NOT NULL,
    acceptedat   timestamptz DEFAULT now(),
    PRIMARY KEY (playfabid, agreementkey)
);

-- ============================================================================
-- MODERATION / ANALYTICS / ROOMS
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.player_reports (
    id                  bigserial PRIMARY KEY,
    reporter_playfabid  text,
    reporter_name       text,
    reported_playfabid  text,
    reported_name       text,
    reason              text,
    room_code           text,
    createdat           timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.gorillanalytics (
    id            bigserial PRIMARY KEY,
    playfabid     text,
    upload_id     text,
    interval_sec  integer,
    start_time    text,
    sessions_json text,
    users_json    text,
    createdat     timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.ghostgames (
    id                             bigserial PRIMARY KEY,
    mothershipid                   uuid,
    ghost_game_id                  text,
    event_timestamp                text,
    final_cores_balance            integer,
    total_cores_collected_by_player integer,
    total_cores_collected_by_group integer,
    total_cores_spent_by_player    integer,
    total_cores_spent_by_group     integer,
    gates_unlocked                 integer,
    died                           integer,
    items_purchased                text,
    shift_cut_data                 text,
    play_duration                  integer,
    started_late                   text,
    time_started                   text,
    reason                         text,
    max_number_in_game             integer,
    end_number_in_game             integer,
    items_picked_up                text,
    revives                        integer,
    num_shifts_played              integer,
    game_version                   text,
    game_environment               text,
    createdat                      timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.rooms (
    gameid    text PRIMARY KEY,
    region    text NOT NULL DEFAULT '',
    isactive  smallint NOT NULL DEFAULT 1,
    createdat timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.room_states (
    gameid     text PRIMARY KEY,
    region     text NOT NULL DEFAULT '',
    state_json text NOT NULL DEFAULT '{}',
    updatedat  timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.dear_lemmings (
    id           bigserial PRIMARY KEY,
    mothershipid uuid NOT NULL,
    message_text text NOT NULL,
    display_name text,
    createdat    timestamptz DEFAULT now()
);

-- ============================================================================
-- Useful indexes
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_players_displayname        ON public.players(displayname);
CREATE INDEX IF NOT EXISTS idx_friendlinks_friend         ON public.friendlinks(friendid);
CREATE INDEX IF NOT EXISTS idx_friendpresence_room        ON public.friendpresence(roomid);
CREATE INDEX IF NOT EXISTS idx_mothershipplayers_userid   ON public.mothershipplayers(userid);
CREATE INDEX IF NOT EXISTS idx_device_players_playfabid   ON public.device_players(playfabid);
CREATE INDEX IF NOT EXISTS idx_sharedmaps_votes           ON public.sharedmaps(votecount DESC);
CREATE INDEX IF NOT EXISTS idx_sharedmaps_created         ON public.sharedmaps(createdat DESC);
CREATE INDEX IF NOT EXISTS idx_sharedgroupdata_group      ON public.sharedgroupdata(groupid);
CREATE INDEX IF NOT EXISTS idx_poll_votes_poll            ON public.poll_votes(poll_id);
CREATE INDEX IF NOT EXISTS idx_code_redemptions_code      ON public.code_redemptions(code);
CREATE INDEX IF NOT EXISTS idx_matchids_active            ON public.matchids(isactive);

-- ============================================================================
-- auto-update updatedat for the hot tables
-- ============================================================================

CREATE OR REPLACE FUNCTION public.update_updatedat_column()
RETURNS trigger AS $$
BEGIN
    NEW.updatedat = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_players_updatedat ON public.players;
CREATE TRIGGER trg_players_updatedat
    BEFORE UPDATE ON public.players
    FOR EACH ROW EXECUTE FUNCTION public.update_updatedat_column();

DROP TRIGGER IF EXISTS trg_friendpresence_updatedat ON public.friendpresence;
CREATE TRIGGER trg_friendpresence_updatedat
    BEFORE UPDATE ON public.friendpresence
    FOR EACH ROW EXECUTE FUNCTION public.update_updatedat_column();

DROP TRIGGER IF EXISTS trg_sharedmaps_updatedat ON public.sharedmaps;
CREATE TRIGGER trg_sharedmaps_updatedat
    BEFORE UPDATE ON public.sharedmaps
    FOR EACH ROW EXECUTE FUNCTION public.update_updatedat_column();

-- ============================================================================
-- Title data comes from PLAYFAB (Server/GetTitleData) - the backend proxies
-- it directly. The mothershiptitledata table stays EMPTY unless you want to
-- manually override specific keys (rows there win over PlayFab).
--
-- Example override (uncomment and edit if ever needed):
-- INSERT INTO public.mothershiptitledata (datakey, datavalue)
-- VALUES ('MOTD', 'MY CUSTOM MESSAGE OF THE DAY')
-- ON CONFLICT (datakey) DO UPDATE SET datavalue = EXCLUDED.datavalue;
-- ============================================================================

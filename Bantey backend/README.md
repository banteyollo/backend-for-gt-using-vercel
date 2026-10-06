so this backend is for newest and oldest (like 2023M to current) so here im gonna give my backend and the method of patching clients

so the backend needs ur stuff like playfab photon and database witch is SupaBase so every one here

SUPABASE_URL  usually has this at the end .supabase.co
supabase_key
playfab_title_id
playfab_secret_key

so fill these with ur stuff

so in the files you have supabase_schema.sql open it and copy and paste to supabase table editor like the command stuff disable rls cuz we dont need it

ok so you also have the full backend file it has app.py main backend and data that has some title datas and siprogression used to spawn gadgets stuff like this
so but the full file on github and api\ must be in the root so dont paste the fodler to git but the stuff inside of it

about photon in settings of ur realtime and vocie in authentication url in custom provide paste ur backend url and this at the end /api/photon

you need webhook too so base url of webhook ur backend url and this at the end /webhook

now in webhook optional settings keys are like this

AsyncJoin  true
HasErrorInfo  true
IsPersistent  false
PathClose  PathClose
PathCreate  PathCreate
PathEvent  PathRaiseEvent
PathGameProperties  PathGameProperties
PathJoin  PathJoin
PathLeave  PathLeave

ok now should be all in photon so now in playfab

so add a title data the title data is here in files from the newest halloween 26

and add Currency in Currency(legacy) short name SR and displayname SHINY ROCKS

and add catalog DLC in catalog(legacy) the DLC is here in files

and add stuff in CloudScript/Functions
so heres every function basically firstly u paste ur backend url then the function anmes below

/CloudScript/ReturnCurrentVersionV2
/CloudScript/TryDistributeCurrencyV2
/CloudScript/AddOrRemoveDLCOwnershipV2
/CloudScript/BroadcastMyRoomV2
/CloudScript/UpdatePersonalCosmeticsList
/api/GetAcceptedAgreements
/CloudScript/SubmitAcceptedAgreements
/CloudScript/Gorillanalytics
/CloudScript/CheckForBadName
/CloudScript/GetRandomName
/CloudScript/ReturnQueueStats
/CloudScript/ReturnVstumpMapStats
/CloudScript/GetCatalogItems

ok now after you setted up backend in vercel
lets patch the client
so you gotta download DnSpy i use netframework and also download uabea

so firstly dnspy patch read the "full customID METHOD.md" and replace the stuff then save the patch

now in uabea you gotta edit theyre stuff to yours
so you see this "UABEA EDITING.txt" it has every monobehaviour u gotta edit
how to edit?

in UABEA open this file so open ur gtag folder u editing and this Gorilla Tag_Data\resources.assets
use filters for easy life
so deselect everything except mono behaviour and search the stuff and edit with ur ids and backend urls

also a bug in UABEA if u search any of these and it says it doesn't exist save and reopen UABEA and use filters and search again should be fine

ok so now if u did it correctly you should have a working backend so private rooms work also names too

also the backend is coded by ai glm5.3 flash i made it cuz i have a mod that gives me every ednpoint the game uses and its response it helped

and ye the game should be fine. if you have any issues DM me on DisCord

MADE BY BANTEY

//dont use it cuz i fixed checkforbadname endpoint so private rooms work also names too

using BepInEx;
using GorillaNetworking;
using GorillaTagScripts;
using HarmonyLib;
using System.Reflection;

namespace DirectRoomJoin
{
    [BepInPlugin("com.fabci.directroomjoin", "Direct Room Join", "1.0.0")]
    [BepInProcess("Gorilla Tag.exe")]
    public class DirectRoomJoinPlugin : BaseUnityPlugin
    {
        private void Awake()
        {
            Harmony.CreateAndPatchAll(typeof(Patch_ProcessRoomState));
            Logger.LogInfo("Direct Room Join Plugin loaded!");
        }
    }

    [HarmonyPatch(typeof(GorillaComputer), "ProcessRoomState")]
    public static class Patch_ProcessRoomState
    {
        // Cache the field info for better performance
        private static FieldInfo _playerInVirtualStumpField =
            AccessTools.Field(typeof(GorillaComputer), "playerInVirtualStump");

        private static FieldInfo _roomToJoinField =
            AccessTools.Field(typeof(GorillaComputer), "roomToJoin");

        private static FieldInfo _networkControllerField =
            AccessTools.Field(typeof(GorillaComputer), "networkController");

        static bool Prefix(
            GorillaComputer __instance,
            GorillaKeyboardBindings buttonPressed
        )
        {
            // Only intercept the ENTER key press
            if (buttonPressed != GorillaKeyboardBindings.enter)
            {
                return true;
            }

            // Check if KID permission allows room joining
            bool flag = KIDManager.HasPermissionToUseFeature(EKIDFeatures.Groups);
            if (!flag)
            {
                return true;
            }

            // Access private fields using AccessTools
            bool playerInVirtualStump = (bool)_playerInVirtualStumpField.GetValue(__instance);
            string roomToJoin = (string)_roomToJoinField.GetValue(__instance);
            PhotonNetworkController networkController = (PhotonNetworkController)_networkControllerField.GetValue(__instance);

            // Check if room name is valid (same logic as original enter case)
            bool canJoin = (!playerInVirtualStump && roomToJoin != "") ||
                           (playerInVirtualStump && roomToJoin.Length > 1);

            if (!canJoin)
            {
                return true;
            }

            // ✅ YOUR CUSTOM CODE: Skip CheckAutoBanListForRoomName
            // Join the room directly
            JoinType joinType = FriendshipGroupDetection.Instance.IsInParty
                ? JoinType.ForceJoinWithParty
                : JoinType.Solo;

            networkController.AttemptToJoinSpecificRoom(
                roomToJoin,
                joinType
            );

            // Return false to skip the original method entirely
            return false;
        }
    }
}

INFO if any of these dont work when u do edit method beside steamauthenticator make a harmonypatch with AI

the new method is customid and it makes everything work
so in authenitcatewithplayfab in playfabauthenticator do this


PlayFabClientAPI.LoginWithCustomID(new LoginWithCustomIDRequest
					{
						CreateAccount = new bool?(true),
						CustomId = ticket
					},


before its probably loginwithsteam instead of customid

and also we gotta change steamauthenticator
==================FULL STEAMAUTHENTICATOR=========================

using System;
using System.Collections;
using System.Text;
using Steamworks;
using UnityEngine;
using UnityEngine.Networking;

public class SteamAuthenticator : MonoBehaviour
{
    // Store device ID for persistence
    private static string cachedDeviceId = null;
    
    // ============================================================
    // REPLACED: GetAuthTicket - Now uses Device ID instead of Steam
    // ============================================================
    public HAuthTicket GetAuthTicket(Action<string> successCallback, Action<EResult> failureCallback)
    {
        // Get or generate device ID
        string deviceId = GetOrCreateDeviceId();
        
        Debug.Log($"[SteamAuthenticator] Using Device ID instead of Steam: {deviceId}");
        
        // Call success with device ID (the game expects a string ticket)
        successCallback?.Invoke(deviceId);
        
        // Return dummy ticket (we're not using Steam anymore)
        return HAuthTicket.Invalid;
    }

    // ============================================================
    // REPLACED: GetAuthTicketForWebApi - Now uses Device ID
    // ============================================================
    public HAuthTicket GetAuthTicketForWebApi(string authenticatorId, Action<string> successCallback, Action<EResult> failureCallback)
    {
        // Get or generate device ID
        string deviceId = GetOrCreateDeviceId();
        
        Debug.Log($"[SteamAuthenticator] Using Device ID for Web API: {deviceId}");
        
        // Call success with device ID
        successCallback?.Invoke(deviceId);
        
        // Return dummy ticket
        return HAuthTicket.Invalid;
    }

    // ============================================================
    // NEW: Get or create device ID
    // ============================================================
    private string GetOrCreateDeviceId()
    {
        // Use cached device ID if available
        if (!string.IsNullOrEmpty(cachedDeviceId))
        {
            return cachedDeviceId;
        }
        
        // Generate from system info
        string deviceId = SystemInfo.deviceUniqueIdentifier;
        
        // Fallback if device unique identifier is not available
        if (string.IsNullOrEmpty(deviceId) || deviceId == "00000000000000000000000000000000")
        {
            // Generate from hardware info
            deviceId = GenerateDeviceId();
        }
        
        cachedDeviceId = deviceId;
        return deviceId;
    }

    // ============================================================
    // NEW: Generate device ID from various sources
    // ============================================================
    private string GenerateDeviceId()
    {
        // Combine multiple hardware identifiers
        string combined = SystemInfo.deviceUniqueIdentifier 
                        + SystemInfo.processorType 
                        + SystemInfo.graphicsDeviceName 
                        + SystemInfo.operatingSystem;
        
        // Hash it to get a consistent ID
        using (System.Security.Cryptography.SHA256 sha256 = System.Security.Cryptography.SHA256.Create())
        {
            byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(combined));
            return BitConverter.ToString(hash).Replace("-", "").Substring(0, 32);
        }
    }
}


# i think that i dont need this cuz i have a MOD Harmony Patch that lets me join room
# also this sometimes doesent compile so use the MOD
===============GorillaComputer PATCH for private ROOMS --Probably cuz i dont have websockets(wss)========================
private void ProcessRoomState(GorillaKeyboardBindings buttonPressed)
{
    if (this.limitOnlineScreens)
    {
        return;
    }
    
    switch (buttonPressed)
    {
    case GorillaKeyboardBindings.delete:
        if ((this.playerInVirtualStump && this.roomToJoin.Length > 1) || (!this.playerInVirtualStump && this.roomToJoin.Length > 0))
        {
            this.roomToJoin = this.roomToJoin.Substring(0, this.roomToJoin.Length - 1);
            return;
        }
        break;
        
    case GorillaKeyboardBindings.enter:
        // ✅ DIRECT FIX: Skip all checks, call private room directly
        if ((!this.playerInVirtualStump && this.roomToJoin != "") || (this.playerInVirtualStump && this.roomToJoin.Length > 1))
        {
            this.networkController.AttemptToJoinSpecificRoom(
                this.roomToJoin, 
                FriendshipGroupDetection.Instance.IsInParty ? JoinType.ForceJoinWithParty : JoinType.Solo
            );
            return;
        }
        break;
        
    case GorillaKeyboardBindings.option1:
        if (!FriendshipGroupDetection.Instance.IsInParty)
        {
            NetworkSystem.Instance.ReturnToSinglePlayer();
            return;
        }
        if (FriendshipGroupDetection.Instance.IsPartyWithinCollider(this.friendJoinCollider, false))
        {
            this.OnGroupJoinButtonPress(0, this.friendJoinCollider);
            return;
        }
        FriendshipGroupDetection.Instance.LeaveParty();
        this.DisconnectAfterDelay(1f);
        return;
        
    case GorillaKeyboardBindings.option2:
        this.RequestUpdatedPermissions();
        return;
        
    case GorillaKeyboardBindings.option3:
        break;
        
    default:
        if (this.roomToJoin.Length < 10)
        {
            string text = this.roomToJoin;
            string text2;
            if (buttonPressed >= GorillaKeyboardBindings.up)
            {
                text2 = buttonPressed.ToString();
            }
            else
            {
                int num = (int)buttonPressed;
                text2 = num.ToString();
            }
            this.roomToJoin = text + text2;
        }
        break;
    }
}


# i think that i dont need this cuz i have a MOD Harmony Patch that lets me join room
=====================NETWORKSYSTEMPUN PATCH for private ROOMS --Probably cuz i dont have websockets(wss)==========================
private async Task<NetJoinResult> MakeOrFindRoom(string roomName, RoomConfig opts, int regionIndex = -1)
{
    if (InRoom)
    {
        await InternalDisconnect();
    }
    
    currentRegionIndex = 0;
    
    // ✅ PRIVATE ROOM: Skip join, create directly
    if (!opts.isPublic)
    {
        Debug.Log("[NetworkSystemPUN] Private room - creating directly: " + roomName);
        return await TryCreateRoom(roomName, opts);
    }
    
    // Public rooms: try to join first
    bool flag = regionIndex >= 0 ? await TryJoinRoomInRegion(roomName, opts, regionIndex) : await TryJoinRoom(roomName, opts);
    
    if (internalState == InternalState.Searching_JoinFailed_Full)
    {
        return NetJoinResult.Failed_Full;
    }
    
    if (!flag)
    {
        return await TryCreateRoom(roomName, opts);
    }
    
    return NetJoinResult.Success;
}
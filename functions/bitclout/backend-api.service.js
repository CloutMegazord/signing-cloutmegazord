class BackendRoutes {
    static ExchangeRateRoute = "/api/v0/get-exchange-rate";
  static BurnBitcoinRoute = "/api/v0/burn-bitcoin";
  static SendBitCloutRoute = "/api/v0/send-bitclout";
  static MinerControlRoute = "/api/v0/miner-control";

  static GetUsersStatelessRoute = "/api/v0/get-users-stateless";
  static RoutePathSubmitPost = "/api/v0/submit-post";
  static RoutePathUploadImage = "/api/v0/upload-image";
  static RoutePathSubmitTransaction = "/api/v0/submit-transaction";
  static RoutePathUpdateProfile = "/api/v0/update-profile";
  static RoutePathGetPostsStateless = "/api/v0/get-posts-stateless";
  static RoutePathGetProfiles = "/api/v0/get-profiles";
  static RoutePathGetSingleProfile = "/api/v0/get-single-profile";
  static RoutePathGetPostsForPublicKey = "/api/v0/get-posts-for-public-key";
  static RoutePathGetDiamondedPosts = "/api/v0/get-diamonded-posts";
  static RoutePathGetHodlersForPublicKey = "/api/v0/get-hodlers-for-public-key";
  static RoutePathSendMessageStateless = "/api/v0/send-message-stateless";
  static RoutePathGetMessagesStateless = "/api/v0/get-messages-stateless";
  static RoutePathMarkContactMessagesRead = "/api/v0/mark-contact-messages-read";
  static RoutePathMarkAllMessagesRead = "/api/v0/mark-all-messages-read";
  static RoutePathGetFollowsStateless = "/api/v0/get-follows-stateless";
  static RoutePathCreateFollowTxnStateless = "/api/v0/create-follow-txn-stateless";
  static RoutePathCreateLikeStateless = "/api/v0/create-like-stateless";
  static RoutePathBuyOrSellCreatorCoin = "/api/v0/buy-or-sell-creator-coin";
  static RoutePathTransferCreatorCoin = "/api/v0/transfer-creator-coin";
  static RoutePathUpdateUserGlobalMetadata = "/api/v0/update-user-global-metadata";
  static RoutePathGetUserGlobalMetadata = "/api/v0/get-user-global-metadata";
  static RoutePathGetNotifications = "/api/v0/get-notifications";
  static RoutePathGetAppState = "/api/v0/get-app-state";
  static RoutePathGetSinglePost = "/api/v0/get-single-post";
  static RoutePathSendPhoneNumberVerificationText = "/api/v0/send-phone-number-verification-text";
  static RoutePathSubmitPhoneNumberVerificationCode = "/api/v0/submit-phone-number-verification-code";
  static RoutePathBlockPublicKey = "/api/v0/block-public-key";
  static RoutePathGetBlockTemplate = "/api/v0/get-block-template";
  static RoutePathGetTxn = "/api/v0/get-txn";
  static RoutePathDeleteIdentities = "/api/v0/delete-identities";
  static RoutePathSendDiamonds = "/api/v0/send-diamonds";
  static RoutePathGetDiamondsForPublicKey = "/api/v0/get-diamonds-for-public-key";

  // Admin routes.
  static NodeControlRoute = "/api/v0/admin/node-control";
  static ReprocessBitcoinBlockRoute = "/api/v0/admin/reprocess-bitcoin-block";
  static RoutePathSwapIdentity = "/api/v0/admin/swap-identity";
  static RoutePathAdminUpdateUserGlobalMetadata = "/api/v0/admin/update-user-global-metadata";
  static RoutePathAdminGetAllUserGlobalMetadata = "/api/v0/admin/get-all-user-global-metadata";
  static RoutePathAdminGetUserGlobalMetadata = "/api/v0/admin/get-user-global-metadata";
  static RoutePathAdminUpdateGlobalFeed = "/api/v0/admin/update-global-feed";
  static RoutePathAdminPinPost = "/api/v0/admin/pin-post";
  static RoutePathAdminRemoveNilPosts = "/api/v0/admin/remove-nil-posts";
  static RoutePathAdminGetMempoolStats = "/api/v0/admin/get-mempool-stats";
  static RoutePathAdminGrantVerificationBadge = "/api/v0/admin/grant-verification-badge";
  static RoutePathAdminRemoveVerificationBadge = "/api/v0/admin/remove-verification-badge";
  static RoutePathAdminGetVerifiedUsers = "/api/v0/admin/get-verified-users";
  static RoutePathAdminGetUsernameVerificationAuditLogs = "/api/v0/admin/get-username-verification-audit-logs";
  static RoutePathUpdateGlobalParams = "/api/v0/admin/update-global-params";
  static RoutePathGetGlobalParams = "/api/v0/admin/get-global-params";
  static RoutePathEvictUnminedBitcoinTxns = "/api/v0/admin/evict-unmined-bitcoin-txns";

  static RoutePathGetFullTikTokURL = "/api/v0/get-full-tiktok-url";
}

class BackendApiService {
    constructor(HttpClient, IdentityService) {
        this.httpClient = HttpClient;
        this.protocol = 'https';
    }

    // Assemble a URL to hit the BE with.
    _makeRequestURL(endpoint, routeName, adminPublicKey) {
        let queryURL =this.protocol + "://" + endpoint + routeName;
        // If the protocol is specified within the endpoint then use that.
        if (endpoint.startsWith("http")) {
            queryURL = endpoint + routeName;
        }
        if (adminPublicKey) {
            queryURL += `?admin_public_key=${adminPublicKey}`;
        }
        return queryURL;
    }

    signAndSubmitTransaction(endpoint, request, PublicKeyBase58Check) {
        return request.pipe(
            switchMap((res) =>
                this.identityService
                .sign({
                    transactionHex: res.TransactionHex,
                    ...this.identityService.identityServiceParamsForKey(PublicKeyBase58Check),
                })
                .pipe(
                    switchMap((signed) => {
                    if (signed.approvalRequired) {
                        return this.identityService
                        .launch("/approve", {
                            tx: res.TransactionHex,
                        })
                        .pipe(
                            map((approved) => {
                            this.setIdentityServiceUsers(approved.users);
                            return { ...res, ...approved };
                            })
                        );
                    } else {
                        return of({ ...res, ...signed });
                    }
                    })
                )
            )
            )
            .pipe(
            switchMap((res) =>
                this.SubmitTransaction(endpoint, res.signedTransactionHex).pipe(
                map((broadcasted) => ({ ...res, ...broadcasted }))
                )
            )
            )
            .pipe(catchError(this._handleError));
    }

    get(endpoint, path) {
        return this.httpClient.get(this._makeRequestURL(endpoint, path));
    }

    post(endpoint, path, body) {
        return this.httpClient.post(this._makeRequestURL(endpoint, path), body);
    }

    static GET_PROFILES_ORDER_BY_INFLUENCER_COIN_PRICE = "influencer_coin_price";
    static BUY_CREATOR_COIN_OPERATION_TYPE = "buy";
    static SELL_CREATOR_COIN_OPERATION_TYPE = "sell";

    // TODO: Cleanup - this should be a configurable value on the node. Leaving it in the frontend
    // is fine for now because BlockCypher has strong anti-abuse measures in place.
    blockCypherToken = "cd455c8a5d404bb0a23880b72f56aa86";

    // Store sent messages and associated metadata in localStorage
    MessageMetaKey = "messageMetaKey";

    // Store successful identityService.import result in localStorage
    IdentityImportCompleteKey = "identityImportComplete";

    // Store the identity users in localStorage
    IdentityUsersKey = "identityUsers";

    // Store last local node URL in localStorage
    LastLocalNodeKey = "lastLocalNode";

    // Store last logged in user public key in localStorage
    LastLoggedInUserKey = "lastLoggedInUser";

    // Store the last identity service URL in localStorage
    LastIdentityServiceKey = "lastIdentityServiceURL";

    // TODO: Wipe all this data when transition is complete
    LegacyUserListKey = "userList";
    LegacySeedListKey = "seedList";

          // TODO: Use Broadcast bool isntead
    SendBitCloutPreview(
        endpoint,
        SenderPublicKeyBase58Check,
        RecipientPublicKeyOrUsername,
        AmountNanos,
        MinFeeRateNanosPerKB
    ){
        return this.post(endpoint, BackendRoutes.SendBitCloutRoute, {
            SenderPublicKeyBase58Check,
            RecipientPublicKeyOrUsername,
            AmountNanos: Math.floor(AmountNanos),
            MinFeeRateNanosPerKB,
        });
    }

    SendBitClout(
        endpoint,
        SenderPublicKeyBase58Check,
        RecipientPublicKeyOrUsername,
        AmountNanos,
        MinFeeRateNanosPerKB
      ){
        const request = this.SendBitCloutPreview(
          endpoint,
          SenderPublicKeyBase58Check,
          RecipientPublicKeyOrUsername,
          AmountNanos,
          MinFeeRateNanosPerKB
        );

        return this.signAndSubmitTransaction(endpoint, request, SenderPublicKeyBase58Check);
      }

    SubmitTransaction(endpoint, TransactionHex) {
        return this.post(endpoint, BackendRoutes.RoutePathSubmitTransaction, {
            TransactionHex,
        });
    }
}

module.exports = BackendApiService;
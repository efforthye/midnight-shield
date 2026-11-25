# Field test verdicts

Every medium-or-worse finding of the field test ([field-test.md](field-test.md)) with its verdict, so the precision figure can be checked by someone other than the author.

- **59 findings are published in full** below: low-risk DApp findings (logs, browser storage, remote proof server, unsafe HTML), findings already reported to the project, and the false positive. Each links to the exact line at the exact commit that was scanned.
- **88 findings are withheld until the projects are told**, because they describe exploitable contract or key-handling bugs. Each is published as a SHA-256 commitment to the full row (repository, commit, file, line, rule, verdict, reason) and a random salt. When a report goes out, the row and its salt are added to [field-verdicts.json](field-verdicts.json) under `revealed`, and `node scripts/check-verdict.mjs` recomputes every hash, so anyone can see the verdict was fixed before the reveal.

Verdicts: 146 real, 1 false positive, out of 147. The verdicts are the author's; the links and commitments are there so they can be checked.

## Published

| Rule | Verdict | Where | Why |
| --- | --- | --- | --- |
| MS002 | false positive | [Debjit2821/midnight-Dapp · contract/src/shadowvote.compact:96](https://github.com/Debjit2821/midnight-Dapp/blob/269598f96d0f6fa6150020fe1a9cb751567cb092/contract/src/shadowvote.compact#L96) | the file is not valid Compact (assert without parentheses), so the finding is about code that does not compile |
| MS002 | real | [MeshJS/midnight-contracts-wizard · packages/contract/src/lending-borrowing/lending-borrowing.compact:289](https://github.com/MeshJS/midnight-contracts-wizard/blob/a1f868d0455c4e53c76f466834a37ce4f409cb9a/packages/contract/src/lending-borrowing/lending-borrowing.compact#L289) | a witness value reaches public state or a return value with no assert constraining it (reported) |
| MS002 | real | [MeshJS/midnight-contracts-wizard · packages/contract/src/lending-borrowing/lending-borrowing.compact:368](https://github.com/MeshJS/midnight-contracts-wizard/blob/a1f868d0455c4e53c76f466834a37ce4f409cb9a/packages/contract/src/lending-borrowing/lending-borrowing.compact#L368) | a witness value reaches public state or a return value with no assert constraining it (reported) |
| MS008 | real | [MeshJS/midnight-contracts-wizard · packages/contract/src/lending-borrowing/lending-borrowing.compact:309](https://github.com/MeshJS/midnight-contracts-wizard/blob/a1f868d0455c4e53c76f466834a37ce4f409cb9a/packages/contract/src/lending-borrowing/lending-borrowing.compact#L309) | a Merkle-authorized action has no nullifier, so it can be repeated (reported) |
| MS008 | real | [MeshJS/midnight-contracts-wizard · packages/contract/src/oracle/oracle.compact:158](https://github.com/MeshJS/midnight-contracts-wizard/blob/a1f868d0455c4e53c76f466834a37ce4f409cb9a/packages/contract/src/oracle/oracle.compact#L158) | a Merkle-authorized action has no nullifier, so it can be repeated (reported) |
| MS009 | real | [MeshJS/midnight-contracts-wizard · packages/contract/src/lending-borrowing/lending-borrowing.compact:309](https://github.com/MeshJS/midnight-contracts-wizard/blob/a1f868d0455c4e53c76f466834a37ce4f409cb9a/packages/contract/src/lending-borrowing/lending-borrowing.compact#L309) | the Merkle root is checked but the leaf is not bound to the caller (reported) |
| MS009 | real | [MeshJS/midnight-contracts-wizard · packages/contract/src/lending-borrowing/lending-borrowing.compact:349](https://github.com/MeshJS/midnight-contracts-wizard/blob/a1f868d0455c4e53c76f466834a37ce4f409cb9a/packages/contract/src/lending-borrowing/lending-borrowing.compact#L349) | the Merkle root is checked but the leaf is not bound to the caller (reported) |
| MS009 | real | [MeshJS/midnight-contracts-wizard · packages/contract/src/lending-borrowing/lending-borrowing.compact:389](https://github.com/MeshJS/midnight-contracts-wizard/blob/a1f868d0455c4e53c76f466834a37ce4f409cb9a/packages/contract/src/lending-borrowing/lending-borrowing.compact#L389) | the Merkle root is checked but the leaf is not bound to the caller (reported) |
| MS009 | real | [MeshJS/midnight-contracts-wizard · packages/contract/src/oracle/oracle.compact:158](https://github.com/MeshJS/midnight-contracts-wizard/blob/a1f868d0455c4e53c76f466834a37ce4f409cb9a/packages/contract/src/oracle/oracle.compact#L158) | the Merkle root is checked but the leaf is not bound to the caller (reported) |
| MS009 | real | [MeshJS/midnight-contracts-wizard · packages/contract/src/oracle/oracle.compact:255](https://github.com/MeshJS/midnight-contracts-wizard/blob/a1f868d0455c4e53c76f466834a37ce4f409cb9a/packages/contract/src/oracle/oracle.compact#L255) | the Merkle root is checked but the leaf is not bound to the caller (reported) |
| MS013 | real | [MeshJS/midnight-contracts-wizard · packages/contract/src/lending-borrowing/lending-borrowing.compact:274](https://github.com/MeshJS/midnight-contracts-wizard/blob/a1f868d0455c4e53c76f466834a37ce4f409cb9a/packages/contract/src/lending-borrowing/lending-borrowing.compact#L274) | an assert only checks a Boolean returned by a witness (reported) |
| MS013 | real | [MeshJS/midnight-contracts-wizard · packages/contract/src/lending-borrowing/lending-borrowing.compact:316](https://github.com/MeshJS/midnight-contracts-wizard/blob/a1f868d0455c4e53c76f466834a37ce4f409cb9a/packages/contract/src/lending-borrowing/lending-borrowing.compact#L316) | an assert only checks a Boolean returned by a witness (reported) |
| MS013 | real | [MeshJS/midnight-contracts-wizard · packages/contract/src/lending-borrowing/lending-borrowing.compact:353](https://github.com/MeshJS/midnight-contracts-wizard/blob/a1f868d0455c4e53c76f466834a37ce4f409cb9a/packages/contract/src/lending-borrowing/lending-borrowing.compact#L353) | an assert only checks a Boolean returned by a witness (reported) |
| MS013 | real | [MeshJS/midnight-contracts-wizard · packages/contract/src/lending-borrowing/lending-borrowing.compact:393](https://github.com/MeshJS/midnight-contracts-wizard/blob/a1f868d0455c4e53c76f466834a37ce4f409cb9a/packages/contract/src/lending-borrowing/lending-borrowing.compact#L393) | an assert only checks a Boolean returned by a witness (reported) |
| MS013 | real | [MeshJS/midnight-contracts-wizard · packages/contract/src/lending-borrowing/lending-borrowing.compact:425](https://github.com/MeshJS/midnight-contracts-wizard/blob/a1f868d0455c4e53c76f466834a37ce4f409cb9a/packages/contract/src/lending-borrowing/lending-borrowing.compact#L425) | an assert only checks a Boolean returned by a witness (reported) |
| MS013 | real | [MeshJS/midnight-contracts-wizard · packages/contract/src/lending-borrowing/lending-borrowing.compact:428](https://github.com/MeshJS/midnight-contracts-wizard/blob/a1f868d0455c4e53c76f466834a37ce4f409cb9a/packages/contract/src/lending-borrowing/lending-borrowing.compact#L428) | an assert only checks a Boolean returned by a witness (reported) |
| MS013 | real | [MeshJS/midnight-contracts-wizard · packages/contract/src/oracle/oracle.compact:276](https://github.com/MeshJS/midnight-contracts-wizard/blob/a1f868d0455c4e53c76f466834a37ce4f409cb9a/packages/contract/src/oracle/oracle.compact#L276) | an assert only checks a Boolean returned by a witness (reported) |
| MS013 | real | [MeshJS/midnight-contracts-wizard · packages/contract/src/staking/staking.compact:170](https://github.com/MeshJS/midnight-contracts-wizard/blob/a1f868d0455c4e53c76f466834a37ce4f409cb9a/packages/contract/src/staking/staking.compact#L170) | an assert only checks a Boolean returned by a witness (reported) |
| MS013 | real | [MeshJS/midnight-contracts-wizard · packages/contract/src/staking/staking.compact:205](https://github.com/MeshJS/midnight-contracts-wizard/blob/a1f868d0455c4e53c76f466834a37ce4f409cb9a/packages/contract/src/staking/staking.compact#L205) | an assert only checks a Boolean returned by a witness (reported) |
| MS101 | real | [MeshJS/midnight-contracts-wizard · packages/cli/src/config.ts:65](https://github.com/MeshJS/midnight-contracts-wizard/blob/a1f868d0455c4e53c76f466834a37ce4f409cb9a/packages/cli/src/config.ts#L65) | the proof server URL points to a remote host (reported) |
| MS101 | real | [akash-mondal-1/Midnight-Vault · frontend/src/lib/midnight-providers.ts:111](https://github.com/akash-mondal-1/Midnight-Vault/blob/c9be5de237366b5dc8a27a017250ad516945b840/frontend/src/lib/midnight-providers.ts#L111) | the proof server URL points to a remote host |
| MS101 | real | [kevan1/midnight-zk-kyc · app/api/midnight-indexer/midnight-client.ts:117](https://github.com/kevan1/midnight-zk-kyc/blob/667b4ab1af775701e1fd4f43094ab4913943949a/app/api/midnight-indexer/midnight-client.ts#L117) | the proof server URL points to a remote host |
| MS101 | real | [kevan1/midnight-zk-kyc · lib/midnight-client.ts:117](https://github.com/kevan1/midnight-zk-kyc/blob/667b4ab1af775701e1fd4f43094ab4913943949a/lib/midnight-client.ts#L117) | the proof server URL points to a remote host |
| MS101 | real | [kevan1/midnight-zk-kyc · lib/zk-proof-utils.ts:9](https://github.com/kevan1/midnight-zk-kyc/blob/667b4ab1af775701e1fd4f43094ab4913943949a/lib/zk-proof-utils.ts#L9) | the proof server URL points to a remote host |
| MS101 | real | [sauravs296/compactforge-midnight · scripts/deploy.ts:40](https://github.com/sauravs296/compactforge-midnight/blob/bb50376a7ff96cc11fc158e75bd3a228406aa581/scripts/deploy.ts#L40) | the proof server URL points to a remote host |
| MS102 | real | [AJTECH001/MIG · bboard-cli/src/midnight-wallet-provider.ts:114](https://github.com/AJTECH001/MIG/blob/52cef9ba7f1c2a8fa4d62e13a030321190353c8c/bboard-cli/src/midnight-wallet-provider.ts#L114) | a seed or secret is printed to a log |
| MS102 | real | [Samk208/mru-proof-of-trade · src/wallet.ts:108](https://github.com/Samk208/mru-proof-of-trade/blob/d6d1167e2aeb4b31477b0b80c416092027e8fa86/src/wallet.ts#L108) | a seed or secret is printed to a log |
| MS102 | real | [aths550/new-moon · auction-cli/src/midnight-wallet-provider.ts:145](https://github.com/aths550/new-moon/blob/10fdda63b53dac8384603b78b344f07b4e11645f/auction-cli/src/midnight-wallet-provider.ts#L145) | a seed or secret is printed to a log |
| MS102 | real | [aths550/new-moon · bboard-cli/src/midnight-wallet-provider.ts:119](https://github.com/aths550/new-moon/blob/10fdda63b53dac8384603b78b344f07b4e11645f/bboard-cli/src/midnight-wallet-provider.ts#L119) | a seed or secret is printed to a log |
| MS102 | real | [aths550/new-moon · scratch/print_address_for_seed.js:48](https://github.com/aths550/new-moon/blob/10fdda63b53dac8384603b78b344f07b4e11645f/scratch/print_address_for_seed.js#L48) | a seed or secret is printed to a log |
| MS102 | real | [choiaewoooon/kirogi-midnight · devnet/src/midnight-wallet-provider.ts:114](https://github.com/choiaewoooon/kirogi-midnight/blob/22ee5c87f83aed358c058c97d0d5d1e6af1c9072/devnet/src/midnight-wallet-provider.ts#L114) | a seed or secret is printed to a log |
| MS102 | real | [iamomm-hack/voting-midnight · voting-cli/src/launcher/deploy-direct.ts:80](https://github.com/iamomm-hack/voting-midnight/blob/0703e0a0595eaf49c268717fee5e816d255abd40/voting-cli/src/launcher/deploy-direct.ts#L80) | a seed or secret is printed to a log |
| MS102 | real | [iamomm-hack/voting-midnight · voting-cli/src/launcher/deploy-direct.ts:171](https://github.com/iamomm-hack/voting-midnight/blob/0703e0a0595eaf49c268717fee5e816d255abd40/voting-cli/src/launcher/deploy-direct.ts#L171) | a seed or secret is printed to a log |
| MS102 | real | [iamomm-hack/voting-midnight · voting-cli/src/midnight-wallet-provider.ts:120](https://github.com/iamomm-hack/voting-midnight/blob/0703e0a0595eaf49c268717fee5e816d255abd40/voting-cli/src/midnight-wallet-provider.ts#L120) | a seed or secret is printed to a log |
| MS102 | real | [kevan1/kyc-midnight-hackathon · bboard-cli/src/index.ts:320](https://github.com/kevan1/kyc-midnight-hackathon/blob/e190eb9e91d3b8d71438af05efcc5a34ed729653/bboard-cli/src/index.ts#L320) | a seed or secret is printed to a log |
| MS102 | real | [mrBinaryMonk375/Private-Voting-System · voting-cli/src/midnight-wallet-provider.ts:114](https://github.com/mrBinaryMonk375/Private-Voting-System/blob/5929cdef64e05ad959d7e0415a4ddf2f00b5f1f2/voting-cli/src/midnight-wallet-provider.ts#L114) | a seed or secret is printed to a log |
| MS102 | real | [nsampurnaa/midnight-app · voting-cli/src/midnight-wallet-provider.ts:114](https://github.com/nsampurnaa/midnight-app/blob/b06bb0f4562015d202d0fc7d7a88ef3363b68d79/voting-cli/src/midnight-wallet-provider.ts#L114) | a seed or secret is printed to a log |
| MS102 | real | [pplmaverick/midnight-private-auction · scripts/debug-commitment.ts:113](https://github.com/pplmaverick/midnight-private-auction/blob/0e3be6fd53cbbf7a7fa4066f7819493c8b9d505e/scripts/debug-commitment.ts#L113) | a seed or secret is printed to a log |
| MS102 | real | [pplmaverick/midnight-private-auction · scripts/debug-commitment.ts:215](https://github.com/pplmaverick/midnight-private-auction/blob/0e3be6fd53cbbf7a7fa4066f7819493c8b9d505e/scripts/debug-commitment.ts#L215) | a seed or secret is printed to a log |
| MS102 | real | [pplmaverick/midnight-private-auction · src/api.ts:357](https://github.com/pplmaverick/midnight-private-auction/blob/0e3be6fd53cbbf7a7fa4066f7819493c8b9d505e/src/api.ts#L357) | a seed or secret is printed to a log |
| MS104 | real | [HimanshuM685/midnight · frontend/src/lib/providers.ts:66](https://github.com/HimanshuM685/midnight/blob/4ed994539f71a67462ea5c6e911fcd553027bad2/frontend/src/lib/providers.ts#L66) | private state or a secret is stored in browser storage |
| MS104 | real | [HimanshuM685/midnight · src/lib/midnightClient.ts:35](https://github.com/HimanshuM685/midnight/blob/4ed994539f71a67462ea5c6e911fcd553027bad2/src/lib/midnightClient.ts#L35) | private state or a secret is stored in browser storage |
| MS104 | real | [Ryjen1/NightHire · frontend/src/services/nightHire.ts:122](https://github.com/Ryjen1/NightHire/blob/49f90af8a2db2ba4f25924fcd3625d061d28987e/frontend/src/services/nightHire.ts#L122) | private state or a secret is stored in browser storage |
| MS104 | real | [aayusha-j/midnight-level2-simple-dao · frontend/src/App.tsx:19](https://github.com/aayusha-j/midnight-level2-simple-dao/blob/8858431d6b564bbfcd9031f655752dfcd8e6727b/frontend/src/App.tsx#L19) | private state or a secret is stored in browser storage |
| MS104 | real | [aayusha-j/midnight-level2-simple-dao · frontend/src/components/CircuitCall.tsx:16](https://github.com/aayusha-j/midnight-level2-simple-dao/blob/8858431d6b564bbfcd9031f655752dfcd8e6727b/frontend/src/components/CircuitCall.tsx#L16) | private state or a secret is stored in browser storage |
| MS104 | real | [akash-mondal-1/Midnight-Vault · leaderboard-ref/leaderboard-ui/src/contexts/BrowserLeaderboardManager.ts:65](https://github.com/akash-mondal-1/Midnight-Vault/blob/c9be5de237366b5dc8a27a017250ad516945b840/leaderboard-ref/leaderboard-ui/src/contexts/BrowserLeaderboardManager.ts#L65) | private state or a secret is stored in browser storage |
| MS104 | real | [aths550/new-moon · frontend/auction-ui/src/lib/identity.ts:31](https://github.com/aths550/new-moon/blob/10fdda63b53dac8384603b78b344f07b4e11645f/frontend/auction-ui/src/lib/identity.ts#L31) | private state or a secret is stored in browser storage |
| MS104 | real | [aths550/new-moon · frontend/auction-ui/src/lib/identity.ts:67](https://github.com/aths550/new-moon/blob/10fdda63b53dac8384603b78b344f07b4e11645f/frontend/auction-ui/src/lib/identity.ts#L67) | private state or a secret is stored in browser storage |
| MS104 | real | [rifatsarwarcodes/Midnight_Buildathon · ui/src/lib/identity.ts:21](https://github.com/rifatsarwarcodes/Midnight_Buildathon/blob/e7acc3892022039f967b95b0256fad137da8418c/ui/src/lib/identity.ts#L21) | private state or a secret is stored in browser storage |
| MS104 | real | [sauravs296/compactforge-midnight · src/components/DeployButton.tsx:66](https://github.com/sauravs296/compactforge-midnight/blob/bb50376a7ff96cc11fc158e75bd3a228406aa581/src/components/DeployButton.tsx#L66) | private state or a secret is stored in browser storage |
| MS104 | real | [sauravs296/compactforge-midnight · src/components/DeployButton.tsx:69](https://github.com/sauravs296/compactforge-midnight/blob/bb50376a7ff96cc11fc158e75bd3a228406aa581/src/components/DeployButton.tsx#L69) | private state or a secret is stored in browser storage |
| MS104 | real | [shakshi-06/SealedAuction · bboard-ui/src/utils/secrets.ts:31](https://github.com/shakshi-06/SealedAuction/blob/cefde1e61a89bdfd7b4e4f9694165106e1aa6cc2/bboard-ui/src/utils/secrets.ts#L31) | private state or a secret is stored in browser storage |
| MS118 | real | [Ryjen1/NightHire · frontend/src/main.tsx:49](https://github.com/Ryjen1/NightHire/blob/49f90af8a2db2ba4f25924fcd3625d061d28987e/frontend/src/main.tsx#L49) | HTML built from a variable is written into the page |
| MS118 | real | [Ryjen1/NightHire · frontend/src/main.tsx:56](https://github.com/Ryjen1/NightHire/blob/49f90af8a2db2ba4f25924fcd3625d061d28987e/frontend/src/main.tsx#L56) | HTML built from a variable is written into the page |
| MS118 | real | [akashjangam15/Midnight_project · my-project/src/main.tsx:25](https://github.com/akashjangam15/Midnight_project/blob/7ab762a3bc8f0b2f20aecb35f04f2510f39e8b56/my-project/src/main.tsx#L25) | HTML built from a variable is written into the page |
| MS118 | real | [lisaaai200/threshold-pass · web/src/main.ts:20](https://github.com/lisaaai200/threshold-pass/blob/fd697f9b5e599093c89387498a6ac7fc356c2d54/web/src/main.ts#L20) | HTML built from a variable is written into the page |
| MS118 | real | [lisaaai200/threshold-pass · web/src/main.ts:35](https://github.com/lisaaai200/threshold-pass/blob/fd697f9b5e599093c89387498a6ac7fc356c2d54/web/src/main.ts#L35) | HTML built from a variable is written into the page |
| MS118 | real | [lisaaai200/threshold-pass · web/src/main.ts:45](https://github.com/lisaaai200/threshold-pass/blob/fd697f9b5e599093c89387498a6ac7fc356c2d54/web/src/main.ts#L45) | HTML built from a variable is written into the page |
| MS118 | real | [lisaaai200/threshold-pass · web/src/main.ts:140](https://github.com/lisaaai200/threshold-pass/blob/fd697f9b5e599093c89387498a6ac7fc356c2d54/web/src/main.ts#L140) | HTML built from a variable is written into the page |

## Withheld (commitments)

| Rule | Severity | Verdict | Commitment |
| --- | --- | --- | --- |
| MS001 | critical | real | `14207a9d77a6dbe05e6f380cf1bb3c0917fbd9696fa0905352f67e7b4322cae8` |
| MS001 | critical | real | `20c346f11450e7ea05289172c84c967ef613779a2a34c3a42bcea02f15c8a341` |
| MS001 | critical | real | `a3e897273a6044562e6e74c9812df607db841eea2752031a59e5b24abb12646d` |
| MS001 | critical | real | `b7aa546132fed7f4fc3cfbf942b4f647811b885bde39ffc448096f62fe111c9c` |
| MS001 | critical | real | `e120daf6ba2aaa519a88594542a36af503364128b8fbdd0ce6905c69c69b407e` |
| MS001 | critical | real | `f85717934c1684cfe87136588276f70db178c0743aa05eca48ef4189b3c634ba` |
| MS002 | medium | real | `a4917002eafbbe52ace8471970701a574d2fdca886091058553c7d7ed0114240` |
| MS002 | medium | real | `b17bbc0d3da58764b3b0f3d61ef23254c0f7922b7de59f5e7174afaae0e8eac1` |
| MS002 | medium | real | `de831552e7ece7e323a425405b65bca8aa2de4e175e544c0b5397f2cdf83491a` |
| MS002 | medium | real | `ea8605911c19f56e88f3cf5ac34b99165df49f064753247c5dd7c95f563c7619` |
| MS007 | high | real | `6106fb46c29235ec321e9245fb7e61202676b2feddfc266fef6cbffa6cc58187` |
| MS007 | high | real | `7b748c6bc8223ac159a502c595a5482c43eff4fb08af2436c97d54736dc440fb` |
| MS007 | high | real | `a78d361786b5dad7212ff6de3366637dc1aaf0fe19c552ab0cfc3303900a0be8` |
| MS007 | high | real | `ee3a27b133dc3193a0ecc48c6b6e4f90482f2b3e36ee8079363e95003942fa50` |
| MS008 | medium | real | `08cfb43fbea8df1c708e3e35a950ba8e2ae076b4fec99e17447435b0582f4d66` |
| MS008 | medium | real | `facdd1a21700e9c2699d1e0c7908c120dffb3f2b0c2da15fbc0b17cab8b49fbd` |
| MS009 | high | real | `26f284b95694e797746dbe2210431846c9e49d89b96a14a3c0e705c4e2d1c6e0` |
| MS009 | high | real | `3618f9715636952293b4dc8d061545dc60407c7f18a5d672e2632adda3226b47` |
| MS009 | high | real | `8c6770cf812a53af51b68b498f91cbccdf9d4d0b32aafb2783ef8c3516f3980d` |
| MS009 | high | real | `a99d9a8b45645d14eb3bc216bda45876e5337bb54248f0cb2c3c61b358a0753d` |
| MS009 | high | real | `bfe4e4df17c0d6fa5b0d84dc2c5c499ee1d5e8eb2396233ffd17b08a75c82540` |
| MS009 | high | real | `c0f4fb0d9925f72ecc482c4509efc1d3dcfc949b0c4101201e0720ca0cecd3ec` |
| MS009 | high | real | `d6ab882713d4b06dd68509e803314a37a4cace660c2c7374e6a38a85359f27d9` |
| MS013 | high | real | `5b15e16520971578e2cd4126694fcb7614af27d81e0a9343ff65463cc4094f8b` |
| MS013 | high | real | `dc7caf308037470903dcd33eb4f07dd7b784ce3edde79287ce577c895a6bb989` |
| MS019 | high | real | `5912dd9748511838cd92aa2ef233bbd75ee7323f3e34f200bd5565720558158c` |
| MS019 | high | real | `5c454148dadb5078146fd63751da955697b363dc5a0a5557d28c5c08d71e0eb0` |
| MS019 | high | real | `b495eb9ea85e617a5071ceb06aca592b38ce920cf3352453403f58309bbf9a7f` |
| MS020 | high | real | `2bf01bfdf2c430284d767ea105ec96a8f0f28e71666dcb7e8149394153a68926` |
| MS020 | high | real | `8b36e2460ce90e53277e8560de917b6e1e77663bec229475bac6401fe1332092` |
| MS020 | high | real | `90d48aaff0aa09f0716dd150efaefc6d39b7fda38e6ab3c50405a27d3c44711d` |
| MS034 | high | real | `171fc7bb2557eb72b15f6d8399c5f61e77130fd57d10c968c69e7fcda026cc66` |
| MS034 | high | real | `58cc73a863caa3c173d1c1ad849ba81a1b2133467ae62056a22217849d9af652` |
| MS034 | high | real | `8a4c72580be812bb9bce730f4130ced4e7041e39913ebc9bfba13e35b846dfae` |
| MS034 | high | real | `bcab4a8effc6a161a4654374bd6c5170f09f294cae3120853537eb6ac31ea6d3` |
| MS036 | critical | real | `79f9e13c957b1b0ab4d2a9e893d4e7df2c1f2c29d6a95910c8c038d96789fc30` |
| MS036 | critical | real | `ed5e6fc07a0d1c82b5b3132b54395ed8ea5cb10bc23888a147b7fe3058a2a126` |
| MS037 | high | real | `083ca35ce519ac9f3f6eb1559b615ba84c4845feced65e8d532faf2f521a2063` |
| MS037 | high | real | `1e54c7e2b88e451c232019e2633ff2784d51da392a195efe13666f40bde20c95` |
| MS037 | high | real | `2b09fd48fd5600689008088076a9fea9c88c50bdb6cee9a5a301022f6cb61911` |
| MS037 | high | real | `3c226411d88d9bdccf4ad2b3bba5c899746a7db4aea3a44da3dffceeeaa6fe59` |
| MS037 | high | real | `4a50a8e28a9629d4c8cf46a6eaa32bdb5533f8a5911c0c2d6027ea4cbea9e74a` |
| MS037 | high | real | `5687c4e746d0c6cb21c5010b30b892e804d5317afc48020f6e23811e76b094c3` |
| MS037 | high | real | `60db38e58b038657fa6ae81a01e2b7d0b2e1e278eda2f953edc887a784864198` |
| MS037 | high | real | `78913955702f5df17c1288f9cc646129f2c292fc70af42424ef16c028f469879` |
| MS037 | high | real | `81d03cb9d3905ac36d57820fd55222c6a212fd0ef8c026282b9954aeae5b251f` |
| MS037 | high | real | `944e15230663c5187d048ef4ec76fe9868aadbc14baa3c385f35668714a0a185` |
| MS037 | high | real | `97a3b276083995abc516d9f22c96116a2f8c620afd23af34b7b042121162ebc5` |
| MS037 | high | real | `aaa7403334279cb4d6a784db05d401c3f24410112b1757e1719594f527962d69` |
| MS037 | high | real | `bf873bf32d80318f4b3e4747ebc13207b867ec31d1c2d6134c1b6d2b81973236` |
| MS037 | high | real | `e5b68e5976b2381e2b68c8e18566b2f8127391f10b90cb7fb15252c7ca18841b` |
| MS037 | high | real | `f879a7f3986cdbd05404f7d9ca027d2de5f48e5b7ca69d712763b207a3783386` |
| MS037 | high | real | `fb8367c1668f87cb5cfe4db749fb15dc2e6ff88d303ab45900b9be4bafde1faa` |
| MS103 | critical | real | `16729a72f13857d75057ac920b0b4a591f6900358d50bab1979d54bc0cd33624` |
| MS103 | critical | real | `239f8908256b61f5ddc6d4ed7cb50090da74942a986bde9c3b6c42e4eb45a339` |
| MS103 | critical | real | `2bbde8270c79d0a29628713b02ac6dc48b6cb0d34d2e16108d11984de4b3a61b` |
| MS103 | critical | real | `2bdd3f12375a8f82abe96c87cb6b5030c55766c3740ccc1bb67a7b24c09c0904` |
| MS103 | critical | real | `427528f122413b682b4c5bbef7fe3dcedc7ad5c92b6f9bd28ac1a29acbddf583` |
| MS103 | critical | real | `5f8b7c7bd2fe1516857e8ae37294de205e817c05318bc4061e01804d7acf7622` |
| MS103 | critical | real | `b829af97720b892a6ab1e80178df843b311e2e536112cb1f0683357e982404e1` |
| MS103 | critical | real | `c63a1545dab9115134a7442279b25521559b11a6795dc5f0ce5e53a87733da2c` |
| MS103 | critical | real | `cf12a17e8aab35ed749738d5f798a4a0acf071f90861ad1dab1b04ef95091f7a` |
| MS103 | critical | real | `da4a83ee4a767b6c9083d358c87c3a431531c1723a9dfce08d7b16acfdaa520e` |
| MS103 | critical | real | `ed825fcb12d5c1a81358f973654aa4ef8ca9e2a35f7817943d94e0e56ed873d1` |
| MS103 | critical | real | `ef564db7a089b9c062825103cb243337cd435ed27bf500e72ffe91253899d78e` |
| MS103 | critical | real | `f03873f64c3af964db7467ca7423cb004890cbb81ca02a161fb4c27438c3e52f` |
| MS103 | critical | real | `f23b040fa5900441de18f5c5bda9ea3cb402467d4f1b8b8d220dda2daa1ffe99` |
| MS113 | critical | real | `08eeb085af0775b0aaf6fd202c505f931d920159926a8ff8807fff079d210577` |
| MS113 | critical | real | `1b078d001507c445c4fed7b7d51d702d41b373f09f5d2304c453b4578da22fbb` |
| MS113 | critical | real | `1ff8bf211410581237257b867cbd57091cbb4abc0667bd73c1df4994b70a8453` |
| MS113 | critical | real | `59a56764b5bd115f794c02cf745c5d6b9d6b152725a9dd5cf33ff11599454ff7` |
| MS113 | critical | real | `93244522ceadc3749c96d8e6c95937e9625cbe1365fe0bd40079a54769729b6c` |
| MS113 | critical | real | `b4e9fb19a231dda557b223b1e9f41f41ce3f9df3b8faa3159139a8dd09bf1c28` |
| MS113 | critical | real | `c1bb5dba7707743947a5b246d65a9ef609a94bce42331c3955584e5ab2a635ab` |
| MS113 | critical | real | `e8242d5e06cc3737466c942938f74ce771a891fd3bafafdb20bdaa642381eb9a` |
| MS120 | high | real | `0974e2d59799d7412904c150c77c32f55e43ed28de8126f0219272571f79a386` |
| MS120 | high | real | `13bc6d11622f12971c7203247b84e980a7ea939546e2409a7cd08253f7c9a608` |
| MS120 | high | real | `18fec1afe440f8c8135ee9b9362d704fd32c4453e668295bba71f4b4cc73fe1f` |
| MS120 | high | real | `29ff818673073d253f1e36bd96ae1a8797a539634da53ed3995713cc3e1edc70` |
| MS120 | high | real | `3d06118f19afc75b3dd7edd8ead116494f9dd939f836009d5dc41600fcab9a29` |
| MS120 | high | real | `72f0c4faeec9a14ded7ac877ab6e0a1148ec5b740db5256f0de79bd9f2780f38` |
| MS120 | high | real | `7ce63541556c14f6149ff36bd7310d2ec3c0bd46d40d995c62d0a61df8a4c60d` |
| MS120 | high | real | `7e88a17fe1a963fddca3ab64c59462ac6512f0c216edec1e2ae87588c00d2c49` |
| MS120 | high | real | `9020861c13466b3576ccd95c4596d52c187fb460deda19fa46481000798645c7` |
| MS120 | high | real | `a6f4c6a4a809f93b92b517a8c39f84d4a2241b4517b32a545b730880b37a575f` |
| MS120 | high | real | `b100252fbc2ac90b533312b909a8bf3624688df5c3a743b12e601c3b9d35a8e6` |
| MS120 | high | real | `c590618d1304ccc6a80dc4e54206b233732f389d9df8d8275ca4fc122afffe91` |
| MS120 | high | real | `fbea86319e781f7c5b8d5c7f68fe439de5010a3e64f42fd67ce2470b06f6314b` |

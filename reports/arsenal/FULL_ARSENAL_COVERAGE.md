# Full Arsenal Coverage

Verdict: **FIXTURE ARSENAL PARTIALLY VERIFIED**

Git SHA: ``  
Arsenal image: `sha256:3766088055a72f82346bf7318cb0acf9ec6b2e82ddf6df6bcba9558f70e9c40d`

## Metrics

- `total_canonical_capabilities`: `174`
- `unique_backends`: `100`
- `unique_external_backends`: `74`
- `healthy_backends`: `17`
- `backend_executions`: `17`
- `fixture_executed_backends`: `15`
- `fixture_executed_capabilities`: `28`
- `fixture_backend_denominator`: `52`
- `fixture_capability_denominator`: `71`
- `fixture_backend_execution_coverage`: `0.28846153846153844`
- `fixture_capability_execution_coverage`: `0.39436619718309857`
- `authorized_real_execution_coverage`: `None`
- `authorized_real_executed_capabilities`: `0`
- `positive_controls_passed`: `17`
- `negative_controls_passed`: `17`
- `never_executed_external_backends`: `59`
- `states`: `{'EXECUTED_PASS': 17, 'EXECUTED_FINDING': 0, 'WAITING_FOR_PREREQUISITE': 20, 'UNAVAILABLE': 23, 'DENIED_BY_POLICY': 0, 'DENIED_POLICY_AMBIGUOUS': 0, 'NOT_IMPLEMENTED': 0, 'BACKEND_UNHEALTHY': 0}`

## Executions

| Capability | State | Run | Evidence |
|---|---|---|---|
| `asset:aegis-agent-permission-audit/agent-tool-permission-analysis` | WAITING_FOR_PREREQUISITE | `arsenal-20260827T203233Z-d4fc2f01` | `77b9201e348a310f9ae0ab5e652ff01a54600892fffb4335896586d09d052fc5` |
| `asset:aegis-artifact-diff/authorized-mobile-release-diff` | WAITING_FOR_PREREQUISITE | `arsenal-20260827T203233Z-951a835f` | `f4909ee6ecf7906a2cb74dd8cd6cfb8782dc691d890ea44b7742f865211b2b24` |
| `asset:aegis-asset-classifier/deterministic-asset-classification` | WAITING_FOR_PREREQUISITE | `arsenal-20260827T203233Z-9a2f9185` | `92970221b71ed985a515d9774eed4f5b13db85b1e884b64b10b6c2b9a8ecd235` |
| `asset:aegis-firmware-arch/firmware-architecture-detection` | WAITING_FOR_PREREQUISITE | `arsenal-20260827T203233Z-0b3f069d` | `8cc0385d046c3dcebc909d9bbbf123e185cbf897fdeeecd498cc1ffc2630e10c` |
| `asset:aegis-memory-poisoning/agent-memory-poisoning-regression` | WAITING_FOR_PREREQUISITE | `arsenal-20260827T203233Z-f68fa2e1` | `af0cdb6fd2fc6fbfa0e0bcae9093f78ffeb40690e968bb0cec5eb382ffe8f223` |
| `asset:aegis-model-provenance/model-provenance-and-hash-ledger` | WAITING_FOR_PREREQUISITE | `arsenal-20260827T203234Z-1d35f9a8` | `fc36d09655b2f3fd27801f63ad72d7761c6afa70465d3b3d548495ca055c843b` |
| `asset:aegis-rag-boundary/rag-retrieval-trust-analysis` | WAITING_FOR_PREREQUISITE | `arsenal-20260827T203234Z-8c846528` | `966e16ac567928aa59efd0acae31f1e0ff065f0e8ef6c3e05ab620417581c29f` |
| `asset:angr/binary-control-flow-analysis` | UNAVAILABLE | `arsenal-20260827T203234Z-8cf548df` | `0c2ef15f9ee21dfa8b949581eb47f90cb20ebeb60183964f32f828367c138941` |
| `asset:apktool/android-resource-and-manifest-decode` | UNAVAILABLE | `arsenal-20260827T203234Z-53625abf` | `66d9951d9548f0cb8903cc13cc9dff7cc268d8fbef0a33452f05f06f91f7cf6b` |
| `asset:binwalk/firmware-structure-analysis` | UNAVAILABLE | `arsenal-20260827T203234Z-5cad75d3` | `d2c243679147324e4dda83a1230b055e20219c79bccec86ecbe9b2f6fde0109e` |
| `asset:capa/binary-capability-analysis` | UNAVAILABLE | `arsenal-20260827T203234Z-36acda86` | `f50ca06e136e2fc1f98fddf7faaac123a8ec66f21316b1db527ff7424022b74e` |
| `asset:checkov/container-image-policy-scan` | WAITING_FOR_PREREQUISITE | `arsenal-20260827T203238Z-6a2fc79a` | `8fc45d0f8ba05746c878c5bca4cb742ef870a7ba5b4d5f32fb00edf03a4d7c7a` |
| `asset:class-dump/objective-c-interface-recovery` | WAITING_FOR_PREREQUISITE | `arsenal-20260827T203238Z-4da1bdd6` | `49c93535ba1d4ff5f091ac44467eaa4550be91a5795a7b9003bca24893e2b2ff` |
| `asset:codeql/cross-file-dataflow` | UNAVAILABLE | `arsenal-20260827T203238Z-37d6be1a` | `6424c2b2951b9bb866134cfd960840dea6e9d5c54fa095d8957bf3de3ad33004` |
| `asset:echidna/smart-contract-property-fuzzing` | UNAVAILABLE | `arsenal-20260827T203238Z-2430a94d` | `a8a17be5d55ce6931a42dd649e3d7edf7f0d28b9c77a913c13d7622f3628eb4c` |
| `asset:electron-asar/electron-package-extraction` | UNAVAILABLE | `arsenal-20260827T203238Z-e257db15` | `8d819231e1a5b474daa22e1106a9d3c67c97ac85afb50fd79e9363d4046def03` |
| `asset:firmadyne/firmware-emulation-fallback` | WAITING_FOR_PREREQUISITE | `arsenal-20260827T203238Z-d971cf86` | `3ecb0f1ab2748c60790f1c4a0f2e0de5cbbb96e862290b4bff7e0742b2e8c27f` |
| `asset:firmae/firmware-emulation` | WAITING_FOR_PREREQUISITE | `arsenal-20260827T203239Z-4c2750b0` | `61b719569a676e1394b90f971f9e198bfc8b62ef16fba4865a64819a3af37109` |
| `asset:floss/static-string-deobfuscation` | UNAVAILABLE | `arsenal-20260827T203239Z-a6e451ea` | `9cf72912a493532cec19dad042037f29e4f17f605f5a8522bc40af9a6bbe3dd0` |
| `asset:foundry/smart-contract-fuzz-and-invariant-tests` | UNAVAILABLE | `arsenal-20260827T203239Z-97fba3a5` | `33e5821781e1e5caf643576b1195a12e9e798c73171ff8eaedaaa67eae856a91` |
| `asset:frida/android-runtime-instrumentation` | WAITING_FOR_PREREQUISITE | `arsenal-20260827T203239Z-1adde36d` | `6e07d17e66fbdaf3726e448351528545e5f43d2c20b11fc5ef406b661d782327` |
| `asset:frida/ios-runtime-instrumentation` | WAITING_FOR_PREREQUISITE | `arsenal-20260827T203239Z-5ce90755` | `1d655b13d2f73789fcad0e0ef3064baa35cc9e303f1cd8b91d604f16d7a56bfc` |
| `asset:ghidra/headless-binary-analysis` | UNAVAILABLE | `arsenal-20260827T203239Z-95f6516e` | `678a9a8dda3093a1fce3854f989f1b2345d814b25e93ddc4d0afa185facb0653` |
| `asset:grype/container-image-vulnerability-scan` | WAITING_FOR_PREREQUISITE | `arsenal-20260827T203240Z-2623dda9` | `42d3a14e73cf6b849e26aee7d14cd38786af0c1923f1503eaee65fb2785155aa` |
| `asset:jadx/android-decompile` | UNAVAILABLE | `arsenal-20260827T203240Z-82e131ab` | `7667f1376c793dc4b4e1c7993e749d2da09c2ec27eacec9d5c07ac54c8c50cc7` |
| `asset:kics/iac-security-scan` | UNAVAILABLE | `arsenal-20260827T203240Z-47983ac4` | `ed2af5cb8108caabb93c1791a5f14c726c74ff338f4ee65f210680e203b1b650` |
| `asset:mobsf/rest-static-analysis` | WAITING_FOR_PREREQUISITE | `arsenal-20260827T203240Z-1b735f85` | `3a1b54b4bdd321587ffa9bb657d2eea5496629e24d8de15c81e0246586bceec5` |
| `asset:modelscan/serialized-model-safety-scan` | UNAVAILABLE | `arsenal-20260827T203240Z-a966f3d6` | `a8e5cbae561801bb4140d4d7f238127c501b3bf8e0e853d24876d77cc71e6f76` |
| `asset:npm/npm-dependency-audit` | WAITING_FOR_PREREQUISITE | `arsenal-20260827T203241Z-ad3c1e14` | `a01364d1cdcd0e8c1940c8885d90298d21bed59f8ca8ecc18080290c738e473a` |
| `asset:objection/android-runtime-exploration` | WAITING_FOR_PREREQUISITE | `arsenal-20260827T203241Z-fbe20b87` | `cdcaf83b9b39ee26f80e5c3d31cfdb3a521aef75cf990783d4cb3a0c37a4f985` |
| `asset:objection/ios-runtime-exploration` | WAITING_FOR_PREREQUISITE | `arsenal-20260827T203241Z-3b5cdc3a` | `3049934bdc960005acbe6c092520961c96195b0403394f485ee11ea9b5d9f313` |
| `asset:otool/ios-macos-load-command-analysis` | WAITING_FOR_PREREQUISITE | `arsenal-20260827T203242Z-c8415a43` | `2e7d14ad9f6539db1a31d99a666fb5d01394d3ee4dc683de0caa14c803e7dda7` |
| `asset:pefile/pe-structure-analysis` | UNAVAILABLE | `arsenal-20260827T203242Z-fcafe51c` | `7bde7aee7be20c37d9b0e6ba2bdf0de43ba31289418e74584646b4d88f98ecc5` |
| `asset:pip-audit/python-dependency-vulnerability-analysis` | UNAVAILABLE | `arsenal-20260827T203242Z-bc1caae8` | `5a94f64d80f4a1542638e4b3d99f3b2385fd87a940cc22857f56ae1c6e789dda` |
| `asset:restler/stateful-openapi-sequence-testing` | UNAVAILABLE | `arsenal-20260827T203242Z-4bd81f8a` | `c26ef0b0bc0a1eb0dbf54a82899ae8e61bfb96d561a278889bbbc94d55ce9152` |
| `asset:rizin/binary-reverse-engineering` | UNAVAILABLE | `arsenal-20260827T203242Z-9098f365` | `ff8a776682630081e02f5cf17856b47393d3504fd99a12f4d5448aaddc4ede3c` |
| `asset:spotbugs/java-bytecode-static-analysis` | UNAVAILABLE | `arsenal-20260827T203242Z-6519dde8` | `c230e5737cf7fed5692c7cba7b868bc92c010e28e6ef46717f5b3981c627e41c` |
| `asset:syft/artifact-sbom` | UNAVAILABLE | `arsenal-20260827T203243Z-959342a0` | `43c363918e8f1109efd9d4ab7aeb7b89160703847e3ecca889d7394c2d63f25b` |
| `asset:syft/container-image-sbom` | UNAVAILABLE | `arsenal-20260827T203243Z-70bd85c8` | `c6b8b698ead436155ad35819ba6af01c1c1177cd2a78ef1a20f0c6a144feb355` |
| `asset:trivy/container-image-security-scan` | WAITING_FOR_PREREQUISITE | `arsenal-20260827T203243Z-e335c791` | `6dfd908f01b5260c716357d860eea44105dceb7c67ea9541b7041c273c072609` |
| `asset:web-ext/browser-extension-structure-lint` | UNAVAILABLE | `arsenal-20260827T203243Z-ef268afe` | `f48c50d3b72e46eb09e616405013a3ce06513115caf75aa800225fbbd8891d49` |
| `asset:yara/approved-rule-binary-scan` | UNAVAILABLE | `arsenal-20260827T203244Z-0b6dd4d4` | `1676f5e945777f000a9341846361f00ac0610b6a21e4f0679ccbfd848fc6e767` |
| `asset:zizmor/github-actions-security-audit` | UNAVAILABLE | `arsenal-20260827T203244Z-d17bb5a6` | `01122cf1a47b110b63f6c3a08a9ef4bc2fbc52e4ddd476bb7e0181f63c33d529` |
| `fixture:ai/llm-security-boundary` | EXECUTED_PASS | `arsenal-20260827T203244Z-71e38599` | `1e241c3bf8b224a5651067483f0f9e86a60e32fd79d541c9cb2db8f3bd2f7f36` |
| `tool:bandit/code` | EXECUTED_PASS | `arsenal-20260827T203245Z-d0bf7531` | `44f814ef2964ba6e5aafa7465b90419c69dbc0f1524972c000116e0770c65142` |
| `tool:brakeman/code` | EXECUTED_PASS | `arsenal-20260827T203246Z-4beb6ac3` | `d7d6620f95c86bbe2848adf0b8ee94a239add23feace4876044d4c6482505508` |
| `tool:checkov/deps` | EXECUTED_PASS | `arsenal-20260827T203250Z-a197e48b` | `7aeb895a40415a6bb15e076ef7f50f63f1164f8abc2253ae052a29d5a1cd01ab` |
| `tool:detect-secrets/secrets` | EXECUTED_PASS | `arsenal-20260827T203259Z-2309945d` | `d22c5998047fe4be3d8c253bfb8332426beefb2f3131c116bc673d9ed2720170` |
| `tool:gitleaks/secrets` | EXECUTED_PASS | `arsenal-20260827T203300Z-b832d86d` | `e20857a52e7f0947ef0604adb360907dc71d3ceabed3d122b5e874148de8dea0` |
| `tool:gosec/code` | EXECUTED_PASS | `arsenal-20260827T203301Z-c0b87080` | `93d6d1fc2b6449ee65b3ddf1669441b48ced9988e837db5f28219bb1c3336298` |
| `tool:grype/deps` | EXECUTED_PASS | `arsenal-20260827T203307Z-d8ef174d` | `f0de750328fc8cfab1d691875e4a714c1fca15719786a4d561aa597e9fd833e1` |
| `tool:mythril/contract` | EXECUTED_PASS | `arsenal-20260827T203318Z-0d641fa2` | `5e2d001da170c6b7a10663eb343bca49594ed7743a893e2d8c6b84e3e1729fa9` |
| `tool:njsscan/code` | EXECUTED_PASS | `arsenal-20260827T203348Z-35cd11b1` | `311868d32868ad82e3dd05a9b5cb2a42c08b320d6ef2d225f046238ff71d9776` |
| `tool:osv-scanner/deps` | EXECUTED_PASS | `arsenal-20260827T203403Z-f6f3f4ae` | `76c0decb263a927e5afc95bc35f3ff8f8263171f28c6f1569b4036063a594d07` |
| `tool:psalm/code` | EXECUTED_PASS | `arsenal-20260827T203428Z-9844d1d5` | `06e4f6aa05ca66a6f872aa3dc502c39f65aec78d50702639a2facec7cfc90f05` |
| `tool:retire-js/deps` | EXECUTED_PASS | `arsenal-20260827T203440Z-cb35eaa2` | `d661d64586f974b3454c59b4cb7f83b2b110d2b1eb5cf286cf7d037e81e5ce3a` |
| `tool:semgrep/code` | EXECUTED_PASS | `arsenal-20260827T203443Z-1da60816` | `b30a3da04299276fa60c33c07c17edd8934e06fb1089ac041d7589c7d67e8cb3` |
| `tool:slither/contract` | EXECUTED_PASS | `arsenal-20260827T203451Z-7a1515cd` | `07580f57133e4bb5eadc07d6966adcf7a921be5c3de35f181a9939acaeff948e` |
| `tool:trivy/deps` | EXECUTED_PASS | `arsenal-20260827T203453Z-5f63279c` | `01fc2a8fe538f306291e2c0c365405f1595c3765efec4bb775730f73bbef9f91` |
| `tool:trivy/secrets` | EXECUTED_PASS | `arsenal-20260827T203454Z-fb3b79ac` | `807cee92beb06153693a60a303e0036793c9fa54a1452bb922daa205b05d7065` |

## Never executed external backends

- `external:analyzeHeadless`
- `external:angr`
- `external:apktool`
- `external:asar`
- `external:azurehound`
- `external:binwalk`
- `external:capa`
- `external:class-dump`
- `external:cloudsplaining`
- `external:codeql`
- `external:dnsx`
- `external:echidna`
- `external:firmadyne`
- `external:firmae`
- `external:floss`
- `external:forge`
- `external:frida`
- `external:garak`
- `external:gau`
- `external:grpcurl`
- `external:http-probe`
- `external:httpx`
- `external:jadx`
- `external:jsluice`
- `external:katana`
- `external:kics`
- `external:kubescape`
- `external:mitmproxy`
- `external:mobsf`
- `external:modelscan`
- `external:naabu`
- `external:nmap`
- `external:npm`
- `external:nuclei`
- `external:objection`
- `external:otool`
- `external:pefile`
- `external:pip-audit`
- `external:playwright`
- `external:promptfoo`
- `external:prowler`
- `external:pyrit`
- `external:restler`
- `external:rizin`
- `external:roadrecon`
- `external:rustscan`
- `external:schemathesis`
- `external:scorecard`
- `external:scout`
- `external:skopeo`
- `external:spotbugs`
- `external:ssh-audit`
- `external:subfinder`
- `external:syft`
- `external:testssl.sh`
- `external:web-ext`
- `external:websocat`
- `external:yara`
- `external:zizmor`

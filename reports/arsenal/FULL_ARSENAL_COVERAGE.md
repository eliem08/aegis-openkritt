# Full Arsenal Coverage

Verdict: **FIXTURE ARSENAL PARTIALLY VERIFIED**

Git SHA: `e4abae3302ff8277f5601f173ffa51fc3d99b3b0`  
Arsenal image: `sha256:043e52e4250b93330adb442dcde599695a12d50d9c144dbf9b5e336f6b80b76a`

## Metrics

- `total_canonical_capabilities`: `174`
- `unique_backends`: `100`
- `unique_external_backends`: `74`
- `healthy_backends`: `40`
- `backend_executions`: `41`
- `fixture_executed_backends`: `39`
- `fixture_executed_capabilities`: `53`
- `fixture_backend_denominator`: `60`
- `fixture_capability_denominator`: `79`
- `fixture_backend_execution_coverage`: `0.65`
- `fixture_capability_execution_coverage`: `0.6708860759493671`
- `authorized_real_execution_coverage`: `None`
- `authorized_real_executed_capabilities`: `0`
- `positive_controls_passed`: `41`
- `negative_controls_passed`: `41`
- `never_executed_external_backends`: `35`
- `states`: `{'EXECUTED_PASS': 41, 'EXECUTED_FINDING': 0, 'WAITING_FOR_PREREQUISITE': 20, 'UNAVAILABLE': 7, 'DENIED_BY_POLICY': 0, 'DENIED_POLICY_AMBIGUOUS': 0, 'NOT_IMPLEMENTED': 0, 'BACKEND_UNHEALTHY': 0}`

## Executions

| Capability | State | Run | Evidence |
|---|---|---|---|
| `asset:aegis-agent-permission-audit/agent-tool-permission-analysis` | WAITING_FOR_PREREQUISITE | `arsenal-20260828T051622Z-74237bb1` | `c4c5695dddae135a4a6ae5e4cdc0bc8ee9630bce9a5ce42e4c3ef523d0a118cd` |
| `asset:aegis-artifact-diff/authorized-mobile-release-diff` | WAITING_FOR_PREREQUISITE | `arsenal-20260828T051622Z-2e0ceab4` | `0c5061d03db90082cc8b8648cbc6e88ef92320ef23ab17a1c2f8cee9cda25027` |
| `asset:aegis-asset-classifier/deterministic-asset-classification` | WAITING_FOR_PREREQUISITE | `arsenal-20260828T051622Z-5d739adc` | `ae5f4f570aed3eece0b61ea467f9dfb7e19f6a1209919100f72267c475d61f9a` |
| `asset:aegis-firmware-arch/firmware-architecture-detection` | WAITING_FOR_PREREQUISITE | `arsenal-20260828T051622Z-e97448ae` | `beb74de68d1b27efd9cfd5ad184108830c59cba6d4d097f58b479151e9fd091d` |
| `asset:aegis-memory-poisoning/agent-memory-poisoning-regression` | WAITING_FOR_PREREQUISITE | `arsenal-20260828T051622Z-946d875a` | `6bca501e9ddfce5c400883543b48348210c9fb87f9a1b13925d005442c0d8ad7` |
| `asset:aegis-model-provenance/model-provenance-and-hash-ledger` | WAITING_FOR_PREREQUISITE | `arsenal-20260828T051623Z-2700889d` | `85fa72553e42654fececeedfb2bc45813201b67a41d17eccb0898be3a2954c40` |
| `asset:aegis-rag-boundary/rag-retrieval-trust-analysis` | WAITING_FOR_PREREQUISITE | `arsenal-20260828T051623Z-281850d9` | `cea996c363a4486725d9042cae72b168c8a3d34104f85014fbdc6cf1e47ab674` |
| `asset:angr/binary-control-flow-analysis` | EXECUTED_PASS | `arsenal-20260828T051624Z-35032d6a` | `a1303ed2f1e42ed94aa095ca4975acee1c1e0255b180a75dfaa43c79efca8856` |
| `asset:apktool/android-resource-and-manifest-decode` | EXECUTED_PASS | `arsenal-20260828T051628Z-e2f25290` | `72c6101f3863e7d7955e733d3f2176f032a7ca2b8da3893782ebe985cbad0584` |
| `asset:binwalk/firmware-structure-analysis` | EXECUTED_PASS | `arsenal-20260828T051631Z-70667746` | `6fbe6de02cfea9b579f5617223592876e5f7bcb77f874d806721c100064a2a1d` |
| `asset:capa/binary-capability-analysis` | EXECUTED_PASS | `arsenal-20260828T051632Z-53739ef3` | `0336e7d313794d90aa17dccdedb351c282a0b5b58dee15f92c07f8ef005f590d` |
| `asset:checkov/container-image-policy-scan` | WAITING_FOR_PREREQUISITE | `arsenal-20260828T051649Z-34ed08b8` | `44a84c4448e0c2d1fed3acaf322fcfca4e7fcdede45fdcc3afd0fce05681f75a` |
| `asset:class-dump/objective-c-interface-recovery` | WAITING_FOR_PREREQUISITE | `arsenal-20260828T051649Z-52f1e3cb` | `fdb5e6309f34327e7d3b713d1174022a60e15d9a3a351914bc6b622bb1c2a9e9` |
| `asset:codeql/cross-file-dataflow` | UNAVAILABLE | `arsenal-20260828T051649Z-c9369b9d` | `fbd85bd589c4e27db8029f2ae399024d292f7186e9e2fa15359612320d6f2e38` |
| `asset:echidna/smart-contract-property-fuzzing` | EXECUTED_PASS | `arsenal-20260828T051649Z-530969e5` | `a6ebf367da16fede0250103f5b0177825e0d9c97eda4337cdd5ffd688ff51dcc` |
| `asset:electron-asar/electron-package-extraction` | EXECUTED_PASS | `arsenal-20260828T051651Z-cfcd924f` | `0b68a3cf77049c2cce35c9376ae1126d288545113abf57c0e51fb388f6640b51` |
| `asset:firmadyne/firmware-emulation-fallback` | WAITING_FOR_PREREQUISITE | `arsenal-20260828T051652Z-43b5cec2` | `0e7347ffb3ddc404b383acb4675e952936624510dc64bf924de14416922dc0f3` |
| `asset:firmae/firmware-emulation` | WAITING_FOR_PREREQUISITE | `arsenal-20260828T051652Z-49ec5dc6` | `67805c1705029f54fb0fbe37deb6d84218095a29c720c856a9e1d5cb9e897cf6` |
| `asset:floss/static-string-deobfuscation` | UNAVAILABLE | `arsenal-20260828T051652Z-6754ac0e` | `56f1350c1caf6fd19ea8c6ec12e0ba5fb2be357d8f4f23685a606a38c6fac59d` |
| `asset:foundry/smart-contract-fuzz-and-invariant-tests` | EXECUTED_PASS | `arsenal-20260828T051652Z-6b4df921` | `392a48a49e43c6ddcba9b64a2a5027e8fa25c96a5c4c0893204773664fb60f13` |
| `asset:frida/android-runtime-instrumentation` | WAITING_FOR_PREREQUISITE | `arsenal-20260828T051655Z-6d1f73a3` | `d2deb5cf993efed1f4f2d9bd536aa286080dc24368c3e4d10b83fdef98b6a621` |
| `asset:frida/ios-runtime-instrumentation` | WAITING_FOR_PREREQUISITE | `arsenal-20260828T051655Z-90f27fcb` | `bb7db680987a10493ec198be32343ae50aa74073fa0c9864814f3bf842d3d340` |
| `asset:ghidra/headless-binary-analysis` | UNAVAILABLE | `arsenal-20260828T051655Z-9b8439fb` | `bfecfc6bd6e2fc232ad16411ea4e637b2abdd9dae962cae78c8f0306d097c9d6` |
| `asset:grpcurl/grpc-service-introspection` | EXECUTED_PASS | `arsenal-20260828T051655Z-81d7aa8c` | `0ca07330991bb552269dc9630daabb3a12eb923d6aa8f9dd246feda435e1d76f` |
| `asset:grype/container-image-vulnerability-scan` | WAITING_FOR_PREREQUISITE | `arsenal-20260828T051657Z-a599528e` | `386ae134b4c038b1bdc0f4ad3e3d14232ef37ca38ed1afb714f969e05cad9a90` |
| `asset:httpx/http-service-enrichment` | EXECUTED_PASS | `arsenal-20260828T051657Z-428d009d` | `b0beaf19ea97199e3a172d1b3c01dbebee9430ec48643eaa7768464c25043e75` |
| `asset:jadx/android-decompile` | UNAVAILABLE | `arsenal-20260828T051659Z-6fe59503` | `fab12fb81fbbf6817822647b8608d88c5df930209a8714c1e922845d935dd919` |
| `asset:kics/iac-security-scan` | EXECUTED_PASS | `arsenal-20260828T051700Z-fec1a834` | `e91a147580ee565704eaff039bd5157c8b3b70ad94ebaddcb22970b616bcf750` |
| `asset:mobsf/rest-static-analysis` | WAITING_FOR_PREREQUISITE | `arsenal-20260828T051701Z-95318903` | `5fbbc18116e099d23d9fc11a00a8825b8422c26d940a93968bfd30798e2167ee` |
| `asset:modelscan/serialized-model-safety-scan` | EXECUTED_PASS | `arsenal-20260828T051701Z-f269096f` | `b0b11c0cbe1fc71894123d18bf0b9d0f4b9477fb26cedc6bd07d76c48d69b472` |
| `asset:naabu/bounded-port-discovery` | EXECUTED_PASS | `arsenal-20260828T051703Z-8de747b3` | `2e3d59ee68cf18f449e026b5ce40636c912df281d16d60b0ffe781c6667db62b` |
| `asset:nmap/bounded-service-fingerprinting` | EXECUTED_PASS | `arsenal-20260828T051710Z-6833eb6c` | `49d402ad40de39ccc85e4dff3792001d1a9808dbff0024795226454181f3e537` |
| `asset:npm/npm-dependency-audit` | EXECUTED_PASS | `arsenal-20260828T051719Z-43d333e4` | `6a54d840a92bd3e4c81ef336bcdca5296fc2ec3cbd55449c6552a6561799fae1` |
| `asset:objection/android-runtime-exploration` | WAITING_FOR_PREREQUISITE | `arsenal-20260828T051720Z-e341e1b6` | `312b238fcc1c7c2a18c436864751a378df5d7220ffcc34a29ca658e9c01a1803` |
| `asset:objection/ios-runtime-exploration` | WAITING_FOR_PREREQUISITE | `arsenal-20260828T051720Z-8a099333` | `7818e3f52f391d9e7ccd2ca32e6c43fca12bc45652d873beedaa480861469502` |
| `asset:otool/ios-macos-load-command-analysis` | WAITING_FOR_PREREQUISITE | `arsenal-20260828T051720Z-28a1a2db` | `8d05fcfaf31557f4b9da3506a47862148ff1a4022b3ad51a8d1c111c140e04f0` |
| `asset:pefile/pe-structure-analysis` | EXECUTED_PASS | `arsenal-20260828T051721Z-6f0a0988` | `43af46b42fdb35db6f30444cc763b9911592b2f7e850b5338c9c0dd7668ccfe3` |
| `asset:pip-audit/python-dependency-vulnerability-analysis` | UNAVAILABLE | `arsenal-20260828T051721Z-38277c84` | `a0219ce08e72ef8141b4a601206f8980847f28198989c71dec75f553082c838e` |
| `asset:restler/stateful-openapi-sequence-testing` | UNAVAILABLE | `arsenal-20260828T051721Z-a225082e` | `224ffb8216ee822dbd2ef40a074d36b9abd9684dfdca5242e926019a8ca3c0c7` |
| `asset:rizin/binary-reverse-engineering` | UNAVAILABLE | `arsenal-20260828T051721Z-858e7b70` | `9e58c35c4ade5026eefff4a539a58a630c2ad19d7960e9e9e327b2be4f106bb0` |
| `asset:rustscan/bounded-fast-port-prefilter` | EXECUTED_PASS | `arsenal-20260828T051721Z-8f7b615f` | `d3a74a04805a964f058da83a097a49c31a8a1bd8f66725e89ba4066de14d6398` |
| `asset:schemathesis/schema-guided-api-testing` | EXECUTED_PASS | `arsenal-20260828T051723Z-52e9e4f9` | `767119ea16c1a5517d0bca45cb13176e8cf5c951cf5707b828f019a66e484538` |
| `asset:skopeo/container-registry-metadata` | EXECUTED_PASS | `arsenal-20260828T051726Z-b85c6d29` | `ae5b78b860c0fcb90a0371801fe3e9cf2fd3e36ba8f3e20692b26bd1e432cf9a` |
| `asset:spotbugs/java-bytecode-static-analysis` | EXECUTED_PASS | `arsenal-20260828T051730Z-ca0883e2` | `57eea191b28edc1029a692fdcccb7a8e7c6088a0a2d74807f8dc80ea6e415fb6` |
| `asset:syft/artifact-sbom` | EXECUTED_PASS | `arsenal-20260828T051741Z-a757b2eb` | `816c2dd9fd00f85e9c55085008572632cc771ddd5bff5f7c027e9df3b72814dc` |
| `asset:syft/container-image-sbom` | WAITING_FOR_PREREQUISITE | `arsenal-20260828T051743Z-d957f243` | `76a76832cd4506dd4b30effaa2767220fe6287084d4f2325f2848b1284942f86` |
| `asset:trivy/container-image-security-scan` | WAITING_FOR_PREREQUISITE | `arsenal-20260828T051743Z-9e9278a2` | `3c49dee248a01cd443e1fbd17c73f0f1781fc3b3a08b2439cf4d4eb02d71587f` |
| `asset:web-ext/browser-extension-structure-lint` | EXECUTED_PASS | `arsenal-20260828T051744Z-f9c4e289` | `d2ca7bf18752d5204abf1e4a98531b7898ffaa709d2821472ec3b5f483564808` |
| `asset:websocat/websocket-protocol-observation` | EXECUTED_PASS | `arsenal-20260828T051747Z-d2025076` | `374ad5efbba5b9a785bb2cab103787d1ecd2646184d15e883f48e296dd73b774` |
| `asset:yara/approved-rule-binary-scan` | EXECUTED_PASS | `arsenal-20260828T051748Z-1fd02623` | `aa995a7d0b1b275e797b47170cec090c9f2e5f42fb4d3dd0d153ddb8484c9a3b` |
| `asset:zizmor/github-actions-security-audit` | EXECUTED_PASS | `arsenal-20260828T051748Z-1c49a92e` | `a5c0dc4cf77933558c6dd6bf65c598114362cf2974ad5b0d395205659abaeeea` |
| `fixture:ai/llm-security-boundary` | EXECUTED_PASS | `arsenal-20260828T051749Z-621c57b6` | `0c4e778e7f3349dc12998115da08b14e7c2455118cc8153d6600876f9b414ef7` |
| `tool:bandit/code` | EXECUTED_PASS | `arsenal-20260828T051749Z-03050d6d` | `6549f91f0a3471ac9403f5eef5e3d3f26acb5874b4f0d2e6f5c048d2b60418a1` |
| `tool:brakeman/code` | EXECUTED_PASS | `arsenal-20260828T051750Z-c85fb767` | `b23b039eb246d8e19134223c98ae6f67f21792afefb9b38a131b7ccfe9407205` |
| `tool:checkov/deps` | EXECUTED_PASS | `arsenal-20260828T051754Z-0c51ee0f` | `9df95409a66ee087b1c5839707263b484510d1dcbf9e05ab433f2df9df726b24` |
| `tool:detect-secrets/secrets` | EXECUTED_PASS | `arsenal-20260828T051802Z-e8032602` | `f328ca8f315ff1b9aabac40d91ffa72a2a246ac0aaa513e333a62e4df9468bce` |
| `tool:gitleaks/secrets` | EXECUTED_PASS | `arsenal-20260828T051803Z-75413af0` | `877b4e90040039ffa73dd685a488298d6c6cd781d9358d3e97507bca5e2cd5cf` |
| `tool:gosec/code` | EXECUTED_PASS | `arsenal-20260828T051803Z-8c498a66` | `c517bf8fad2b3910c7a4eef2cb9344afdf5ce7f8af27d6b947e39b1238e37fd8` |
| `tool:grype/deps` | EXECUTED_PASS | `arsenal-20260828T051810Z-d33430ae` | `25d6b5bbba8f678f251619bc94e1a8bba1d5a905bde3619834c801762fbcde7a` |
| `tool:mythril/contract` | EXECUTED_PASS | `arsenal-20260828T051819Z-5a664854` | `c84a6007b72e5d2e7afee79a5209e1bd2491cf028c34b277ea314418239cceb0` |
| `tool:njsscan/code` | EXECUTED_PASS | `arsenal-20260828T051844Z-ec53ba78` | `9788d8463b58d3fa7945a108e7313807ae1521cb542fa722a146b5cb98509d55` |
| `tool:osv-scanner/deps` | EXECUTED_PASS | `arsenal-20260828T051904Z-0a056ab0` | `5a2edd6d34a085d385032cfad659b15267f3f0d3bc6ffe5cf4b79c2e176f5f49` |
| `tool:psalm/code` | EXECUTED_PASS | `arsenal-20260828T051925Z-9c75b7fd` | `d7653d0b27fd819969137ea31e8f5271f1ef5122ee0650913d29c8c3457c7c61` |
| `tool:retire-js/deps` | EXECUTED_PASS | `arsenal-20260828T051935Z-9ebe05a2` | `153193a1fc291eaa7433bcb9f5775ec6c9474bab9257f33cad80851f1c8484d3` |
| `tool:semgrep/code` | EXECUTED_PASS | `arsenal-20260828T051937Z-9100f8fe` | `8211e46f0ffc2acf43f7c3ddbded4af5246eeb7f7861f791d397a5e13a8ef5d6` |
| `tool:slither/contract` | EXECUTED_PASS | `arsenal-20260828T051945Z-58744c65` | `2d3f5a3b520140860bc280309598bd320e186de7d45e17e9a0addd7e61a4889b` |
| `tool:trivy/deps` | EXECUTED_PASS | `arsenal-20260828T051946Z-e51b1ec5` | `13e8bedcbbd512900a6b9481be385034b697a4a4ade734933983a07ad2f29704` |
| `tool:trivy/secrets` | EXECUTED_PASS | `arsenal-20260828T051947Z-4b85e35b` | `c6ca8a660c89fe25d0e439ada0e76c515d3443282e31e19c67f69d48493e8965` |

## Never executed external backends

- `external:analyzeHeadless`
- `external:azurehound`
- `external:class-dump`
- `external:cloudsplaining`
- `external:codeql`
- `external:dnsx`
- `external:firmadyne`
- `external:firmae`
- `external:floss`
- `external:frida`
- `external:garak`
- `external:gau`
- `external:http-probe`
- `external:jadx`
- `external:jsluice`
- `external:katana`
- `external:kubescape`
- `external:mitmproxy`
- `external:mobsf`
- `external:nuclei`
- `external:objection`
- `external:otool`
- `external:pip-audit`
- `external:playwright`
- `external:promptfoo`
- `external:prowler`
- `external:pyrit`
- `external:restler`
- `external:rizin`
- `external:roadrecon`
- `external:scorecard`
- `external:scout`
- `external:ssh-audit`
- `external:subfinder`
- `external:testssl.sh`

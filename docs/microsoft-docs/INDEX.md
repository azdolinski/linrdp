# Microsoft Open Specifications — RDP

Pobrane z learn.microsoft.com / winprotocoldocs CDN.

Dla każdej specyfikacji są trzy pliki:

- `[MS-X].pdf` — wersja bieżąca (URL bez daty na CDN),
- `[MS-X]-YYMMDD.docx` — najnowsza datowana rewizja,
- `ms-x.txt` — plain text wyciągnięty z DOCX, do grepowania.

W `.txt` jedna linia = jeden akapit (komórki tabel też), a nagłówki mają
odtworzone numery sekcji oddzielone tabulatorem, więc działa np.:

```bash
grep -n '^2\.2\.9\.1\.1\.3\.1\.2\.1\s' docs/microsoft-docs/ms-rdpbcgr.txt
grep -rn 'RDPGFX_WIRE_TO_SURFACE_PDU_1' docs/microsoft-docs/*.txt
```

Skrypty:

- `refresh.py` — pobiera/odświeża PDF i DOCX (`python3 refresh.py` lub `python3 refresh.py ms-rdpegfx`),
- `docx2txt.py` — regeneruje `.txt` z DOCX (`python3 docx2txt.py` lub `python3 docx2txt.py MS-RDPEGFX`).


## Rodzina MS-RDP* (40)

| Dokument | Rewizja | Tytuł | Strona |
|---|---|---|---|
| `[MS-RDPADRV]` | 2024-04-23 | Remote Desktop Protocol: Audio Level and Drive Letter Persistence Virtual Channel Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpadrv/4f15ac3b-0cbd-4cce-9a3e-b5a3f4c50727) |
| `[MS-RDPBCGR]` | 2026-03-09 | Remote Desktop Protocol: Basic Connectivity and Graphics Remoting | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/5073f4ed-1e93-45e1-b039-6e30c385867c) |
| `[MS-RDPCR2]` | 2017-06-01 | Remote Desktop Protocol: Composited Remoting V2 | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpcr2/04c2c5e7-3e23-4a7f-b319-835f7d049822) |
| `[MS-RDPEA]` | 2024-04-23 | Remote Desktop Protocol: Audio Output Virtual Channel Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpea/bea2d5cf-e3b9-4419-92e5-0e074ff9bc5b) |
| `[MS-RDPEAI]` | 2024-04-23 | Remote Desktop Protocol: Audio Input Redirection Virtual Channel Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeai/d04ffa42-5a0f-4f80-abb1-cc26f71c9452) |
| `[MS-RDPEAR]` | 2024-04-23 | Remote Desktop Protocol Authentication Redirection Virtual Channel | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpear/a32e17ec-5869-4fad-bdae-d35f342fcb6f) |
| `[MS-RDPECAM]` | 2024-04-23 | Remote Desktop Protocol: Video Capture Virtual Channel Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpecam/92af6790-b79c-4813-9c07-7c545bed0242) |
| `[MS-RDPECI]` | 2024-04-23 | Remote Desktop Protocol: Core Input Virtual Channel Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeci/7be99a27-1c39-47f1-a76a-e38869ee892a) |
| `[MS-RDPECLIP]` | 2024-04-23 | Remote Desktop Protocol: Clipboard Virtual Channel Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeclip/fb9b7e0b-6db4-41c2-b83c-f889c1ee7688) |
| `[MS-RDPEDC]` | 2017-06-01 | Remote Desktop Protocol: Desktop Composition Virtual Channel Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpedc/869980fb-29ba-426d-8361-f7b6d287d2ea) |
| `[MS-RDPEDISP]` | 2024-04-23 | Remote Desktop Protocol: Display Update Virtual Channel Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpedisp/d2954508-f487-48bc-8731-39743e0854a9) |
| `[MS-RDPEDYC]` | 2024-04-23 | Remote Desktop Protocol: Dynamic Channel Virtual Channel Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpedyc/3bd53020-9b64-4c9a-97fc-90a79e7e1e06) |
| `[MS-RDPEECO]` | 2024-04-23 | Remote Desktop Protocol: Virtual Channel Echo Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeeco/dd36d1eb-2e97-4b24-b4a3-0ca68d500521) |
| `[MS-RDPEFS]` | 2024-04-23 | Remote Desktop Protocol: File System Virtual Channel Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/34d9de58-b2b5-40b6-b970-f82d4603bdb5) |
| `[MS-RDPEGDI]` | 2024-04-23 | Remote Desktop Protocol: Graphics Device Interface (GDI) Acceleration Extensions | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/745f2eee-d110-464c-8aca-06fc1814f6ad) |
| `[MS-RDPEGFX]` | 2026-05-11 | Remote Desktop Protocol: Graphics Pipeline Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/da5c75f9-cd99-450c-98c4-014a496942b0) |
| `[MS-RDPEGT]` | 2024-04-23 | Remote Desktop Protocol: Geometry Tracking Virtual Channel Protocol Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegt/64dd4742-7a1c-47a7-ad23-d1f696d8781d) |
| `[MS-RDPEI]` | 2024-04-23 | Remote Desktop Protocol: Input Virtual Channel Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpei/72a8cb65-7f6c-407c-a21a-3d970721fed0) |
| `[MS-RDPEL]` | 2024-04-23 | Remote Desktop Protocol: Location Virtual Channel Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpel/4397a0af-c821-4b75-9068-476fb579c327) |
| `[MS-RDPELE]` | 2024-04-23 | Remote Desktop Protocol: Licensing Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/3d3f160a-3ab3-4dfb-ba4e-47c27cd79409) |
| `[MS-RDPEMC]` | 2024-04-23 | Remote Desktop Protocol: Multiparty Virtual Channel Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpemc/1c867b2b-40b8-459a-9af6-906b6e0096fc) |
| `[MS-RDPEMSC]` | 2024-04-23 | Remote Desktop Protocol: Mouse Cursor Virtual Channel Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpemsc/2591b507-cd5a-4537-be29-b45540543dc8) |
| `[MS-RDPEMT]` | 2024-04-23 | Remote Desktop Protocol: Multitransport Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpemt/d22b606c-32c4-4647-b356-86f75e23a22c) |
| `[MS-RDPEPC]` | 2024-04-23 | Remote Desktop Protocol: Print Virtual Channel Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpepc/f36d96c2-c0f7-4186-96b1-16c8e2e1e47c) |
| `[MS-RDPEPNP]` | 2024-04-23 | Remote Desktop Protocol: Plug and Play Devices Virtual Channel Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpepnp/7463a339-d9c0-4dd1-ac3e-04ffa73f6932) |
| `[MS-RDPEPS]` | 2024-04-23 | Remote Desktop Protocol: Session Selection Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeps/83aeefd1-c4a1-4807-8072-2a597c8cf19b) |
| `[MS-RDPERP]` | 2026-07-14 | Remote Desktop Protocol: Remote Programs Virtual Channel Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdperp/83275957-2d0e-4c52-88d1-1b4c998c6bec) |
| `[MS-RDPESC]` | 2024-04-23 | Remote Desktop Protocol: Smart Card Virtual Channel Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpesc/0428ca28-b4dc-46a3-97c3-01887fa44a90) |
| `[MS-RDPESP]` | 2024-04-23 | Remote Desktop Protocol: Serial and Parallel Port Virtual Channel Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpesp/04ae8f6b-a2fe-4989-9314-09bff11fa086) |
| `[MS-RDPET]` | 2021-06-25 | Remote Desktop Protocol: Telemetry Virtual Channel Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpet/f2fd580b-75bf-42aa-9952-ae8d9ac8f658) |
| `[MS-RDPETXT]` | 2024-11-19 | Remote Desktop Protocol: Text Input Virtual Channel Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpetxt/cf2a87c7-bae1-4eb9-8a9a-63427e6d03f8) |
| `[MS-RDPEUDP]` | 2025-11-21 | Remote Desktop Protocol: UDP Transport Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/2744a3ee-04fb-407b-a9e3-b3b2ded422b1) |
| `[MS-RDPEUDP2]` | 2024-04-23 | Remote Desktop Protocol: UDP Transport Extension Version 2 | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp2/9db34630-e880-4bfd-9d8d-50bc044c3288) |
| `[MS-RDPEUSB]` | 2024-04-23 | Remote Desktop Protocol: USB Devices Virtual Channel Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeusb/a1004d0e-99e9-4968-894b-0b924ef2f125) |
| `[MS-RDPEV]` | 2024-04-23 | Remote Desktop Protocol: Video Redirection Virtual Channel Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpev/ff2a9f63-cbcc-4615-849f-03752a2b440b) |
| `[MS-RDPEVOR]` | 2024-04-23 | Remote Desktop Protocol: Video Optimized Remoting Virtual Channel Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpevor/a9947d55-9408-4cf8-b113-555b436bd3ce) |
| `[MS-RDPEWA]` | 2026-03-30 | Remote Desktop Protocol: WebAuthn Virtual Channel Protocol | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpewa/68f2df2e-7c40-4a93-9bb0-517e4283a991) |
| `[MS-RDPEXPS]` | 2024-04-23 | Remote Desktop Protocol: XML Paper Specification (XPS) Print Virtual Channel Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpexps/0231eff1-ec78-4371-b19c-6f81e1cc55ee) |
| `[MS-RDPNSC]` | 2024-04-23 | Remote Desktop Protocol: NSCodec Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpnsc/543fd1f1-8074-4122-8944-1017261810ca) |
| `[MS-RDPRFX]` | 2024-04-23 | Remote Desktop Protocol: RemoteFX Codec Extension | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdprfx/62495a4a-a495-46ea-b459-5cde04c44549) |

## Powiązane (11)

| Dokument | Rewizja | Tytuł | Strona |
|---|---|---|---|
| `[MS-CSSP]` | 2024-04-23 | Credential Security Support Provider (CredSSP) Protocol | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/85f57821-40bb-46aa-bfcb-ba9590b8fc30) |
| `[MS-RA]` | 2026-01-13 | Remote Assistance Protocol | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ra/49390b4f-b04b-46e0-ac03-76684c63ce87) |
| `[MS-RAI]` | 2024-04-23 | Remote Assistance Initiation Protocol | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rai/8711afb1-c382-4ba7-8b38-f344fb2c4030) |
| `[MS-RAIOP]` | 2024-04-23 | Remote Assistance Initiation over PNRP Protocol | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-raiop/22794246-19cc-44f7-823d-358a37ad7306) |
| `[MS-RCMP]` | 2024-04-23 | Remote Certificate Mapping Protocol | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rcmp/54627196-90dd-4e96-8c7f-7520066785ba) |
| `[MS-RDSOD]` | 2023-03-13 | Remote Desktop Services Protocols Overview | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdsod/072543f9-4bd4-4dc6-ab97-9a04bf9d2c6a) |
| `[MS-RDWR]` | 2024-04-23 | Remote Desktop Workspace Runtime Protocol | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdwr/f521ae33-861a-46e6-9fda-7c5f4f4155da) |
| `[MS-RSMC]` | 2024-04-23 | Remote Session Monitoring and Control Protocol | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rsmc/8cb97c03-5d33-4bdc-bb58-fef70cb45ad1) |
| `[MS-TSGU]` | 2024-04-23 | Terminal Services Gateway Server Protocol | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsgu/0007d661-a86d-4e8f-89f7-7f77f8824188) |
| `[MS-TSTS]` | 2025-11-21 | Terminal Services Terminal Server Runtime Interface Protocol | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/1eb45af1-94f1-4c42-9e13-dd0a018646fd) |
| `[MS-TSWP]` | 2024-04-23 | Terminal Services Workspace Provisioning Protocol | [learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tswp/1fc83092-67b5-4091-bd6f-256ce6658e80) |

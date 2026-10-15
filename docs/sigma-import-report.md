# Sigma 社区规则导入报告

> 由 `backend/scripts/import_sigma_community.py` 生成，勿手工编辑。
> 来源：https://github.com/SigmaHQ/sigma · 版本：`b4ba1f2+converter-syntax+typescope` · 生成时间：2026-10-14 05:56 UTC

## 导入漏斗

| 阶段 | 数量 | 说明 |
| --- | ---: | --- |
| 候选规则 | 2418 | 来自 windows/builtin、windows/create_remote_thread、windows/create_stream_hash、windows/dns_query、windows/driver_load、windows/file、windows/image_load、windows/network_connection、windows/pipe_created、windows/powershell、windows/process_access、windows/process_creation、windows/process_tampering、windows/raw_access_thread、windows/registry、windows/sysmon、windows/wmi_event |
| 排除已落盘重复 | 2 | 与既有规则文件同 id，重复导入会让同一行为产出双份事件 |
| 转换成功 | 2302 | logsource / 修饰符 / 通配 / 条件展开无法保持语义的一律整条跳过 |
| 去重后 | 2302 | 同 uuid / 同标题 / 同判据只留一条 |
| 误报裁剪后 | 2289 | 正常流量用例上必须零命中 |
| 带 `author` 元数据 | 2289 / 2289 | 取自源 Sigma 规则的 author 字段 |
| 带 `references` 元数据 | 2227 / 2289 | 只收 http(s) 链接；源规则里另有 107 条非链接参考（如 `Internal Research`）未纳入 |

**级别分布（保留的 2289 条）**：high 1127、medium 961、low 138、critical 54、info 9

## 被排除的已落盘重复规则（2 条）

这些规则的 id 已经存在于其它规则文件（典型是 `90-sigma.yaml` 里人工精选的那几条），再次导入会让同一行为同时产出内置事件与 `[Sigma]` 事件，故在转换前排除：

| 规则文件 | 标题 |
| --- | --- |
| `win_security_not_allowed_rdp_access.yml` | Denied Access To Remote Desktop |
| `win_security_rdp_reverse_tunnel.yml` | RDP over Reverse SSH Tunnel WFP |

## 跳过原因（Top 15）

> 这里只给每类原因一个示例。查「某条具体规则为什么没进来」请用文末的「附录：逐条跳过清单」，或用文件名 / 标题在本文档内检索。

| 原因 | 条数 | 示例 |
| --- | ---: | --- |
| logsource 无法映射 | 60 | win_exchange_transportagent.yml：logsource 无法映射：product=windows category=- service=msexchange-management |
| 暂不支持修饰符 | 20 | win_security_successful_external_remote_rdp_login.yml：暂不支持修饰符：cidr |
| 取反后分支过多，无法保持语义转换 | 15 | win_codeintegrity_attempted_dll_load.yml：取反后分支过多，无法保持语义转换 |
| 条件展开后分支过多，无法保持语义转换 | 12 | win_firewall_as_add_rule.yml：条件展开后分支过多，无法保持语义转换 |
| |all 仅支持与 contains / startswith / endswith / re 组合 | 5 | win_exchange_proxylogon_oabvirtualdir.yml：/all 仅支持与 contains / startswith / endswith / re 组合 |
| 未知修饰符 | 2 | file_event_win_susp_registry_hive_file_creation.yml：未知修饰符：i |

## 因命中正常流量被剔除（13 条）

这些规则在本地「正常流量」用例上产生了事件，按「不得虚假告警」的红线不导入：

| 规则 | 命中的正常流量用例 |
| --- | --- |
| `sigma.4281cb20-2994-4580-aa63-c8b86d019934` Hiding Files with Attrib.exe | sysmon-attrib-hidden-only-negative |
| `sigma.7c9340a9-e2ee-4e43-94c5-c54ebbea1006` File And SubFolder Enumeration Via Dir Command | sysmon-single-directory-listing-negative |
| `sigma.7be5fb68-f9ef-476d-8b51-0256ebece19e` Suspicious Execution of Hostname | sysmon-benign-administration-negative |
| `sigma.d95de845-b83c-4a9a-8a6a-4fc802ebf6c0` Suspicious Group And Account Reconnaissance Activity Using Net.EXE | sysmon-localgroup-list-negative |
| `sigma.88872991-7445-4a22-90b2-a3adadb0e827` Stop Windows Service Via Net.EXE | sysmon-normal-service-stop-negative |
| `sigma.f4bbd493-b796-416e-bbf2-121235348529` Non Interactive PowerShell Process Spawned | sysmon-normal-interpreter-usage-negative |
| `sigma.87e3c4e8-a6a8-4ad9-bb4f-46e7ff99a180` Change PowerShell Policies to an Insecure Level | sysmon-normal-interpreter-usage-negative |
| `sigma.754ed792-634f-40ae-b3bc-e0448d33f695` Suspicious PowerShell Parent Process | sysmon-normal-interpreter-usage-negative |
| `sigma.d522eca2-2973-4391-a3e0-ef0374321dae` Abused Debug Privilege by Arbitrary Parent Processes | sysmon-normal-interpreter-usage-negative |
| `sigma.beaa66d6-aa1b-4e3c-80f5-e0145369bfaf` Potentially Suspicious EventLog Recon Activity Using Log Query Utilities | sysmon-wevtutil-query-negative |
| `sigma.502b42de-4306-40b4-9596-6f590c81f073` Local Accounts Discovery | sysmon-net-user-query-negative |
| `sigma.d4ca7c59-e9e4-42d8-bf57-91a776efcb87` LOLBIN Execution From Abnormal Drive | sysmon-certutil-hashfile-negative |
| `sigma.221b251a-357a-49a9-920a-271802777cc0` Potential Process Reconnaissance via Wmic.EXE | sysmon-wmic-process-query-negative |

## 与内置检测重叠（26 条，属重复检出不是误报）

这些规则会在已有攻击样本上再次命中，说明它们与内置规则覆盖同一批行为。保留是为了不丢覆盖面，但分析结果里会同时出现内置事件与 `[Sigma]` 事件：

| 规则 | 重叠的攻击样本用例 |
| --- | --- |
| `sigma.00bb5bd5-1379-4fcf-a965-a5b6f7478064` | windows-event-kv-credential-attack-scenario |
| `sigma.b28e58e4-2a72-4fae-bdee-0fbe904db642` | windows-event-kv-credential-attack-scenario |
| `sigma.9fbf5927-5261-4284-a71d-f681029ea574` | scenario-sysmon-intrusion-chain |
| `sigma.cc9cbe82-7bc0-4ef5-bc23-bbfb83947be7` | sysmon-certutil-decode |
| `sigma.4b046706-5789-4673-b111-66f25fe99534` | sysmon-data-destruction-cipher-w |
| `sigma.863218bd-c7d0-4c52-80cd-0a96c09f54af` | scenario-sysmon-intrusion-chain |
| `sigma.cd219ff3-fa99-45d4-8380-a7d15116c6dc` | sysmon-create-local-account |
| `sigma.438025f9-5856-4663-83f7-52f878a70a50` | sysmon-encoded-command-execution |
| `sigma.ca2092a1-c273-4878-9b4b-0d60115bf5ea` | sysmon-encoded-command-execution |
| `sigma.b9d9cc83-380b-4ba3-8d8f-60c0e7e2930c` | sysmon-encoded-command-execution |
| `sigma.88f680b8-070e-402c-ae11-d2914f2257f1` | sysmon-encoded-command-execution |
| `sigma.17769c90-230e-488b-a463-e05c08e9d48f` | sysmon-defender-exclusion-added |
| `sigma.fb843269-508c-4b76-8b8d-88679db22ce7` | sysmon-encoded-command-execution |
| `sigma.fd877b94-9bb5-4191-bb25-d79cbd93c167` | sysmon-sam-hive-export |
| `sigma.92626ddd-662c-49e3-ac59-f6535f12d189` | sysmon-scheduled-task-persistence |
| `sigma.24c8392b-aa3c-46b7-a545-43f71657fe98` | sysmon-scheduled-task-persistence |
| `sigma.ad720b90-25ad-43ff-9b5e-5c841facc8e5` | sysmon-account-added-to-admins |
| `sigma.cc36992a-4671-4f21-a91d-6c2b72a2edf5` | sysmon-eventlog-cleared |
| `sigma.ffa6861c-4461-4f59-8a41-578c39f3f23e` | sysmon-lsass-memory-dump |
| `sigma.c09dad97-1c78-4f71-b127-7edb2b8e491a` | scenario-sysmon-intrusion-chain |
| `sigma.ce72ef99-22f1-43d4-8695-419dcb5d9330` | sysmon-security-service-stop |
| `sigma.c947b146-0abc-4c87-9c64-b17e9d7274a2` | sysmon-inhibit-recovery-vssadmin |
| `sigma.7cccd811-7ae9-4ebe-9afd-cb5c406b824b` | sysmon-lsass-memory-dump |
| `sigma.2e65275c-8288-4ab4-aeb7-6274f58b6b20` | sysmon-lsass-memory-dump |
| `sigma.5afee48e-67dd-4e03-a783-f74259dcf998` | sysmon-lsass-memory-dump |
| `sigma.7cce6fc8-a07f-4d84-a53e-96e1879843c9` | sysmon-lsass-memory-dump |

## 使用与限制（必须一起读）

- 这 2289 条是**社区规则**，事件名带 `[Sigma]` 前缀、`source: sigma`，与内置规则区分。
- 规则里的字段名就是 EVTX 的标准字段名（`OriginalFileName` / `Details` / `ParentCommandLine` …），解析器按标准结构把 `<System>` 事件头与 `<EventData>` 里每个 `<Data Name="…">` 原样落进记录，转换时**直连**这些字段，不再做「从原文里抠字段」的近似匹配。
- ⚠️ **它们没有本地正样本验证**：只做过「在正常流量用例上零命中」的筛查，不代表不会在真实环境误报。质量报告会把它们单列为「未验证的导入规则」。
- 一键停用全部社区规则：`RULE_SIGMA_IMPORTED_ENABLED=false`；单条停用按规则 id 生成的 `RULE_<标题>_ENABLED`。
- 重新生成：`cd backend && .venv\Scripts\python.exe scripts\import_sigma_community.py --sigma-dir <SigmaHQ 检出目录> --source-version <commit> --write`。

## 附录：逐条跳过清单（114 条）

按「原因 → 文件名」排序。原因里的字段名 / 修饰符名就是本项目记录模型缺失的部分，补上对应映射后重跑即可自动纳入：

| 规则文件 | 标题 | 原因 |
| --- | --- | --- |
| `win_alert_mimikatz_keywords.yml` | Mimikatz Use | logsource 无法映射：product=windows category=- service=- |
| `win_exchange_transportagent.yml` | MSExchange Transport Agent Installation - Builtin | logsource 无法映射：product=windows category=- service=msexchange-management |
| `posh_pc_remotefxvgpudisablement_abuse.yml` | Potential RemoteFXvGPUDisablement.EXE Abuse | logsource 无法映射：product=windows category=- service=powershell-classic |
| `posh_pc_susp_zip_compress.yml` | Zip A Folder With PowerShell For Staging In Temp - PowerShell | logsource 无法映射：product=windows category=- service=powershell-classic |
| `posh_pc_wsman_com_provider_no_powershell.yml` | Suspicious Non PowerShell WSMAN COM Provider | logsource 无法映射：product=windows category=- service=powershell-classic |
| `file_access_win_susp_credential_manager_access.yml` | Credential Manager Access By Uncommon Applications | logsource 无法映射：product=windows category=file_access service=- |
| `file_access_win_susp_credhist.yml` | Access To Windows Credential History File By Uncommon Applications | logsource 无法映射：product=windows category=file_access service=- |
| `file_access_win_susp_crypto_currency_wallets.yml` | Access To Crypto Currency Wallets By Uncommon Applications | logsource 无法映射：product=windows category=file_access service=- |
| `file_access_win_susp_dpapi_master_key_access.yml` | Access To Windows DPAPI Master Keys By Uncommon Applications | logsource 无法映射：product=windows category=file_access service=- |
| `file_access_win_susp_gpo_files.yml` | Access To Potentially Sensitive Sysvol Files By Uncommon Applications | logsource 无法映射：product=windows category=file_access service=- |
| `file_access_win_susp_process_access_browser_cred_files.yml` | Suspicious File Access to Browser Credential Storage | logsource 无法映射：product=windows category=file_access service=- |
| `file_access_win_teams_sensitive_files.yml` | Microsoft Teams Sensitive File Access By Uncommon Applications | logsource 无法映射：product=windows category=file_access service=- |
| `file_change_win_unusual_modification_by_dns_exe.yml` | Unusual File Modification by dns.exe | logsource 无法映射：product=windows category=file_change service=- |
| `file_executable_detected_win_susp_embeded_sed_file.yml` | Potentially Suspicious Self Extraction Directive File Created | logsource 无法映射：product=windows category=file_executable_detected service=- |
| `file_rename_win_ransomware.yml` | Suspicious Appended Extension | logsource 无法映射：product=windows category=file_rename service=- |
| `posh_pc_tamper_windows_defender_set_mp.yml` | Tamper Windows Defender - PSClassic | logsource 无法映射：product=windows category=ps_classic_provider_start service=- |
| `posh_pc_abuse_nslookup_with_dns_records.yml` | Nslookup PowerShell Download Cradle | logsource 无法映射：product=windows category=ps_classic_start service=- |
| `posh_pc_delete_volume_shadow_copies.yml` | Delete Volume Shadow Copies Via WMI With PowerShell | logsource 无法映射：product=windows category=ps_classic_start service=- |
| `posh_pc_downgrade_attack.yml` | PowerShell Downgrade Attack - PowerShell | logsource 无法映射：product=windows category=ps_classic_start service=- |
| `posh_pc_download_via_webclient.yml` | PowerShell Download Via Net.WebClient - PowerShell Classic | logsource 无法映射：product=windows category=ps_classic_start service=- |
| `posh_pc_exe_calling_ps.yml` | PowerShell Called from an Executable Version Mismatch | logsource 无法映射：product=windows category=ps_classic_start service=- |
| `posh_pc_powercat.yml` | Netcat The Powershell Version | logsource 无法映射：product=windows category=ps_classic_start service=- |
| `posh_pc_remote_powershell_session.yml` | Remote PowerShell Session (PS Classic) | logsource 无法映射：product=windows category=ps_classic_start service=- |
| `posh_pc_renamed_powershell.yml` | Renamed Powershell Under Powershell Channel | logsource 无法映射：product=windows category=ps_classic_start service=- |
| `posh_pc_susp_get_nettcpconnection.yml` | Use Get-NetTCPConnection | logsource 无法映射：product=windows category=ps_classic_start service=- |
| `posh_pm_active_directory_module_dll_import.yml` | Potential Active Directory Enumeration Using AD Module - PsModule | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_alternate_powershell_hosts.yml` | Alternate PowerShell Hosts - PowerShell Module | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_bad_opsec_artifacts.yml` | Bad Opsec Powershell Code Artifacts | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_clear_powershell_history.yml` | Clear PowerShell History - PowerShell Module | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_decompress_commands.yml` | PowerShell Decompress Commands | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_exploit_scripts.yml` | Malicious PowerShell Scripts - PoshModule | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_get_addbaccount.yml` | Suspicious Get-ADDBAccount Usage | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_get_clipboard.yml` | PowerShell Get Clipboard | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_hktl_evil_winrm_execution.yml` | HackTool - Evil-WinRm Execution - PowerShell Module | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_invoke_obfuscation_clip.yml` | Invoke-Obfuscation CLIP+ Launcher - PowerShell Module | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_invoke_obfuscation_obfuscated_iex.yml` | Invoke-Obfuscation Obfuscated IEX Invocation - PowerShell Module | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_invoke_obfuscation_stdin.yml` | Invoke-Obfuscation STDIN+ Launcher - PowerShell Module | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_invoke_obfuscation_var.yml` | Invoke-Obfuscation VAR+ Launcher - PowerShell Module | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_invoke_obfuscation_via_compress.yml` | Invoke-Obfuscation COMPRESS OBFUSCATION - PowerShell Module | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_invoke_obfuscation_via_rundll.yml` | Invoke-Obfuscation RUNDLL LAUNCHER - PowerShell Module | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_invoke_obfuscation_via_stdin.yml` | Invoke-Obfuscation Via Stdin - PowerShell Module | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_invoke_obfuscation_via_use_clip.yml` | Invoke-Obfuscation Via Use Clip - PowerShell Module | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_invoke_obfuscation_via_use_mhsta.yml` | Invoke-Obfuscation Via Use MSHTA - PowerShell Module | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_invoke_obfuscation_via_use_rundll32.yml` | Invoke-Obfuscation Via Use Rundll32 - PowerShell Module | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_invoke_obfuscation_via_var.yml` | Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - PowerShell Module | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_malicious_commandlets.yml` | Malicious PowerShell Commandlets - PoshModule | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_remote_powershell_session.yml` | Remote PowerShell Session (PS Module) | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_remotefxvgpudisablement_abuse.yml` | Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell Module | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_susp_ad_group_reco.yml` | AD Groups Or Users Enumeration Using PowerShell - PoshModule | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_susp_download.yml` | Suspicious PowerShell Download - PoshModule | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_susp_get_nettcpconnection.yml` | Use Get-NetTCPConnection - PowerShell Module | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_susp_invocation_generic.yml` | Suspicious PowerShell Invocations - Generic - PowerShell Module | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_susp_invocation_specific.yml` | Suspicious PowerShell Invocations - Specific - PowerShell Module | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_susp_local_group_reco.yml` | Suspicious Get Local Groups Information | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_susp_reset_computermachinepassword.yml` | Suspicious Computer Machine Password by PowerShell | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_susp_smb_share_reco.yml` | Suspicious Get Information for SMB Share - PowerShell Module | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_susp_zip_compress.yml` | Zip A Folder With PowerShell For Staging In Temp  - PowerShell Module | logsource 无法映射：product=windows category=ps_module service=- |
| `posh_pm_syncappvpublishingserver_exe.yml` | SyncAppvPublishingServer Bypass Powershell Restriction - PS Module | logsource 无法映射：product=windows category=ps_module service=- |
| `sysmon_config_modification_error.yml` | Sysmon Configuration Error | logsource 无法映射：product=windows category=sysmon_error service=- |
| `sysmon_config_modification_status.yml` | Sysmon Configuration Modification | logsource 无法映射：product=windows category=sysmon_status service=- |
| `win_exchange_proxylogon_oabvirtualdir.yml` | ProxyLogon MSExchange OabVirtualDirectory | /all 仅支持与 contains / startswith / endswith / re 组合 |
| `win_exchange_proxyshell_certificate_generation.yml` | Certificate Request Export to Exchange Webserver | /all 仅支持与 contains / startswith / endswith / re 组合 |
| `win_exchange_proxyshell_mailbox_export.yml` | Mailbox Export to Exchange Webserver | /all 仅支持与 contains / startswith / endswith / re 组合 |
| `win_exchange_proxyshell_remove_mailbox_export.yml` | Remove Exported Mailbox from Exchange Webserver | /all 仅支持与 contains / startswith / endswith / re 组合 |
| `win_exchange_set_oabvirtualdirectory_externalurl.yml` | Exchange Set OabVirtualDirectory ExternalUrl Property | /all 仅支持与 contains / startswith / endswith / re 组合 |
| `create_remote_thread_win_susp_uncommon_source_image.yml` | Remote Thread Creation By Uncommon Source Image | 取反后分支过多，无法保持语义转换 |
| `dns_query_win_domain_azurewebsites.yml` | DNS Query To AzureWebsites.NET By Non-Browser Process | 取反后分支过多，无法保持语义转换 |
| `dns_query_win_remote_access_software_domains_non_browsers.yml` | DNS Query To Remote Access Software Domain From Non-Browser App | 取反后分支过多，无法保持语义转换 |
| `file_event_win_shell_write_susp_files_extensions.yml` | Windows Binaries Write Suspicious Extensions | 取反后分支过多，无法保持语义转换 |
| `image_load_side_load_from_non_system_location.yml` | Potential System DLL Sideloading From Non System Locations | 取反后分支过多，无法保持语义转换 |
| `net_connection_win_domain_azurewebsites.yml` | Network Connection Initiated To AzureWebsites.NET By Non-Browser Process | 取反后分支过多，无法保持语义转换 |
| `net_connection_win_domain_dead_drop_resolvers.yml` | New Connection Initiated To Potential Dead Drop Resolver Domain | 取反后分支过多，无法保持语义转换 |
| `proc_access_win_susp_direct_ntopenprocess_call.yml` | Potential Direct Syscall of NtOpenProcess | 取反后分支过多，无法保持语义转换 |
| `proc_creation_win_squirrel_proxy_execution.yml` | Process Proxy Execution Via Squirrel.EXE | 取反后分支过多，无法保持语义转换 |
| `registry_delete_removal_com_hijacking_registry_key.yml` | Removal of Potential COM Hijacking Registry Keys | 取反后分支过多，无法保持语义转换 |
| `registry_set_asep_reg_keys_modification_currentversion.yml` | CurrentVersion Autorun Keys Modification | 取反后分支过多，无法保持语义转换 |
| `registry_set_asep_reg_keys_modification_currentversion_nt.yml` | CurrentVersion NT Autorun Keys Modification | 取反后分支过多，无法保持语义转换 |
| `registry_set_asep_reg_keys_modification_wow6432node.yml` | Wow6432Node CurrentVersion Autorun Keys Modification | 取反后分支过多，无法保持语义转换 |
| `win_codeintegrity_attempted_dll_load.yml` | CodeIntegrity - Unmet Signing Level Requirements By File Under Validation | 取反后分支过多，无法保持语义转换 |
| `win_security_susp_lsass_dump_generic.yml` | Potentially Suspicious AccessMask Requested From LSASS | 取反后分支过多，无法保持语义转换 |
| `net_connection_win_cmstp_initiated_connection.yml` | Outbound Network Connection Initiated By Cmstp.EXE | 暂不支持修饰符：cidr |
| `net_connection_win_dialer_initiated_connection.yml` | Outbound Network Connection Initiated By Microsoft Dialer | 暂不支持修饰符：cidr |
| `net_connection_win_office_outbound_non_local_ip.yml` | Office Application Initiated Network Connection To Non-Local IP | 暂不支持修饰符：cidr |
| `net_connection_win_rdp_reverse_tunnel.yml` | RDP Over Reverse SSH Tunnel | 暂不支持修饰符：cidr |
| `net_connection_win_regasm_network_activity.yml` | RegAsm.EXE Initiating Network Connection To Public IP | 暂不支持修饰符：cidr |
| `net_connection_win_rundll32_net_connections.yml` | Rundll32 Internet Connection | 暂不支持修饰符：cidr |
| `net_connection_win_susp_malware_callback_port.yml` | Potentially Suspicious Malware Callback Communication | 暂不支持修饰符：cidr |
| `net_connection_win_susp_malware_callback_ports_uncommon.yml` | Communication To Uncommon Destination Ports | 暂不支持修饰符：cidr |
| `net_connection_win_susp_outbound_mobsync_connection.yml` | Microsoft Sync Center Suspicious Network Connections | 暂不支持修饰符：cidr |
| `net_connection_win_winlogon_net_connections.yml` | Outbound Network Connection To Public IP Via Winlogon | 暂不支持修饰符：cidr |
| `net_connection_win_wscript_cscript_local_connection.yml` | Local Network Connection Initiated By Script Interpreter | 暂不支持修饰符：cidr |
| `net_connection_win_wscript_cscript_outbound_connection.yml` | Outbound Network Connection Initiated By Script Interpreter | 暂不支持修饰符：cidr |
| `net_connection_win_wuauclt_network_connection.yml` | Potentially Suspicious Wuauclt Network Connection | 暂不支持修饰符：cidr |
| `win_security_successful_external_remote_rdp_login.yml` | External Remote RDP Logon from Public IP | 暂不支持修饰符：cidr |
| `win_security_successful_external_remote_smb_login.yml` | External Remote SMB Logon from Public IP | 暂不支持修饰符：cidr |
| `win_security_susp_failed_logon_source.yml` | Failed Logon From Public IP | 暂不支持修饰符：cidr |
| `win_smbserver_connectivity_unsigned_and_unencrypted_share_connection.yml` | Unsigned or Unencrypted SMB Connection to Share Established | 暂不支持修饰符：cidr |
| `file_delete_win_delete_own_image.yml` | Process Deletion of Its Own Executable | 暂不支持修饰符：fieldref |
| `proc_creation_win_susp_cross_user_process_spawn.yml` | Suspicious Cross-User Process Spawn | 暂不支持修饰符：fieldref |
| `win_security_explicit_credential_local_logon.yml` | Potentially Suspicious Explicit Credential Local Logon | 暂不支持修饰符：fieldref |
| `file_event_win_susp_registry_hive_file_creation.yml` | Registry Hive File Staged Outside Standard User Profile Path | 未知修饰符：i |
| `proc_creation_win_susp_copy_system_dir.yml` | Suspicious Copy From or To System Directory | 未知修饰符：i |
| `create_remote_thread_win_susp_relevant_source_image.yml` | Rare Remote Thread Creation By Uncommon Source Image | 条件展开后分支过多，无法保持语义转换 |
| `file_event_win_creation_system_file.yml` | Files With System Process Name In Unsuspected Locations | 条件展开后分支过多，无法保持语义转换 |
| `file_event_win_office_susp_file_extension.yml` | File With Uncommon Extension Created By An Office Application | 条件展开后分支过多，无法保持语义转换 |
| `image_load_dll_system_management_automation_susp_load.yml` | PowerShell Core DLL Loaded By Non PowerShell Process | 条件展开后分支过多，无法保持语义转换 |
| `proc_access_win_lsass_susp_access_flag.yml` | Potentially Suspicious GrantedAccess Flags On LSASS | 条件展开后分支过多，无法保持语义转换 |
| `proc_creation_win_rundll32_susp_activity.yml` | Potentially Suspicious Rundll32 Activity | 条件展开后分支过多，无法保持语义转换 |
| `proc_creation_win_schtasks_env_folder.yml` | Schedule Task Creation From Env Variable Or Potentially Suspicious Path Via Schtasks.EXE | 条件展开后分支过多，无法保持语义转换 |
| `proc_creation_win_susp_bad_opsec_sacrificial_processes.yml` | Bad Opsec Defaults Sacrificial Processes With Improper Arguments | 条件展开后分支过多，无法保持语义转换 |
| `proc_creation_win_susp_script_exec_from_env_folder.yml` | Script Interpreter Execution From Suspicious Folder | 条件展开后分支过多，无法保持语义转换 |
| `proc_creation_win_susp_system_user_anomaly.yml` | Suspicious SYSTEM User Process Creation | 条件展开后分支过多，无法保持语义转换 |
| `raw_access_thread_susp_disk_access_using_uncommon_tools.yml` | Potential Defense Evasion Via Raw Disk Access By Uncommon Tools | 条件展开后分支过多，无法保持语义转换 |
| `win_firewall_as_add_rule.yml` | Uncommon New Firewall Rule Added In Windows Firewall Exception List | 条件展开后分支过多，无法保持语义转换 |

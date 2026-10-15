# 规则库体检报告

> 由 `backend/scripts/rule_health.py --write` 生成，勿手工编辑。

## 总览

- 规则总数：**2272**
- 阻断项：**0**（必须为 0）
- 观察项：**33**（已知且可接受，但不应变多）

## 阻断项

- 无

## 观察项

| 类型 | 条数 |
| --- | ---: |
| `event_type_collision` | 33 |

明细：

- [event_type_collision] event.type=`privileged_login` 被 2 条规则共用（ssh.privileged_login、windows.privileged_logon）
- [event_type_collision] event.type=`sigma_abuse_of_service_permissions_to_hide_services_vi` 被 2 条规则共用（sigma.514e4c3a-c77d-4cde-a00f-046425e2301e、sigma.953945c5-22fe-4a92-9f8a-a9edc1e522da）
- [event_type_collision] event.type=`sigma_adcs_certificate_template_configuration_vulnerab` 被 2 条规则共用（sigma.5ee3a654-372f-11ec-8d3d-0242ac130003、sigma.bfbd3291-de87-4b7c-88a2-d6a5deb28668）
- [event_type_collision] event.type=`sigma_awl_bypass_with_winrm_vbs_and_malicious_wsmpty_x` 被 2 条规则共用（sigma.074e0ded-6ced-4ebd-8b4d-53f55908119d、sigma.d353dac0-1b41-46c2-820c-d7d2561fc6ed）
- [event_type_collision] event.type=`sigma_compress_data_and_lock_with_password_for_exfiltr` 被 2 条规则共用（sigma.9fbf5927-5261-4284-a71d-f681029ea574、sigma.e2e80da2-8c66-4e00-ae3c-2eebd29f6b6d）
- [event_type_collision] event.type=`sigma_computer_discovery_and_export_via_get_adcomputer` 被 2 条规则共用（sigma.435e10e4-992a-4281-96f3-38b11106adde、sigma.db885529-903f-4c5d-9864-28fe199e6370）
- [event_type_collision] event.type=`sigma_deletion_of_volume_shadow_copies_via_wmi_with_po` 被 2 条规则共用（sigma.21ff4ca9-f13a-41ad-b828-0077b2af2e40、sigma.c1337eb8-921a-4b59-855b-4ba188ddcc42）
- [event_type_collision] event.type=`sigma_hiding_user_account_via_specialaccounts_registry` 被 2 条规则共用（sigma.9ec9fb1b-e059-4489-9642-f270c207923d、sigma.f8aebc67-a56d-4ec9-9fbe-7b0e8b7b4efd）
- [event_type_collision] event.type=`sigma_ie_zonemap_setting_downgraded_to_mycomputer_zone` 被 2 条规则共用（sigma.10344bb3-7f65-46c2-b915-2d00d47be5b0、sigma.3fd4c8d7-8362-4557-a8e6-83b29cc0d724）
- [event_type_collision] event.type=`sigma_import_powershell_modules_from_suspicious_direct` 被 2 条规则共用（sigma.21f9162c-5f5d-4b01-89a8-b705bd7d10ab、sigma.c31364f7-8be6-4b77-8483-dd2b5a7b69a3）
- [event_type_collision] event.type=`sigma_meterpreter_or_cobalt_strike_getsystem_service_i` 被 2 条规则共用（sigma.843544a7-56e0-4dcc-a44f-5cc266dd97d6、sigma.ecbc5e16-58e0-4521-9c60-eb9a7ea4ad34）
- [event_type_collision] event.type=`sigma_new_firewall_rule_added_in_windows_firewall_exce` 被 2 条规则共用（sigma.9e2575e7-2cb9-4da1-adc8-ed94221dca5e、sigma.eca81e8d-09e1-4d04-8614-c91f44fd0519）
- [event_type_collision] event.type=`sigma_outlook_enableunsafeclientmailrules_setting_enab` 被 2 条规则共用（sigma.55f0a3a1-846e-40eb-8273-677371b8d912、sigma.6763c6c8-bd01-4687-bc8d-4fa52cf8ba08）
- [event_type_collision] event.type=`sigma_potential_active_directory_enumeration_using_ad_` 被 2 条规则共用（sigma.70bc5215-526f-4477-963c-a47a5c9ebd12、sigma.9e620995-f2d8-4630-8430-4afd89f77604）
- [event_type_collision] event.type=`sigma_potential_credential_dumping_attempt_using_new_n` 被 2 条规则共用（sigma.0442defa-b4a2-41c9-ae2c-ea7042fc4701、sigma.baef1ec6-2ca9-47a3-97cc-4cf2bda10b77）
- [event_type_collision] event.type=`sigma_potential_dcom_internetexplorer_application_dll_` 被 2 条规则共用（sigma.2f7979ae-f82b-45af-ac1d-2b10e93b0baa、sigma.f354eba5-623b-450f-b073-0b5b2773b6aa）
- [event_type_collision] event.type=`sigma_potential_defense_evasion_activity_via_emoji_usa` 被 4 条规则共用（sigma.225274c4-8dd1-40db-9e09-71dff4f6fb3c、sigma.4a30ac0c-b9d6-4e01-b71a-5f851bbf4259、sigma.c98f2a0d-e1b8-4f76-90d3-359caf88d6b9、sigma.f9578658-9e71-4711-b634-3f9b50cd3c06）
- [event_type_collision] event.type=`sigma_potential_hidden_directory_creation_via_ntfs_ind` 被 2 条规则共用（sigma.0900463c-b33b-49a8-be1d-552a3b553dae、sigma.a8f866e1-bdd4-425e-a27a-37619238d9c7）
- [event_type_collision] event.type=`sigma_potential_homoglyph_attack_using_lookalike_chara` 被 2 条规则共用（sigma.32e280f1-8ad4-46ef-9e80-910657611fbc、sigma.4f1707b1-b50b-45b4-b5a2-3978b5a5d0d6）
- [event_type_collision] event.type=`sigma_potential_provisioning_registry_key_abuse_for_bi` 被 2 条规则共用（sigma.2a4b3e61-9d22-4e4a-b60f-6e8f0cde6f25、sigma.7021255e-5db3-4946-a8b9-0ba7a4644a69）
- [event_type_collision] event.type=`sigma_potential_signing_bypass_via_windows_developer_f` 被 2 条规则共用（sigma.a383dec4-deec-4e6e-913b-ed9249670848、sigma.b110ebaf-697f-4da1-afd5-b536fa27a2c1）
- [event_type_collision] event.type=`sigma_potentially_suspicious_call_to_win32_nteventlogf` 被 2 条规则共用（sigma.caf201a9-c2ce-4a26-9c3a-2b9525413711、sigma.e2812b49-bae0-4b21-b366-7c142eafcde2）
- [event_type_collision] event.type=`sigma_potentially_suspicious_desktop_background_change` 被 2 条规则共用（sigma.85b88e05-dadc-430b-8a9e-53ff1cd30aae、sigma.8cbc9475-8d05-4e27-9c32-df960716c701）
- [event_type_collision] event.type=`sigma_potentially_suspicious_execution_of_regasm_regsv` 被 2 条规则共用（sigma.cc368ed0-2411-45dc-a222-510ace303cb2、sigma.e9f8f8cc-07cc-4e81-b724-f387db9175e4）
- [event_type_collision] event.type=`sigma_powershell_dynamic_module_invocation_via_exporte` 被 2 条规则共用（sigma.0c3ebe9f-df09-4e00-be0f-73d4ca8d62f6、sigma.4ff4ad3e-9fb5-4a70-9962-d6ea58090318）
- [event_type_collision] event.type=`sigma_python_function_execution_security_warning_disab` 被 2 条规则共用（sigma.023c654f-8f16-44d9-bb2b-00ff36a62af9、sigma.17e53739-a1fc-4a62-b1b9-87711c2d5e44）
- [event_type_collision] event.type=`sigma_remote_access_tool_services_have_been_installed_` 被 2 条规则共用（sigma.1a31b18a-f00c-4061-9900-f735b96c99fc、sigma.c8b00925-926c-47e3-beea-298fd563728e）
- [event_type_collision] event.type=`sigma_security_event_logging_disabled_via_minint_regis` 被 2 条规则共用（sigma.1a4bd6af-99ac-4466-b5b2-7b72b4a05462、sigma.8839e550-52d7-4958-9f2f-e13c1e736838）
- [event_type_collision] event.type=`sigma_suspicious_file_download_from_file_sharing_domai` 被 2 条规则共用（sigma.56454143-524f-49fb-b1c6-3fb8b1ad41fb、sigma.a0d7e4d2-bede-4141-8896-bc6e237e977c）
- [event_type_collision] event.type=`sigma_suspicious_frombase64string_usage_on_gzip_archiv` 被 2 条规则共用（sigma.d75d6b6b-adb9-48f7-824b-ac2e786efe1f、sigma.df69cb1d-b891-4cd9-90c7-d617d90100ce）
- [event_type_collision] event.type=`sigma_suspicious_non_browser_network_communication_wit` 被 2 条规则共用（sigma.7e9cf7b6-e827-11ed-a05b-0242ac120003、sigma.c3dbbc9f-ef1d-470a-a90a-d343448d5875）
- [event_type_collision] event.type=`sigma_suspicious_service_dacl_modification_via_set_ser` 被 2 条规则共用（sigma.22d80745-6f2c-46da-826b-77adaededd74、sigma.a95b9b42-1308-4735-a1af-abb1c5e6f5ac）
- [event_type_collision] event.type=`sigma_unsigned_appx_installation_attempt_using_add_app` 被 2 条规则共用（sigma.37651c2a-42cd-4a69-ae0d-22a4349aa04a、sigma.975b2262-9a49-439d-92a6-0709cccdf0b2）

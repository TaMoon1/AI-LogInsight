# 规则质量报告（基准语料评估）

> 本文件由 `backend/scripts/eval_rules.py --write` 生成，请勿手工编辑。
> 语料位于 `backend/evaluation/corpus/`：每个用例包含一段标注日志与期望命中的规则
> （含风险等级、次数、来源 IP），另有负样本验证阈值以下不误报。

## 总览

- 用例：**123 / 123** 通过
- 内置规则正样本覆盖：**74 / 74**（共 1852 条规则 = 内置 74 + 导入 1778）
- 命中：TP **111** · FP **0** · FN **0**
- 准确率（precision）**100.0%** · 召回率（recall）**100.0%**
- 未被任何用例覆盖的内置规则：无
- ⚠️ **未验证的导入规则：1771 条**（社区规则只做过「正常流量零命中」筛查，没有本地正样本；事件名带 `[Sigma]` 前缀）
- 导入规则在攻击样本上重复命中：**25** 次（属重复检出，不是误报——误报的定义是正常流量被当成异常）

## 未验证的导入规则清单

> 以下规则已经导入并通过正常流量零命中筛查，但尚无本地正样本；它们不计入内置规则的已验证覆盖。

- `sigma.002bdb95-0cf1-46a6-9e08-d38c128a6127`
- `sigma.00321fee-ca72-4cce-b011-5415af3b9960`
- `sigma.0058b9e5-bcd7-40d4-9205-95ca5a16d7b2`
- `sigma.00ba9da1-b510-4f6b-b258-8d338836180f`
- `sigma.00d49ed5-4491-4271-a8db-650a4ef6f8c1`
- `sigma.0152550d-3a26-4efd-9f0e-54a0b28ae2f3`
- `sigma.01aeb693-138d-49d2-9403-c4f52d7d3d62`
- `sigma.01c42d3c-242d-4655-85b2-34f1739632f7`
- `sigma.01d2e2a1-5f09-44f7-9fc1-24faa7479b6d`
- `sigma.02030f2f-6199-49ec-b258-ea71b07e03dc`
- `sigma.022eaba8-f0bf-4dd9-9217-4604b0bb3bb0`
- `sigma.023394c4-29d5-46ab-92b8-6a534c6f447b`
- `sigma.023c654f-8f16-44d9-bb2b-00ff36a62af9`
- `sigma.0248a7bc-8a9a-4cd8-a57e-3ae8e073a073`
- `sigma.0255a820-e564-4e40-af2b-6ac61160335c`
- `sigma.02773bed-83bf-469f-b7ff-e676e7d78bab`
- `sigma.028c7842-4243-41cd-be6f-12f3cf1a26c7`
- `sigma.02b18447-ea83-4b1b-8805-714a8a34546a`
- `sigma.02b64f1b-3f33-4e67-aede-ef3b0a5a8fcf`
- `sigma.02c39d30-02b5-45d2-b435-8aebfe5a8629`
- `sigma.02ee49e2-e294-4d0f-9278-f5b3212fc588`
- `sigma.02f7c9c1-1ae8-4c6a-8add-04693807f92f`
- `sigma.03552375-cc2c-4883-bbe4-7958d5a980be`
- `sigma.0372e1f9-0fd2-40f7-be1b-a7b2b848fa7b`
- `sigma.037dcd71-33a8-4392-bb01-293c94663e5a`
- `sigma.03cc0c25-389f-4bf8-b48d-11878079f1ca`
- `sigma.03f4ca17-de95-428d-a75a-4ee78b047256`
- `sigma.0403d67d-6227-4ea8-8145-4e72db7da120`
- `sigma.043c4b8b-3a54-4780-9682-081cb6b8185c`
- `sigma.0442defa-b4a2-41c9-ae2c-ea7042fc4701`
- `sigma.044ba588-dff4-4918-9808-3f95e8160606`
- `sigma.046218bd-e0d8-4113-a3c3-895a12b2b298`
- `sigma.04b45a8a-d11d-49e4-9acc-4a1b524407a5`
- `sigma.055fb54c-a8f4-4aee-bd44-f74cf30a0d9d`
- `sigma.056c7317-9a09-4bd4-9067-d051312752ea`
- `sigma.058f4380-962d-40a5-afce-50207d36d7e2`
- `sigma.059c5af9-5131-4d8d-92b2-de4ad6146712`
- `sigma.05a2ab7e-ce11-4b63-86db-ab32e763e11d`
- `sigma.05b2aa93-1210-42c8-8d9a-2fcc13b284f5`
- `sigma.05ebafc8-7aa2-4bcd-a269-2aec93f9e842`
- `sigma.05f3c945-dcc8-4393-9f3d-af65077a8f86`
- `sigma.0649be4a-aeb0-45b0-b89e-7f1668f6d9c0`
- `sigma.065b00ca-5d5c-4557-ac95-64a6d0b64d86`
- `sigma.065cceea-77ec-4030-9052-fc0affea7110`
- `sigma.0685b176-c816-4837-8e7b-1216f346636b`
- `sigma.074e0ded-6ced-4ebd-8b4d-53f55908119d`
- `sigma.076ebe48-cc05-4d8f-9d41-89245cd93a14`
- `sigma.07743f65-7ec9-404a-a519-913db7118a8d`
- `sigma.07837ab9-60e1-481f-a74d-c31fb496a94c`
- `sigma.07a99744-56ac-40d2-97b7-2095967b0e03`
- `sigma.07aa184a-870d-413d-893a-157f317f6f58`
- `sigma.07e3cb2c-0608-410d-be4b-1511cb1a0448`
- `sigma.08200f85-2678-463e-9c32-88dce2f073d1`
- `sigma.086ae989-9ca6-4fe7-895a-759c5544f247`
- `sigma.087790e3-3287-436c-bccf-cbd0184a7db1`
- `sigma.089fc3d2-71e8-4763-a8a5-c97fbb0a403e`
- `sigma.0900463c-b33b-49a8-be1d-552a3b553dae`
- `sigma.092af964-4233-4373-b4ba-d86ea2890288`
- `sigma.0944e002-e3f6-4eb5-bf69-3a3067b53d73`
- `sigma.0955e4e1-c281-4fb9-9ee1-5ee7b4b754d2`
- `sigma.09576804-7a05-458e-a817-eb718ca91f54`
- `sigma.098d7118-55bc-4912-a836-dc6483a8d150`
- `sigma.0a1255c5-d732-4b62-ac02-b5152d34fb83`
- `sigma.0a13e132-651d-11eb-ae93-0242ac130002`
- `sigma.0a4f6091-223b-41f6-8743-f322ec84930b`
- `sigma.0a98a10c-685d-4ab0-bddc-b6bdd1d48458`
- `sigma.0a99eb3e-1617-41bd-b095-13dc767f3def`
- `sigma.0afbd410-de03-4078-8491-f132303cb67d`
- `sigma.0afecb6e-6223-4a82-99fb-bf5b981e92a5`
- `sigma.0b0cd537-fc77-4e6e-a973-e53495c1083d`
- `sigma.0b4ae027-2a2d-4b93-8c7e-962caaba5b2a`
- `sigma.0b7163dc-7eee-4960-af17-c0cd517f92da`
- `sigma.0b8baa3f-575c-46ee-8715-d6f28cc7d33c`
- `sigma.0b9ad457-2554-44c1-82c2-d56a99c42377`
- `sigma.0ba1da6d-b6ce-4366-828c-18826c9de23e`
- `sigma.0ba863e6-def5-4e50-9cea-4dd8c7dc46a4`
- `sigma.0badd08f-c6a3-4630-90d3-6875cca440be`
- `sigma.0bbc6369-43e3-453d-9944-cae58821c173`
- `sigma.0bcfabcb-7929-47f4-93d6-b33fb67d34d1`
- `sigma.0c3ebe9f-df09-4e00-be0f-73d4ca8d62f6`
- `sigma.0c3fac91-5627-46e8-a6a8-a0d7b9b8ae1b`
- `sigma.0c718a5e-4284-4fb9-b4d9-b9a50b3a1974`
- `sigma.0c92f2e6-f08f-4b73-9216-ecb0ca634689`
- `sigma.0c93308a-3f1b-40a9-b649-57ea1a1c1d63`
- `sigma.0cb8d736-995d-4ce7-a31e-1e8d452a1459`
- `sigma.0cf2e1c6-8d10-4273-8059-738778f981ad`
- `sigma.0d34ed8b-1c12-4ff2-828c-16fc860b766d`
- `sigma.0d5675be-bc88-4172-86d3-1e96a4476536`
- `sigma.0d7ceeef-3539-4392-8953-3dc664912714`
- `sigma.0dba975d-a193-4ed1-a067-424df57570d1`
- `sigma.0e0255bf-2548-47b8-9582-c0955c9283f5`
- `sigma.0e20c89d-2264-44ae-8238-aeeaba609ece`
- `sigma.0e29e3a7-1ad8-40aa-b691-9f82ecd33d66`
- `sigma.0e4164da-94bc-450d-a7be-a4b176179f1f`
- `sigma.0e6a9e62-627e-496c-aef5-bfa39da29b5e`
- `sigma.0e8cfe08-02c9-4815-a2f8-0d157b7ed33e`
- `sigma.0ea52357-cd59-4340-9981-c46c7e900428`
- `sigma.0ea8db81-2ff6-4525-9448-33bbe7effc13`
- `sigma.0eb46774-f1ab-4a74-8238-1155855f2263`
- `sigma.0ed99dda-6a35-11ef-8c99-0242ac120002`
- `sigma.0ee4d8a5-4e67-4faf-acfa-62a78457d1f2`
- `sigma.0ef56343-059e-4cb6-adc1-4c3c967c5e46`
- `sigma.0f0450f3-8b47-441e-a31b-15a91dc243e2`
- `sigma.0f16d9cf-0616-45c8-8fad-becc11b5a41c`
- `sigma.0f60b28c-64dd-4e2c-9a63-5334d3e3a6e6`
- `sigma.0f63e1ef-1eb9-4226-9d54-8927ca08520a`
- `sigma.0f6da907-5854-4be6-859a-e9958747b0aa`
- `sigma.0f9c21f1-6a73-4b0e-9809-cb562cb8d981`
- `sigma.0fc35fc3-efe6-4898-8a37-0b233339524f`
- `sigma.100ef69e-3327-481c-8e5c-6d80d9507556`
- `sigma.1012f107-b8f1-4271-af30-5aed2de89b39`
- `sigma.1027d292-dd87-4a1a-8701-2abe04d7783c`
- `sigma.10344bb3-7f65-46c2-b915-2d00d47be5b0`
- `sigma.104cdb48-a7a8-4ca7-a453-32942c6e5dcb`
- `sigma.1070db9a-3e5d-412e-8e7b-7183b616e1b3`
- `sigma.10c14723-61c7-4c75-92ca-9af245723ad2`
- `sigma.10fb649c-3600-4d37-b1e6-56ea90bb7e09`
- `sigma.1114e048-b69c-4f41-bc20-657245ae6e3f`
- `sigma.114de787-4eb2-48cc-abdb-c0b449f93ea4`
- `sigma.114e7f1c-f137-48c8-8f54-3088c24ce4b9`
- `sigma.117d3d3a-755c-4a61-b23e-9171146d094c`
- `sigma.1193d960-2369-499f-a158-7b50a31df682`
- `sigma.11b1ed55-154d-4e82-8ad7-83739298f720`
- `sigma.11b52f18-aaec-4d60-9143-5dd8cc4706b9`
- `sigma.11d00fff-5dc3-428c-8184-801f292faec0`
- `sigma.123e4e6d-b123-48f8-b261-7214938acaf0`
- `sigma.1277f594-a7d1-4f28-a2d3-73af5cbeab43`
- `sigma.12827a56-61a4-476a-a9cb-f3068f191073`
- `sigma.129966c9-de17-4334-a123-8b58172e664d`
- `sigma.12b8e9f5-96b2-41e1-9a42-8c6779a5c184`
- `sigma.12ba6a38-adb3-4d6b-91ba-a7fb248e3199`
- `sigma.12e6d621-194f-4f59-90cc-1959e21e69f7`
- `sigma.12f6b752-042d-483e-bf9c-915a6d06ad75`
- `sigma.12fbff88-16b5-4b42-9754-cd001a789fb3`
- `sigma.130c9e58-28ac-4f83-8574-0a4cc913b97e`
- `sigma.1321dc4e-a1fe-481d-a016-52c45f0c8b4f`
- `sigma.1327381e-6ab0-4f38-b583-4c1b8346a56b`
- `sigma.138d3531-8793-4f50-a2cd-f291b2863d78`
- `sigma.13acf386-b8c6-4fe0-9a6e-c4756b974698`
- `sigma.13addce7-47b2-4ca0-a98f-1de964d1d669`
- `sigma.13c02350-4177-4e45-ac17-cf7ca628ff5e`
- `sigma.13cfeb75-9e33-4d04-b0f7-ab8faaa95a59`
- `sigma.13e6fe51-d478-4c7e-b0f2-6da9b400a829`
- `sigma.13fc89a9-971e-4ca6-b9dc-aa53a445bf40`
- `sigma.1412aa78-a24c-4abd-83df-767dfb2c5bbe`
- `sigma.1444443e-6757-43e4-9ea4-c8fc705f79a2`
- `sigma.145095eb-e273-443b-83d0-f9b519b7867b`
- `sigma.145322e4-0fd3-486b-81ca-9addc75736d8`
- `sigma.146aace8-9bd6-42ba-be7a-0070d8027b76`
- `sigma.148431ce-4b70-403d-8525-fcc2993f29ea`
- `sigma.14bcba49-a428-42d9-b943-e2ce0f0f7ae6`
- `sigma.152f3630-77c1-4284-bcc0-4cc68ab2f6e7`
- `sigma.15434e33-5027-4914-88d5-3d4145ec25a9`
- `sigma.1547e27c-3974-43e2-a7d7-7f484fb928ec`
- `sigma.155dbf56-e0a4-4dd0-8905-8a98705045e8`
- `sigma.15619216-e993-4721-b590-4c520615a67d`
- `sigma.15904280-565c-4b73-9303-3291f964e7f9`
- `sigma.15b75071-74cc-47e0-b4c6-b43744a62a2b`
- `sigma.15bd98ea-55f4-4d37-b09a-e7caa0fa2221`
- `sigma.15c7904e-6ad1-4a45-9b46-5fb25df37fd2`
- `sigma.160d2780-31f7-4922-8b3a-efce30e63e96`
- `sigma.162ab1e4-6874-4564-853c-53ec3ab8be01`
- `sigma.164eda96-11b2-430b-85ff-6a265c15bf32`
- `sigma.16905e21-66ee-42fe-b256-1318ada2d770`
- `sigma.16c37b52-b141-42a5-a3ea-bbe098444397`
- `sigma.16f5d8ca-44bd-47c8-acbe-6fc95a16c12f`
- `sigma.16fe46bb-4f64-46aa-817d-ff7bec4a2352`
- `sigma.1723e720-616d-4ddc-ab02-f7e3685a4713`
- `sigma.175997c5-803c-4b08-8bb0-70b099f47595`
- `sigma.1775e15e-b61b-4d14-a1a3-80981298085a`
- `sigma.17769c90-230e-488b-a463-e05c08e9d48f`
- `sigma.178e615d-e666-498b-9630-9ed363038101`
- `sigma.17a1be64-8d88-40bf-b5ff-a4f7a50ebcc8`
- `sigma.17d619c1-e020-4347-957e-1d1207455c93`
- `sigma.17e53739-a1fc-4a62-b1b9-87711c2d5e44`
- `sigma.17f0c0a8-8bd5-4ee0-8c5f-a342c0199f35`
- `sigma.180c7c5c-d64b-4a63-86e9-68910451bc8b`
- `sigma.1816994b-42e1-4fb1-afd2-134d88184f71`
- `sigma.18249279-932f-45e2-b37a-8925f2597670`
- `sigma.185d7418-f250-42d0-b72e-0c8b70661e93`
- `sigma.18749301-f1c5-4efc-a4c3-276ff1f5b6f8`
- `sigma.18988e1b-9087-4f8a-82fe-0414dce49878`
- `sigma.18beca67-ab3e-4ee3-ba7a-a46ca8d7d0cc`
- `sigma.18ee686c-38a3-4f65-9f44-48a077141f42`
- `sigma.18f2065c-d36c-464a-a748-bcf909acb2e3`
- `sigma.18f37338-b9bd-4117-a039-280c81f7a596`
- `sigma.1908fcc1-1b92-4272-8214-0fbaf2fa5163`
- `sigma.192a0330-c20b-4356-90b6-7b7049ae0b87`
- `sigma.193d5ccd-6f59-40c6-b5b0-8e32d5ddd3d1`
- `sigma.198effb6-6c98-4d0c-9ea3-451fa143c45c`
- `sigma.19b08b1c-861d-4e75-a1ef-ea0c1baf202b`
- `sigma.1a0a2ff1-611b-4dac-8216-8a7b47c618a6`
- `sigma.1a0d4aba-7668-4365-9ce4-6d79ab088dfd`
- `sigma.1a1ed54a-2ba4-4221-94d5-01dee560d71e`
- `sigma.1a2d6c47-75b0-45bd-b133-2c0be75349fd`
- `sigma.1a31b18a-f00c-4061-9900-f735b96c99fc`
- `sigma.1a4bd6af-99ac-4466-b5b2-7b72b4a05462`
- `sigma.1a5c46e9-f32f-42f7-b2bc-6e9084db7fbf`
- `sigma.1a5fefe6-734f-452e-a07d-fc1c35bce4b2`
- `sigma.1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc`
- `sigma.1ac8666b-046f-4201-8aba-1951aaec03a3`
- `sigma.1af57a4b-460a-4738-9034-db68b880c665`
- `sigma.1b2ae822-6fe1-43ba-aa7c-d1a3b3d1d5f2`
- `sigma.1b3b01c7-84e9-4072-86e5-fc285a41ff23`
- `sigma.1bbf25b9-8038-4154-a50b-118f2a32be27`
- `sigma.1c0e41cd-21bb-4433-9acc-4a2cd6367b9b`
- `sigma.1c12727d-02bf-45ff-a9f3-d49806a3cf43`
- `sigma.1c3121ed-041b-4d97-a075-07f54f20fb4a`
- `sigma.1c480e10-7ee1-46d4-8ed2-85f9789e3ce4`
- `sigma.1c526788-0abe-4713-862f-b520da5e5316`
- `sigma.1c67a717-32ba-409b-a45d-0fb704a73a81`
- `sigma.1c8774a0-44d4-4db0-91f8-e792359c70bd`
- `sigma.1c8e96cd-2bed-487d-9de0-b46c90cade56`
- `sigma.1ca6bd18-0ba0-44ca-851c-92ed89a61085`
- `sigma.1cb0c6ce-3d00-44fc-ab9c-6d6d577bf20b`
- `sigma.1cbbeaaf-3c8c-4e4c-9d72-49485b6a176b`
- `sigma.1cc50f3f-1fc8-4acf-b2e9-6f172e1fdebd`
- `sigma.1cdd9a09-06c9-4769-99ff-626e2b3991b8`
- `sigma.1ce8c8a3-2723-48ed-8246-906ac91061a6`
- `sigma.1cf465a1-2609-4c15-9b66-c32dbe4bfd67`
- `sigma.1d08ac94-400d-4469-a82f-daee9a908849`
- `sigma.1d2ab8ac-1a01-423b-9c39-001510eae8e8`
- `sigma.1d2de8a6-4803-4fde-b85b-f58f3aa7a705`
- `sigma.1d61f71d-59d2-479e-9562-4ff5f4ead16b`
- `sigma.1dd05363-104e-4b4a-b963-196a534b03a1`
- `sigma.1de68c67-af5c-4097-9c85-fe5578e09e67`
- `sigma.1e0e1a81-e79b-44bc-935b-ddb9c8006b3d`
- `sigma.1e53dd56-8d83-4eb4-a43e-b790a05510aa`
- `sigma.1e59c230-6670-45bf-83b0-98903780607e`
- `sigma.1e75c1cc-c5d4-42aa-ac3d-91b0b68b3b4c`
- `sigma.1e8a9b4d-3c2a-4f9b-8d1e-7c6a5b4f3d2e`
- `sigma.1edff897-9146-48d2-9066-52e8d8f80a2f`
- `sigma.1eeed653-dbc8-4187-ad0c-eeebb20e6599`
- `sigma.1f0489be-b496-4ddf-b3a9-5900f2044e9c`
- `sigma.1f0b4cac-9c81-41f4-95d0-8475ff46b3e2`
- `sigma.1f0f6176-6482-4027-b151-00071af39d7e`
- `sigma.1f1a8509-2cbb-44f5-8751-8e1571518ce2`
- `sigma.1f1d8209-636e-4c6c-a137-781cca8b82f9`
- `sigma.1fb76ab8-fa60-4b01-bddd-71e89bf555da`
- `sigma.20384606-a124-4fec-acbb-8bd373728613`
- `sigma.204b17ae-4007-471b-917b-b917b315c5db`
- `sigma.2074e137-1b73-4e2d-88ba-5a3407dbdce0`
- `sigma.208748f7-881d-47ac-a29c-07ea84bf691d`
- `sigma.20a5ffa1-3848-4584-b6f8-c7c7fd9f69c8`
- `sigma.20d96d95-5a20-4cf1-a483-f3bda8a7c037`
- `sigma.2111118f-7e46-4fc8-974a-59fd8ec95196`
- `sigma.213d6a77-3d55-4ce8-ba74-fcfef741974e`
- `sigma.214641c2-c579-4ecb-8427-0cf19df6842e`
- `sigma.2158f96f-43c2-43cb-952a-ab4580f32382`
- `sigma.218d2855-2bba-4f61-9c85-81d0ea63ac71`
- `sigma.21d856f9-9281-4ded-9377-51a1a6e2a432`
- `sigma.21ff4ca9-f13a-41ad-b828-0077b2af2e40`
- `sigma.220457c1-1c9f-4c2e-afe6-9598926222c1`
- `sigma.22154f0e-5132-4a54-aa78-cc62f6def531`
- `sigma.222129f7-f4dc-4568-b0d2-22440a9639ba`
- `sigma.222720a7-047f-4054-baa5-bab9be757db0`
- `sigma.224f140f-3553-4cd1-af78-13d81bf9f7cc`
- `sigma.225274c4-8dd1-40db-9e09-71dff4f6fb3c`
- `sigma.2267fe65-0681-42ad-9a6d-46553d3f3480`
- `sigma.22e58743-4ac8-4a9f-bf19-00a0428d8c5f`
- `sigma.236d8e89-ed95-4789-a982-36f4643738ba`
- `sigma.23ceaf5c-b6f1-4a32-8559-f2ff734be516`
- `sigma.241e802a-b65e-484f-88cd-c2dc10f9206d`
- `sigma.243380fa-11eb-4141-af92-e14925e77c1b`
- `sigma.2433a154-bb3d-42e4-86c3-a26bdac91c45`
- `sigma.24357373-078f-44ed-9ac4-6d334a668a11`
- `sigma.24549159-ac1b-479c-8175-d42aea947cae`
- `sigma.24c77512-782b-448a-8950-eddb0785fc71`
- `sigma.24c8392b-aa3c-46b7-a545-43f71657fe98`
- `sigma.24de4f3b-804c-4165-b442-5a06a2302c7e`
- `sigma.24e3e58a-646b-4b50-adef-02ef935b9fc8`
- `sigma.25676e10-2121-446e-80a4-71ff8506af47`
- `sigma.2569ed8c-1147-498a-9b8c-2ad3656b10ed`
- `sigma.259e5a6a-b8d2-4c38-86e2-26c5e651361d`
- `sigma.25b9c01c-350d-4b95-bed1-836d04a4f324`
- `sigma.25cde13e-8e20-4c29-b949-4e795b76f16f`
- `sigma.25eabf56-22f0-4915-a1ed-056b8dae0a68`
- `sigma.25ffa65d-76d8-4da5-a832-3f2b0136e133`
- `sigma.2632954e-db1c-49cb-9936-67d1ef1d17d2`
- `sigma.26481afe-db26-4228-b264-25a29fe6efc7`
- `sigma.26488ad0-f9fd-4536-876f-52fea846a2e4`
- `sigma.264982dc-dbad-4dce-b707-1e0d3e0f73d9`
- `sigma.26d3f0a2-f514-4a3f-a8a7-e7e48a8d9160`
- `sigma.2704ab9e-afe2-4854-a3b1-0c0706d03578`
- `sigma.275641a5-a492-45e2-a817-7c81e9d9d3e9`
- `sigma.277a4393-446c-449a-b0ed-7fdc7795244c`
- `sigma.277efb8f-60be-4f10-b4d3-037802f37167`
- `sigma.2782fbd8-b662-4eb5-9962-5bfbfb671e7b`
- `sigma.27aec9c9-dbb0-4939-8422-1742242471d0`
- `sigma.27ba3207-dd30-4812-abbf-5d20c57d474e`
- `sigma.27ee9438-90dc-4bef-904b-d3ef927f5e7e`
- `sigma.28036918-04d3-423d-91c0-55ecf99fb892`
- `sigma.28208707-fe31-437f-9a7f-4b1108b94d2e`
- `sigma.285b85b1-a555-4095-8652-a8a4106af63f`
- `sigma.28a452f3-786c-4fd8-b8f2-bddbe9d616d1`
- `sigma.28ac00d6-22d9-4a3c-927f-bbd770104573`
- `sigma.28c8f68b-098d-45af-8d43-8089f3e35403`
- `sigma.295a59c1-7b79-4b47-a930-df12c15fc9c2`
- `sigma.2a072a96-a086-49fa-bcb5-15cc5a619093`
- `sigma.2a4b3e61-9d22-4e4a-b60f-6e8f0cde6f25`
- `sigma.2a926e6a-4b81-4011-8a96-e36cc8c04302`
- `sigma.2aa0a6b4-a865-495b-ab51-c28249537b75`
- `sigma.2afafd61-6aae-4df4-baed-139fa1f4c345`
- `sigma.2afe6582-e149-11ea-87d0-0242ac130003`
- `sigma.2c1486f5-02e8-4f86-9099-b97f2da4ed77`
- `sigma.2c28c248-7f50-417a-9186-a85b223010ee`
- `sigma.2c32b543-1058-4808-91c6-5b31b8bed6c5`
- `sigma.2c99737c-585d-4431-b61a-c911d86ff32f`
- `sigma.2cf29f11-e356-4f61-98c0-1bdb9393d6da`
- `sigma.2d22a514-e024-4428-9dba-41505bd63a5b`
- `sigma.2d367498-5112-4ae5-a06a-96e7bc33a211`
- `sigma.2d3cdeec-c0db-45b4-aa86-082f7eb75701`
- `sigma.2d510d8d-912b-45c5-b1df-36faa3d8c3f4`
- `sigma.2daa93a0-a5fb-41c5-8cd8-3c11294bfd1f`
- `sigma.2db93a3f-3249-4f73-9e68-0e77a0f8ae7e`
- `sigma.2dbd9d3d-9e27-42a8-b8df-f13825c6c3d5`
- `sigma.2dd2c217-bf68-437a-b57c-fe9fd01d5de8`
- `sigma.2ddef153-167b-4e89-86b6-757a9e65dcac`
- `sigma.2e65275c-8288-4ab4-aeb7-6274f58b6b20`
- `sigma.2f400434-01e1-416b-b52c-bb5bfbb9eb78`
- `sigma.2f78da12-f7c7-430b-8b19-a28f269b77a3`
- `sigma.2f7979ae-f82b-45af-ac1d-2b10e93b0baa`
- `sigma.2f869d59-7f6a-4931-992c-cce556ff2d53`
- `sigma.2f9356ae-bf43-41b8-b858-4496d83b2acb`
- `sigma.2fbbe9ff-0afc-470b-bdc0-592198339968`
- `sigma.2fdaf50b-9fd5-449f-ba69-f17248119af6`
- `sigma.2fdefcb3-dbda-401e-ae23-f0db027628bc`
- `sigma.2ff692c2-4594-41ec-8fcb-46587de769e0`
- `sigma.300bac00-e041-4ee2-9c36-e262656a6ecc`
- `sigma.3037d961-21e9-4732-b27a-637bcc7bf539`
- `sigma.304afd73-55a5-4bb9-8c21-0b1fc84ea9e4`
- `sigma.30bf1789-379d-4fdc-900f-55cd0a90a801`
- `sigma.30d07da2-83ab-45d8-ae75-ec7c0edcaffc`
- `sigma.30e92f50-bb5a-4884-98b5-d20aa80f3d7a`
- `sigma.30edb182-aa75-42c0-b0a9-e998bb29067c`
- `sigma.30fc8de7-d833-40c4-96b6-28319fbc4f6c`
- `sigma.311b6ce2-7890-4383-a8c2-663a9f6b43cd`
- `sigma.312d0384-401c-4b8b-abdf-685ffba9a332`
- `sigma.313d6012-51a0-4d93-8dfc-de8553239e25`
- `sigma.318557a5-150c-4c8d-b70e-a9910e199857`
- `sigma.31c51af6-e7aa-4da7-84d4-8f32cc580af2`
- `sigma.31e124fb-5dc4-42a0-83b3-44a69c77b271`
- `sigma.3215aa19-f060-4332-86d5-5602511f3ca8`
- `sigma.322ed9ec-fcab-4f67-9a34-e7c6aef43614`
- `sigma.32410e29-5f94-4568-b6a3-d91a8adad863`
- `sigma.3268b746-88d8-4cd3-bffc-30077d02c787`
- `sigma.327ff235-94eb-4f06-b9de-aaee571324be`
- `sigma.32b96012-7892-429e-b26c-ac2bf46066ff`
- `sigma.32e19d25-4aed-4860-a55a-be99cb0bf7ed`
- `sigma.32e280f1-8ad4-46ef-9e80-910657611fbc`
- `sigma.33339be3-148b-4e16-af56-ad16ec6c7e7b`
- `sigma.3371f518-5fe3-4cf6-a14b-2a0ae3fd8a4f`
- `sigma.3390fbef-c98d-4bdd-a863-d65ed7c610dd`
- `sigma.33be4333-2c6b-44f4-ae28-102cdbde0a31`
- `sigma.33efc23c-6ea2-4503-8cfe-bdf82ce8f705`
- `sigma.33efc23c-6ea2-4503-8cfe-bdf82ce8f719`
- `sigma.33f41cdd-35ac-4ba8-814b-c6a4244a1ad4`
- `sigma.340a090b-c4e9-412e-bb36-b4b16fe96f9b`
- `sigma.34746e8c-5fb8-415a-b135-0abc167e912a`
- `sigma.347906f3-e207-4d18-ae5b-a9403d6bcdef`
- `sigma.34986307-b7f4-49be-92f3-e7a4d01ac5db`
- `sigma.34aa0252-6039-40ff-951f-939fd6ce47d8`
- `sigma.34ebb878-1b15-4895-b352-ca2eeb99b274`
- `sigma.350dfb37-3706-4cdc-9e2e-5e24bc3a46df`
- `sigma.35ba1d85-724d-42a3-889f-2e2362bcaf23`
- `sigma.35bc7e28-ee6b-492f-ab04-da58fcf6402e`
- `sigma.360a1340-398a-46b6-8d06-99b905dc69d2`
- `sigma.36210e0d-5b19-485d-a087-c096088885f0`
- `sigma.36475a7d-0f6d-4dce-9b01-6aeb473bbaf1`
- `sigma.36480ae1-a1cb-4eaa-a0d6-29801d7e9142`
- `sigma.36803969-5421-41ec-b92f-8500f79c23b0`
- `sigma.36d88494-1d43-4dc0-b3fa-35c8fea0ca9d`
- `sigma.36e037c4-c228-4866-b6a3-48eb292b9955`
- `sigma.37651c2a-42cd-4a69-ae0d-22a4349aa04a`
- `sigma.378a05d8-963c-46c9-bcce-13c7657eac99`
- `sigma.37b437cf-3fc5-4c8e-9c94-1d7c9aff842b`
- `sigma.37c1333a-a0db-48be-b64b-7393b2386e3b`
- `sigma.37db85d1-b089-490a-a59a-c7b6f984f480`
- `sigma.37e8d358-6408-4853-82f4-98333fca7014`
- `sigma.38646daa-e78f-4ace-9de0-55547b2d30da`
- `sigma.38879043-7e1e-47a9-8d46-6bec88e201df`
- `sigma.38a1ac5f-9c74-47d2-a345-dd6f5eb4e7c8`
- `sigma.39019a4e-317f-4ce3-ae63-309a8c6b53c5`
- `sigma.395907ee-96e5-4666-af2e-2ca91688e151`
- `sigma.39698b3f-da92-4bc6-bfb5-645a98386e45`
- `sigma.396ae3eb-4174-4b9b-880e-dc0364d78a19`
- `sigma.396f6630-f3ac-44e3-bfc8-1b161bc00c4e`
- `sigma.39a80702-d7ca-4a83-b776-525b1f86a36d`
- `sigma.39a94fd1-8c9a-4ff6-bf22-c058762f8014`
- `sigma.39b31e81-5f5f-4898-9c0e-2160cfc0f9bf`
- `sigma.39ed3c80-e6a1-431b-9df3-911ac53d08a7`
- `sigma.39f1f9f2-9636-45de-98f6-a4046aa8e4b9`
- `sigma.39f919f3-980b-4e6f-a975-8af7e507ef2b`
- `sigma.3a6586ad-127a-4d3b-a677-1e6eacdf8fde`
- `sigma.3a734d25-df5c-4b99-8034-af1ddb5883a4`
- `sigma.3a8da4e0-36c1-40d2-8b29-b3e890d5172a`
- `sigma.3a9fa2ec-30bc-4ebd-b49e-7c9cff225502`
- `sigma.3ab65069-d82a-4d44-a759-466661a082d1`
- `sigma.3ab79e90-9fab-4cdf-a7b2-6522bc742adb`
- `sigma.3abd6094-7027-475f-9630-8ab9be7b9725`
- `sigma.3ae1a046-f7db-439d-b7ce-b8b366b81fa6`
- `sigma.3ae9974a-eb09-4044-8e70-8980a50c12c8`
- `sigma.3aff0be0-7802-4a7e-a4fa-c60c74bc5e1d`
- `sigma.3b3c7f55-f771-4dd6-8a6e-08d057a17caf`
- `sigma.3b4e950b-a3ea-44d3-877e-432071990709`
- `sigma.3b5b0213-0460-4e3f-8937-3abf98ff7dcc`
- `sigma.3b5ba899-9842-4bc2-acc2-12308498bf42`
- `sigma.3b6ab547-8ec2-4991-b9d2-2b06702a48d7`
- `sigma.3b8f4c92-6a51-4d7e-9c3a-8e2d1f5a7b09`
- `sigma.3bad990e-4848-4a78-9530-b427d854aac0`
- `sigma.3c05e90d-7eba-4324-9972-5d7f711a60a8`
- `sigma.3c1b5fb0-c72f-45ba-abd1-4d4c353144ab`
- `sigma.3c89a1e8-0fba-449e-8f1b-8409d6267ec8`
- `sigma.3d0ed417-3d94-4963-a562-4a92c940656a`
- `sigma.3d27f6dd-1c74-4687-b4fa-ca849d128d1c`
- `sigma.3d2a2d59-929c-4b78-8c1a-145dfe9e07b1`
- `sigma.3d3aa6cd-6272-44d6-8afc-7e88dfef7061`
- `sigma.3d48c9d3-1aa6-418d-98d3-8fd3c01a564e`
- `sigma.3d7679bd-0c00-440c-97b0-3f204273e6c7`
- `sigma.3da70954-0f2c-4103-adff-b7440368f50e`
- `sigma.3dfd06d2-eaf4-4532-9555-68aca59f57c4`
- `sigma.3e2f1b2c-4d5e-11ee-be56-0242ac120002`
- `sigma.3e3ceccd-6c06-48b8-b5ff-ab1d25db8c1d`
- `sigma.3e8207c5-fcd2-4ea6-9418-15d45b4890e4`
- `sigma.3ef5605c-9eb9-47b0-9a71-b727e6aa5c3b`
- `sigma.3f5491e2-8db8-496b-9e95-1029fce852d4`
- `sigma.3f6b7b62-61aa-45db-96bd-9c31b36b653c`
- `sigma.3fd4c8d7-8362-4557-a8e6-83b29cc0d724`
- `sigma.409f8a98-4496-4aaa-818a-c931c0a8b832`
- `sigma.40aa399c-7b02-4715-8e5f-73572b493f33`
- `sigma.40b19fa6-d835-400c-b301-41f3a2baacaf`
- `sigma.40b6e656-4e11-4c0c-8772-c1cc6dae34ce`
- `sigma.40b95d31-1afc-469e-8d34-9a3a667d058e`
- `sigma.40f9af16-589d-4984-b78d-8c2aec023197`
- `sigma.411742ad-89b0-49cb-a7b0-3971b5c1e0a4`
- `sigma.41421f44-58f9-455d-838a-c398859841d4`
- `sigma.418a3163-3247-4b7b-9933-dcfcb7c52ea9`
- `sigma.41bb431f-56d8-4691-bb56-ed34e390906f`
- `sigma.41ca393d-538c-408a-ac27-cf1e038be80c`
- `sigma.41f407b5-3096-44ea-a74f-96d04fbc41be`
- `sigma.41f6531d-af6e-4c6e-918f-b946f2b85a36`
- `sigma.42205c73-75c8-4a63-9db1-e3782e06fda0`
- `sigma.42333b2c-b425-441c-b70e-99404a17170f`
- `sigma.424273ea-7cf8-43a6-b712-375f925e481f`
- `sigma.42a5f1e7-9603-4f6d-97ae-3f37d130d794`
- `sigma.42a993dd-bb3e-48c8-b372-4d6684c4106c`
- `sigma.42b1a5b8-353f-4f10-b256-39de4467faff`
- `sigma.42c575ea-e41e-41f1-b248-8093c3e82a28`
- `sigma.43103702-5886-11ed-9b6a-0242ac120002`
- `sigma.431a1fdb-4799-4f3b-91c3-a683b003fc49`
- `sigma.434c08ba-8406-4d15-8b24-782cb071a691`
- `sigma.4358e5a5-7542-4dcb-b9f3-87667371839b`
- `sigma.435e10e4-992a-4281-96f3-38b11106adde`
- `sigma.438025f9-5856-4663-83f7-52f878a70a50`
- `sigma.439957a7-ad86-4a8f-9705-a28131c6821b`
- `sigma.43d91656-a9b2-4541-b7e2-6a9bd3a13f4e`
- `sigma.43e32da2-fdd0-4156-90de-50dfd62636f9`
- `sigma.43fa5350-db63-4b8f-9a01-789a427074e1`
- `sigma.44030449-b0df-4c94-aae1-502359ab28ee`
- `sigma.44143844-0631-49ab-97a0-96387d6b2d7c`
- `sigma.44a22d59-b175-4f13-8c16-cbaef5b581ff`
- `sigma.44e24481-6202-4c62-9127-5a0ae8e3fe3d`
- `sigma.452bce90-6fb0-43cc-97a5-affc283139b3`
- `sigma.45545954-4016-43c6-855e-eae8f1c369dc`
- `sigma.455b9d50-15a1-4b99-853f-8d37655a4c1b`
- `sigma.459f2f98-397b-4a4a-9f47-6a5ec2f1c69d`
- `sigma.45a594aa-1fbd-4972-a809-ff5a99dd81b8`
- `sigma.45d3a03d-f441-458c-8883-df101a3bb146`
- `sigma.45e112d0-7759-4c2a-aa36-9f8fb79d3393`
- `sigma.460479f3-80b7-42da-9c43-2cc1d54dbccd`
- `sigma.46123129-1024-423e-9fae-43af4a0fa9a5`
- `sigma.4627c6ae-6899-46e2-aa0c-6ebcb1becd19`
- `sigma.46490193-1b22-4c29-bdd6-5bf63907216f`
- `sigma.46a68649-f218-4f86-aea1-16a759d81820`
- `sigma.46dd5308-4572-4d12-aa43-8938f0184d4f`
- `sigma.470ec5fa-7b4e-4071-b200-4c753100f49b`
- `sigma.47147b5b-9e17-4d76-b8d2-7bac24c5ce1b`
- `sigma.4720b7df-40c3-48fd-bbdf-fd4b3c464f0d`
- `sigma.4782eb5a-a513-4523-a0ac-f3082b26ac5c`
- `sigma.47e4bab7-c626-47dc-967b-255608c9a920`
- `sigma.480421f9-417f-4d3b-9552-fd2728443ec8`
- `sigma.480e7e51-e797-47e3-8d72-ebfce65b6d8d`
- `sigma.4833155a-4053-4c9c-a997-777fcea0baa7`
- `sigma.48437c39-9e5f-47fb-af95-3d663c3f2919`
- `sigma.487bb375-12ef-41f6-baae-c6a1572b4dd1`
- `sigma.487c7524-f892-4054-b263-8a0ace63fc25`
- `sigma.48917adc-a28e-4f5d-b729-11e75da8941f`
- `sigma.48a61b29-389f-4032-b317-b30de6b95314`
- `sigma.48bbc537-b652-4b4e-bd1d-281172df448f`
- `sigma.48d91a3a-2363-43ba-a456-ca71ac3da5c2`
- `sigma.48ea844d-19b1-4642-944e-fe39c2cc1fec`
- `sigma.4916a35e-bfc4-47d0-8e25-a003d7067061`
- `sigma.4931188c-178e-4ee7-a348-39e8a7a56821`
- `sigma.496a0e47-0a33-4dca-b009-9e6ca3591f39`
- `sigma.4976aa50-8f41-45c6-8b15-ab3fc10e79ed`
- `sigma.49be8799-7b4d-4fda-ad23-cafbefdebbc5`
- `sigma.49d9671b-0a0a-4c09-8280-d215bfd30662`
- `sigma.49e5bc24-8b86-49f1-b743-535f332c2856`
- `sigma.49f2f17b-b4c8-4172-a68b-d5bf95d05130`
- `sigma.4a2a2c3e-209f-4d01-b513-4155a540b469`
- `sigma.4a30ac0c-b9d6-4e01-b71a-5f851bbf4259`
- `sigma.4a5f5a5e-ac01-474b-9b4e-d61298c9df1d`
- `sigma.4a6713f6-3331-11ed-a261-0242ac120002`
- `sigma.4aa6040b-3f28-44e3-a769-9208e5feb5ec`
- `sigma.4aafb0fa-bff5-4b9d-b99e-8093e659c65f`
- `sigma.4abc0ec4-db5a-412f-9632-26659cddf145`
- `sigma.4ac1f50b-3bd0-4968-902d-868b4647937e`
- `sigma.4ac47ed3-44c2-4b1f-9d51-bf46e8914126`
- `sigma.4ae3e30b-b03f-43aa-87e3-b622f4048eed`
- `sigma.4ae81040-fc1c-4249-bfa3-938d260214d9`
- `sigma.4b046706-5789-4673-b111-66f25fe99534`
- `sigma.4b13db67-0c45-40f1-aba8-66a1a7198a1e`
- `sigma.4b60e6f2-bf39-47b4-b4ea-398e33cfe253`
- `sigma.4b657234-038e-4ad5-997c-4be42340bce4`
- `sigma.4b8f6d3a-9c5e-4f2a-a7d8-6b9c3e5f2a8d`
- `sigma.4b991083-3d0e-44ce-8fc4-b254025d8d4b`
- `sigma.4bb79b62-ef12-4861-981d-2aab43fab642`
- `sigma.4bc90587-e6ca-4b41-be0b-ed4d04e4ed0c`
- `sigma.4beb6ae0-f85b-41e2-8f18-8668abc8af78`
- `sigma.4bf943c6-5146-4273-98dd-e958fd1e3abf`
- `sigma.4c0aaedc-154c-4427-ada0-d80ef9c9deb6`
- `sigma.4c54ba8f-73d2-4d40-8890-d9cf1dca3d30`
- `sigma.4c7f49ee-2638-43bb-b85b-ce676c30b260`
- `sigma.4cbef972-f347-4170-b62a-8253f6168e6d`
- `sigma.4d431012-2ab5-4db7-a84e-b29809da2172`
- `sigma.4d7cda18-1b12-4e52-b45c-d28653210df8`
- `sigma.4d7f1827-1637-4def-8d8a-fd254f9454df`
- `sigma.4e2ed651-1906-4a59-a78a-18220fca1b22`
- `sigma.4e7050dd-e548-483f-b7d6-527ab4fa784d`
- `sigma.4e762605-34a8-406d-b72e-c1a089313320`
- `sigma.4e87b8e2-2ee9-4b2a-a715-4727d297ece0`
- `sigma.4ebc877f-4612-45cb-b3a5-8e3834db36c9`
- `sigma.4eddc365-79b4-43ff-a9d7-99422dc34b93`
- `sigma.4ede543c-e098-43d9-a28f-dd784a13132f`
- `sigma.4edf51e1-cb83-4e1a-bc39-800e396068e3`
- `sigma.4eec988f-7bf0-49f1-8675-1e6a510b3a2a`
- `sigma.4f154fb6-27d1-4813-a759-78b93e0b9c48`
- `sigma.4f1707b1-b50b-45b4-b5a2-3978b5a5d0d6`
- `sigma.4f281b83-0200-4b34-bf35-d24687ea57c2`
- `sigma.4f2cd9b6-4a17-440f-bb2a-687abb65993a`
- `sigma.4f647cfa-b598-4e12-ad69-c68dd16caef8`
- `sigma.4f73421b-5a0b-4bbf-a892-5a7fb99bea66`
- `sigma.4f7a6757-ff79-46db-9687-66501a02d9ec`
- `sigma.4f84b697-c9ed-4420-8ab5-e09af5b2345d`
- `sigma.4fd6b1c7-19b8-4488-97f6-00f0924991a3`
- `sigma.4fe074b4-b833-4081-8f24-7dcfeca72b42`
- `sigma.4fee3d51-8069-4a4c-a0f7-924fcaff2c70`
- `sigma.503d581c-7df0-4bbe-b9be-5840c0ecc1fc`
- `sigma.50919691-7302-437f-8e10-1fe088afa145`
- `sigma.509e84b9-a71a-40e0-834f-05470369bd1e`
- `sigma.50a0aa3d-ab16-4594-a8aa-5145a6e6792b`
- `sigma.50d66fb0-03f8-4da0-8add-84e77d12a020`
- `sigma.50e54b8d-ad73-43f8-96a1-5191685b17a4`
- `sigma.514e4c3a-c77d-4cde-a00f-046425e2301e`
- `sigma.514e7e3e-b3b4-4a67-af60-be20f139198b`
- `sigma.515c8be5-e5df-4c5e-8f6d-a4a2f05e4b48`
- `sigma.517490a7-115a-48c6-8862-1a481504d5a8`
- `sigma.51aa9387-1c53-4153-91cc-d73c59ae1ca9`
- `sigma.51ae86a2-e2e1-4097-ad85-c46cb6851de4`
- `sigma.51cbac1e-eee3-4a90-b1b7-358efb81fa0a`
- `sigma.51e33403-2a37-4d66-a574-1fda1782cc31`
- `sigma.5205613d-2a63-4412-a895-3a2458b587b3`
- `sigma.526be59f-a573-4eea-b5f7-f0973207634d`
- `sigma.52753ea4-b3a0-4365-910d-36cff487b789`
- `sigma.52788a70-f1da-40dd-8fbd-73b5865d6568`
- `sigma.52a85084-6989-40c3-8f32-091e12e13f09`
- `sigma.52cad028-0ff0-4854-8f67-d25dfcbc78b4`
- `sigma.52d097e2-063e-4c9c-8fbb-855c8948d135`
- `sigma.52ff7941-8211-46f9-84f8-9903efb7077d`
- `sigma.530576ee-3b62-4bce-9a03-9aac6c61788a`
- `sigma.530a6faa-ff3d-4022-b315-50828e77eef5`
- `sigma.53330955-dc52-487f-a3a2-da24dcff99b5`
- `sigma.534f2ef7-e8a2-4433-816d-c91bccde289b`
- `sigma.536e2947-3729-478c-9903-745aaffe60d2`
- `sigma.5394fcc7-aeb2-43b5-9a09-cac9fc5edcd5`
- `sigma.53ad8e36-f573-46bf-97e4-15ba5bf4bb51`
- `sigma.53d4bb30-3f36-4e8a-b078-69d36c4a79ff`
- `sigma.53d8d3e1-ca33-4012-adf3-e05a4d652e34`
- `sigma.53ef0cef-fa24-4f25-a34a-6c72dfa2e6e2`
- `sigma.54127bd4-f541-4ac3-afdb-ea073f63f692`
- `sigma.545a5da6-f103-4919-a519-e9aec1026ee4`
- `sigma.54773c5f-f1cc-4703-9126-2f797d96a69d`
- `sigma.54f0434b-726f-48a1-b2aa-067df14516e4`
- `sigma.550bbb84-ce5d-4e61-84ad-e590f0024dcd`
- `sigma.551d9c1f-816c-445b-a7a6-7a3864720d60`
- `sigma.554601fb-9b71-4bcc-abf4-21a611be4fde`
- `sigma.555155a2-03bf-4fe7-af74-d176b3fdbe16`
- `sigma.5589ab4f-a767-433c-961d-c91f3f704db1`
- `sigma.5594e67a-7f92-4a04-b65d-1a42fd824a60`
- `sigma.55e29995-75e7-451a-bef0-6225e2f13597`
- `sigma.55f0a3a1-846e-40eb-8273-677371b8d912`
- `sigma.56321594-9087-49d9-bf10-524fe8479452`
- `sigma.56454143-524f-49fb-b1c6-3fb8b1ad41fb`
- `sigma.5687f942-867b-4578-ade7-1e341c46e99a`
- `sigma.56abae0c-6212-4b97-adc0-0b559bb950c3`
- `sigma.56c217c3-2de2-479b-990f-5c109ba8458f`
- `sigma.56d19cb4-6414-4769-9644-1ed35ffbb148`
- `sigma.56e05d41-ce99-4ecd-912d-93f019ee0b71`
- `sigma.570ae5ec-33dc-427c-b815-db86228ad43e`
- `sigma.571498c8-908e-40b4-910b-d2369159a3da`
- `sigma.5722dff1-4bdd-4949-86ab-fbaf707e767a`
- `sigma.575dce0c-8139-4e30-9295-1ee75969f7fe`
- `sigma.576426ad-0131-4001-ae01-be175da0c108`
- `sigma.57b649ef-ff42-4fb0-8bf6-62da243a1708`
- `sigma.57bff678-25d1-4d6c-8211-8ca106d12053`
- `sigma.57c4bf16-227f-4394-8ec7-1b745ee061c3`
- `sigma.5817e76f-4804-41e6-8f1d-5fa0b3ecae2d`
- `sigma.584bca0f-3608-4402-80fd-4075ff6072e3`
- `sigma.589ac73f-8e12-409c-964e-31a2f5775ae2`
- `sigma.58f4ea09-0fc2-4520-ba18-b85c540b0eaf`
- `sigma.58f50261-c53b-4c88-bd12-1d71f12eda4c`
- `sigma.590a5f4c-6c8c-4f10-8307-89afe9453a9d`
- `sigma.59e938ff-0d6d-4dc3-b13f-36cc28734d4e`
- `sigma.5a2b21ee-6aaa-4234-ac9d-59a59edf90a1`
- `sigma.5a3164f2-b373-4152-93cf-090b13c12d27`
- `sigma.5a44727c-3b85-4713-8c44-4401d5499629`
- `sigma.5a5152f1-463f-436b-b2f5-8eceb3964b42`
- `sigma.5a6e1e16-07de-48d8-8aae-faa766c05e88`
- `sigma.5a93eb65-dffa-4543-b761-94aa60098fb6`
- `sigma.5a9e1b2c-8f7d-4a1e-9b3c-0f6d7e5a4b1f`
- `sigma.5aad0995-46ab-41bd-a9ff-724f41114971`
- `sigma.5af54681-df95-4c26-854f-2565e13cfab0`
- `sigma.5b16df71-8615-4f7f-ac9b-6c43c0509e61`
- `sigma.5b175490-b652-4b02-b1de-5b5b4083c5f8`
- `sigma.5b40a734-99b6-4b98-a1d0-1cea51a08ab2`
- `sigma.5b768e71-86f2-4879-b448-81061cbae951`
- `sigma.5b80a791-ad9b-4b75-bcc1-ad4e1e89c200`
- `sigma.5b872a46-3b90-45c1-8419-f675db8053aa`
- `sigma.5bac7a56-da88-4c27-922e-c81e113b20cb`
- `sigma.5bb68627-3198-40ca-b458-49f973db8752`
- `sigma.5cb299fc-5fb1-4d07-b989-0644c68b6043`
- `sigma.5cc2cda8-f261-4d88-a2de-e9e193c86716`
- `sigma.5cc90652-4cbd-4241-aa3b-4b462fa5a248`
- `sigma.5cdb711b-5740-4fb2-ba88-f7945027afac`
- `sigma.5cddf373-ef00-4112-ad72-960ac29bac34`
- `sigma.5ce0f04e-3efc-42af-839d-5b3a543b76c0`
- `sigma.5d19eb78-5b5b-4ef2-a9f0-4bfa94d58a13`
- `sigma.5d6c375a-18ae-4952-b4f6-8b803f6c8555`
- `sigma.5d756aee-ad3e-4306-ad95-cb1abec48de2`
- `sigma.5de03871-5d46-4539-a82d-3aa992a69a83`
- `sigma.5df86130-4e95-4a54-90f7-26541b40aec2`
- `sigma.5e3cc4d8-3e68-43db-8656-eaaeefdec9cc`
- `sigma.5e6a80c8-2d45-4633-9ef4-fa2671a39c5c`
- `sigma.5e95028c-5229-4214-afae-d653d573d0ec`
- `sigma.5e993621-67d4-488a-b9ae-b420d08b96cb`
- `sigma.5edc2273-c26f-406c-83f3-f4d948e740dd`
- `sigma.5ee3a654-372f-11ec-8d3d-0242ac130003`
- `sigma.5f60740a-f57b-4e76-82a1-15b6ff2cb134`
- `sigma.5f6a601c-2ecb-498b-9c33-660362323afa`
- `sigma.5f87308a-0a5b-4623-ae15-d8fa1809bc60`
- `sigma.5f9db380-ea57-4d1e-beab-8a2d33397e93`
- `sigma.5fc297ae-25b6-488a-8f25-cc12ac29b744`
- `sigma.5fdce3ac-e7f9-4ecd-a3aa-a4d78ebbf0af`
- `sigma.6004abd0-afa4-4557-ba90-49d172e0a299`
- `sigma.602a1f13-c640-4d73-b053-be9a2fa58b96`
- `sigma.60936b49-fca0-4f32-993d-7415edcf9a5d`
- `sigma.60bfeac3-0d35-4302-8efb-1dd16f715bc6`
- `sigma.60f16a96-db70-42eb-8f76-16763e333590`
- `sigma.60fc936d-2eb0-4543-8a13-911c750a1dfc`
- `sigma.611eab06-a145-4dfa-a295-3ccc5c20f59a`
- `sigma.6120ac2a-a34b-42c0-a9bd-1fb9f459f348`
- `sigma.612e47e9-8a59-43a6-b404-f48683f45bd6`
- `sigma.613c03ba-0779-4a53-8a1f-47f914a4ded3`
- `sigma.614a7e17-5643-4d89-b6fe-f9df1a79641c`
- `sigma.614cf376-6651-47c4-9dcc-6b9527f749f4`
- `sigma.61a7697c-cb79-42a8-a2ff-5f0cdfae0130`
- `sigma.62120148-6b7a-42be-8b91-271c04e281a3`
- `sigma.6225c53a-a96e-4235-b28f-8d7997cd96eb`
- `sigma.62510e69-616b-4078-b371-847da438cc03`
- `sigma.62b20d44-1546-4e61-afce-8e175eb9473c`
- `sigma.62b7ccc9-23b4-471e-aa15-6da3663c4d59`
- `sigma.62e0298b-e994-4189-bc87-bc699aa62d97`
- `sigma.62ed5b55-f991-406a-85d9-e8e8fdf18789`
- `sigma.62f7c9bf-9135-49b2-8aeb-1e54a6ecc13c`
- `sigma.631b22a4-70f4-4e2f-9ea8-42f84d9df6d8`
- `sigma.6345b048-8441-43a7-9bed-541133633d7a`
- `sigma.634b00d5-ccc3-4a06-ae3b-0ec8444dd51b`
- `sigma.63647769-326d-4dde-a419-b925cc0caf42`
- `sigma.6385697e-9f1b-40bd-8817-f4a91f40508e`
- `sigma.639c9081-f482-47d3-a0bd-ddee3d4ecd76`
- `sigma.63d1ccc0-2a43-4f4b-9289-361b308991ff`
- `sigma.63de06b9-a385-40b5-8b32-73f2b9ef84b6`
- `sigma.63e3365d-4824-42d8-8b82-e56810fefa0c`
- `sigma.63e4f530-65dc-49cc-8f80-ccfa95c69d43`
- `sigma.641a4bfb-c017-44f7-800c-2aee0184ce9b`
- `sigma.643bdcac-8b82-49f4-9fd9-25a90b929f3b`
- `sigma.646bc99f-6682-4b47-a73a-17b1b64c9d34`
- `sigma.646ea171-dded-4578-8a4d-65e9822892e3`
- `sigma.64760eef-87f7-4ed3-93fd-655668ea9420`
- `sigma.647c7b9e-d784-4fda-b9a0-45c565a7b729`
- `sigma.651f87f7-12db-47f9-84c5-f27b081b94b6`
- `sigma.65236ec7-ace0-4f0c-82fd-737b04fd4dcb`
- `sigma.654fcc6d-840d-4844-9b07-2c3300e54a26`
- `sigma.6597be7b-ac61-4ac8-bef4-d3ec88174853`
- `sigma.65c3ca2c-525f-4ced-968e-246a713d164f`
- `sigma.6640f31c-01ad-49b5-beb5-83498a5cd8bd`
- `sigma.66b6be3d-55d0-4f47-9855-d69df21740ea`
- `sigma.66c3b204-9f88-4d0a-a7f7-8a57d521ca55`
- `sigma.66e563f9-1cbd-4a22-a957-d8b7c0f44372`
- `sigma.674202d0-b22a-4af4-ae5f-2eda1f3da1af`
- `sigma.6763c6c8-bd01-4687-bc8d-4fa52cf8ba08`
- `sigma.67a6c006-3fbe-46a7-9074-2ba3b82c3000`
- `sigma.67bc0e75-c0a9-4cfc-8754-84a505b63c04`
- `sigma.67f113fa-e23d-4271-befa-30113b3e08b1`
- `sigma.6812a10b-60ea-420c-832f-dfcc33b646ba`
- `sigma.68578b43-65df-4f81-9a9b-92f32711a951`
- `sigma.686c0b4b-9dd3-4847-9077-d6c1bbe36fcb`
- `sigma.68bcd73b-37ef-49cb-95fc-edc809730be6`
- `sigma.68c8acb4-1b60-4890-8e82-3ddf7a6dba84`
- `sigma.68d37776-61db-42f5-bf54-27e87072d17e`
- `sigma.6902955a-01b7-432c-b32a-6f5f81d8f625`
- `sigma.692f0bec-83ba-4d04-af7e-e884a96059b6`
- `sigma.6938366d-8954-4ddc-baff-c830b3ba8fcd`
- `sigma.696bfb54-227e-4602-ac5b-30d9d2053312`
- `sigma.69aeb277-f15f-4d2d-b32a-55e883609563`
- `sigma.69bd9b97-2be2-41b6-9816-fb08757a4d1a`
- `sigma.69ca006d-b9a9-47f5-80ff-ecd4d25d481a`
- `sigma.69ca12af-119d-44ed-b50f-a47af0ebc364`
- `sigma.6a53d871-682d-40b6-83e0-b7c1a6c4e3a5`
- `sigma.6aa1d992-5925-4e9f-a49b-845e51d1de01`
- `sigma.6b269392-9eba-40b5-acb6-55c882b20ba6`
- `sigma.6b369ced-4b1d-48f1-b427-fdc0de0790bd`
- `sigma.6b65c28e-11f3-46cb-902a-68f2cafaf474`
- `sigma.6b6976a3-b0e6-4723-ac24-ae38a737af41`
- `sigma.6ba5a05f-b095-4f0a-8654-b825f4f16334`
- `sigma.6bba49bf-7f8c-47d6-a1bb-6b4dece4640e`
- `sigma.6bd75993-9888-4f91-9404-e1e4e4e34b77`
- `sigma.6c0a7755-6d31-44fa-80e1-133e57752680`
- `sigma.6c0ce3b6-85e2-49d4-9c3f-6e008ce9796e`
- `sigma.6c304b02-06e6-402d-8be4-d5833cdf8198`
- `sigma.6c6d9280-e6d0-4b9d-80ac-254701b64916`
- `sigma.6c82cf5c-090d-4d57-9188-533577631108`
- `sigma.6c8fbee5-dee8-49bc-851d-c3142d02aa47`
- `sigma.6c96fc76-0eb1-11eb-adc1-0242ac120002`
- `sigma.6d3a3952-6530-44a3-8554-cf17c116c615`
- `sigma.6da2c9f5-7c53-401b-aacb-92c040ce1215`
- `sigma.6daac7fc-77d1-449a-a71a-e6b4d59a0e54`
- `sigma.6db5eaf9-88f7-4ed9-af7d-9ef2ad12f236`
- `sigma.6ddff2e8-ea1a-45d0-8938-93dfc1d67ae7`
- `sigma.6e22722b-dfb1-4508-a911-49ac840b40f8`
- `sigma.6e2a900a-ced9-4e4a-a9c2-13e706f9518a`
- `sigma.6e90ae7a-7cd3-473f-a035-4ebb72d961da`
- `sigma.6e968eb1-5f05-4dac-94e9-fd0c5cb49fd6`
- `sigma.6ea3bf32-9680-422d-9f50-e90716b12a66`
- `sigma.6ea858a8-ba71-4a12-b2cc-5d83312404c7`
- `sigma.6f0947a4-1c5e-4e0d-8ac7-53159b8f23ca`
- `sigma.6f1a11aa-4b8a-4b7f-9e13-4d3e4ff0e0d4`
- `sigma.6f3e2987-db24-4c78-a860-b4f4095a7095`
- `sigma.6f535e01-ca1f-40be-ab8d-45b19c0c8b7f`
- `sigma.6f8b3439-a203-45dc-a88b-abf57ea15ccf`
- `sigma.6fb63b40-e02a-403e-9ffd-3bcc1d749442`
- `sigma.6fe4aa1e-0531-4510-8be2-782154b73b48`
- `sigma.7002aa10-b8d4-47ae-b5ba-51ab07e228b9`
- `sigma.7021255e-5db3-4946-a8b9-0ba7a4644a69`
- `sigma.7047d730-036f-4f40-b9d8-1c63e36d5e62`
- `sigma.7050bba1-1aed-454e-8f73-3f46f09ce56a`
- `sigma.707e097c-e20f-4f67-8807-1f72ff4500d6`
- `sigma.70ad0861-d1fe-491c-a45f-fa48148a300d`
- `sigma.70bc5215-526f-4477-963c-a47a5c9ebd12`
- `sigma.71158e3f-df67-472b-930e-7d287acaa3e1`
- `sigma.7124aebe-4cd7-4ccb-8df0-6d6b93c96795`
- `sigma.71c276aa-49cd-43d2-b920-2dcd3e6962d5`
- `sigma.72124974-a68b-4366-b990-d30e0b2a190d`
- `sigma.724ea201-6514-4f38-9739-e5973c34f49a`
- `sigma.725a9768-0f5e-4cb3-aec2-bc5719c6831a`
- `sigma.7280c9f3-a5af-45d0-916a-bc01cb4151c9`
- `sigma.72862bf2-0eb1-11eb-adc1-0242ac120002`
- `sigma.729ce0ea-5d8f-4769-9762-e35de441586d`
- `sigma.730fc21b-eaff-474b-ad23-90fd265d4988`
- `sigma.731231b9-0b5d-4219-94dd-abb6959aa7ea`
- `sigma.734f8d9b-42b8-41b2-bcf5-abaf49d5a3c8`
- `sigma.736ffa74-5f6f-44ca-94ef-1c0df4f51d2a`
- `sigma.737e618a-a410-49b5-bec3-9e55ff7fbc15`
- `sigma.73921b9c-cafd-4446-b0c6-fdb0ace42bc0`
- `sigma.73a883d0-0348-4be4-a8d8-51031c2564f8`
- `sigma.74403157-20f5-415d-89a7-c505779585cf`
- `sigma.744a188b-0415-4792-896f-11ddb0588dbc`
- `sigma.74697c29-1b30-4e1f-a517-33574061821d`
- `sigma.749c9f5e-b353-4b90-a9c1-05243357ca4b`
- `sigma.74a12f18-505c-4114-8d0b-8448dd5485c6`
- `sigma.74a2b202-73e0-4693-9a3a-9d36146d0775`
- `sigma.74a2b37d-fea4-41e0-9ac7-c9fbcf1f60cc`
- `sigma.74babdd6-a758-4549-9632-26535279e654`
- `sigma.75180c5f-4ea1-461a-a4f6-6e4700c065d4`
- `sigma.7530b96f-ad8e-431d-a04d-ac85cc461fdc`
- `sigma.7530cd3d-7671-43e3-b209-976966f6ea48`
- `sigma.758ff488-18d5-4cbe-8ec4-02b6285a434f`
- `sigma.7595ba94-cf3b-4471-aa03-4f6baa9e5fad`
- `sigma.75bf09fa-1dd7-4d18-9af9-dd9e492562eb`
- `sigma.75bfe6e6-cd8e-429e-91d3-03921e1d7962`
- `sigma.75d0a94e-6252-448d-a7be-d953dff527bb`
- `sigma.75edd216-1939-4c73-8d61-7f3a0d85b5cc`
- `sigma.75edd3fd-7146-48e5-9848-3013d7f0282c`
- `sigma.75f7a0e2-7154-4c4d-9eae-5cdb4e0a5c13`
- `sigma.760e75d8-c3b5-409b-a9bf-6130b4c4603f`
- `sigma.762bb580-79b4-40f4-8b9e-9349ce1710f4`
- `sigma.762f2482-ff21-4970-8939-0aa317a886bb`
- `sigma.7638e5fe-600c-4289-a968-f49dd537ec7d`
- `sigma.7679d464-4f74-45e2-9e01-ac66c5eb041a`
- `sigma.76f55eaa-d27f-4213-9d45-7b0e4b60bbae`
- `sigma.771d1eb5-9587-4568-95fb-9ec44153a012`
- `sigma.778ba9a8-45e4-4b80-8e3e-34a419f0b85e`
- `sigma.77946e79-97f1-45a2-84b4-f37b5c0d8682`
- `sigma.77df53a5-1d78-4f32-bc5a-0e7465bd8f41`
- `sigma.782d6f3e-4c5d-4b8c-92a3-1d05fed72e63`
- `sigma.7864a175-3654-4824-9f0d-f0da18ab27c0`
- `sigma.786cdae8-fefb-4eb2-9227-04e34060db01`
- `sigma.7892ec59-c5bb-496d-8968-e5d210ca3ac4`
- `sigma.78f10490-f2f4-4d19-a75b-4e0683bf3b8d`
- `sigma.790317c0-0a36-4a6a-a105-6e576bf99a14`
- `sigma.797011dc-44f4-4e6f-9f10-a8ceefbe566b`
- `sigma.79b06761-465f-4f88-9ef2-150e24d3d737`
- `sigma.79ce34ca-af29-4d0e-b832-fc1b377020db`
- `sigma.79df3f68-dccb-48e9-9171-b75cbc37c51d`
- `sigma.79f4ede3-402e-41c8-bc3e-ebbf5f162581`
- `sigma.7a01183d-71a2-46ad-ad5c-acd989ac1793`
- `sigma.7a02e22e-b885-4404-b38b-1ddc7e65258a`
- `sigma.7a1b4c5e-8f3d-4b9a-7c2e-1f4a5b8c6d9e`
- `sigma.7a4d9232-92fc-404d-8ce1-4c92e7caf539`
- `sigma.7a74da6b-ea76-47db-92cc-874ad90df734`
- `sigma.7a922f1b-2635-4d6c-91ef-af228b198ad3`
- `sigma.7aa4e81a-a65c-4e10-9f81-b200eb229d7d`
- `sigma.7aa7009a-28b9-4344-8c1f-159489a390df`
- `sigma.7b10f171-7f04-47c7-9fa2-5be43c76e535`
- `sigma.7b14c76a-c602-4ae6-9717-eff868153fc0`
- `sigma.7b434893-c57d-4f41-908d-6a17bf1ae98f`
- `sigma.7b449a5e-1db5-4dd0-a2dc-4e3a67282538`
- `sigma.7b4f794b-590a-4ad4-ba18-7964a2832205`
- `sigma.7b582f1a-b318-4c6a-bf4e-66fe49bf55a5`
- `sigma.7b687634-ab20-11ea-bb37-0242ac130002`
- `sigma.7b6a7418-3afc-11f0-aff4-000d3abf478c`
- `sigma.7bd3902d-8b8b-4dd4-838a-c6862d40150d`
- `sigma.7c06ab9b-b1d2-4ba9-b06e-09491ded20d9`
- `sigma.7c0dcd3d-acf8-4f71-9570-f448b0034f94`
- `sigma.7c81fec3-1c1d-43b0-996a-46753041b1b6`
- `sigma.7c8af9b2-dcae-41a2-a9db-b28c288b5f08`
- `sigma.7c9fed65-039a-4055-8c23-fa763d94aff6`
- `sigma.7cce6fc8-a07f-4d84-a53e-96e1879843c9`
- `sigma.7cd1dcdc-6edf-4896-86dc-d1f19ad64903`
- `sigma.7cff77e1-9663-46a3-8260-17f2e1aa9d0a`
- `sigma.7d1aaf3d-4304-425c-b7c3-162055e0b3ab`
- `sigma.7d4aaec2-08ed-4430-8b96-28420e030e04`
- `sigma.7d4cdc5a-0076-40ca-aac8-f7e714570e47`
- `sigma.7d604714-e071-49ff-8726-edeb95a70679`
- `sigma.7d6d30b8-5b91-4b90-a891-46cccaf29598`
- `sigma.7d9263bd-dc47-4a58-bc92-5474abab390c`
- `sigma.7d995e63-ec83-4aa3-89d5-8a17b5c87c86`
- `sigma.7dbbcac2-57a0-45ac-b306-ff30a8bd2981`
- `sigma.7dc2dedd-7603-461a-bc13-15803d132355`
- `sigma.7df1713a-1a5b-4a4b-a071-dc83b144a101`
- `sigma.7e6237fe-3ddb-438f-9381-9bf9de5af8d0`
- `sigma.7e8f2d3b-9c1a-4f67-b9e8-8d9006e0e51f`
- `sigma.7e9c7999-0f9b-4d4a-a6ed-af6d553d4af4`
- `sigma.7e9cf7b6-e827-11ed-a05b-0242ac120003`
- `sigma.7e9cf7b6-e827-11ed-a05b-15959c120003`
- `sigma.7ec2c172-dceb-4c10-92c9-87c1881b7e18`
- `sigma.7eedcc9d-9fdb-4d94-9c54-474e8affc0c7`
- `sigma.7efd2c8d-8b18-45b7-947d-adfe9ed04f61`
- `sigma.7eff1a7f-dd45-4c20-877a-f21e342a7611`
- `sigma.7f103213-a04e-4d59-8261-213dddf22314`
- `sigma.7f2376f9-42ee-4dfc-9360-fecff9a88fc8`
- `sigma.7f2954d2-99c2-4d42-a065-ca36740f187b`
- `sigma.7f3a9c2d-4e8b-4a7f-9d3e-5c6f8a9b2e1d`
- `sigma.7f43c430-5001-4f8b-aaa9-c3b88f18fa5c`
- `sigma.7f4c43f9-b1a5-4c7d-b24a-b41bf3a3ebf2`
- `sigma.7f5d1c9a-3e83-48df-95a7-2b98aae6c13c`
- `sigma.7f741dcf-fc22-4759-87b4-9ae8376676a2`
- `sigma.7fd164ba-126a-4d9c-9392-0d4f7c243df0`
- `sigma.7fff6773-2baa-46de-a24a-b6eec1aba2d1`
- `sigma.801bd44f-ceed-4eb6-887c-11544633c0aa`
- `sigma.8023f872-3f1d-4301-a384-801889917ab4`
- `sigma.805c55d9-31e6-4846-9878-c34c75054fe9`
- `sigma.80b708f3-d034-40e4-a6c8-d23b7a7db3d1`
- `sigma.80e1f67a-4596-4351-98f5-a9c3efabac95`
- `sigma.80fc36aa-945e-4181-89f2-2f907ab6775d`
- `sigma.811e0002-b13b-4a15-9d00-a613fce66e42`
- `sigma.811f459f-9231-45d4-959a-0266c6311987`
- `sigma.81315b50-6b60-4d8f-9928-3466e1022515`
- `sigma.814c95cc-8192-4378-a70a-f1aafd877af1`
- `sigma.814ddeca-3d31-4265-8e07-8cc54fb44903`
- `sigma.817f252c-5143-4dae-b418-48c3e9f63728`
- `sigma.81a0ecb5-0a41-4ba1-b2ba-c944eb92bfa2`
- `sigma.81bcb81b-5b1f-474b-b373-52c871aaa7b1`
- `sigma.81ebd28b-9607-4478-bf06-974ed9d53ed7`
- `sigma.8202070f-edeb-4d31-a010-a26c72ac5600`
- `sigma.8218c875-90b9-42e2-b60d-0b0069816d10`
- `sigma.82343930-652f-43f5-ab70-2ee9fdd6d5e9`
- `sigma.833ef470-fa01-4631-a79b-6f291c9ac498`
- `sigma.83475063-b1c8-4774-9568-69bbda71a539`
- `sigma.835e75bf-4bfd-47a4-b8a6-b766cac8bcb7`
- `sigma.83809e84-4475-4b69-bc3e-4aad8568612f`
- `sigma.83865853-59aa-449e-9600-74b9d89a6d6e`
- `sigma.843544a7-56e0-4dcc-a44f-5cc266dd97d6`
- `sigma.8468111a-ef07-4654-903b-b863a80bbc95`
- `sigma.847def9e-924d-4e90-b7c4-5f581395a2b4`
- `sigma.84972c80-251c-4c3a-9079-4f00aad93938`
- `sigma.84b14121-9d14-416e-800b-f3b829c5a14d`
- `sigma.84b1706c-932a-44c4-ae28-892b28a25b94`
- `sigma.84b1ecf9-6eff-4004-bafb-bae5c0e251b2`
- `sigma.850d55f9-6eeb-4492-ad69-a72338f65ba4`
- `sigma.8518ed3d-f7c9-4601-a26c-f361a4256a0c`
- `sigma.8537c866-072e-460d-bfff-aaf39cbd73d3`
- `sigma.853e74f9-9392-4935-ad3b-2e8c040dae86`
- `sigma.855bc8b5-2ae8-402e-a9ed-b889e6df1900`
- `sigma.85a8e5ba-bd03-4bfb-bbfa-a4409a8f8b98`
- `sigma.85b0b087-eddf-4a2b-b033-d771fa2b9775`
- `sigma.85b88e05-dadc-430b-8a9e-53ff1cd30aae`
- `sigma.85c312b7-f44d-4a51-a024-d671c40b49fc`
- `sigma.85cce894-dd8b-4427-a958-5cc47a4dc9b9`
- `sigma.85d23b42-9a9d-4f8f-b3d7-d2733c1d58f5`
- `sigma.85de1f22-d189-44e4-8239-dc276b45379b`
- `sigma.85f520e7-6f5e-43ca-874c-222e5bf9c0de`
- `sigma.85ff530b-261d-48c6-a441-facaa2e81e48`
- `sigma.863218bd-c7d0-4c52-80cd-0a96c09f54af`
- `sigma.86588b36-c6d3-465f-9cee-8f9093e07798`
- `sigma.867356ee-9352-41c9-a8f2-1be690d78216`
- `sigma.869b9ca7-9ea2-4a5a-8325-e80e62f75445`
- `sigma.871b9555-69ca-4993-99d3-35a59f9f3599`
- `sigma.87261fb2-69d0-42fe-b9de-88c6b5f65a43`
- `sigma.87a476dc-0079-4583-a985-dee7a20a03de`
- `sigma.8823e85d-31d8-473e-b7f4-92da070f0fc6`
- `sigma.882e858a-3233-4ba8-855e-2f3d3575803d`
- `sigma.882fbe50-d8d7-4e29-ae80-0648a8556866`
- `sigma.883835a7-df45-43e4-bf1d-4268768afda4`
- `sigma.8839e550-52d7-4958-9f2f-e13c1e736838`
- `sigma.883faa95-175a-4e22-8181-e5761aeb373c`
- `sigma.88656cec-6c3b-487c-82c0-f73ebb805503`
- `sigma.889719ef-dd62-43df-86c3-768fb08dc7c0`
- `sigma.88a87a10-384b-4ad7-8871-2f9bf9259ce5`
- `sigma.88d306e9-8e2d-4025-9768-28757d2732db`
- `sigma.88d6e60c-759d-4ac1-a447-c0f1466c2d21`
- `sigma.88f46b67-14d4-4f45-ac2c-d66984f22191`
- `sigma.899133d5-4d7c-4a7f-94ee-27355c879d90`
- `sigma.89a9a0e0-f61a-42e5-8957-b1479565a658`
- `sigma.89c42960-f244-4dad-9151-ae9b1a3287a2`
- `sigma.89ca78fd-b37c-4310-b3d3-81a023f83936`
- `sigma.89f75308-5b1b-4390-b2d8-d6b2340efaf8`
- `sigma.8a1b2c3d-4e5f-6789-abcd-ef1234567890`
- `sigma.8a3038e8-9c9d-46f8-b184-66234a160f6f`
- `sigma.8a4519e8-e64a-40b6-ae85-ba8ad2177559`
- `sigma.8a582fe2-0882-4b89-a82a-da6b2dc32937`
- `sigma.8a7e90c5-fe6e-45dc-889e-057fe4378bd9`
- `sigma.8a8379b8-780b-4dbf-b1e9-31c8d112fefb`
- `sigma.8b0e12da-d3c3-49db-bb4f-256703f380e5`
- `sigma.8b7273a4-ba5d-4d8a-b04f-11f2900d043a`
- `sigma.8b93a509-1cb8-42e1-97aa-ee24224cdc15`
- `sigma.8b9606c9-28be-4a38-b146-0e313cc232c1`
- `sigma.8bc64091-6875-4881-aaf9-7bd25b5dda08`
- `sigma.8c0eca51-0f88-4db2-9183-fdfb10c703f9`
- `sigma.8c31f563-f9a7-450c-bfa8-35f8f32f1f61`
- `sigma.8c3c76ca-8f8b-4b1d-aaf3-81aebcd367c9`
- `sigma.8ca7004b-e620-4ecb-870e-86129b5b8e75`
- `sigma.8cbc9475-8d05-4e27-9c32-df960716c701`
- `sigma.8cd538a4-62d5-4e83-810b-12d41e428d6e`
- `sigma.8d01b53f-456f-48ee-90f6-bc28e67d4e35`
- `sigma.8d5aca11-22b3-4f22-b7ba-90e60533e1fb`
- `sigma.8d7e392e-9b28-49e1-831d-5949c6281228`
- `sigma.8d85cf08-bf97-4260-ba49-986a2a65129c`
- `sigma.8de1cbe8-d6f5-496d-8237-5f44a721c7a0`
- `sigma.8de89e52-f6e1-4b5b-afd1-41ecfa300d48`
- `sigma.8e0bb260-d4b2-4fff-bb8d-3f82118e6892`
- `sigma.8e1cb247-6cf6-42fa-b440-3f27d57e9936`
- `sigma.8e3c7994-131e-4ba5-b6ea-804d49113a26`
- `sigma.8e4cf0e5-aa5d-4dc3-beff-dc26917744a9`
- `sigma.8e95e73e-ba02-4a87-b4d7-0929b8053038`
- `sigma.8eef149c-bd26-49f2-9e5a-9b00e3af499b`
- `sigma.8f02c935-effe-45b3-8fc9-ef8696a9e41d`
- `sigma.8f2a5c3d-9e4b-4a7c-8d1f-2e5a6b9c3d7e`
- `sigma.8f3ab69a-aa22-4943-aa58-e0a52fdf6818`
- `sigma.8f88e3f6-2a49-48f5-a5c4-2f7eedf78710`
- `sigma.8fbe98a8-8f9d-44f8-aa71-8c572e29ef06`
- `sigma.8fbf3271-1ef6-4e94-8210-03c2317947f6`
- `sigma.8ffc5407-52e3-478f-9596-0a7371eafe13`
- `sigma.903076ff-f442-475a-b667-4f246bcc203b`
- `sigma.9082ff1f-88ab-4678-a3cc-5bcff99fc74d`
- `sigma.90d50722-0483-4065-8e35-57efaadd354d`
- `sigma.90d6bd71-dffb-4989-8d86-a827fedd6624`
- `sigma.90dcf730-1b71-4ae7-9ffc-6fcf62bd0132`
- `sigma.90f342e1-1aaa-4e43-b092-39fda57ed11e`
- `sigma.90fb5e62-ca1f-4e22-b42e-cc521874c938`
- `sigma.910ab938-668b-401b-b08c-b596e80fdca5`
- `sigma.91174a41-dc8f-401b-be89-7bfc140612a0`
- `sigma.91239011-fe3c-4b54-9f24-15c86bb65913`
- `sigma.916eb839-895e-47f8-99ee-3008bf377a3e`
- `sigma.91903aba-1088-42ee-b680-d6d94fe002b0`
- `sigma.919f2ef0-be2d-4a7a-b635-eb2b41fde044`
- `sigma.91a2c315-9ee6-4052-a853-6f6a8238f90d`
- `sigma.91c49341-e2ef-40c0-ac45-49ec5c3fe26c`
- `sigma.91c945bc-2ad1-4799-a591-4d00198a1215`
- `sigma.91edcfb1-2529-4ac2-9ecc-7617f895c7e4`
- `sigma.9212f354-7775-4e28-9c9f-8f0a4544e664`
- `sigma.921aa10f-2e74-4cca-9498-98f9ca4d6fdf`
- `sigma.9248c7e1-2bf3-4661-a22c-600a8040b446`
- `sigma.9257c05b-4a4a-48e5-a670-b7b073cf401b`
- `sigma.92626ddd-662c-49e3-ac59-f6535f12d189`
- `sigma.92772523-d9c1-4c93-9547-b0ca500baba3`
- `sigma.92a974db-ab84-457f-9ec0-55db83d7a825`
- `sigma.92fa78e7-4d39-45f1-91a3-8b23f3f1088d`
- `sigma.93199800-b52a-4dec-b762-75212c196542`
- `sigma.932fb0d8-692b-4b0f-a26e-5643a50fe7d6`
- `sigma.9386d78a-7207-4048-9c9f-a93a7c2d1c05`
- `sigma.93a19907-d4f9-4deb-9f91-aac4692776a6`
- `sigma.93d298a1-d28f-47f1-a468-d971e7796679`
- `sigma.93d94efc-d7ad-4161-ad7d-1638c4f908d8`
- `sigma.941e5c45-cda7-4864-8cea-bbb7458d194a`
- `sigma.944e8941-f6f6-4ee8-ac05-1c224e923c0e`
- `sigma.94771a71-ba41-4b6e-a757-b531372eaab6`
- `sigma.94dc4390-6b7c-4784-8ffc-335334404650`
- `sigma.9501f8e6-8e3d-48fc-a8a6-1089dd5d7ef4`
- `sigma.95022b85-ff2a-49fa-939a-d7b8f56eeb9b`
- `sigma.9525dc73-0327-438c-8c04-13c0e037e9da`
- `sigma.9577edbb-851f-4243-8c91-1d5b50c1a39b`
- `sigma.95e60a2b-4705-444b-b7da-ba0ea81a3ee2`
- `sigma.95eadcb2-92e4-4ed1-9031-92547773a6db`
- `sigma.96036718-71cc-4027-a538-d1587e0006a7`
- `sigma.961e0abb-1b1e-4c84-a453-aafe56ad0d34`
- `sigma.961e33d1-4f86-4fcf-80ab-930a708b2f82`
- `sigma.962fe167-e48d-4fd6-9974-11e5b9a5d6d1`
- `sigma.9637e8a5-7131-4f7f-bdc7-2b05d8670c43`
- `sigma.966315ef-c5e1-4767-ba25-fce9c8de3660`
- `sigma.968eef52-9cff-4454-8992-1e74b9cbad6c`
- `sigma.970007b7-ce32-49d0-a4a4-fbef016950bd`
- `sigma.9703792d-fd9a-456d-a672-ff92efe4806a`
- `sigma.970823b7-273b-460a-8afc-3a6811998529`
- `sigma.9711de76-5d4f-4c50-a94f-21e4e8f8384d`
- `sigma.9719a8aa-401c-41af-8108-ced7ec9cd75c`
- `sigma.973ef012-8f1a-4c40-93b4-7e659a5cd17f`
- `sigma.974515da-6cc5-4c95-ae65-f97f9150ec7f`
- `sigma.976dd1f2-a484-45ec-aa1d-0e87e882262b`
- `sigma.979baf41-ca44-4540-9d0c-4fcef3b5a3a4`
- `sigma.97a80ec7-0e2f-4d05-9ef4-65760e634f6b`
- `sigma.97aa2e88-555c-450d-85a6-229bcd87efb8`
- `sigma.97b9ce1e-c5ab-11ea-87d0-0242ac130003`
- `sigma.97dbf6e2-e436-44d8-abee-4261b24d3e41`
- `sigma.9801abb8-e297-4dbf-9fbd-57dde0e830ad`
- `sigma.98054878-5eab-434c-85d4-72d4e5a3361b`
- `sigma.9827ae57-3802-418f-994b-d5ecf5cd974b`
- `sigma.982e9f2d-1a85-4d5b-aea4-31f5e97c6555`
- `sigma.9847f263-4a81-424f-970c-875dab15b79b`
- `sigma.98767d61-b2e8-4d71-b661-e36783ee24c1`
- `sigma.98a96a5a-64a0-4c42-92c5-489da3866cb0`
- `sigma.98b53e78-ebaf-46f8-be06-421aafd176d9`
- `sigma.98c5aeef-32d5-492f-b174-64a691896d25`
- `sigma.98dedfdd-8333-49d4-9f23-d7018cccae53`
- `sigma.992dd79f-dde8-4bb0-9085-6350ba97cfb3`
- `sigma.993c2665-e6ef-40e3-a62a-e1a97686af79`
- `sigma.994bfd6d-0a2e-481e-a861-934069fcf5f5`
- `sigma.9976fa64-2804-423c-8a5b-646ade840773`
- `sigma.99793437-3e16-439b-be0f-078782cf953d`
- `sigma.99b7460d-c9f1-40d7-a316-1f36f61d52ee`
- `sigma.99c840f2-2012-46fd-9141-c761987550ef`
- `sigma.99c8be4f-3087-4f9f-9c24-8c7e257b442e`
- `sigma.99cf1e02-00fb-4c0d-8375-563f978dfd37`
- `sigma.9a019ffc-3580-4c9d-8d87-079f7e8d3fd4`
- `sigma.9a132afa-654e-11eb-ae93-0242ac130002`
- `sigma.9a4ccd1a-3526-4d99-b980-9f9c5d3a6ff3`
- `sigma.9a4ff3b8-6187-4fd2-8e8b-e0eae1129495`
- `sigma.9ace0707-b560-49b8-b6ca-5148b42f39fb`
- `sigma.9b0f8a61-91b2-464f-aceb-0527e0a45020`
- `sigma.9b64de98-9db3-4033-bd7a-f51430105f00`
- `sigma.9b8d9203-4e0f-4cd9-bb06-4cc4ea6d0e9a`
- `sigma.9bd04a79-dabe-4f1f-a5ff-92430265c96b`
- `sigma.9c0295ce-d60d-40bd-bd74-84673b7592b1`
- `sigma.9c14c9fa-1a63-4a64-8e57-d19280559490`
- `sigma.9c226817-8dc9-46c2-a58d-66655aafd7dc`
- `sigma.9c5037d1-c568-49b3-88c7-9846a5bdc2be`
- `sigma.9c7e131a-0f2c-4ae0-9d43-b04f4e266d43`
- `sigma.9c8afa4d-0022-48f0-9456-3712466f9701`
- `sigma.9cc85849-3b02-4cb5-b371-3a1ff54f2218`
- `sigma.9ccba514-7cb6-4c5c-b377-700758f2f120`
- `sigma.9cfe4b27-1e56-48b4-b7a8-d46851c91a44`
- `sigma.9d15044a-7cfe-4d23-8085-6ebc11df7685`
- `sigma.9d3436ef-9476-4c43-acca-90ce06bdf33a`
- `sigma.9d5a1274-922a-49d0-87f3-8c653483b909`
- `sigma.9d7ca793-f6bd-471c-8d0f-11e68b2f0d2f`
- `sigma.9d8f9bb8-01af-4e15-a3a2-349071530530`
- `sigma.9df0dd3a-1a5c-47e3-a2bc-30ed177646a0`
- `sigma.9df5f547-c86a-433e-b533-f2794357e242`
- `sigma.9e02c8ec-02b9-43e8-81eb-34a475ba7965`
- `sigma.9e099d99-44c2-42b6-a6d8-54c3545cab29`
- `sigma.9e3357ba-09d4-4fbd-a7c5-ad6386314513`
- `sigma.9e36ed87-4986-482e-8e3b-5c23ffff11bf`
- `sigma.9e3cb244-bdb8-4632-8c90-6079c8f4f16d`
- `sigma.9e4b7d3a-6f2c-4e9a-8d1b-3c5e7a9f2b4d`
- `sigma.9e50a8b3-dd05-4eb8-9153-bdb6b79d50b0`
- `sigma.9e716b33-63b2-46da-86a4-bd3c3b9b5dfb`
- `sigma.9e8894c0-0ae0-11ef-9d85-1f2942bec57c`
- `sigma.9eb99343-d336-4020-a3cd-67f3819e68ee`
- `sigma.9ec9fb1b-e059-4489-9642-f270c207923d`
- `sigma.9ef27c24-4903-4192-881a-3adde7ff92a5`
- `sigma.9f0a8bf3-a65b-440a-8c1e-5cb1547c8e70`
- `sigma.9f38c1db-e2ae-40bf-81d0-5b68f73fb512`
- `sigma.9f4662ac-17ca-43aa-8f12-5d7b989d0101`
- `sigma.9f50fe98-fe5c-4a2d-86c7-fad7f63ed622`
- `sigma.9f546b25-5f12-4c8d-8532-5893dcb1e4b8`
- `sigma.9f8fc146-1d1a-4dbf-b8fd-dfae15e08541`
- `sigma.9fb6b26e-7f9e-4517-a48b-8cac4a1b6c60`
- `sigma.9fbf5927-5261-4284-a71d-f681029ea574`
- `sigma.9fc3072c-dc8f-4bf7-b231-18950000fadd`
- `sigma.9fc51a3c-81b3-4fa7-b35f-7c02cf10fd2d`
- `sigma.9fff585c-c33e-4a86-b3cd-39312079a65f`
- `sigma.a018fdc3-46a3-44e5-9afb-2cd4af1d4b39`
- `sigma.a01b8329-5953-4f73-ae2d-aa01e1f35f00`
- `sigma.a0459f02-ac51-4c09-b511-b8c9203fc429`
- `sigma.a05baa88-e922-4001-bc4d-8738135f27de`
- `sigma.a07f0359-4c90-4dc4-a681-8ffea40b4f47`
- `sigma.a0a278fe-2c0e-4de2-ac3c-c68b08a9ba98`
- `sigma.a0cb7110-edf0-47a4-9177-541a4083128a`
- `sigma.a0d7e4d2-bede-4141-8896-bc6e237e977c`
- `sigma.a0e417e2-2fa1-40da-b6d2-e094cd5e1191`
- `sigma.a10a2c40-2c4d-49f8-b557-1a946bc55d9d`
- `sigma.a1473adb-5338-4a20-b4c3-126763e2d3d3`
- `sigma.a166f74e-bf44-409d-b9ba-ea4b2dd8b3cd`
- `sigma.a16980c2-0c56-4de0-9a79-17971979efdd`
- `sigma.a18e0862-127b-43ca-be12-1a542c75c7c5`
- `sigma.a197e378-d31b-41c0-9635-cfdf1c1bb423`
- `sigma.a1b1fd53-9c4a-444c-bae0-34a330fc7aa8`
- `sigma.a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6`
- `sigma.a1d9eec5-33b2-4177-8d24-27fe754d0812`
- `sigma.a1e11042-a74a-46e6-b07c-c4ce8ecc239b`
- `sigma.a20391f8-76fb-437b-abc0-dba2df1952c6`
- `sigma.a20def93-0709-4eae-9bd2-31206e21e6b2`
- `sigma.a21bcd7e-38ec-49ad-b69a-9ea17e69509e`
- `sigma.a27e5fa9-c35e-4e3d-b7e0-1ce2af66ad12`
- `sigma.a2863fbc-d5cb-48d5-83fb-d976d4b1743b`
- `sigma.a2910908-e86f-4687-aeba-76a5f996e652`
- `sigma.a29808fd-ef50-49ff-9c7a-59a9b040b404`
- `sigma.a29c1813-ab1f-4dde-b489-330b952e91ae`
- `sigma.a2e5019d-a658-4c6a-92bf-7197b54e2cae`
- `sigma.a2ea3ae7-d3d0-40a0-a55c-25a45c87cac1`
- `sigma.a31eeaed-3fd5-478e-a8ba-e62c6b3f9ecc`
- `sigma.a34f79a3-8e5f-4cc3-b765-de00695452c2`
- `sigma.a35f5a72-f347-4e36-8895-9869b0d5fc6d`
- `sigma.a383dec4-deec-4e6e-913b-ed9249670848`
- `sigma.a3ab73f1-bd46-4319-8f06-4b20d0617886`
- `sigma.a4694263-59a8-4608-a3a0-6f8d3a51664c`
- `sigma.a4824fca-976f-4964-b334-0621379e84c4`
- `sigma.a4c90ea1-2634-4ca0-adbb-35eae169b6fc`
- `sigma.a4e3d776-f12e-42c2-8510-9e6ed1f43ec3`
- `sigma.a537cfc3-4297-4789-92b5-345bfd845ad0`
- `sigma.a54f842a-3713-4b45-8c84-5f136fdebd3c`
- `sigma.a58353df-af43-4753-bad0-cd83ef35eef5`
- `sigma.a5a2d357-1ab8-4675-a967-ef9990a59391`
- `sigma.a5c7a43f-6009-4a8c-80c5-32abf1c53ecc`
- `sigma.a62b37e0-45d3-48d9-a517-90c1a1b0186b`
- `sigma.a642964e-bead-4bed-8910-1bb4d63e3b4d`
- `sigma.a66bc059-c370-472c-a0d7-f8fd1bf9d583`
- `sigma.a6976974-ea6f-4e97-818e-ea08625c52cb`
- `sigma.a6a39bdb-935c-4f0a-ab77-35f4bbf44d33`
- `sigma.a6b33c02-8305-488f-8585-03cb2a7763f2`
- `sigma.a6fc3c46-23b8-4996-9ea2-573f4c4d88c5`
- `sigma.a70dcb37-3bee-453a-99df-d0c683151be6`
- `sigma.a743ceba-c771-4d75-97eb-8a90f7f4844c`
- `sigma.a746c9b8-a2fb-4ee5-a428-92bee9e99060`
- `sigma.a7664b14-75fb-4a50-a223-cb9bc0afbacf`
- `sigma.a77c1610-fc73-4019-8e29-0f51efc04a51`
- `sigma.a7df0e9e-91a5-459a-a003-4cde67c2ff5d`
- `sigma.a7ee1722-c3c5-aeff-3212-c777e4733217`
- `sigma.a80f662f-022f-4429-9b8c-b1a41aaa6688`
- `sigma.a85f7765-698a-4088-afa0-ecfbf8d01fa4`
- `sigma.a85ffc3a-e8fd-4040-93bf-78aff284d801`
- `sigma.a8f29a7b-b137-4446-80a0-b804272f3da2`
- `sigma.a8f866e1-bdd4-425e-a27a-37619238d9c7`
- `sigma.a95b9b42-1308-4735-a1af-abb1c5e6f5ac`
- `sigma.a96970af-f126-420d-90e1-d37bf25e50e1`
- `sigma.a982fc9c-6333-4ffb-a51d-addb04e8b529`
- `sigma.a9b6c011-ab69-4ddb-bc0a-c4f21c80ec47`
- `sigma.a9e416a8-e613-4f8b-88b8-a7d1d1af2f61`
- `sigma.aa0b3a82-eacc-4ec3-9150-b5a9a3e3f82f`
- `sigma.aa1697b7-d611-4f9a-9cb2-5125b4ccfd5c`
- `sigma.aa2efee7-34dd-446e-8a37-40790a66efd7`
- `sigma.aa37cbb0-da36-42cb-a90f-fdf216fc7467`
- `sigma.aa3a6f94-890e-4e22-b634-ffdfd54792cc`
- `sigma.aa6f6ea6-0676-40dd-b510-6e46f02d8867`
- `sigma.aa8e035d-7be4-48d3-a944-102aec04400d`
- `sigma.aaafa146-074c-11eb-adc1-0242ac120002`
- `sigma.aaf46cdc-934e-4284-b329-34aa701e3771`
- `sigma.ab37a6ec-6068-432b-a64e-2c7bf95b1d22`
- `sigma.ab4561b1-6c7e-48a7-ad08-087cfb9ce8f1`
- `sigma.ab567429-1dfb-4674-b6d2-979fd2f9d125`
- `sigma.ab6bffca-beff-4baa-af11-6733f296d57a`
- `sigma.ab70c354-d9ac-4e11-bbb6-ec8e3b153357`
- `sigma.ab871450-37dc-4a3a-997f-6662aa8ae0f1`
- `sigma.ab9e3b40-0c85-4ba1-aede-455d226fd124`
- `sigma.aba15bdd-657f-422a-bab3-ac2d2a0d6f1c`
- `sigma.ac175779-025a-4f12-98b0-acdaeb77ea85`
- `sigma.ac1c92b4-ac81-405a-9978-4604d78cc47e`
- `sigma.ac20ae82-8758-4f38-958e-b44a3140ca88`
- `sigma.ac8866c7-ce44-46fd-8c17-b24acff96ca8`
- `sigma.ac9159cc-c364-4304-8f0a-d63fc1a0aabb`
- `sigma.acfa2210-0d71-4eeb-b477-afab494d596c`
- `sigma.ad691d92-15f2-4181-9aa4-723c74f9ddc3`
- `sigma.ad720b90-25ad-43ff-9b5e-5c841facc8e5`
- `sigma.ad89044a-8f49-4673-9a55-cbd88a1b374f`
- `sigma.ad92e3f9-7eb6-460e-96b1-582b0ccbb980`
- `sigma.ada4b0c4-758b-46ac-9033-9004613a150d`
- `sigma.add64136-62e5-48ea-807e-88638d02df1e`
- `sigma.ae215552-081e-44c7-805f-be16f975c8a2`
- `sigma.ae6f14e6-14de-45b0-9f44-c0986f50dc89`
- `sigma.ae9b0bd7-8888-4606-b444-0ed7410cb728`
- `sigma.ae9c6a7c-9521-42a6-915e-5aaa8689d529`
- `sigma.aef9d1f1-7396-4e92-a927-4567c7a495c1`
- `sigma.af491bca-e752-4b44-9c86-df5680533dbc`
- `sigma.af5732ed-764e-489d-826d-0447c8b36242`
- `sigma.af77cf95-c469-471c-b6a0-946c685c4798`
- `sigma.afa71271-6a97-4e47-810f-83120fb1a4ce`
- `sigma.afe52666-401e-4a02-b4ff-5d128990b8cb`
- `sigma.b0524451-19af-4efa-a46f-562a977f792e`
- `sigma.b07e58cf-cacc-4135-8473-ccb2eba63dd2`
- `sigma.b0ce780f-10bd-496d-9067-066d23dc3aa5`
- `sigma.b110ebaf-697f-4da1-afd5-b536fa27a2c1`
- `sigma.b124ddf4-778d-418e-907f-6dd3fc0d31cd`
- `sigma.b1377339-fda6-477a-b455-ac0923f9ec2c`
- `sigma.b17ea6f7-6e90-447e-a799-e6c0a493d6ce`
- `sigma.b1876533-4ed5-4a83-90f3-b8645840a413`
- `sigma.b18c9d4c-fac9-4708-bd06-dd5bfacf200f`
- `sigma.b19146a3-25d4-41b4-928b-1e2a92641b1b`
- `sigma.b1c50487-1967-4315-a026-6491686d860e`
- `sigma.b1cb4ab6-ac31-43f4-adf1-d9d08957419c`
- `sigma.b1e0b3f5-b62e-41be-886a-daffde446ad4`
- `sigma.b1e5da3b-ca8e-4adf-915c-9921f3d85481`
- `sigma.b1f73849-6329-4069-bc8f-78a604bb8b23`
- `sigma.b210394c-ba12-4f89-9117-44a2464b9511`
- `sigma.b222df08-0e07-11eb-adc1-0242ac120002`
- `sigma.b2309017-4235-44fe-b5af-b15363011957`
- `sigma.b2317cfa-4a47-4ead-b3ff-297438c0bc2d`
- `sigma.b237c54b-0f15-4612-a819-44b735e0de27`
- `sigma.b23818c7-e575-4d13-8012-332075ec0a2b`
- `sigma.b243b280-65fe-48df-ba07-6ddea7646427`
- `sigma.b27077d6-23e6-45d2-81a0-e2b356eea5fd`
- `sigma.b2815d0d-7481-4bf0-9b6c-a4c48a94b349`
- `sigma.b28e58e4-2a72-4fae-bdee-0fbe904db642`
- `sigma.b2ddd389-f676-4ac4-845a-e00781a48e5f`
- `sigma.b30a8bc5-e21b-4ca2-9420-0a94019ac56a`
- `sigma.b3503044-60ce-4bf4-bbcb-e3db98788823`
- `sigma.b3512211-c67e-4707-bedc-66efc7848863`
- `sigma.b36d01a3-ddaf-4804-be18-18a6247adfcd`
- `sigma.b37998de-a70b-4f33-b219-ec36bf433dc0`
- `sigma.b3ad3c0f-c949-47a1-a30e-b0491ccae876`
- `sigma.b3d34dc5-2efd-4ae3-845f-8ec14921f449`
- `sigma.b3d57a5c-c92e-4b48-9a79-5f124b7cf964`
- `sigma.b3e6418f-7c7a-4fad-993a-93b65027a9f1`
- `sigma.b447f7de-1e53-4cbf-bfb4-f1f6d0b04e4e`
- `sigma.b471f462-eb0d-4832-be35-28d94bdb4780`
- `sigma.b4926b47-a9d7-434c-b3a0-adc3fa0bd13e`
- `sigma.b4c8da4a-1c12-46b0-8a2b-0a8521d03442`
- `sigma.b4dc61f5-6cce-468e-a608-b48b469feaa2`
- `sigma.b52e84a3-029e-4529-b09b-71d19dd27e94`
- `sigma.b53317a0-8acf-4fd1-8de8-a5401e776b96`
- `sigma.b55ca2a3-7cff-4dda-8bdd-c7bfa63bf544`
- `sigma.b5746143-59d6-4603-8d06-acbd60e166ee`
- `sigma.b57ba453-b384-4ab9-9f40-1038086b4e53`
- `sigma.b5b29e4e-31fa-4fdf-b058-296e7a1aa0c2`
- `sigma.b5b78988-486d-4a80-b991-930eff3ff8bf`
- `sigma.b5c7395f-e501-4a08-94d4-57fe7a9da9d2`
- `sigma.b61e87c0-50db-4b2e-8986-6a2be94b33b0`
- `sigma.b6457d63-d2a2-4e29-859d-4e7affc153d1`
- `sigma.b64a026b-8deb-4c1d-92fd-98893209dff1`
- `sigma.b655a06a-31c0-477a-95c2-3726b83d649d`
- `sigma.b66474aa-bd92-4333-a16c-298155b120df`
- `sigma.b6676963-0353-4f88-90f5-36c20d443c6a`
- `sigma.b697e69c-746f-4a86-9f59-7bfff8eab881`
- `sigma.b6b49cd1-34d6-4ead-b1bf-176e9edba9a4`
- `sigma.b6d235fc-1d38-4b12-adbe-325f06728f37`
- `sigma.b6d98a4f-cef0-4abf-bbf6-24132854a83d`
- `sigma.b6e04788-29e1-4557-bb14-77f761848ab8`
- `sigma.b6f91281-20aa-446a-b986-38a92813a18f`
- `sigma.b730a276-6b63-41b8-bcf8-55930c8fc6ee`
- `sigma.b7916c2a-fa2f-4795-9477-32b731f70f11`
- `sigma.b7966f4a-b333-455b-8370-8ca53c229762`
- `sigma.b7b19cb6-9b32-4fc4-a108-73f19acfe262`
- `sigma.b7e2a8d4-74bb-4b78-adc9-3f92af2d4829`
- `sigma.b86852fb-4c77-48f9-8519-eb1b2c308b59`
- `sigma.b86f6dea-0b2f-41f5-bdcc-a057bd19cd6a`
- `sigma.b888e3f2-224d-4435-b00b-9dd66e9ea1f1`
- `sigma.b8b1b304-a60f-4999-9a6e-c547bde03ffd`
- `sigma.b96b2031-7c17-4473-afe7-a30ce714db29`
- `sigma.b97cd4b1-30b8-4a9d-bd72-6293928d52bc`
- `sigma.b98968aa-dbc0-4a9c-ac35-108363cbf8d5`
- `sigma.b98a10af-1e1e-44a7-bab2-4cc026917648`
- `sigma.b98d0db6-511d-45de-ad02-e82a98729620`
- `sigma.b99a1518-1ad5-4f65-bc95-1ffff97a8fd0`
- `sigma.b9aeac14-2ffd-4ad3-b967-1354a4e628c3`
- `sigma.b9cbbc17-d00d-4e3d-a827-b06d03d2380d`
- `sigma.b9d9cc83-380b-4ba3-8d8f-60c0e7e2930c`
- `sigma.b9e8c7d6-a5f4-4e3d-8b1a-9f0c8d7e6a5b`
- `sigma.b9f0e6f5-09b4-4358-bae4-08408705bd5c`
- `sigma.ba1f7802-adc7-48b4-9ecb-81e227fddfd5`
- `sigma.ba226dcf-d390-4642-b9af-b534872f1156`
- `sigma.ba3874b9-0fae-465f-836c-eb5d071a1789`
- `sigma.ba3f5c1b-6272-4119-9dbd-0bc8d21c2702`
- `sigma.ba42babc-0666-4393-a4f7-ceaf5a69191e`
- `sigma.ba4cfc11-d0fa-4d94-bf20-7c332c412e76`
- `sigma.bab049ca-7471-4828-9024-38279a4c04da`
- `sigma.bac9fb54-2da7-44e9-988f-11e9a5edbc0c`
- `sigma.baca5663-583c-45f9-b5dc-ea96a22ce542`
- `sigma.bacf58c6-e199-4040-a94f-95dea0f1e45a`
- `sigma.baecf8fb-edbf-429f-9ade-31fc3f22b970`
- `sigma.baef1ec6-2ca9-47a3-97cc-4cf2bda10b77`
- `sigma.bafac3d6-7de9-4dd9-8874-4a1194b493ed`
- `sigma.bb09dd3e-2b78-4819-8e35-a7c1b874e449`
- `sigma.bb0e87ce-c89f-4857-84fa-095e4483e9cb`
- `sigma.bb58aa4a-b80b-415a-a2c0-2f65a4c81009`
- `sigma.bb76d96b-821c-47cf-944b-7ce377864492`
- `sigma.bb780e0c-16cf-4383-8383-1e5471db6cf9`
- `sigma.bbb7e38c-0b41-4a11-b306-d2a457b7ac2b`
- `sigma.bbc865e4-7fcd-45a6-8ff1-95ced28ec5b2`
- `sigma.bbf59793-6efb-4fa1-95ca-a7d288e52c88`
- `sigma.bc275be9-0bec-4d77-8c8f-281a2df6710f`
- `sigma.bc2e25ed-b92b-4daa-b074-b502bdd1982b`
- `sigma.bc92ca75-cd42-4d61-9a37-9d5aa259c88b`
- `sigma.bd1212e5-78da-431e-95fa-c58e3237a8e6`
- `sigma.bd1c6866-65fc-44b2-be51-5588fcff82b9`
- `sigma.bd8b828d-0dca-48e1-8a63-8a58ecf2644f`
- `sigma.bdd8157d-8e85-4397-bb82-f06cc9c71dbb`
- `sigma.bdeb2cff-af74-4094-8426-724dc937f20a`
- `sigma.bdeeabc9-ff2a-4a51-be59-bb253aac7891`
- `sigma.be344333-921d-4c4d-8bb8-e584cf584780`
- `sigma.be58d2e2-06c8-4f58-b666-b99f6dc3b6cd`
- `sigma.bed2a484-9348-4143-8a8a-b801c979301c`
- `sigma.bedfc8ad-d1c7-4e37-a20e-e2b0dbee759c`
- `sigma.bef0bc5a-b9ae-425d-85c6-7b2d705980c6`
- `sigma.bef37fa2-f205-4a7b-b484-0759bfd5f86f`
- `sigma.bf344fea-d947-4ef4-9192-34d008315d3a`
- `sigma.bf361876-6620-407a-812f-bfe11e51e924`
- `sigma.bf4fc428-dcc3-4bbd-99fe-2422aeee2544`
- `sigma.bf9e1387-b040-4393-9851-1598f8ecfae9`
- `sigma.bfbd3291-de87-4b7c-88a2-d6a5deb28668`
- `sigma.c02e96b7-c63a-4c47-bd83-4a9f74afcfb2`
- `sigma.c048f047-7e2a-4888-b302-55f509d4a91d`
- `sigma.c0514f28-fdae-42df-b886-06e2b2bc5b37`
- `sigma.c082c2b0-525b-4dbc-9a26-a57dc4692074`
- `sigma.c09dad97-1c78-4f71-b127-7edb2b8e491a`
- `sigma.c0b2768a-dd06-4671-8339-b16ca8d1f27f`
- `sigma.c0b40568-b1e9-4b03-8d6c-b096da6da9ab`
- `sigma.c0e0bdec-3e3d-47aa-9974-05539c999c89`
- `sigma.c11aecef-9c37-45a6-9c07-bc0782f963fd`
- `sigma.c15a46a0-07d4-4c87-b4b6-89207835a83b`
- `sigma.c17d47b7-dcd6-4109-87eb-d1817bd4cbc9`
- `sigma.c1d867fe-8d95-4487-aab4-e53f2d339f90`
- `sigma.c260b6db-48ba-4b4a-a76f-2f67644e99d2`
- `sigma.c265cf08-3f99-46c1-8d59-328247057d57`
- `sigma.c27515df-97a9-4162-8a60-dc0eeb51b775`
- `sigma.c2b86e67-b880-4eec-b045-50bc98ef4844`
- `sigma.c2c76b77-32be-4d1f-82c9-7e544bdfe0eb`
- `sigma.c30fb093-1109-4dc8-88a8-b30d11c95a5d`
- `sigma.c31364f7-8be6-4b77-8483-dd2b5a7b69a3`
- `sigma.c363385c-f75d-4753-a108-c1a8e28bdbda`
- `sigma.c39f0c81-7348-4965-ab27-2fde35a1b641`
- `sigma.c3a99af4-35a9-4668-879e-c09aeb4f2bdf`
- `sigma.c3cefdf4-6703-4e1c-bad8-bf422fc5015a`
- `sigma.c3d76afc-93df-461e-8e67-9b2bad3f2ac4`
- `sigma.c3dbbc9f-ef1d-470a-a90a-d343448d5875`
- `sigma.c3e76af5-4ce0-4a14-9c9a-25ceb8fda182`
- `sigma.c3edc6a5-d9d4-48d8-930e-aab518390917`
- `sigma.c420410f-c2d8-4010-856b-dffe21866437`
- `sigma.c43a5405-e8e1-4221-9ac9-dbe3fa14e886`
- `sigma.c43c26be-2e87-46c7-8661-284588c5a53e`
- `sigma.c443012c-7928-43bf-ac20-7eda5efe61ad`
- `sigma.c453ab7a-1f5c-4716-a3b4-dea8135fb43a`
- `sigma.c484e533-ee16-4a93-b6ac-f0ea4868b2f1`
- `sigma.c49c5062-0966-4170-9efd-9968c913a6cf`
- `sigma.c4e49831-1496-40cf-8ce1-b53f942b02f9`
- `sigma.c4e92a97-a9ff-4392-9d2d-7a4c642768ca`
- `sigma.c4eeeeae-89f4-43a7-8b48-8d1bdfa66c78`
- `sigma.c4ff1eac-84ad-44dd-a6fb-d56a92fc43a9`
- `sigma.c539afac-c12a-46ed-b1bd-5a5567c9f045`
- `sigma.c57872c7-614f-4d7f-a40d-b78c8df2d30d`
- `sigma.c598cc0c-9e70-4852-b9eb-8921af79f598`
- `sigma.c5c00f49-b3f9-45a6-997e-cfdecc6e1967`
- `sigma.c5f6a85d-b647-40f7-bbad-c10b66bab038`
- `sigma.c615d676-f655-46b9-b913-78729021e5d7`
- `sigma.c61daa90-3c1e-4f18-af62-8f288b5c9aaf`
- `sigma.c625d754-6a3d-4f65-9c9a-536aea960d37`
- `sigma.c633622e-cab9-4eaa-bb13-66a1d68b3e47`
- `sigma.c6c56ada-612b-42d1-9a29-adad3c5c2c1e`
- `sigma.c73124a7-3e89-44a3-bdc1-25fe4df754b1`
- `sigma.c740d4cf-a1e9-41de-bb16-8a46a4f57918`
- `sigma.c74c0390-3e20-41fd-a69a-128f0275a5ea`
- `sigma.c74d7efc-8826-45d9-b8bb-f04fac9e4eff`
- `sigma.c7942406-33dd-4377-a564-0f62db0593a3`
- `sigma.c79da740-5030-45ec-a2e0-479e824a562c`
- `sigma.c7c8aa1c-5aff-408e-828b-998e3620b341`
- `sigma.c7d33b50-f690-4b51-8cfb-0fb912a31e57`
- `sigma.c7da8edc-49ae-45a2-9e61-9fd860e4e73d`
- `sigma.c7dcacd0-cc59-4004-b0a4-1d6cdebe6f3e`
- `sigma.c7e91a02-d771-4a6d-a700-42587e0b1095`
- `sigma.c80e66d8-1780-48a9-b412-46663fd21ac0`
- `sigma.c83bf4b5-cdf0-437c-90fa-43d734f7c476`
- `sigma.c86133ad-4725-4bd0-8170-210788e0a7ba`
- `sigma.c86500e9-a645-4680-98d7-f882c70c1ea3`
- `sigma.c8a180d6-47a3-4345-a609-53f9c3d834fc`
- `sigma.c8b00925-926c-47e3-beea-298fd563728e`
- `sigma.c8da0dfd-4ed0-4b68-962d-13c9c884384e`
- `sigma.c90362e0-2df3-4e61-94fe-b37615814cb1`
- `sigma.c9192ad9-75e5-43eb-8647-82a0a5b493e3`
- `sigma.c947b146-0abc-4c87-9c64-b17e9d7274a2`
- `sigma.c9783e20-4793-4164-ba96-d9ee483992c4`
- `sigma.c98f2a0d-e1b8-4f76-90d3-359caf88d6b9`
- `sigma.c9eb55c3-b468-40ab-9089-db2862e42137`
- `sigma.c9fbe8e9-119d-40a6-9b59-dd58a5d84429`
- `sigma.ca2092a1-c273-4878-9b4b-0d60115bf5ea`
- `sigma.ca387a8e-1c84-4da3-9993-028b45342d30`
- `sigma.ca5583e9-8f80-46ac-ab91-7f314d13b984`
- `sigma.ca621ba5-54ab-4035-9942-d378e6fcde3c`
- `sigma.caa06de8-fdef-4c91-826a-7f9e163eef4b`
- `sigma.caa9a802-8bd8-4b9e-a5cd-4d6221670219`
- `sigma.cad1fe90-2406-44dc-bd03-59d0b58fe722`
- `sigma.caf201a9-c2ce-4a26-9c3a-2b9525413711`
- `sigma.cafeeba3-01da-4ab4-b6c4-a31b1d9730c7`
- `sigma.cb0fe7c5-f3a3-484d-aa25-d350a7912729`
- `sigma.cb5a2333-56cf-4562-8fcb-22ba1bca728d`
- `sigma.cb7c4a03-2871-43c0-9bbb-18bbdb079896`
- `sigma.cb9cc1d1-e84e-4bdc-b7ad-c31b1b7908ec`
- `sigma.cbb9e3d1-2386-4e59-912e-62f1484f7a89`
- `sigma.cbec226f-63d9-4eca-9f52-dfb6652f24df`
- `sigma.cc1abf27-78a3-4ac5-a51c-f3070b1d8e40`
- `sigma.cc268ac1-42d9-40fd-9ed3-8c4e1a5b87e6`
- `sigma.cc368ed0-2411-45dc-a222-510ace303cb2`
- `sigma.cc36992a-4671-4f21-a91d-6c2b72a2edf5`
- `sigma.cc4e02ba-9c06-48e2-b09e-2500cace9ae0`
- `sigma.cc7abbd0-762b-41e3-8a26-57ad50d2eea3`
- `sigma.ccb5742c-c248-4982-8c5c-5571b9275ad3`
- `sigma.cd0f7229-d16f-42de-8fe3-fba365fbcb3a`
- `sigma.cd1f961e-0b96-436b-b7c6-38da4583ec00`
- `sigma.cd219ff3-fa99-45d4-8380-a7d15116c6dc`
- `sigma.cd277474-5c52-4423-a52b-ac2d7969902f`
- `sigma.cd3d1298-eb3b-476c-ac67-12847de55813`
- `sigma.cd5cfd80-aa5f-44c0-9c20-108c4ae12e3c`
- `sigma.cd71385d-fd9b-4691-9b98-2b1f7e508714`
- `sigma.cd764533-2e07-40d6-a718-cfeec7f2da7f`
- `sigma.cd8b36ac-8e4a-4c2f-a402-a29b8fbd5bca`
- `sigma.cd8c163e-a19b-402e-bdd5-419ff5859f12`
- `sigma.cd951fdc-4b2f-47f5-ba99-a33bf61e3770`
- `sigma.cdf05894-89e7-4ead-b2b0-0a5f97a90f2f`
- `sigma.ce7066a6-508a-42d3-995b-2952c65dc2ce`
- `sigma.ce72ef99-22f1-43d4-8695-419dcb5d9330`
- `sigma.ce7cf472-6fcc-490a-9481-3786840b5d9b`
- `sigma.cea2b7ea-792b-405f-95a1-b903ea06458f`
- `sigma.cea72823-df4d-4567-950c-0b579eaf0846`
- `sigma.cec8e918-30f7-4e2d-9bfa-a59cc97ae60f`
- `sigma.cf0c254b-22f1-4b2b-8221-e137b3c0af94`
- `sigma.cf2e938e-9a3e-4fe8-a347-411642b28a9f`
- `sigma.cf93e05e-d798-4d9e-b522-b0248dc61eaf`
- `sigma.cfeed607-6aa4-4bbd-9627-b637deb723c8`
- `sigma.d00a9a72-2c09-4459-ad03-5e0a23351e36`
- `sigma.d042284c-a296-4988-9be5-f424fadcc28c`
- `sigma.d047726b-c71c-4048-a99b-2e2f50dc107d`
- `sigma.d04ae2b8-ad54-4de0-bd87-4bc1da66aa59`
- `sigma.d059842b-6b9d-4ed1-b5c3-5b89143c6ede`
- `sigma.d06be4b9-8045-428b-a567-740a26d9db25`
- `sigma.d08a2711-ee8b-4323-bdec-b7d85e892b31`
- `sigma.d08dd86f-681e-4a00-a92c-1db218754417`
- `sigma.d0dae994-26c6-4d2d-83b5-b3c8b79ae513`
- `sigma.d102b8f5-61dc-4e68-bd83-9a3187c67377`
- `sigma.d20ee2f4-822c-4827-9e15-41500b1fff10`
- `sigma.d21374ff-f574-44a7-9998-4a8c8bf33d7d`
- `sigma.d223b46b-5621-4037-88fe-fda32eead684`
- `sigma.d22df9cd-2aee-4089-93c7-9dc4eae77f2c`
- `sigma.d22e2925-cfd8-463f-96f6-89cec9d9bc5f`
- `sigma.d26ce60c-2151-403c-9a42-49420d87b5e4`
- `sigma.d2b749ee-4225-417e-b20e-a8d2193cbb84`
- `sigma.d2eb17db-1d39-41dc-b57f-301f6512fa75`
- `sigma.d353dac0-1b41-46c2-820c-d7d2561fc6ed`
- `sigma.d38d2fa4-98e6-4a24-aff1-410b0c9ad177`
- `sigma.d3abac66-f11c-4ed0-8acb-50cc29c97eed`
- `sigma.d3b70aad-097e-409c-9df2-450f80dc476b`
- `sigma.d3bf399f-b0cf-4250-8bb4-dfc192ab81dc`
- `sigma.d3c3861d-c504-4c77-ba55-224ba82d0118`
- `sigma.d4498716-1d52-438f-8084-4a603157d131`
- `sigma.d474c8fe-bb69-4ea0-b7d9-f682b56d52d3`
- `sigma.d487ed4a-fd24-436d-a0b2-f4e95f7b2635`
- `sigma.d4e2745c-f0c6-4bde-a3ab-b553b3f693cc`
- `sigma.d526c60a-e236-4011-b165-831ffa52ab70`
- `sigma.d557dc06-62e8-4468-a8e8-7984124908ce`
- `sigma.d55b793d-f847-4eea-b59a-5ab09908ac90`
- `sigma.d58ba5c6-0ed7-4b9d-a433-6878379efda9`
- `sigma.d5b9ae7a-e6fc-405e-80ff-2ff9dcc64e7e`
- `sigma.d65aee4d-2292-4cea-b832-83accd6cfa43`
- `sigma.d67572a0-e2ec-45d6-b8db-c100d14b8ef2`
- `sigma.d679950c-abb7-43a6-80fb-2a480c4fc450`
- `sigma.d6a9b252-c666-4de6-8806-5561bbbd3bdc`
- `sigma.d6b5520d-3934-48b4-928c-2aa3f92d6963`
- `sigma.d6c2ce7e-afb5-4337-9ca4-4b5254ed0565`
- `sigma.d6ce7ebd-260b-4323-9768-a9631c8d4db2`
- `sigma.d75d6b6b-adb9-48f7-824b-ac2e786efe1f`
- `sigma.d7654f02-e04b-4934-9838-65c46f187ebc`
- `sigma.d7662ff6-9e97-4596-a61d-9839e32dee8d`
- `sigma.d78b5d61-187d-44b6-bf02-93486a80de5a`
- `sigma.d797268e-28a9-49a7-b9a8-2f5039011c5c`
- `sigma.d7b50671-d1ad-4871-aa60-5aa5b331fe04`
- `sigma.d7b81144-b866-48a4-9bcc-275dc69d870e`
- `sigma.d7bcd677-645d-4691-a8d4-7a5602b780d1`
- `sigma.d7c75059-2901-4578-b209-8837fd31c6a8`
- `sigma.d7eb979b-c2b5-4a6f-a3a7-c87ce6763819`
- `sigma.d80d5c81-04ba-45b4-84e4-92eba40e0ad3`
- `sigma.d81871ef-5738-47ab-9797-7a9c90cd4bfb`
- `sigma.d85873ef-a0f8-4c48-a53a-6b621f11729d`
- `sigma.d87bd452-6da1-456e-8155-7dc988157b7d`
- `sigma.d88d0ab2-e696-4d40-a2ed-9790064e66b3`
- `sigma.d9047477-0359-48c9-b8c7-792cedcdc9c4`
- `sigma.d9367cbb-c2e0-47ce-bdc0-128cb6da898d`
- `sigma.d937b75f-a665-4480-88a5-2f20e9f9b22a`
- `sigma.d99b79d2-0a6f-4f46-ad8b-260b6e17f982`
- `sigma.da2738f2-fadb-4394-afa7-0a0674885afa`
- `sigma.da92713f-ca2d-4fab-8320-098013d3f43a`
- `sigma.dae8171c-5ec6-4396-b210-8466585b53e9`
- `sigma.dbbd9f66-2ed3-4ca2-98a4-6ea985dd1a1c`
- `sigma.dc5c24af-6995-49b2-86eb-a9ff62199e82`
- `sigma.dcaa3f04-70c3-427a-80b4-b870d73c94c4`
- `sigma.dcdbc940-0bff-46b2-95f3-2d73f848e33b`
- `sigma.dcf2db1f-f091-425b-a821-c05875b8925a`
- `sigma.dcff7e85-d01f-4eb5-badd-84e2e6be8294`
- `sigma.dd2a821e-3b07-4d3b-a9ac-929fe4c6ca0c`
- `sigma.dd3ee8cc-f751-41c9-ba53-5a32ed47e563`
- `sigma.dd6b39d9-d9be-4a3b-8fe0-fe3c6a5c1795`
- `sigma.dd80db93-6ec2-4f4c-a017-ad40da6ffe81`
- `sigma.dd8756e7-a3a0-4768-b47e-8f545d1a751c`
- `sigma.ddd171b5-2cc6-4975-9e78-f0eccd08cc76`
- `sigma.ddeff553-5233-4ae9-bbab-d64d2bd634be`
- `sigma.de16d92c-c446-4d53-8938-10aeef41c8b6`
- `sigma.de46c52b-0bf8-4936-a327-aace94f94ac6`
- `sigma.de587dce-915e-4218-aac4-835ca6af6f70`
- `sigma.de7ce410-b3fb-4e8a-b38c-3b999e2c3420`
- `sigma.deb9b646-a508-44ee-b7c9-d8965921c6b6`
- `sigma.dee0a7a3-f200-4112-a99b-952196d81e42`
- `sigma.dee4af55-1f22-4e1d-a9d2-4bdc7ecb472a`
- `sigma.def8b624-e08f-4ae1-8612-1ba21190da6b`
- `sigma.df1f26d3-bea7-4700-9ea2-ad3e990cf90e`
- `sigma.df4dc653-1029-47ba-8231-3c44238cc0ae`
- `sigma.df55196f-f105-44d3-a675-e9dfb6cc2f2b`
- `sigma.df68f791-ad95-447f-a271-640a0dab9cf8`
- `sigma.df6ecb8b-7822-4f4b-b412-08f524b4576c`
- `sigma.dfa03a09-8b92-4d83-8e74-f72839b1c407`
- `sigma.dfb5b4e8-91d0-4291-b40a-e3b0d3942c45`
- `sigma.dfd2fcb7-8bd5-4daa-b132-5adb61d6ad45`
- `sigma.dff1e1cc-d3fd-47c8-bfc2-aeb878a754c0`
- `sigma.e01fa958-6893-41d4-ae03-182477c5e77d`
- `sigma.e074832a-eada-4fd7-94a1-10642b130e16`
- `sigma.e0813366-0407-449a-9869-a2db1119dc41`
- `sigma.e0b06658-7d1d-4cd3-bf15-03467507ff7c`
- `sigma.e0b0c2ab-3d52-46d9-8cb7-049dc775fbd1`
- `sigma.e0c69ebd-b54f-4aed-8ae3-e3467843f3f0`
- `sigma.e0d1ad53-c7eb-48ec-a87a-72393cc6cedc`
- `sigma.e0f8ab85-0ac9-423b-a73a-81b3c7b1aa97`
- `sigma.e13f668e-7f95-443d-98d2-1816a7648a7b`
- `sigma.e1561947-b4e3-4a74-9bdd-83baed21bdb5`
- `sigma.e15b518d-b4ce-4410-a9cd-501f23ce4a18`
- `sigma.e1693bc8-7168-4eab-8718-cdcaa68a1738`
- `sigma.e173ad47-4388-4012-ae62-bd13f71c18a8`
- `sigma.e1aa95de-610a-427d-b9e7-9b46cfafbe6a`
- `sigma.e1e0b7d7-e10b-4ee4-ac49-a4bda05d320d`
- `sigma.e20b5b14-ce93-4230-88af-981983ef6e74`
- `sigma.e212d415-0e93-435f-9e1a-f29005bb4723`
- `sigma.e218595b-bbe7-4ee5-8a96-f32a24ad3468`
- `sigma.e22a6eb2-f8a5-44b5-8b44-a2dbd47b1144`
- `sigma.e2482f8d-3443-4237-b906-cc145d87a076`
- `sigma.e290b10b-1023-4452-a4a9-eb31a9013b3a`
- `sigma.e2e80da2-8c66-4e00-ae3c-2eebd29f6b6d`
- `sigma.e31033fc-33f0-4020-9a16-faf9b31cbf08`
- `sigma.e312efd0-35a1-407f-8439-b8d434b438a6`
- `sigma.e328cc73-f92a-42fb-b3fa-7c2cffda981a`
- `sigma.e32d4572-9826-4738-b651-95fa63747e8a`
- `sigma.e32f92d1-523e-49c3-9374-bdb13b46a3ba`
- `sigma.e36941d0-c0f0-443f-bc6f-cb2952eb69ea`
- `sigma.e37db05d-d1f9-49c8-b464-cee1a4b11638`
- `sigma.e3845023-ca9a-4024-b2b2-5422156d5527`
- `sigma.e3b50fa5-3c3f-444e-937b-0a99d33731cd`
- `sigma.e3fdf743-f05b-4051-990a-b66919be1743`
- `sigma.e4a6b256-3e47-40fc-89d2-7a477edd6915`
- `sigma.e4a74e34-ecde-4aab-b2fb-9112dd01aed0`
- `sigma.e4d22291-f3d5-4b78-9a0c-a1fbaf32a6a4`
- `sigma.e4ed6030-ffe5-4e6a-8a8a-ab3c1ab9d94e`
- `sigma.e52cb31c-10ed-4aea-bcb7-593c9f4a315b`
- `sigma.e54979bd-c5f9-4d6c-967b-a04b19ac4c74`
- `sigma.e568650b-5dcd-4658-8f34-ded0b1e13992`
- `sigma.e56d3073-83ff-4021-90fe-c658e0709e72`
- `sigma.e5ac86dd-2da1-454b-be74-05d26c769d7d`
- `sigma.e5d36acd-acb4-4c6f-a13f-9eb203d50099`
- `sigma.e61e8a88-59a9-451c-874e-70fcc9740d67`
- `sigma.e6313acd-208c-44fc-a0ff-db85d572e90e`
- `sigma.e6474a1b-5390-49cd-ab41-8d88655f7394`
- `sigma.e66779cc-383e-4224-a3a4-267eeb585c40`
- `sigma.e6c54d94-498c-4562-a37c-b469d8e9a275`
- `sigma.e6e88853-5f20-4c4a-8d26-cd469fd8d31f`
- `sigma.e6fe26ee-d063-4f5b-b007-39e90aaf50e3`
- `sigma.e76ca062-4de0-4d79-8d90-160a0d335eca`
- `sigma.e7888eb1-13b0-4616-bd99-4bc0c2b054b9`
- `sigma.e78c408a-e2ea-43cd-b5ea-51975cf358c0`
- `sigma.e7a21b5f-d8c4-4ae5-b8d9-93c5d3f28e1c`
- `sigma.e7a2fd40-3ae1-4a85-bf80-15cf624fb1b1`
- `sigma.e7b18879-676e-4a0e-ae18-27039185a8e7`
- `sigma.e81528db-fc02-45e8-8e98-4e84aba1f10b`
- `sigma.e83e8899-c9b2-483b-b355-5decc942b959`
- `sigma.e84d89c4-f544-41ca-a6af-4b92fd38b023`
- `sigma.e88a6ddc-74f7-463b-9b26-f69fc0d2ce85`
- `sigma.e890acee-d488-420e-8f20-d9b19b3c3d43`
- `sigma.e8a52bbd-bced-459f-bd93-64db45ce7657`
- `sigma.e8a95b5e-c891-46e2-b33a-93937d3abc31`
- `sigma.e8d34729-86a4-4140-adfd-0a29c2106307`
- `sigma.e9142d84-fbe0-401d-ac50-3e519fb00c89`
- `sigma.e92a4287-e072-4a40-9739-370c106bb750`
- `sigma.e94b9ddc-eec5-4bb8-8a58-b9dc5f4e185f`
- `sigma.e96253b8-6b3b-4f90-9e59-3b24b99cf9b4`
- `sigma.e97d9903-53b2-41fc-8cb9-889ed4093e80`
- `sigma.e9b61244-893f-427c-b287-3e708f321c6b`
- `sigma.e9c8808f-4cfb-4ba9-97d4-e5f3beaa244d`
- `sigma.e9d4ab66-a532-4ef7-a502-66a9e4a34f5d`
- `sigma.e9f55347-2928-4c06-88e5-1a7f8169942e`
- `sigma.e9f8f8cc-07cc-4e81-b724-f387db9175e4`
- `sigma.e9faba72-4974-4ab2-a4c5-46e25ad59e9b`
- `sigma.ea011323-7045-460b-b2d7-0f7442ea6b38`
- `sigma.ea9bf0fa-edec-4fb8-8b78-b119f2528186`
- `sigma.eb1c4225-1c23-4241-8dd4-051389fde4ce`
- `sigma.eb2d07d4-49cb-4523-801a-da002df36602`
- `sigma.ebea773c-a8f1-42ad-a856-00cb221966e8`
- `sigma.ebef4391-1a81-4761-a40a-1db446c0e625`
- `sigma.ebfe73c2-5bc9-4ed9-aaa8-8b54b2b4777d`
- `sigma.ec0722a3-eb5c-4a56-8ab2-bf6f20708592`
- `sigma.ec1d5e28-8f3b-4188-a6f8-6e8df81dc28e`
- `sigma.ec290c06-9b6b-4338-8b6b-095c0f284f10`
- `sigma.ec570e53-4c76-45a9-804d-dc3f355ff7a7`
- `sigma.ec82e2a5-81ea-4211-a1f8-37a0286df2c2`
- `sigma.ec88289a-7e1a-4cc3-8d18-bd1f60e4b9ba`
- `sigma.eca49c87-8a75-4f13-9c73-a5a29e845f03`
- `sigma.eca8ae39-5c3c-4321-b538-9e64fe25822e`
- `sigma.eca91c7c-9214-47b9-b4c5-cb1d7e4f2350`
- `sigma.ecbc5e16-58e0-4521-9c60-eb9a7ea4ad34`
- `sigma.ed5d72a6-f8f4-479d-ba79-02f6a80d7471`
- `sigma.ed74fe75-7594-4b4b-ae38-e38e3fd2eb23`
- `sigma.ed825c86-c009-4014-b413-b76003e33d35`
- `sigma.edc2f8ae-2412-4dfd-b9d5-0c57727e70be`
- `sigma.edd8a48c-1b9f-4ba1-83aa-490338cd1ccb`
- `sigma.edf3485d-dac4-4d50-90e4-b0e5813f7e60`
- `sigma.ee218c12-627a-4d27-9e30-d6fb2fe22ed2`
- `sigma.ee37eb7c-a4e7-4cd5-8fa4-efa27f1c3f31`
- `sigma.ee5e119b-1f75-4b34-add8-3be976961e39`
- `sigma.ee63c85c-6d51-4d12-ad09-04e25877a947`
- `sigma.ee77a5db-b0f3-4be2-bfd4-b58be1c6b15a`
- `sigma.ee9ca27c-9bd7-4cee-9b01-6e906be7cae3`
- `sigma.eeb30123-9fbd-4ee8-aaa0-2e545bbed6dc`
- `sigma.eee00933-a761-4cd0-be70-c42fe91731e7`
- `sigma.ef61af62-bc74-4f58-b49b-626448227652`
- `sigma.ef64fc9c-a45e-43cc-8fd8-7d75d73b4c99`
- `sigma.ef9dcfed-690c-4c5d-a9d1-482cd422225c`
- `sigma.efc21479-9e83-41da-8cf1-122e06ba8db3`
- `sigma.efdd8dd5-cee8-4e59-9390-7d4d5e4dd6f6`
- `sigma.efec536f-72e8-4656-8960-5e85d091345b`
- `sigma.f033f3f3-fd24-4995-97d8-a3bb17550a88`
- `sigma.f0507c0f-a3a2-40f5-acc6-7f543c334993`
- `sigma.f0540f7e-2db3-4432-b9e0-3965486744bc`
- `sigma.f0767f15-0fb3-44b9-851e-e8d9a6d0005d`
- `sigma.f0ca6c24-3225-47d5-b1f5-352bf07ecfa7`
- `sigma.f0cdd048-82dc-4f7a-8a7a-b87a52b6d0fd`
- `sigma.f0d1feba-4344-4ca9-8121-a6c97bd6df52`
- `sigma.f0e2b768-5220-47dd-b891-d57b96fc0ec1`
- `sigma.f0f7be61-9cf5-43be-9836-99d6ef448a18`
- `sigma.f1086bf7-a0c4-4a37-9102-01e573caf4a0`
- `sigma.f10ed525-97fe-4fed-be7c-2feecca941b1`
- `sigma.f117933c-980c-4f78-b384-e3d838111165`
- `sigma.f11f2808-adb4-46c0-802a-8660db50fa99`
- `sigma.f14719ce-d3ab-4e25-9ce6-2899092260b0`
- `sigma.f14e169e-9978-4c69-acb3-1cff8200bc36`
- `sigma.f17211f1-1f24-4d0c-829f-31e28dc93cdd`
- `sigma.f1edd233-30b5-4823-9e6a-c4171b24d316`
- `sigma.f1f3bf22-deb2-418d-8cce-e1a45e46a5bd`
- `sigma.f208d6d8-d83a-4c2c-960d-877c37da84e5`
- `sigma.f241cf1b-3a6b-4e1a-b4f9-133c00dd95ca`
- `sigma.f2485272-a156-4773-82d7-1d178bc4905b`
- `sigma.f24bcaea-0cd1-11eb-adc1-0242ac120002`
- `sigma.f26307d8-14cd-47e3-a26b-4b4769f24af6`
- `sigma.f26c6093-6f14-4b12-800f-0fcb46f5ffd0`
- `sigma.f26eb764-fd89-464b-85e2-dc4a8e6e77b8`
- `sigma.f2c64357-b1d2-41b7-849f-34d2682c0fad`
- `sigma.f331aa1f-8c53-4fc3-b083-cc159bc971cb`
- `sigma.f356a9c4-effd-4608-bbf8-408afd5cd006`
- `sigma.f35c5d71-b489-4e22-a115-f003df287317`
- `sigma.f376c8a7-a2d0-4ddc-aa0c-16c17236d962`
- `sigma.f37aba28-a9e6-4045-882c-d5004043b337`
- `sigma.f37b4bce-49d0-4087-9f5b-58bffda77316`
- `sigma.f38a82d2-fba3-4781-b549-525efbec8506`
- `sigma.f38ce0b9-5e97-4b47-a211-7dc8d8b871da`
- `sigma.f3d39c45-de1a-4486-a687-ab126124f744`
- `sigma.f4264e47-f522-4c38-a420-04525d5b880f`
- `sigma.f426547a-e0f7-441a-b63e-854ac5bdf54d`
- `sigma.f44800ac-38ec-471f-936e-3fa7d9c53100`
- `sigma.f4a623c2-4ef5-4c33-b811-0642f702c9f1`
- `sigma.f4ff7323-b5fc-4323-8b52-6b9408e15788`
- `sigma.f50f3c09-557d-492d-81db-9064a8d4e211`
- `sigma.f512acbf-e662-4903-843e-97ce4652b740`
- `sigma.f5240972-3938-4e56-8e4b-e33893176c1f`
- `sigma.f53714ec-5077-420e-ad20-907ff9bb2958`
- `sigma.f548a603-c9f2-4c89-b511-b089f7e94549`
- `sigma.f576a613-2392-4067-9d1a-9345fb58d8d1`
- `sigma.f57c58b3-ee69-4ef5-9041-455bf39aaa89`
- `sigma.f57f8d16-1f39-4dcb-a604-6c73d9b54b3d`
- `sigma.f598ea0c-c25a-4f72-a219-50c44411c791`
- `sigma.f59c3faf-50f3-464b-9f4c-1b67ab512d99`
- `sigma.f5d19838-41b5-476c-98d8-ba8af4929ee2`
- `sigma.f5e3b62f-e577-4e59-931e-0a15b2b94e1e`
- `sigma.f5fe36cf-f1ec-4c23-903d-09a3110f6bbb`
- `sigma.f63508a0-c809-4435-b3be-ed819394d612`
- `sigma.f63b56ee-3f79-4b8a-97fb-5c48007e8573`
- `sigma.f64e5c19-879c-4bae-b471-6d84c8339677`
- `sigma.f663a6d9-9d1b-49b8-b2b1-0637914d199a`
- `sigma.f674e36a-4b91-431e-8aef-f8a96c2aca35`
- `sigma.f69a87ea-955e-4fb4-adb2-bb9fd6685632`
- `sigma.f6c68d5f-e101-4b86-8c84-7d96851fd65c`
- `sigma.f6d1dd2f-b8ce-40ca-bc23-062efb686b34`
- `sigma.f6de9536-0441-4b3f-a646-f4e00f300ffd`
- `sigma.f6ecd1cf-19b8-4488-97f6-00f0924991a3`
- `sigma.f72aa3e8-49f9-4c7d-bd74-f8ab84ff9bbb`
- `sigma.f7375e28-5c14-432f-b8d1-1db26c832df3`
- `sigma.f7385ee2-0e0c-11eb-adc1-0242ac120002`
- `sigma.f742bde7-9528-42e5-bd82-84f51a8387d2`
- `sigma.f7644214-0eb0-4ace-9455-331ec4c09253`
- `sigma.f7997770-92c3-4ec9-b112-774c4ef96f96`
- `sigma.f7b5f842-a6af-4da5-9e95-e32478f3cd2f`
- `sigma.f7d7ebd5-a016-46e2-9c54-f9932f2d386d`
- `sigma.f7f9ab88-7557-4a69-b30e-0a8f91b3a0e7`
- `sigma.f8748f2c-89dc-4d95-afb0-5a2dfdbad332`
- `sigma.f89b08d0-77ad-4728-817b-9b16c5a69c7a`
- `sigma.f8ad2e2c-40b6-4117-84d7-20b89896ab23`
- `sigma.f8aebc67-a56d-4ec9-9fbe-7b0e8b7b4efd`
- `sigma.f8c1e80b-c73a-476a-ae24-6c72528b1521`
- `sigma.f8d6a15e-4bc8-4c27-8e5d-2b10f0b73e5b`
- `sigma.f91ed517-a6ba-471d-9910-b3b4a398c0f3`
- `sigma.f92a6f1e-a512-4a15-9735-da09e78d7273`
- `sigma.f956c7c1-0f60-4bc5-b7d7-b39ab3c08908`
- `sigma.f9578658-9e71-4711-b634-3f9b50cd3c06`
- `sigma.f9999590-1f94-4a34-a91e-951e47bedefd`
- `sigma.f99abdf0-6283-4e71-bd2b-b5c048a94743`
- `sigma.f9f62824-de4e-40ca-afe7-8358f76a876d`
- `sigma.fa00b701-44c6-4679-994d-5a18afa8a707`
- `sigma.fa277e82-9b78-42dd-b05c-05555c7b6015`
- `sigma.fa3c117a-bc0d-416e-a31b-0c0e80653efb`
- `sigma.fa5b1358-b040-4403-9868-15f7d9ab6329`
- `sigma.faa031b5-21ed-4e02-8881-2591f98d82ed`
- `sigma.faa48cae-6b25-4f00-a094-08947fef582f`
- `sigma.fabb0e80-030c-4e3e-a104-d09676991ac3`
- `sigma.fabfb3a7-3ce1-4445-9c7c-3c27f1051cdd`
- `sigma.fad91067-08c5-4d1a-8d8c-d96a21b37814`
- `sigma.fadb84f0-4e84-4f6d-a1ce-9ef2bffb6ccd`
- `sigma.fb50eb7a-5ab1-43ae-bcc9-091818cb8424`
- `sigma.fb843269-508c-4b76-8b8d-88679db22ce7`
- `sigma.fb9d3ff7-7348-46ab-af8c-b55f5fbf39b4`
- `sigma.fbd7c32d-db2a-4418-b92c-566eb8911133`
- `sigma.fc014922-5def-4da9-a0fc-28c973f41bfb`
- `sigma.fc0e89b5-adb0-43c1-b749-c12a10ec37de`
- `sigma.fc4f4817-0c53-4683-a4ee-b17a64bc1039`
- `sigma.fca949cc-79ca-446e-8064-01aa7e52ece5`
- `sigma.fcc6d700-68d9-4241-9a1a-06874d621b06`
- `sigma.fccfb43e-09a7-4bd2-8b37-a5a7df33386d`
- `sigma.fcddca7c-b9c0-4ddf-98da-e1e2d18b0157`
- `sigma.fcdf69e5-a3d3-452a-9724-26f2308bf2b1`
- `sigma.fd0f5778-d3cb-4c9a-9695-66759d04702a`
- `sigma.fd877b94-9bb5-4191-bb25-d79cbd93c167`
- `sigma.fdbf0b9d-0182-4c43-893b-a1eaab92d085`
- `sigma.fdeebdf0-9f3f-4d08-84a6-4c4d13e39fe4`
- `sigma.fdfcbd78-48f1-4a4b-90ac-d82241e368c5`
- `sigma.fe20dda1-6f37-4379-bbe0-a98d400cae90`
- `sigma.fec96f39-988b-4586-b746-b93d59fd1922`
- `sigma.fecfd1a1-cc78-4313-a1ea-2ee2e8ec27a7`
- `sigma.fed85bf9-e075-4280-9159-fbe8a023d6fa`
- `sigma.ff151c33-45fa-475d-af4f-c2f93571f4fe`
- `sigma.ff23ffbc-3378-435e-992f-0624dcf93ab4`
- `sigma.ff2fff64-4cd6-4a2b-ba7d-e28a30bbe66b`
- `sigma.ff3b6b39-e765-42f9-bb2c-ea6761e0e0f6`
- `sigma.ff992eac-6449-4c60-8c1d-91c9722a1d48`
- `sigma.ffa28e60-bdb1-46e0-9f82-05f7a61cc06e`
- `sigma.ffa6861c-4461-4f59-8a41-578c39f3f23e`

## 重复检出明细

- sigma.863218bd-c7d0-4c52-80cd-0a96c09f54af 重复命中 scenario-sysmon-intrusion-chain
- sigma.9fbf5927-5261-4284-a71d-f681029ea574 重复命中 scenario-sysmon-intrusion-chain
- sigma.c09dad97-1c78-4f71-b127-7edb2b8e491a 重复命中 scenario-sysmon-intrusion-chain
- sigma.863218bd-c7d0-4c52-80cd-0a96c09f54af 重复命中 sysmon-lolbin-payload-download
- sigma.c09dad97-1c78-4f71-b127-7edb2b8e491a 重复命中 sysmon-execution-from-inetcache
- sigma.9fbf5927-5261-4284-a71d-f681029ea574 重复命中 sysmon-password-protected-archive
- sigma.438025f9-5856-4663-83f7-52f878a70a50 重复命中 sysmon-encoded-command-execution
- sigma.ca2092a1-c273-4878-9b4b-0d60115bf5ea 重复命中 sysmon-encoded-command-execution
- sigma.b9d9cc83-380b-4ba3-8d8f-60c0e7e2930c 重复命中 sysmon-encoded-command-execution
- sigma.fb843269-508c-4b76-8b8d-88679db22ce7 重复命中 sysmon-encoded-command-execution
- sigma.438025f9-5856-4663-83f7-52f878a70a50 重复命中 sysmon-document-spawns-command-shell
- sigma.24c8392b-aa3c-46b7-a545-43f71657fe98 重复命中 sysmon-scheduled-task-persistence
- sigma.92626ddd-662c-49e3-ac59-f6535f12d189 重复命中 sysmon-scheduled-task-persistence
- sigma.c947b146-0abc-4c87-9c64-b17e9d7274a2 重复命中 sysmon-inhibit-recovery-vssadmin
- sigma.ce72ef99-22f1-43d4-8695-419dcb5d9330 重复命中 sysmon-security-service-stop
- sigma.4b046706-5789-4673-b111-66f25fe99534 重复命中 sysmon-data-destruction-cipher-w
- sigma.ffa6861c-4461-4f59-8a41-578c39f3f23e 重复命中 sysmon-lsass-memory-dump
- sigma.2e65275c-8288-4ab4-aeb7-6274f58b6b20 重复命中 sysmon-lsass-memory-dump
- sigma.7cce6fc8-a07f-4d84-a53e-96e1879843c9 重复命中 sysmon-lsass-memory-dump
- sigma.fd877b94-9bb5-4191-bb25-d79cbd93c167 重复命中 sysmon-sam-hive-export
- sigma.cc36992a-4671-4f21-a91d-6c2b72a2edf5 重复命中 sysmon-eventlog-cleared
- sigma.17769c90-230e-488b-a463-e05c08e9d48f 重复命中 sysmon-defender-exclusion-added
- sigma.cd219ff3-fa99-45d4-8380-a7d15116c6dc 重复命中 sysmon-create-local-account
- sigma.ad720b90-25ad-43ff-9b5e-5c841facc8e5 重复命中 sysmon-account-added-to-admins
- sigma.b28e58e4-2a72-4fae-bdee-0fbe904db642 重复命中 windows-event-kv-credential-attack-scenario

## 逐规则结果

| 规则 | 正样本 | TP | FP | FN | 结论 |
| --- | ---: | ---: | ---: | ---: | --- |
| `app.auth_threshold_block` | 1 | 1 | 0 | 0 | 通过 |
| `app.restricted_resource_access` | 1 | 1 | 0 | 0 | 通过 |
| `app.sensitive_path_probe` | 1 | 1 | 0 | 0 | 通过 |
| `auth.bruteforce` | 1 | 1 | 0 | 0 | 通过 |
| `auth.bruteforce.success` | 1 | 1 | 0 | 0 | 通过 |
| `auth.password_spray` | 1 | 1 | 0 | 0 | 通过 |
| `db.bruteforce` | 5 | 5 | 0 | 0 | 通过 |
| `db.bruteforce.success` | 1 | 1 | 0 | 0 | 通过 |
| `db.data_exfiltration` | 1 | 1 | 0 | 0 | 通过 |
| `db.destructive_query` | 2 | 2 | 0 | 0 | 通过 |
| `db.privilege_escalation` | 1 | 1 | 0 | 0 | 通过 |
| `db.privileged_login` | 1 | 1 | 0 | 0 | 通过 |
| `db.sql_injection` | 1 | 1 | 0 | 0 | 通过 |
| `firewall.port_scan` | 1 | 1 | 0 | 0 | 通过 |
| `rdp.bruteforce` | 1 | 1 | 0 | 0 | 通过 |
| `rdp.bruteforce.success` | 2 | 2 | 0 | 0 | 通过 |
| `sigma.002bdb95-0cf1-46a6-9e08-d38c128a6127` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.00321fee-ca72-4cce-b011-5415af3b9960` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0058b9e5-bcd7-40d4-9205-95ca5a16d7b2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.00ba9da1-b510-4f6b-b258-8d338836180f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.00d49ed5-4491-4271-a8db-650a4ef6f8c1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0152550d-3a26-4efd-9f0e-54a0b28ae2f3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.01aeb693-138d-49d2-9403-c4f52d7d3d62` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.01c42d3c-242d-4655-85b2-34f1739632f7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.01d2e2a1-5f09-44f7-9fc1-24faa7479b6d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.02030f2f-6199-49ec-b258-ea71b07e03dc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.022eaba8-f0bf-4dd9-9217-4604b0bb3bb0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.023394c4-29d5-46ab-92b8-6a534c6f447b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.023c654f-8f16-44d9-bb2b-00ff36a62af9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0248a7bc-8a9a-4cd8-a57e-3ae8e073a073` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0255a820-e564-4e40-af2b-6ac61160335c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.02773bed-83bf-469f-b7ff-e676e7d78bab` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.028c7842-4243-41cd-be6f-12f3cf1a26c7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.02b18447-ea83-4b1b-8805-714a8a34546a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.02b64f1b-3f33-4e67-aede-ef3b0a5a8fcf` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.02c39d30-02b5-45d2-b435-8aebfe5a8629` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.02ee49e2-e294-4d0f-9278-f5b3212fc588` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.02f7c9c1-1ae8-4c6a-8add-04693807f92f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.03552375-cc2c-4883-bbe4-7958d5a980be` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0372e1f9-0fd2-40f7-be1b-a7b2b848fa7b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.037dcd71-33a8-4392-bb01-293c94663e5a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.03cc0c25-389f-4bf8-b48d-11878079f1ca` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.03f4ca17-de95-428d-a75a-4ee78b047256` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0403d67d-6227-4ea8-8145-4e72db7da120` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.043c4b8b-3a54-4780-9682-081cb6b8185c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0442defa-b4a2-41c9-ae2c-ea7042fc4701` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.044ba588-dff4-4918-9808-3f95e8160606` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.046218bd-e0d8-4113-a3c3-895a12b2b298` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.04b45a8a-d11d-49e4-9acc-4a1b524407a5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.055fb54c-a8f4-4aee-bd44-f74cf30a0d9d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.056c7317-9a09-4bd4-9067-d051312752ea` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.058f4380-962d-40a5-afce-50207d36d7e2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.059c5af9-5131-4d8d-92b2-de4ad6146712` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.05a2ab7e-ce11-4b63-86db-ab32e763e11d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.05b2aa93-1210-42c8-8d9a-2fcc13b284f5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.05ebafc8-7aa2-4bcd-a269-2aec93f9e842` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.05f3c945-dcc8-4393-9f3d-af65077a8f86` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0649be4a-aeb0-45b0-b89e-7f1668f6d9c0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.065b00ca-5d5c-4557-ac95-64a6d0b64d86` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.065cceea-77ec-4030-9052-fc0affea7110` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0685b176-c816-4837-8e7b-1216f346636b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.074e0ded-6ced-4ebd-8b4d-53f55908119d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.076ebe48-cc05-4d8f-9d41-89245cd93a14` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.07743f65-7ec9-404a-a519-913db7118a8d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.07837ab9-60e1-481f-a74d-c31fb496a94c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.07a99744-56ac-40d2-97b7-2095967b0e03` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.07aa184a-870d-413d-893a-157f317f6f58` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.07e3cb2c-0608-410d-be4b-1511cb1a0448` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.08200f85-2678-463e-9c32-88dce2f073d1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.086ae989-9ca6-4fe7-895a-759c5544f247` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.087790e3-3287-436c-bccf-cbd0184a7db1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.089fc3d2-71e8-4763-a8a5-c97fbb0a403e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0900463c-b33b-49a8-be1d-552a3b553dae` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.092af964-4233-4373-b4ba-d86ea2890288` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0944e002-e3f6-4eb5-bf69-3a3067b53d73` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0955e4e1-c281-4fb9-9ee1-5ee7b4b754d2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.09576804-7a05-458e-a817-eb718ca91f54` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.098d7118-55bc-4912-a836-dc6483a8d150` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0a1255c5-d732-4b62-ac02-b5152d34fb83` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0a13e132-651d-11eb-ae93-0242ac130002` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0a4f6091-223b-41f6-8743-f322ec84930b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0a98a10c-685d-4ab0-bddc-b6bdd1d48458` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0a99eb3e-1617-41bd-b095-13dc767f3def` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0afbd410-de03-4078-8491-f132303cb67d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0afecb6e-6223-4a82-99fb-bf5b981e92a5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0b0cd537-fc77-4e6e-a973-e53495c1083d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0b4ae027-2a2d-4b93-8c7e-962caaba5b2a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0b7163dc-7eee-4960-af17-c0cd517f92da` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0b8baa3f-575c-46ee-8715-d6f28cc7d33c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0b9ad457-2554-44c1-82c2-d56a99c42377` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0ba1da6d-b6ce-4366-828c-18826c9de23e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0ba863e6-def5-4e50-9cea-4dd8c7dc46a4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0badd08f-c6a3-4630-90d3-6875cca440be` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0bbc6369-43e3-453d-9944-cae58821c173` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0bcfabcb-7929-47f4-93d6-b33fb67d34d1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0c3ebe9f-df09-4e00-be0f-73d4ca8d62f6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0c3fac91-5627-46e8-a6a8-a0d7b9b8ae1b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0c718a5e-4284-4fb9-b4d9-b9a50b3a1974` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0c92f2e6-f08f-4b73-9216-ecb0ca634689` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0c93308a-3f1b-40a9-b649-57ea1a1c1d63` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0cb8d736-995d-4ce7-a31e-1e8d452a1459` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0cf2e1c6-8d10-4273-8059-738778f981ad` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0d34ed8b-1c12-4ff2-828c-16fc860b766d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0d5675be-bc88-4172-86d3-1e96a4476536` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0d7ceeef-3539-4392-8953-3dc664912714` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0dba975d-a193-4ed1-a067-424df57570d1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0e0255bf-2548-47b8-9582-c0955c9283f5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0e20c89d-2264-44ae-8238-aeeaba609ece` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0e29e3a7-1ad8-40aa-b691-9f82ecd33d66` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0e4164da-94bc-450d-a7be-a4b176179f1f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0e6a9e62-627e-496c-aef5-bfa39da29b5e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0e8cfe08-02c9-4815-a2f8-0d157b7ed33e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0ea52357-cd59-4340-9981-c46c7e900428` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0ea8db81-2ff6-4525-9448-33bbe7effc13` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0eb46774-f1ab-4a74-8238-1155855f2263` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0ed99dda-6a35-11ef-8c99-0242ac120002` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0ee4d8a5-4e67-4faf-acfa-62a78457d1f2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0ef56343-059e-4cb6-adc1-4c3c967c5e46` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0f0450f3-8b47-441e-a31b-15a91dc243e2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0f16d9cf-0616-45c8-8fad-becc11b5a41c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0f60b28c-64dd-4e2c-9a63-5334d3e3a6e6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0f63e1ef-1eb9-4226-9d54-8927ca08520a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0f6da907-5854-4be6-859a-e9958747b0aa` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0f9c21f1-6a73-4b0e-9809-cb562cb8d981` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.0fc35fc3-efe6-4898-8a37-0b233339524f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.100ef69e-3327-481c-8e5c-6d80d9507556` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1012f107-b8f1-4271-af30-5aed2de89b39` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1027d292-dd87-4a1a-8701-2abe04d7783c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.10344bb3-7f65-46c2-b915-2d00d47be5b0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.104cdb48-a7a8-4ca7-a453-32942c6e5dcb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1070db9a-3e5d-412e-8e7b-7183b616e1b3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.10c14723-61c7-4c75-92ca-9af245723ad2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.10fb649c-3600-4d37-b1e6-56ea90bb7e09` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1114e048-b69c-4f41-bc20-657245ae6e3f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.114de787-4eb2-48cc-abdb-c0b449f93ea4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.114e7f1c-f137-48c8-8f54-3088c24ce4b9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.117d3d3a-755c-4a61-b23e-9171146d094c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1193d960-2369-499f-a158-7b50a31df682` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.11b1ed55-154d-4e82-8ad7-83739298f720` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.11b52f18-aaec-4d60-9143-5dd8cc4706b9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.11d00fff-5dc3-428c-8184-801f292faec0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.123e4e6d-b123-48f8-b261-7214938acaf0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1277f594-a7d1-4f28-a2d3-73af5cbeab43` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.12827a56-61a4-476a-a9cb-f3068f191073` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.129966c9-de17-4334-a123-8b58172e664d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.12b8e9f5-96b2-41e1-9a42-8c6779a5c184` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.12ba6a38-adb3-4d6b-91ba-a7fb248e3199` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.12e6d621-194f-4f59-90cc-1959e21e69f7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.12f6b752-042d-483e-bf9c-915a6d06ad75` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.12fbff88-16b5-4b42-9754-cd001a789fb3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.130c9e58-28ac-4f83-8574-0a4cc913b97e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1321dc4e-a1fe-481d-a016-52c45f0c8b4f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1327381e-6ab0-4f38-b583-4c1b8346a56b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.138d3531-8793-4f50-a2cd-f291b2863d78` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.13acf386-b8c6-4fe0-9a6e-c4756b974698` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.13addce7-47b2-4ca0-a98f-1de964d1d669` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.13c02350-4177-4e45-ac17-cf7ca628ff5e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.13cfeb75-9e33-4d04-b0f7-ab8faaa95a59` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.13e6fe51-d478-4c7e-b0f2-6da9b400a829` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.13fc89a9-971e-4ca6-b9dc-aa53a445bf40` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1412aa78-a24c-4abd-83df-767dfb2c5bbe` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1444443e-6757-43e4-9ea4-c8fc705f79a2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.145095eb-e273-443b-83d0-f9b519b7867b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.145322e4-0fd3-486b-81ca-9addc75736d8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.146aace8-9bd6-42ba-be7a-0070d8027b76` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.148431ce-4b70-403d-8525-fcc2993f29ea` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.14bcba49-a428-42d9-b943-e2ce0f0f7ae6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.152f3630-77c1-4284-bcc0-4cc68ab2f6e7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.15434e33-5027-4914-88d5-3d4145ec25a9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1547e27c-3974-43e2-a7d7-7f484fb928ec` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.155dbf56-e0a4-4dd0-8905-8a98705045e8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.15619216-e993-4721-b590-4c520615a67d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.15904280-565c-4b73-9303-3291f964e7f9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.15b75071-74cc-47e0-b4c6-b43744a62a2b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.15bd98ea-55f4-4d37-b09a-e7caa0fa2221` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.15c7904e-6ad1-4a45-9b46-5fb25df37fd2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.160d2780-31f7-4922-8b3a-efce30e63e96` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.162ab1e4-6874-4564-853c-53ec3ab8be01` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.164eda96-11b2-430b-85ff-6a265c15bf32` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.16905e21-66ee-42fe-b256-1318ada2d770` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.16c37b52-b141-42a5-a3ea-bbe098444397` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.16f5d8ca-44bd-47c8-acbe-6fc95a16c12f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.16fe46bb-4f64-46aa-817d-ff7bec4a2352` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1723e720-616d-4ddc-ab02-f7e3685a4713` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.175997c5-803c-4b08-8bb0-70b099f47595` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1775e15e-b61b-4d14-a1a3-80981298085a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.17769c90-230e-488b-a463-e05c08e9d48f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.178e615d-e666-498b-9630-9ed363038101` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.17a1be64-8d88-40bf-b5ff-a4f7a50ebcc8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.17d619c1-e020-4347-957e-1d1207455c93` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.17e53739-a1fc-4a62-b1b9-87711c2d5e44` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.17f0c0a8-8bd5-4ee0-8c5f-a342c0199f35` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.180c7c5c-d64b-4a63-86e9-68910451bc8b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1816994b-42e1-4fb1-afd2-134d88184f71` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.18249279-932f-45e2-b37a-8925f2597670` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.185d7418-f250-42d0-b72e-0c8b70661e93` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.18749301-f1c5-4efc-a4c3-276ff1f5b6f8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.18988e1b-9087-4f8a-82fe-0414dce49878` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.18beca67-ab3e-4ee3-ba7a-a46ca8d7d0cc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.18ee686c-38a3-4f65-9f44-48a077141f42` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.18f2065c-d36c-464a-a748-bcf909acb2e3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.18f37338-b9bd-4117-a039-280c81f7a596` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1908fcc1-1b92-4272-8214-0fbaf2fa5163` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.192a0330-c20b-4356-90b6-7b7049ae0b87` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.193d5ccd-6f59-40c6-b5b0-8e32d5ddd3d1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.198effb6-6c98-4d0c-9ea3-451fa143c45c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.19aa4f58-94ca-45ff-bc34-92e533c0994a` | 1 | 1 | 0 | 0 | 通过 |
| `sigma.19b08b1c-861d-4e75-a1ef-ea0c1baf202b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1a0a2ff1-611b-4dac-8216-8a7b47c618a6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1a0d4aba-7668-4365-9ce4-6d79ab088dfd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1a1ed54a-2ba4-4221-94d5-01dee560d71e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1a2d6c47-75b0-45bd-b133-2c0be75349fd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1a31b18a-f00c-4061-9900-f735b96c99fc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1a4bd6af-99ac-4466-b5b2-7b72b4a05462` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1a5c46e9-f32f-42f7-b2bc-6e9084db7fbf` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1a5fefe6-734f-452e-a07d-fc1c35bce4b2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1ac8666b-046f-4201-8aba-1951aaec03a3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1af57a4b-460a-4738-9034-db68b880c665` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1b2ae822-6fe1-43ba-aa7c-d1a3b3d1d5f2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1b3b01c7-84e9-4072-86e5-fc285a41ff23` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1bbf25b9-8038-4154-a50b-118f2a32be27` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1c0e41cd-21bb-4433-9acc-4a2cd6367b9b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1c12727d-02bf-45ff-a9f3-d49806a3cf43` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1c3121ed-041b-4d97-a075-07f54f20fb4a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1c480e10-7ee1-46d4-8ed2-85f9789e3ce4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1c526788-0abe-4713-862f-b520da5e5316` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1c67a717-32ba-409b-a45d-0fb704a73a81` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1c8774a0-44d4-4db0-91f8-e792359c70bd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1c8e96cd-2bed-487d-9de0-b46c90cade56` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1ca6bd18-0ba0-44ca-851c-92ed89a61085` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1cb0c6ce-3d00-44fc-ab9c-6d6d577bf20b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1cbbeaaf-3c8c-4e4c-9d72-49485b6a176b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1cc50f3f-1fc8-4acf-b2e9-6f172e1fdebd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1cdd9a09-06c9-4769-99ff-626e2b3991b8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1ce8c8a3-2723-48ed-8246-906ac91061a6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1cf465a1-2609-4c15-9b66-c32dbe4bfd67` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1d08ac94-400d-4469-a82f-daee9a908849` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1d2ab8ac-1a01-423b-9c39-001510eae8e8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1d2de8a6-4803-4fde-b85b-f58f3aa7a705` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1d61f71d-59d2-479e-9562-4ff5f4ead16b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1dd05363-104e-4b4a-b963-196a534b03a1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1de68c67-af5c-4097-9c85-fe5578e09e67` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1e0e1a81-e79b-44bc-935b-ddb9c8006b3d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1e53dd56-8d83-4eb4-a43e-b790a05510aa` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1e59c230-6670-45bf-83b0-98903780607e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1e75c1cc-c5d4-42aa-ac3d-91b0b68b3b4c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1e8a9b4d-3c2a-4f9b-8d1e-7c6a5b4f3d2e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1edff897-9146-48d2-9066-52e8d8f80a2f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1eeed653-dbc8-4187-ad0c-eeebb20e6599` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1f0489be-b496-4ddf-b3a9-5900f2044e9c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1f0b4cac-9c81-41f4-95d0-8475ff46b3e2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1f0f6176-6482-4027-b151-00071af39d7e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1f1a8509-2cbb-44f5-8751-8e1571518ce2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1f1d8209-636e-4c6c-a137-781cca8b82f9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.1fb76ab8-fa60-4b01-bddd-71e89bf555da` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.20384606-a124-4fec-acbb-8bd373728613` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.204b17ae-4007-471b-917b-b917b315c5db` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2074e137-1b73-4e2d-88ba-5a3407dbdce0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.208748f7-881d-47ac-a29c-07ea84bf691d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.20a5ffa1-3848-4584-b6f8-c7c7fd9f69c8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.20d96d95-5a20-4cf1-a483-f3bda8a7c037` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2111118f-7e46-4fc8-974a-59fd8ec95196` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.213d6a77-3d55-4ce8-ba74-fcfef741974e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.214641c2-c579-4ecb-8427-0cf19df6842e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2158f96f-43c2-43cb-952a-ab4580f32382` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.218d2855-2bba-4f61-9c85-81d0ea63ac71` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.21d856f9-9281-4ded-9377-51a1a6e2a432` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.21ff4ca9-f13a-41ad-b828-0077b2af2e40` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.220457c1-1c9f-4c2e-afe6-9598926222c1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.22154f0e-5132-4a54-aa78-cc62f6def531` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.222129f7-f4dc-4568-b0d2-22440a9639ba` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.222720a7-047f-4054-baa5-bab9be757db0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.224f140f-3553-4cd1-af78-13d81bf9f7cc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.225274c4-8dd1-40db-9e09-71dff4f6fb3c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2267fe65-0681-42ad-9a6d-46553d3f3480` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.22e58743-4ac8-4a9f-bf19-00a0428d8c5f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.236d8e89-ed95-4789-a982-36f4643738ba` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.23ceaf5c-b6f1-4a32-8559-f2ff734be516` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.241e802a-b65e-484f-88cd-c2dc10f9206d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.243380fa-11eb-4141-af92-e14925e77c1b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2433a154-bb3d-42e4-86c3-a26bdac91c45` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.24357373-078f-44ed-9ac4-6d334a668a11` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.24549159-ac1b-479c-8175-d42aea947cae` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.24c77512-782b-448a-8950-eddb0785fc71` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.24c8392b-aa3c-46b7-a545-43f71657fe98` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.24de4f3b-804c-4165-b442-5a06a2302c7e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.24e3e58a-646b-4b50-adef-02ef935b9fc8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.25676e10-2121-446e-80a4-71ff8506af47` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2569ed8c-1147-498a-9b8c-2ad3656b10ed` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.259e5a6a-b8d2-4c38-86e2-26c5e651361d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.25b9c01c-350d-4b95-bed1-836d04a4f324` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.25cde13e-8e20-4c29-b949-4e795b76f16f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.25eabf56-22f0-4915-a1ed-056b8dae0a68` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.25ffa65d-76d8-4da5-a832-3f2b0136e133` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2632954e-db1c-49cb-9936-67d1ef1d17d2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.26481afe-db26-4228-b264-25a29fe6efc7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.26488ad0-f9fd-4536-876f-52fea846a2e4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.264982dc-dbad-4dce-b707-1e0d3e0f73d9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.26d3f0a2-f514-4a3f-a8a7-e7e48a8d9160` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2704ab9e-afe2-4854-a3b1-0c0706d03578` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.275641a5-a492-45e2-a817-7c81e9d9d3e9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.277a4393-446c-449a-b0ed-7fdc7795244c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.277efb8f-60be-4f10-b4d3-037802f37167` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2782fbd8-b662-4eb5-9962-5bfbfb671e7b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.27aec9c9-dbb0-4939-8422-1742242471d0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.27ba3207-dd30-4812-abbf-5d20c57d474e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.27ee9438-90dc-4bef-904b-d3ef927f5e7e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.28036918-04d3-423d-91c0-55ecf99fb892` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.28208707-fe31-437f-9a7f-4b1108b94d2e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.285b85b1-a555-4095-8652-a8a4106af63f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.28a452f3-786c-4fd8-b8f2-bddbe9d616d1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.28ac00d6-22d9-4a3c-927f-bbd770104573` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.28c8f68b-098d-45af-8d43-8089f3e35403` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.295a59c1-7b79-4b47-a930-df12c15fc9c2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2a072a96-a086-49fa-bcb5-15cc5a619093` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2a4b3e61-9d22-4e4a-b60f-6e8f0cde6f25` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2a926e6a-4b81-4011-8a96-e36cc8c04302` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2aa0a6b4-a865-495b-ab51-c28249537b75` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2afafd61-6aae-4df4-baed-139fa1f4c345` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2afe6582-e149-11ea-87d0-0242ac130003` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2c1486f5-02e8-4f86-9099-b97f2da4ed77` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2c28c248-7f50-417a-9186-a85b223010ee` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2c32b543-1058-4808-91c6-5b31b8bed6c5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2c99737c-585d-4431-b61a-c911d86ff32f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2cf29f11-e356-4f61-98c0-1bdb9393d6da` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2d22a514-e024-4428-9dba-41505bd63a5b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2d367498-5112-4ae5-a06a-96e7bc33a211` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2d3cdeec-c0db-45b4-aa86-082f7eb75701` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2d510d8d-912b-45c5-b1df-36faa3d8c3f4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2daa93a0-a5fb-41c5-8cd8-3c11294bfd1f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2db93a3f-3249-4f73-9e68-0e77a0f8ae7e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2dbd9d3d-9e27-42a8-b8df-f13825c6c3d5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2dd2c217-bf68-437a-b57c-fe9fd01d5de8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2ddef153-167b-4e89-86b6-757a9e65dcac` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2e65275c-8288-4ab4-aeb7-6274f58b6b20` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2f400434-01e1-416b-b52c-bb5bfbb9eb78` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2f78da12-f7c7-430b-8b19-a28f269b77a3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2f7979ae-f82b-45af-ac1d-2b10e93b0baa` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2f869d59-7f6a-4931-992c-cce556ff2d53` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2f9356ae-bf43-41b8-b858-4496d83b2acb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2fbbe9ff-0afc-470b-bdc0-592198339968` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2fdaf50b-9fd5-449f-ba69-f17248119af6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2fdefcb3-dbda-401e-ae23-f0db027628bc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.2ff692c2-4594-41ec-8fcb-46587de769e0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.300bac00-e041-4ee2-9c36-e262656a6ecc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3037d961-21e9-4732-b27a-637bcc7bf539` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.304afd73-55a5-4bb9-8c21-0b1fc84ea9e4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.30bf1789-379d-4fdc-900f-55cd0a90a801` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.30d07da2-83ab-45d8-ae75-ec7c0edcaffc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.30e92f50-bb5a-4884-98b5-d20aa80f3d7a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.30edb182-aa75-42c0-b0a9-e998bb29067c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.30fc8de7-d833-40c4-96b6-28319fbc4f6c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.311b6ce2-7890-4383-a8c2-663a9f6b43cd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.312d0384-401c-4b8b-abdf-685ffba9a332` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.313d6012-51a0-4d93-8dfc-de8553239e25` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.318557a5-150c-4c8d-b70e-a9910e199857` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.31c51af6-e7aa-4da7-84d4-8f32cc580af2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.31e124fb-5dc4-42a0-83b3-44a69c77b271` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3215aa19-f060-4332-86d5-5602511f3ca8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.322ed9ec-fcab-4f67-9a34-e7c6aef43614` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.32410e29-5f94-4568-b6a3-d91a8adad863` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3268b746-88d8-4cd3-bffc-30077d02c787` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.327ff235-94eb-4f06-b9de-aaee571324be` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.32b96012-7892-429e-b26c-ac2bf46066ff` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.32e19d25-4aed-4860-a55a-be99cb0bf7ed` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.32e280f1-8ad4-46ef-9e80-910657611fbc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.33339be3-148b-4e16-af56-ad16ec6c7e7b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3371f518-5fe3-4cf6-a14b-2a0ae3fd8a4f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3390fbef-c98d-4bdd-a863-d65ed7c610dd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.33be4333-2c6b-44f4-ae28-102cdbde0a31` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.33efc23c-6ea2-4503-8cfe-bdf82ce8f705` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.33efc23c-6ea2-4503-8cfe-bdf82ce8f719` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.33f41cdd-35ac-4ba8-814b-c6a4244a1ad4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.340a090b-c4e9-412e-bb36-b4b16fe96f9b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.34746e8c-5fb8-415a-b135-0abc167e912a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.347906f3-e207-4d18-ae5b-a9403d6bcdef` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.34986307-b7f4-49be-92f3-e7a4d01ac5db` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.34aa0252-6039-40ff-951f-939fd6ce47d8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.34ebb878-1b15-4895-b352-ca2eeb99b274` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.350dfb37-3706-4cdc-9e2e-5e24bc3a46df` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.35ba1d85-724d-42a3-889f-2e2362bcaf23` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.35bc7e28-ee6b-492f-ab04-da58fcf6402e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.360a1340-398a-46b6-8d06-99b905dc69d2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.36210e0d-5b19-485d-a087-c096088885f0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.36475a7d-0f6d-4dce-9b01-6aeb473bbaf1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.36480ae1-a1cb-4eaa-a0d6-29801d7e9142` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.36803969-5421-41ec-b92f-8500f79c23b0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.36d88494-1d43-4dc0-b3fa-35c8fea0ca9d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.36e037c4-c228-4866-b6a3-48eb292b9955` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.37651c2a-42cd-4a69-ae0d-22a4349aa04a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.378a05d8-963c-46c9-bcce-13c7657eac99` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.37b437cf-3fc5-4c8e-9c94-1d7c9aff842b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.37c1333a-a0db-48be-b64b-7393b2386e3b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.37db85d1-b089-490a-a59a-c7b6f984f480` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.37e8d358-6408-4853-82f4-98333fca7014` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.38646daa-e78f-4ace-9de0-55547b2d30da` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.38879043-7e1e-47a9-8d46-6bec88e201df` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.38a1ac5f-9c74-47d2-a345-dd6f5eb4e7c8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.39019a4e-317f-4ce3-ae63-309a8c6b53c5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.395907ee-96e5-4666-af2e-2ca91688e151` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.39698b3f-da92-4bc6-bfb5-645a98386e45` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.396ae3eb-4174-4b9b-880e-dc0364d78a19` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.396f6630-f3ac-44e3-bfc8-1b161bc00c4e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.39a80702-d7ca-4a83-b776-525b1f86a36d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.39a94fd1-8c9a-4ff6-bf22-c058762f8014` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.39b31e81-5f5f-4898-9c0e-2160cfc0f9bf` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.39ed3c80-e6a1-431b-9df3-911ac53d08a7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.39f1f9f2-9636-45de-98f6-a4046aa8e4b9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.39f919f3-980b-4e6f-a975-8af7e507ef2b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3a6586ad-127a-4d3b-a677-1e6eacdf8fde` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3a734d25-df5c-4b99-8034-af1ddb5883a4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3a8da4e0-36c1-40d2-8b29-b3e890d5172a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3a9fa2ec-30bc-4ebd-b49e-7c9cff225502` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3ab65069-d82a-4d44-a759-466661a082d1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3ab79e90-9fab-4cdf-a7b2-6522bc742adb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3abd6094-7027-475f-9630-8ab9be7b9725` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3ae1a046-f7db-439d-b7ce-b8b366b81fa6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3ae9974a-eb09-4044-8e70-8980a50c12c8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3aff0be0-7802-4a7e-a4fa-c60c74bc5e1d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3b3c7f55-f771-4dd6-8a6e-08d057a17caf` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3b4e950b-a3ea-44d3-877e-432071990709` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3b5b0213-0460-4e3f-8937-3abf98ff7dcc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3b5ba899-9842-4bc2-acc2-12308498bf42` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3b6ab547-8ec2-4991-b9d2-2b06702a48d7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3b8f4c92-6a51-4d7e-9c3a-8e2d1f5a7b09` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3bad990e-4848-4a78-9530-b427d854aac0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3c05e90d-7eba-4324-9972-5d7f711a60a8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3c1b5fb0-c72f-45ba-abd1-4d4c353144ab` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3c89a1e8-0fba-449e-8f1b-8409d6267ec8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3d0ed417-3d94-4963-a562-4a92c940656a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3d27f6dd-1c74-4687-b4fa-ca849d128d1c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3d2a2d59-929c-4b78-8c1a-145dfe9e07b1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3d3aa6cd-6272-44d6-8afc-7e88dfef7061` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3d48c9d3-1aa6-418d-98d3-8fd3c01a564e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3d7679bd-0c00-440c-97b0-3f204273e6c7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3da70954-0f2c-4103-adff-b7440368f50e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3dfd06d2-eaf4-4532-9555-68aca59f57c4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3e2f1b2c-4d5e-11ee-be56-0242ac120002` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3e3ceccd-6c06-48b8-b5ff-ab1d25db8c1d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3e8207c5-fcd2-4ea6-9418-15d45b4890e4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3ef5605c-9eb9-47b0-9a71-b727e6aa5c3b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3f5491e2-8db8-496b-9e95-1029fce852d4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3f6b7b62-61aa-45db-96bd-9c31b36b653c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.3fd4c8d7-8362-4557-a8e6-83b29cc0d724` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.409f8a98-4496-4aaa-818a-c931c0a8b832` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.40aa399c-7b02-4715-8e5f-73572b493f33` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.40b19fa6-d835-400c-b301-41f3a2baacaf` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.40b6e656-4e11-4c0c-8772-c1cc6dae34ce` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.40b95d31-1afc-469e-8d34-9a3a667d058e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.40f9af16-589d-4984-b78d-8c2aec023197` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.411742ad-89b0-49cb-a7b0-3971b5c1e0a4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.41421f44-58f9-455d-838a-c398859841d4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.418a3163-3247-4b7b-9933-dcfcb7c52ea9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.41bb431f-56d8-4691-bb56-ed34e390906f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.41ca393d-538c-408a-ac27-cf1e038be80c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.41f407b5-3096-44ea-a74f-96d04fbc41be` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.41f6531d-af6e-4c6e-918f-b946f2b85a36` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.42205c73-75c8-4a63-9db1-e3782e06fda0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.42333b2c-b425-441c-b70e-99404a17170f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.424273ea-7cf8-43a6-b712-375f925e481f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.42a5f1e7-9603-4f6d-97ae-3f37d130d794` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.42a993dd-bb3e-48c8-b372-4d6684c4106c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.42b1a5b8-353f-4f10-b256-39de4467faff` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.42c575ea-e41e-41f1-b248-8093c3e82a28` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.43103702-5886-11ed-9b6a-0242ac120002` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.431a1fdb-4799-4f3b-91c3-a683b003fc49` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.434c08ba-8406-4d15-8b24-782cb071a691` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4358e5a5-7542-4dcb-b9f3-87667371839b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.435e10e4-992a-4281-96f3-38b11106adde` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.438025f9-5856-4663-83f7-52f878a70a50` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.439957a7-ad86-4a8f-9705-a28131c6821b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.43d91656-a9b2-4541-b7e2-6a9bd3a13f4e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.43e32da2-fdd0-4156-90de-50dfd62636f9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.43fa5350-db63-4b8f-9a01-789a427074e1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.44030449-b0df-4c94-aae1-502359ab28ee` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.44143844-0631-49ab-97a0-96387d6b2d7c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.44a22d59-b175-4f13-8c16-cbaef5b581ff` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.44e24481-6202-4c62-9127-5a0ae8e3fe3d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.452bce90-6fb0-43cc-97a5-affc283139b3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.45545954-4016-43c6-855e-eae8f1c369dc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.455b9d50-15a1-4b99-853f-8d37655a4c1b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.459f2f98-397b-4a4a-9f47-6a5ec2f1c69d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.45a594aa-1fbd-4972-a809-ff5a99dd81b8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.45d3a03d-f441-458c-8883-df101a3bb146` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.45e112d0-7759-4c2a-aa36-9f8fb79d3393` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.460479f3-80b7-42da-9c43-2cc1d54dbccd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.46123129-1024-423e-9fae-43af4a0fa9a5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4627c6ae-6899-46e2-aa0c-6ebcb1becd19` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.46490193-1b22-4c29-bdd6-5bf63907216f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.46a68649-f218-4f86-aea1-16a759d81820` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.46dd5308-4572-4d12-aa43-8938f0184d4f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.470ec5fa-7b4e-4071-b200-4c753100f49b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.47147b5b-9e17-4d76-b8d2-7bac24c5ce1b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4720b7df-40c3-48fd-bbdf-fd4b3c464f0d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4782eb5a-a513-4523-a0ac-f3082b26ac5c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.47e4bab7-c626-47dc-967b-255608c9a920` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.480421f9-417f-4d3b-9552-fd2728443ec8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.480e7e51-e797-47e3-8d72-ebfce65b6d8d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4833155a-4053-4c9c-a997-777fcea0baa7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.48437c39-9e5f-47fb-af95-3d663c3f2919` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.487bb375-12ef-41f6-baae-c6a1572b4dd1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.487c7524-f892-4054-b263-8a0ace63fc25` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.48917adc-a28e-4f5d-b729-11e75da8941f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.48a61b29-389f-4032-b317-b30de6b95314` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.48bbc537-b652-4b4e-bd1d-281172df448f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.48d91a3a-2363-43ba-a456-ca71ac3da5c2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.48ea844d-19b1-4642-944e-fe39c2cc1fec` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4916a35e-bfc4-47d0-8e25-a003d7067061` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4931188c-178e-4ee7-a348-39e8a7a56821` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.496a0e47-0a33-4dca-b009-9e6ca3591f39` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4976aa50-8f41-45c6-8b15-ab3fc10e79ed` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.49be8799-7b4d-4fda-ad23-cafbefdebbc5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.49d9671b-0a0a-4c09-8280-d215bfd30662` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.49e5bc24-8b86-49f1-b743-535f332c2856` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.49f2f17b-b4c8-4172-a68b-d5bf95d05130` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4a2a2c3e-209f-4d01-b513-4155a540b469` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4a30ac0c-b9d6-4e01-b71a-5f851bbf4259` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4a5f5a5e-ac01-474b-9b4e-d61298c9df1d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4a6713f6-3331-11ed-a261-0242ac120002` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4aa6040b-3f28-44e3-a769-9208e5feb5ec` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4aafb0fa-bff5-4b9d-b99e-8093e659c65f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4abc0ec4-db5a-412f-9632-26659cddf145` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4ac1f50b-3bd0-4968-902d-868b4647937e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4ac47ed3-44c2-4b1f-9d51-bf46e8914126` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4ae3e30b-b03f-43aa-87e3-b622f4048eed` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4ae81040-fc1c-4249-bfa3-938d260214d9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4b046706-5789-4673-b111-66f25fe99534` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4b13db67-0c45-40f1-aba8-66a1a7198a1e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4b60e6f2-bf39-47b4-b4ea-398e33cfe253` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4b657234-038e-4ad5-997c-4be42340bce4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4b8f6d3a-9c5e-4f2a-a7d8-6b9c3e5f2a8d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4b991083-3d0e-44ce-8fc4-b254025d8d4b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4bb79b62-ef12-4861-981d-2aab43fab642` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4bc90587-e6ca-4b41-be0b-ed4d04e4ed0c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4beb6ae0-f85b-41e2-8f18-8668abc8af78` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4bf943c6-5146-4273-98dd-e958fd1e3abf` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4c0aaedc-154c-4427-ada0-d80ef9c9deb6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4c54ba8f-73d2-4d40-8890-d9cf1dca3d30` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4c7f49ee-2638-43bb-b85b-ce676c30b260` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4cbef972-f347-4170-b62a-8253f6168e6d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4d431012-2ab5-4db7-a84e-b29809da2172` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4d7cda18-1b12-4e52-b45c-d28653210df8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4d7f1827-1637-4def-8d8a-fd254f9454df` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4e2ed651-1906-4a59-a78a-18220fca1b22` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4e7050dd-e548-483f-b7d6-527ab4fa784d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4e762605-34a8-406d-b72e-c1a089313320` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4e87b8e2-2ee9-4b2a-a715-4727d297ece0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4ebc877f-4612-45cb-b3a5-8e3834db36c9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4eddc365-79b4-43ff-a9d7-99422dc34b93` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4ede543c-e098-43d9-a28f-dd784a13132f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4edf51e1-cb83-4e1a-bc39-800e396068e3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4eec988f-7bf0-49f1-8675-1e6a510b3a2a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4f154fb6-27d1-4813-a759-78b93e0b9c48` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4f1707b1-b50b-45b4-b5a2-3978b5a5d0d6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4f281b83-0200-4b34-bf35-d24687ea57c2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4f2cd9b6-4a17-440f-bb2a-687abb65993a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4f647cfa-b598-4e12-ad69-c68dd16caef8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4f73421b-5a0b-4bbf-a892-5a7fb99bea66` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4f7a6757-ff79-46db-9687-66501a02d9ec` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4f84b697-c9ed-4420-8ab5-e09af5b2345d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4fd6b1c7-19b8-4488-97f6-00f0924991a3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4fe074b4-b833-4081-8f24-7dcfeca72b42` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.4fee3d51-8069-4a4c-a0f7-924fcaff2c70` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.503d581c-7df0-4bbe-b9be-5840c0ecc1fc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.50919691-7302-437f-8e10-1fe088afa145` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.509e84b9-a71a-40e0-834f-05470369bd1e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.50a0aa3d-ab16-4594-a8aa-5145a6e6792b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.50d66fb0-03f8-4da0-8add-84e77d12a020` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.50e54b8d-ad73-43f8-96a1-5191685b17a4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.514e4c3a-c77d-4cde-a00f-046425e2301e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.514e7e3e-b3b4-4a67-af60-be20f139198b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.515c8be5-e5df-4c5e-8f6d-a4a2f05e4b48` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.517490a7-115a-48c6-8862-1a481504d5a8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.51aa9387-1c53-4153-91cc-d73c59ae1ca9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.51ae86a2-e2e1-4097-ad85-c46cb6851de4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.51cbac1e-eee3-4a90-b1b7-358efb81fa0a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.51e33403-2a37-4d66-a574-1fda1782cc31` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5205613d-2a63-4412-a895-3a2458b587b3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.526be59f-a573-4eea-b5f7-f0973207634d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.52753ea4-b3a0-4365-910d-36cff487b789` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.52788a70-f1da-40dd-8fbd-73b5865d6568` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.52a85084-6989-40c3-8f32-091e12e13f09` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.52cad028-0ff0-4854-8f67-d25dfcbc78b4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.52d097e2-063e-4c9c-8fbb-855c8948d135` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.52ff7941-8211-46f9-84f8-9903efb7077d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.530576ee-3b62-4bce-9a03-9aac6c61788a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.530a6faa-ff3d-4022-b315-50828e77eef5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.53330955-dc52-487f-a3a2-da24dcff99b5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.534f2ef7-e8a2-4433-816d-c91bccde289b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.536e2947-3729-478c-9903-745aaffe60d2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5394fcc7-aeb2-43b5-9a09-cac9fc5edcd5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.53ad8e36-f573-46bf-97e4-15ba5bf4bb51` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.53d4bb30-3f36-4e8a-b078-69d36c4a79ff` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.53d8d3e1-ca33-4012-adf3-e05a4d652e34` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.53ef0cef-fa24-4f25-a34a-6c72dfa2e6e2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.54127bd4-f541-4ac3-afdb-ea073f63f692` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.545a5da6-f103-4919-a519-e9aec1026ee4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.54773c5f-f1cc-4703-9126-2f797d96a69d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.54f0434b-726f-48a1-b2aa-067df14516e4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.550bbb84-ce5d-4e61-84ad-e590f0024dcd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5513deaf-f49a-46c2-a6c8-3f111b5cb453` | 1 | 1 | 0 | 0 | 通过 |
| `sigma.551d9c1f-816c-445b-a7a6-7a3864720d60` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.554601fb-9b71-4bcc-abf4-21a611be4fde` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.555155a2-03bf-4fe7-af74-d176b3fdbe16` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5589ab4f-a767-433c-961d-c91f3f704db1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5594e67a-7f92-4a04-b65d-1a42fd824a60` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.55e29995-75e7-451a-bef0-6225e2f13597` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.55f0a3a1-846e-40eb-8273-677371b8d912` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.56321594-9087-49d9-bf10-524fe8479452` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.56454143-524f-49fb-b1c6-3fb8b1ad41fb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5687f942-867b-4578-ade7-1e341c46e99a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.56abae0c-6212-4b97-adc0-0b559bb950c3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.56c217c3-2de2-479b-990f-5c109ba8458f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.56d19cb4-6414-4769-9644-1ed35ffbb148` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.56e05d41-ce99-4ecd-912d-93f019ee0b71` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.570ae5ec-33dc-427c-b815-db86228ad43e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.571498c8-908e-40b4-910b-d2369159a3da` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5722dff1-4bdd-4949-86ab-fbaf707e767a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.575dce0c-8139-4e30-9295-1ee75969f7fe` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.576426ad-0131-4001-ae01-be175da0c108` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.57b649ef-ff42-4fb0-8bf6-62da243a1708` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.57bff678-25d1-4d6c-8211-8ca106d12053` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.57c4bf16-227f-4394-8ec7-1b745ee061c3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5817e76f-4804-41e6-8f1d-5fa0b3ecae2d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.583aa0a2-30b1-4d62-8bf3-ab73689efe6c` | 1 | 1 | 0 | 0 | 通过 |
| `sigma.584bca0f-3608-4402-80fd-4075ff6072e3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.589ac73f-8e12-409c-964e-31a2f5775ae2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.58f4ea09-0fc2-4520-ba18-b85c540b0eaf` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.58f50261-c53b-4c88-bd12-1d71f12eda4c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.590a5f4c-6c8c-4f10-8307-89afe9453a9d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.59e938ff-0d6d-4dc3-b13f-36cc28734d4e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5a2b21ee-6aaa-4234-ac9d-59a59edf90a1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5a3164f2-b373-4152-93cf-090b13c12d27` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5a44727c-3b85-4713-8c44-4401d5499629` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5a5152f1-463f-436b-b2f5-8eceb3964b42` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5a6e1e16-07de-48d8-8aae-faa766c05e88` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5a93eb65-dffa-4543-b761-94aa60098fb6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5a9e1b2c-8f7d-4a1e-9b3c-0f6d7e5a4b1f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5aad0995-46ab-41bd-a9ff-724f41114971` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5af54681-df95-4c26-854f-2565e13cfab0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5b16df71-8615-4f7f-ac9b-6c43c0509e61` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5b175490-b652-4b02-b1de-5b5b4083c5f8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5b40a734-99b6-4b98-a1d0-1cea51a08ab2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5b768e71-86f2-4879-b448-81061cbae951` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5b80a791-ad9b-4b75-bcc1-ad4e1e89c200` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5b872a46-3b90-45c1-8419-f675db8053aa` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5bac7a56-da88-4c27-922e-c81e113b20cb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5bb68627-3198-40ca-b458-49f973db8752` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5cb299fc-5fb1-4d07-b989-0644c68b6043` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5cc2cda8-f261-4d88-a2de-e9e193c86716` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5cc90652-4cbd-4241-aa3b-4b462fa5a248` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5cdb711b-5740-4fb2-ba88-f7945027afac` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5cddf373-ef00-4112-ad72-960ac29bac34` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5ce0f04e-3efc-42af-839d-5b3a543b76c0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5d19eb78-5b5b-4ef2-a9f0-4bfa94d58a13` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5d6c375a-18ae-4952-b4f6-8b803f6c8555` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5d756aee-ad3e-4306-ad95-cb1abec48de2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5de03871-5d46-4539-a82d-3aa992a69a83` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5df86130-4e95-4a54-90f7-26541b40aec2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5e3cc4d8-3e68-43db-8656-eaaeefdec9cc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5e6a80c8-2d45-4633-9ef4-fa2671a39c5c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5e95028c-5229-4214-afae-d653d573d0ec` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5e993621-67d4-488a-b9ae-b420d08b96cb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5edc2273-c26f-406c-83f3-f4d948e740dd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5ee3a654-372f-11ec-8d3d-0242ac130003` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5f60740a-f57b-4e76-82a1-15b6ff2cb134` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5f6a601c-2ecb-498b-9c33-660362323afa` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5f87308a-0a5b-4623-ae15-d8fa1809bc60` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5f9db380-ea57-4d1e-beab-8a2d33397e93` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5fc297ae-25b6-488a-8f25-cc12ac29b744` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.5fdce3ac-e7f9-4ecd-a3aa-a4d78ebbf0af` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6004abd0-afa4-4557-ba90-49d172e0a299` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.602a1f13-c640-4d73-b053-be9a2fa58b96` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.60936b49-fca0-4f32-993d-7415edcf9a5d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.60bfeac3-0d35-4302-8efb-1dd16f715bc6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.60f16a96-db70-42eb-8f76-16763e333590` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.60fc936d-2eb0-4543-8a13-911c750a1dfc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.611eab06-a145-4dfa-a295-3ccc5c20f59a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6120ac2a-a34b-42c0-a9bd-1fb9f459f348` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.612e47e9-8a59-43a6-b404-f48683f45bd6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.613c03ba-0779-4a53-8a1f-47f914a4ded3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.614a7e17-5643-4d89-b6fe-f9df1a79641c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.614cf376-6651-47c4-9dcc-6b9527f749f4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.61a7697c-cb79-42a8-a2ff-5f0cdfae0130` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.62120148-6b7a-42be-8b91-271c04e281a3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6225c53a-a96e-4235-b28f-8d7997cd96eb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.62510e69-616b-4078-b371-847da438cc03` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.62b20d44-1546-4e61-afce-8e175eb9473c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.62b7ccc9-23b4-471e-aa15-6da3663c4d59` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.62e0298b-e994-4189-bc87-bc699aa62d97` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.62ed5b55-f991-406a-85d9-e8e8fdf18789` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.62f7c9bf-9135-49b2-8aeb-1e54a6ecc13c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.631b22a4-70f4-4e2f-9ea8-42f84d9df6d8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6345b048-8441-43a7-9bed-541133633d7a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.634b00d5-ccc3-4a06-ae3b-0ec8444dd51b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.63647769-326d-4dde-a419-b925cc0caf42` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6385697e-9f1b-40bd-8817-f4a91f40508e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.639c9081-f482-47d3-a0bd-ddee3d4ecd76` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.63d1ccc0-2a43-4f4b-9289-361b308991ff` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.63de06b9-a385-40b5-8b32-73f2b9ef84b6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.63e3365d-4824-42d8-8b82-e56810fefa0c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.63e4f530-65dc-49cc-8f80-ccfa95c69d43` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.641a4bfb-c017-44f7-800c-2aee0184ce9b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.643bdcac-8b82-49f4-9fd9-25a90b929f3b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.646bc99f-6682-4b47-a73a-17b1b64c9d34` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.646ea171-dded-4578-8a4d-65e9822892e3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.64760eef-87f7-4ed3-93fd-655668ea9420` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.647c7b9e-d784-4fda-b9a0-45c565a7b729` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.651f87f7-12db-47f9-84c5-f27b081b94b6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.65236ec7-ace0-4f0c-82fd-737b04fd4dcb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.65354b83-a2ea-4ea6-8414-3ab38be0d409` | 1 | 1 | 0 | 0 | 通过 |
| `sigma.654fcc6d-840d-4844-9b07-2c3300e54a26` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6597be7b-ac61-4ac8-bef4-d3ec88174853` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.65c3ca2c-525f-4ced-968e-246a713d164f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6640f31c-01ad-49b5-beb5-83498a5cd8bd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.66b6be3d-55d0-4f47-9855-d69df21740ea` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.66c3b204-9f88-4d0a-a7f7-8a57d521ca55` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.66e563f9-1cbd-4a22-a957-d8b7c0f44372` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.674202d0-b22a-4af4-ae5f-2eda1f3da1af` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6763c6c8-bd01-4687-bc8d-4fa52cf8ba08` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.67a6c006-3fbe-46a7-9074-2ba3b82c3000` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.67bc0e75-c0a9-4cfc-8754-84a505b63c04` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.67f113fa-e23d-4271-befa-30113b3e08b1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6812a10b-60ea-420c-832f-dfcc33b646ba` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.68578b43-65df-4f81-9a9b-92f32711a951` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.686c0b4b-9dd3-4847-9077-d6c1bbe36fcb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.68bcd73b-37ef-49cb-95fc-edc809730be6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.68c8acb4-1b60-4890-8e82-3ddf7a6dba84` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.68d37776-61db-42f5-bf54-27e87072d17e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6902955a-01b7-432c-b32a-6f5f81d8f625` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.692f0bec-83ba-4d04-af7e-e884a96059b6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6938366d-8954-4ddc-baff-c830b3ba8fcd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.696bfb54-227e-4602-ac5b-30d9d2053312` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.69aeb277-f15f-4d2d-b32a-55e883609563` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.69bd9b97-2be2-41b6-9816-fb08757a4d1a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.69ca006d-b9a9-47f5-80ff-ecd4d25d481a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.69ca12af-119d-44ed-b50f-a47af0ebc364` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6a53d871-682d-40b6-83e0-b7c1a6c4e3a5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6aa1d992-5925-4e9f-a49b-845e51d1de01` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6b269392-9eba-40b5-acb6-55c882b20ba6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6b369ced-4b1d-48f1-b427-fdc0de0790bd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6b65c28e-11f3-46cb-902a-68f2cafaf474` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6b6976a3-b0e6-4723-ac24-ae38a737af41` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6ba5a05f-b095-4f0a-8654-b825f4f16334` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6bba49bf-7f8c-47d6-a1bb-6b4dece4640e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6bd75993-9888-4f91-9404-e1e4e4e34b77` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6c0a7755-6d31-44fa-80e1-133e57752680` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6c0ce3b6-85e2-49d4-9c3f-6e008ce9796e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6c304b02-06e6-402d-8be4-d5833cdf8198` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6c6d9280-e6d0-4b9d-80ac-254701b64916` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6c82cf5c-090d-4d57-9188-533577631108` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6c8fbee5-dee8-49bc-851d-c3142d02aa47` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6c96fc76-0eb1-11eb-adc1-0242ac120002` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6d3a3952-6530-44a3-8554-cf17c116c615` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6da2c9f5-7c53-401b-aacb-92c040ce1215` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6daac7fc-77d1-449a-a71a-e6b4d59a0e54` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6db5eaf9-88f7-4ed9-af7d-9ef2ad12f236` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6ddff2e8-ea1a-45d0-8938-93dfc1d67ae7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6e22722b-dfb1-4508-a911-49ac840b40f8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6e2a900a-ced9-4e4a-a9c2-13e706f9518a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6e90ae7a-7cd3-473f-a035-4ebb72d961da` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6e968eb1-5f05-4dac-94e9-fd0c5cb49fd6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6ea3bf32-9680-422d-9f50-e90716b12a66` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6ea858a8-ba71-4a12-b2cc-5d83312404c7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6f0947a4-1c5e-4e0d-8ac7-53159b8f23ca` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6f1a11aa-4b8a-4b7f-9e13-4d3e4ff0e0d4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6f3e2987-db24-4c78-a860-b4f4095a7095` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6f535e01-ca1f-40be-ab8d-45b19c0c8b7f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6f8b3439-a203-45dc-a88b-abf57ea15ccf` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6fb63b40-e02a-403e-9ffd-3bcc1d749442` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.6fe4aa1e-0531-4510-8be2-782154b73b48` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7002aa10-b8d4-47ae-b5ba-51ab07e228b9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7021255e-5db3-4946-a8b9-0ba7a4644a69` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7047d730-036f-4f40-b9d8-1c63e36d5e62` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7050bba1-1aed-454e-8f73-3f46f09ce56a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.707e097c-e20f-4f67-8807-1f72ff4500d6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.70ad0861-d1fe-491c-a45f-fa48148a300d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.70bc5215-526f-4477-963c-a47a5c9ebd12` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.71158e3f-df67-472b-930e-7d287acaa3e1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7124aebe-4cd7-4ccb-8df0-6d6b93c96795` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.71c276aa-49cd-43d2-b920-2dcd3e6962d5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.72124974-a68b-4366-b990-d30e0b2a190d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.724ea201-6514-4f38-9739-e5973c34f49a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.725a9768-0f5e-4cb3-aec2-bc5719c6831a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7280c9f3-a5af-45d0-916a-bc01cb4151c9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.72862bf2-0eb1-11eb-adc1-0242ac120002` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.729ce0ea-5d8f-4769-9762-e35de441586d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.730fc21b-eaff-474b-ad23-90fd265d4988` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.731231b9-0b5d-4219-94dd-abb6959aa7ea` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.734f8d9b-42b8-41b2-bcf5-abaf49d5a3c8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.736ffa74-5f6f-44ca-94ef-1c0df4f51d2a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.737e618a-a410-49b5-bec3-9e55ff7fbc15` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.73921b9c-cafd-4446-b0c6-fdb0ace42bc0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.73a883d0-0348-4be4-a8d8-51031c2564f8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.74403157-20f5-415d-89a7-c505779585cf` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.744a188b-0415-4792-896f-11ddb0588dbc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.74697c29-1b30-4e1f-a517-33574061821d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.749c9f5e-b353-4b90-a9c1-05243357ca4b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.74a12f18-505c-4114-8d0b-8448dd5485c6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.74a2b202-73e0-4693-9a3a-9d36146d0775` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.74a2b37d-fea4-41e0-9ac7-c9fbcf1f60cc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.74babdd6-a758-4549-9632-26535279e654` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.75180c5f-4ea1-461a-a4f6-6e4700c065d4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7530b96f-ad8e-431d-a04d-ac85cc461fdc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7530cd3d-7671-43e3-b209-976966f6ea48` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.758ff488-18d5-4cbe-8ec4-02b6285a434f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7595ba94-cf3b-4471-aa03-4f6baa9e5fad` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.75bf09fa-1dd7-4d18-9af9-dd9e492562eb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.75bfe6e6-cd8e-429e-91d3-03921e1d7962` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.75d0a94e-6252-448d-a7be-d953dff527bb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.75edd216-1939-4c73-8d61-7f3a0d85b5cc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.75edd3fd-7146-48e5-9848-3013d7f0282c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.75f7a0e2-7154-4c4d-9eae-5cdb4e0a5c13` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.760e75d8-c3b5-409b-a9bf-6130b4c4603f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.762bb580-79b4-40f4-8b9e-9349ce1710f4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.762f2482-ff21-4970-8939-0aa317a886bb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7638e5fe-600c-4289-a968-f49dd537ec7d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7679d464-4f74-45e2-9e01-ac66c5eb041a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.76f55eaa-d27f-4213-9d45-7b0e4b60bbae` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.771d1eb5-9587-4568-95fb-9ec44153a012` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7745c2ea-24a5-4290-b680-04359cb84b35` | 1 | 1 | 0 | 0 | 通过 |
| `sigma.778ba9a8-45e4-4b80-8e3e-34a419f0b85e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.77946e79-97f1-45a2-84b4-f37b5c0d8682` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.77df53a5-1d78-4f32-bc5a-0e7465bd8f41` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.782d6f3e-4c5d-4b8c-92a3-1d05fed72e63` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7864a175-3654-4824-9f0d-f0da18ab27c0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.786cdae8-fefb-4eb2-9227-04e34060db01` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7892ec59-c5bb-496d-8968-e5d210ca3ac4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.78f10490-f2f4-4d19-a75b-4e0683bf3b8d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.790317c0-0a36-4a6a-a105-6e576bf99a14` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.797011dc-44f4-4e6f-9f10-a8ceefbe566b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.79b06761-465f-4f88-9ef2-150e24d3d737` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.79ce34ca-af29-4d0e-b832-fc1b377020db` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.79df3f68-dccb-48e9-9171-b75cbc37c51d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.79f4ede3-402e-41c8-bc3e-ebbf5f162581` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7a01183d-71a2-46ad-ad5c-acd989ac1793` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7a02e22e-b885-4404-b38b-1ddc7e65258a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7a1b4c5e-8f3d-4b9a-7c2e-1f4a5b8c6d9e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7a4d9232-92fc-404d-8ce1-4c92e7caf539` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7a74da6b-ea76-47db-92cc-874ad90df734` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7a922f1b-2635-4d6c-91ef-af228b198ad3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7aa4e81a-a65c-4e10-9f81-b200eb229d7d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7aa7009a-28b9-4344-8c1f-159489a390df` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7b10f171-7f04-47c7-9fa2-5be43c76e535` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7b14c76a-c602-4ae6-9717-eff868153fc0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7b434893-c57d-4f41-908d-6a17bf1ae98f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7b449a5e-1db5-4dd0-a2dc-4e3a67282538` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7b4f794b-590a-4ad4-ba18-7964a2832205` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7b582f1a-b318-4c6a-bf4e-66fe49bf55a5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7b687634-ab20-11ea-bb37-0242ac130002` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7b6a7418-3afc-11f0-aff4-000d3abf478c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7bd3902d-8b8b-4dd4-838a-c6862d40150d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7c06ab9b-b1d2-4ba9-b06e-09491ded20d9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7c0dcd3d-acf8-4f71-9570-f448b0034f94` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7c81fec3-1c1d-43b0-996a-46753041b1b6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7c8af9b2-dcae-41a2-a9db-b28c288b5f08` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7c9fed65-039a-4055-8c23-fa763d94aff6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7cce6fc8-a07f-4d84-a53e-96e1879843c9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7cd1dcdc-6edf-4896-86dc-d1f19ad64903` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7cff77e1-9663-46a3-8260-17f2e1aa9d0a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7d1aaf3d-4304-425c-b7c3-162055e0b3ab` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7d4aaec2-08ed-4430-8b96-28420e030e04` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7d4cdc5a-0076-40ca-aac8-f7e714570e47` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7d604714-e071-49ff-8726-edeb95a70679` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7d6d30b8-5b91-4b90-a891-46cccaf29598` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7d9263bd-dc47-4a58-bc92-5474abab390c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7d995e63-ec83-4aa3-89d5-8a17b5c87c86` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7dbbcac2-57a0-45ac-b306-ff30a8bd2981` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7dc2dedd-7603-461a-bc13-15803d132355` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7df1713a-1a5b-4a4b-a071-dc83b144a101` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7e6237fe-3ddb-438f-9381-9bf9de5af8d0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7e8f2d3b-9c1a-4f67-b9e8-8d9006e0e51f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7e9c7999-0f9b-4d4a-a6ed-af6d553d4af4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7e9cf7b6-e827-11ed-a05b-0242ac120003` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7e9cf7b6-e827-11ed-a05b-15959c120003` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7ec2c172-dceb-4c10-92c9-87c1881b7e18` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7eedcc9d-9fdb-4d94-9c54-474e8affc0c7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7efd2c8d-8b18-45b7-947d-adfe9ed04f61` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7eff1a7f-dd45-4c20-877a-f21e342a7611` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7f103213-a04e-4d59-8261-213dddf22314` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7f2376f9-42ee-4dfc-9360-fecff9a88fc8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7f2954d2-99c2-4d42-a065-ca36740f187b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7f3a9c2d-4e8b-4a7f-9d3e-5c6f8a9b2e1d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7f43c430-5001-4f8b-aaa9-c3b88f18fa5c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7f4c43f9-b1a5-4c7d-b24a-b41bf3a3ebf2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7f5d1c9a-3e83-48df-95a7-2b98aae6c13c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7f741dcf-fc22-4759-87b4-9ae8376676a2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7fd164ba-126a-4d9c-9392-0d4f7c243df0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.7fff6773-2baa-46de-a24a-b6eec1aba2d1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.801bd44f-ceed-4eb6-887c-11544633c0aa` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8023f872-3f1d-4301-a384-801889917ab4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.805c55d9-31e6-4846-9878-c34c75054fe9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.80b708f3-d034-40e4-a6c8-d23b7a7db3d1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.80e1f67a-4596-4351-98f5-a9c3efabac95` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.80fc36aa-945e-4181-89f2-2f907ab6775d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.811e0002-b13b-4a15-9d00-a613fce66e42` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.811f459f-9231-45d4-959a-0266c6311987` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.81315b50-6b60-4d8f-9928-3466e1022515` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.814c95cc-8192-4378-a70a-f1aafd877af1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.814ddeca-3d31-4265-8e07-8cc54fb44903` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.817f252c-5143-4dae-b418-48c3e9f63728` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.81a0ecb5-0a41-4ba1-b2ba-c944eb92bfa2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.81bcb81b-5b1f-474b-b373-52c871aaa7b1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.81ebd28b-9607-4478-bf06-974ed9d53ed7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8202070f-edeb-4d31-a010-a26c72ac5600` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8218c875-90b9-42e2-b60d-0b0069816d10` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.82343930-652f-43f5-ab70-2ee9fdd6d5e9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.833ef470-fa01-4631-a79b-6f291c9ac498` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.83475063-b1c8-4774-9568-69bbda71a539` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.835e75bf-4bfd-47a4-b8a6-b766cac8bcb7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.83809e84-4475-4b69-bc3e-4aad8568612f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.83865853-59aa-449e-9600-74b9d89a6d6e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.843544a7-56e0-4dcc-a44f-5cc266dd97d6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8468111a-ef07-4654-903b-b863a80bbc95` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.847def9e-924d-4e90-b7c4-5f581395a2b4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.84972c80-251c-4c3a-9079-4f00aad93938` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.84b14121-9d14-416e-800b-f3b829c5a14d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.84b1706c-932a-44c4-ae28-892b28a25b94` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.84b1ecf9-6eff-4004-bafb-bae5c0e251b2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.850d55f9-6eeb-4492-ad69-a72338f65ba4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8518ed3d-f7c9-4601-a26c-f361a4256a0c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8537c866-072e-460d-bfff-aaf39cbd73d3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.853e74f9-9392-4935-ad3b-2e8c040dae86` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.855bc8b5-2ae8-402e-a9ed-b889e6df1900` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.85a8e5ba-bd03-4bfb-bbfa-a4409a8f8b98` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.85b0b087-eddf-4a2b-b033-d771fa2b9775` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.85b88e05-dadc-430b-8a9e-53ff1cd30aae` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.85c312b7-f44d-4a51-a024-d671c40b49fc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.85cce894-dd8b-4427-a958-5cc47a4dc9b9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.85d23b42-9a9d-4f8f-b3d7-d2733c1d58f5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.85de1f22-d189-44e4-8239-dc276b45379b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.85f520e7-6f5e-43ca-874c-222e5bf9c0de` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.85ff530b-261d-48c6-a441-facaa2e81e48` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.863218bd-c7d0-4c52-80cd-0a96c09f54af` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.86588b36-c6d3-465f-9cee-8f9093e07798` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.867356ee-9352-41c9-a8f2-1be690d78216` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.869b9ca7-9ea2-4a5a-8325-e80e62f75445` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.871b9555-69ca-4993-99d3-35a59f9f3599` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.87261fb2-69d0-42fe-b9de-88c6b5f65a43` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.87a476dc-0079-4583-a985-dee7a20a03de` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8823e85d-31d8-473e-b7f4-92da070f0fc6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.882e858a-3233-4ba8-855e-2f3d3575803d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.882fbe50-d8d7-4e29-ae80-0648a8556866` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.883835a7-df45-43e4-bf1d-4268768afda4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8839e550-52d7-4958-9f2f-e13c1e736838` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.883faa95-175a-4e22-8181-e5761aeb373c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.88656cec-6c3b-487c-82c0-f73ebb805503` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.889719ef-dd62-43df-86c3-768fb08dc7c0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.88a87a10-384b-4ad7-8871-2f9bf9259ce5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.88d306e9-8e2d-4025-9768-28757d2732db` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.88d6e60c-759d-4ac1-a447-c0f1466c2d21` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.88f46b67-14d4-4f45-ac2c-d66984f22191` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.899133d5-4d7c-4a7f-94ee-27355c879d90` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.89a9a0e0-f61a-42e5-8957-b1479565a658` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.89c42960-f244-4dad-9151-ae9b1a3287a2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.89ca78fd-b37c-4310-b3d3-81a023f83936` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.89f75308-5b1b-4390-b2d8-d6b2340efaf8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8a1b2c3d-4e5f-6789-abcd-ef1234567890` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8a3038e8-9c9d-46f8-b184-66234a160f6f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8a4519e8-e64a-40b6-ae85-ba8ad2177559` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8a582fe2-0882-4b89-a82a-da6b2dc32937` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8a7e90c5-fe6e-45dc-889e-057fe4378bd9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8a8379b8-780b-4dbf-b1e9-31c8d112fefb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8b0e12da-d3c3-49db-bb4f-256703f380e5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8b7273a4-ba5d-4d8a-b04f-11f2900d043a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8b93a509-1cb8-42e1-97aa-ee24224cdc15` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8b9606c9-28be-4a38-b146-0e313cc232c1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8bc64091-6875-4881-aaf9-7bd25b5dda08` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8c0eca51-0f88-4db2-9183-fdfb10c703f9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8c31f563-f9a7-450c-bfa8-35f8f32f1f61` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8c3c76ca-8f8b-4b1d-aaf3-81aebcd367c9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8ca7004b-e620-4ecb-870e-86129b5b8e75` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8cbc9475-8d05-4e27-9c32-df960716c701` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8cd538a4-62d5-4e83-810b-12d41e428d6e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8d01b53f-456f-48ee-90f6-bc28e67d4e35` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8d5aca11-22b3-4f22-b7ba-90e60533e1fb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8d7e392e-9b28-49e1-831d-5949c6281228` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8d85cf08-bf97-4260-ba49-986a2a65129c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8de1cbe8-d6f5-496d-8237-5f44a721c7a0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8de89e52-f6e1-4b5b-afd1-41ecfa300d48` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8e0bb260-d4b2-4fff-bb8d-3f82118e6892` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8e1cb247-6cf6-42fa-b440-3f27d57e9936` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8e3c7994-131e-4ba5-b6ea-804d49113a26` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8e4cf0e5-aa5d-4dc3-beff-dc26917744a9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8e5c03fa-b7f0-11ea-b242-07e0576828d9` | 1 | 1 | 0 | 0 | 通过 |
| `sigma.8e95e73e-ba02-4a87-b4d7-0929b8053038` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8eef149c-bd26-49f2-9e5a-9b00e3af499b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8f02c935-effe-45b3-8fc9-ef8696a9e41d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8f2a5c3d-9e4b-4a7c-8d1f-2e5a6b9c3d7e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8f3ab69a-aa22-4943-aa58-e0a52fdf6818` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8f88e3f6-2a49-48f5-a5c4-2f7eedf78710` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8fbe98a8-8f9d-44f8-aa71-8c572e29ef06` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8fbf3271-1ef6-4e94-8210-03c2317947f6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.8ffc5407-52e3-478f-9596-0a7371eafe13` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.903076ff-f442-475a-b667-4f246bcc203b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9082ff1f-88ab-4678-a3cc-5bcff99fc74d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.90d50722-0483-4065-8e35-57efaadd354d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.90d6bd71-dffb-4989-8d86-a827fedd6624` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.90dcf730-1b71-4ae7-9ffc-6fcf62bd0132` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.90f342e1-1aaa-4e43-b092-39fda57ed11e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.90fb5e62-ca1f-4e22-b42e-cc521874c938` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.910ab938-668b-401b-b08c-b596e80fdca5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.91174a41-dc8f-401b-be89-7bfc140612a0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.91239011-fe3c-4b54-9f24-15c86bb65913` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.916eb839-895e-47f8-99ee-3008bf377a3e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.91903aba-1088-42ee-b680-d6d94fe002b0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.919f2ef0-be2d-4a7a-b635-eb2b41fde044` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.91a2c315-9ee6-4052-a853-6f6a8238f90d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.91c49341-e2ef-40c0-ac45-49ec5c3fe26c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.91c945bc-2ad1-4799-a591-4d00198a1215` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.91edcfb1-2529-4ac2-9ecc-7617f895c7e4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9212f354-7775-4e28-9c9f-8f0a4544e664` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.921aa10f-2e74-4cca-9498-98f9ca4d6fdf` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9248c7e1-2bf3-4661-a22c-600a8040b446` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9257c05b-4a4a-48e5-a670-b7b073cf401b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.92626ddd-662c-49e3-ac59-f6535f12d189` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.92772523-d9c1-4c93-9547-b0ca500baba3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.92a974db-ab84-457f-9ec0-55db83d7a825` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.92fa78e7-4d39-45f1-91a3-8b23f3f1088d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.93199800-b52a-4dec-b762-75212c196542` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.932fb0d8-692b-4b0f-a26e-5643a50fe7d6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9386d78a-7207-4048-9c9f-a93a7c2d1c05` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.93a19907-d4f9-4deb-9f91-aac4692776a6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.93d298a1-d28f-47f1-a468-d971e7796679` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.93d94efc-d7ad-4161-ad7d-1638c4f908d8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.941e5c45-cda7-4864-8cea-bbb7458d194a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.944e8941-f6f6-4ee8-ac05-1c224e923c0e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.94771a71-ba41-4b6e-a757-b531372eaab6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.94dc4390-6b7c-4784-8ffc-335334404650` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9501f8e6-8e3d-48fc-a8a6-1089dd5d7ef4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.95022b85-ff2a-49fa-939a-d7b8f56eeb9b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9525dc73-0327-438c-8c04-13c0e037e9da` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.953d460b-f810-420a-97a2-cfca4c98e602` | 1 | 1 | 0 | 0 | 通过 |
| `sigma.9577edbb-851f-4243-8c91-1d5b50c1a39b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.95e60a2b-4705-444b-b7da-ba0ea81a3ee2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.95eadcb2-92e4-4ed1-9031-92547773a6db` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.96036718-71cc-4027-a538-d1587e0006a7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.961e0abb-1b1e-4c84-a453-aafe56ad0d34` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.961e33d1-4f86-4fcf-80ab-930a708b2f82` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.962fe167-e48d-4fd6-9974-11e5b9a5d6d1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9637e8a5-7131-4f7f-bdc7-2b05d8670c43` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.966315ef-c5e1-4767-ba25-fce9c8de3660` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.968eef52-9cff-4454-8992-1e74b9cbad6c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.970007b7-ce32-49d0-a4a4-fbef016950bd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9703792d-fd9a-456d-a672-ff92efe4806a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.970823b7-273b-460a-8afc-3a6811998529` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9711de76-5d4f-4c50-a94f-21e4e8f8384d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9719a8aa-401c-41af-8108-ced7ec9cd75c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.973ef012-8f1a-4c40-93b4-7e659a5cd17f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.974515da-6cc5-4c95-ae65-f97f9150ec7f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.976dd1f2-a484-45ec-aa1d-0e87e882262b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.979baf41-ca44-4540-9d0c-4fcef3b5a3a4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.97a80ec7-0e2f-4d05-9ef4-65760e634f6b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.97aa2e88-555c-450d-85a6-229bcd87efb8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.97b9ce1e-c5ab-11ea-87d0-0242ac130003` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.97dbf6e2-e436-44d8-abee-4261b24d3e41` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9801abb8-e297-4dbf-9fbd-57dde0e830ad` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.98054878-5eab-434c-85d4-72d4e5a3361b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9827ae57-3802-418f-994b-d5ecf5cd974b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.982e9f2d-1a85-4d5b-aea4-31f5e97c6555` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9847f263-4a81-424f-970c-875dab15b79b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.98767d61-b2e8-4d71-b661-e36783ee24c1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.98a96a5a-64a0-4c42-92c5-489da3866cb0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.98b53e78-ebaf-46f8-be06-421aafd176d9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.98c5aeef-32d5-492f-b174-64a691896d25` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.98dedfdd-8333-49d4-9f23-d7018cccae53` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.992dd79f-dde8-4bb0-9085-6350ba97cfb3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.993c2665-e6ef-40e3-a62a-e1a97686af79` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.994bfd6d-0a2e-481e-a861-934069fcf5f5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9976fa64-2804-423c-8a5b-646ade840773` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.99793437-3e16-439b-be0f-078782cf953d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.99b7460d-c9f1-40d7-a316-1f36f61d52ee` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.99c840f2-2012-46fd-9141-c761987550ef` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.99c8be4f-3087-4f9f-9c24-8c7e257b442e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.99cf1e02-00fb-4c0d-8375-563f978dfd37` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9a019ffc-3580-4c9d-8d87-079f7e8d3fd4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9a132afa-654e-11eb-ae93-0242ac130002` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9a4ccd1a-3526-4d99-b980-9f9c5d3a6ff3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9a4ff3b8-6187-4fd2-8e8b-e0eae1129495` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9ace0707-b560-49b8-b6ca-5148b42f39fb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9b0f8a61-91b2-464f-aceb-0527e0a45020` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9b64de98-9db3-4033-bd7a-f51430105f00` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9b8d9203-4e0f-4cd9-bb06-4cc4ea6d0e9a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9bd04a79-dabe-4f1f-a5ff-92430265c96b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9c0295ce-d60d-40bd-bd74-84673b7592b1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9c14c9fa-1a63-4a64-8e57-d19280559490` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9c226817-8dc9-46c2-a58d-66655aafd7dc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9c5037d1-c568-49b3-88c7-9846a5bdc2be` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9c7e131a-0f2c-4ae0-9d43-b04f4e266d43` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9c8afa4d-0022-48f0-9456-3712466f9701` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9cc85849-3b02-4cb5-b371-3a1ff54f2218` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9ccba514-7cb6-4c5c-b377-700758f2f120` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9cfe4b27-1e56-48b4-b7a8-d46851c91a44` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9d15044a-7cfe-4d23-8085-6ebc11df7685` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9d3436ef-9476-4c43-acca-90ce06bdf33a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9d5a1274-922a-49d0-87f3-8c653483b909` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9d7ca793-f6bd-471c-8d0f-11e68b2f0d2f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9d8f9bb8-01af-4e15-a3a2-349071530530` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9df0dd3a-1a5c-47e3-a2bc-30ed177646a0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9df5f547-c86a-433e-b533-f2794357e242` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9e02c8ec-02b9-43e8-81eb-34a475ba7965` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9e099d99-44c2-42b6-a6d8-54c3545cab29` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9e3357ba-09d4-4fbd-a7c5-ad6386314513` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9e36ed87-4986-482e-8e3b-5c23ffff11bf` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9e3cb244-bdb8-4632-8c90-6079c8f4f16d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9e4b7d3a-6f2c-4e9a-8d1b-3c5e7a9f2b4d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9e50a8b3-dd05-4eb8-9153-bdb6b79d50b0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9e716b33-63b2-46da-86a4-bd3c3b9b5dfb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9e8894c0-0ae0-11ef-9d85-1f2942bec57c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9eb99343-d336-4020-a3cd-67f3819e68ee` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9ec9fb1b-e059-4489-9642-f270c207923d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9ef27c24-4903-4192-881a-3adde7ff92a5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9f0a8bf3-a65b-440a-8c1e-5cb1547c8e70` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9f38c1db-e2ae-40bf-81d0-5b68f73fb512` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9f4662ac-17ca-43aa-8f12-5d7b989d0101` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9f50fe98-fe5c-4a2d-86c7-fad7f63ed622` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9f546b25-5f12-4c8d-8532-5893dcb1e4b8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9f8fc146-1d1a-4dbf-b8fd-dfae15e08541` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9fb6b26e-7f9e-4517-a48b-8cac4a1b6c60` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9fbf5927-5261-4284-a71d-f681029ea574` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9fc3072c-dc8f-4bf7-b231-18950000fadd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9fc51a3c-81b3-4fa7-b35f-7c02cf10fd2d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.9fff585c-c33e-4a86-b3cd-39312079a65f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a018fdc3-46a3-44e5-9afb-2cd4af1d4b39` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a01b8329-5953-4f73-ae2d-aa01e1f35f00` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a0459f02-ac51-4c09-b511-b8c9203fc429` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a05baa88-e922-4001-bc4d-8738135f27de` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a07f0359-4c90-4dc4-a681-8ffea40b4f47` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a0a278fe-2c0e-4de2-ac3c-c68b08a9ba98` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a0cb7110-edf0-47a4-9177-541a4083128a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a0d7e4d2-bede-4141-8896-bc6e237e977c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a0e417e2-2fa1-40da-b6d2-e094cd5e1191` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a10a2c40-2c4d-49f8-b557-1a946bc55d9d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a1473adb-5338-4a20-b4c3-126763e2d3d3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a166f74e-bf44-409d-b9ba-ea4b2dd8b3cd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a16980c2-0c56-4de0-9a79-17971979efdd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a18e0862-127b-43ca-be12-1a542c75c7c5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a197e378-d31b-41c0-9635-cfdf1c1bb423` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a1b1fd53-9c4a-444c-bae0-34a330fc7aa8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a1d9eec5-33b2-4177-8d24-27fe754d0812` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a1e11042-a74a-46e6-b07c-c4ce8ecc239b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a20391f8-76fb-437b-abc0-dba2df1952c6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a20def93-0709-4eae-9bd2-31206e21e6b2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a21bcd7e-38ec-49ad-b69a-9ea17e69509e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a27e5fa9-c35e-4e3d-b7e0-1ce2af66ad12` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a2863fbc-d5cb-48d5-83fb-d976d4b1743b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a2910908-e86f-4687-aeba-76a5f996e652` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a29808fd-ef50-49ff-9c7a-59a9b040b404` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a29c1813-ab1f-4dde-b489-330b952e91ae` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a2e5019d-a658-4c6a-92bf-7197b54e2cae` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a2ea3ae7-d3d0-40a0-a55c-25a45c87cac1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a31eeaed-3fd5-478e-a8ba-e62c6b3f9ecc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a34f79a3-8e5f-4cc3-b765-de00695452c2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a35f5a72-f347-4e36-8895-9869b0d5fc6d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a383dec4-deec-4e6e-913b-ed9249670848` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a3ab73f1-bd46-4319-8f06-4b20d0617886` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a4694263-59a8-4608-a3a0-6f8d3a51664c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a4824fca-976f-4964-b334-0621379e84c4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a4c90ea1-2634-4ca0-adbb-35eae169b6fc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a4e3d776-f12e-42c2-8510-9e6ed1f43ec3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a537cfc3-4297-4789-92b5-345bfd845ad0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a54f842a-3713-4b45-8c84-5f136fdebd3c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a58353df-af43-4753-bad0-cd83ef35eef5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a5a2d357-1ab8-4675-a967-ef9990a59391` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a5c7a43f-6009-4a8c-80c5-32abf1c53ecc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a62b37e0-45d3-48d9-a517-90c1a1b0186b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a642964e-bead-4bed-8910-1bb4d63e3b4d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a66bc059-c370-472c-a0d7-f8fd1bf9d583` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a6976974-ea6f-4e97-818e-ea08625c52cb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a6a39bdb-935c-4f0a-ab77-35f4bbf44d33` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a6b33c02-8305-488f-8585-03cb2a7763f2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a6fc3c46-23b8-4996-9ea2-573f4c4d88c5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a70dcb37-3bee-453a-99df-d0c683151be6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a743ceba-c771-4d75-97eb-8a90f7f4844c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a746c9b8-a2fb-4ee5-a428-92bee9e99060` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a7664b14-75fb-4a50-a223-cb9bc0afbacf` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a77c1610-fc73-4019-8e29-0f51efc04a51` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a7df0e9e-91a5-459a-a003-4cde67c2ff5d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a7ee1722-c3c5-aeff-3212-c777e4733217` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a80f662f-022f-4429-9b8c-b1a41aaa6688` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a85f7765-698a-4088-afa0-ecfbf8d01fa4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a85ffc3a-e8fd-4040-93bf-78aff284d801` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a8f29a7b-b137-4446-80a0-b804272f3da2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a8f866e1-bdd4-425e-a27a-37619238d9c7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a95b9b42-1308-4735-a1af-abb1c5e6f5ac` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a96970af-f126-420d-90e1-d37bf25e50e1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a982fc9c-6333-4ffb-a51d-addb04e8b529` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a9b6c011-ab69-4ddb-bc0a-c4f21c80ec47` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.a9e416a8-e613-4f8b-88b8-a7d1d1af2f61` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.aa0b3a82-eacc-4ec3-9150-b5a9a3e3f82f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.aa1697b7-d611-4f9a-9cb2-5125b4ccfd5c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.aa2efee7-34dd-446e-8a37-40790a66efd7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.aa37cbb0-da36-42cb-a90f-fdf216fc7467` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.aa3a6f94-890e-4e22-b634-ffdfd54792cc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.aa6f6ea6-0676-40dd-b510-6e46f02d8867` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.aa8e035d-7be4-48d3-a944-102aec04400d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.aaafa146-074c-11eb-adc1-0242ac120002` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.aaf46cdc-934e-4284-b329-34aa701e3771` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ab37a6ec-6068-432b-a64e-2c7bf95b1d22` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ab4561b1-6c7e-48a7-ad08-087cfb9ce8f1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ab567429-1dfb-4674-b6d2-979fd2f9d125` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ab6bffca-beff-4baa-af11-6733f296d57a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ab70c354-d9ac-4e11-bbb6-ec8e3b153357` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ab871450-37dc-4a3a-997f-6662aa8ae0f1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ab9e3b40-0c85-4ba1-aede-455d226fd124` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.aba15bdd-657f-422a-bab3-ac2d2a0d6f1c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ac175779-025a-4f12-98b0-acdaeb77ea85` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ac1c92b4-ac81-405a-9978-4604d78cc47e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ac20ae82-8758-4f38-958e-b44a3140ca88` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ac8866c7-ce44-46fd-8c17-b24acff96ca8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ac9159cc-c364-4304-8f0a-d63fc1a0aabb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.acfa2210-0d71-4eeb-b477-afab494d596c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ad691d92-15f2-4181-9aa4-723c74f9ddc3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ad720b90-25ad-43ff-9b5e-5c841facc8e5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ad89044a-8f49-4673-9a55-cbd88a1b374f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ad92e3f9-7eb6-460e-96b1-582b0ccbb980` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ada4b0c4-758b-46ac-9033-9004613a150d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.add64136-62e5-48ea-807e-88638d02df1e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ae215552-081e-44c7-805f-be16f975c8a2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ae6f14e6-14de-45b0-9f44-c0986f50dc89` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ae9b0bd7-8888-4606-b444-0ed7410cb728` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ae9c6a7c-9521-42a6-915e-5aaa8689d529` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.aef9d1f1-7396-4e92-a927-4567c7a495c1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.af491bca-e752-4b44-9c86-df5680533dbc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.af5732ed-764e-489d-826d-0447c8b36242` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.af77cf95-c469-471c-b6a0-946c685c4798` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.afa71271-6a97-4e47-810f-83120fb1a4ce` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.afe52666-401e-4a02-b4ff-5d128990b8cb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b0524451-19af-4efa-a46f-562a977f792e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b07e58cf-cacc-4135-8473-ccb2eba63dd2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b0ce780f-10bd-496d-9067-066d23dc3aa5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b110ebaf-697f-4da1-afd5-b536fa27a2c1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b124ddf4-778d-418e-907f-6dd3fc0d31cd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b1377339-fda6-477a-b455-ac0923f9ec2c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b17ea6f7-6e90-447e-a799-e6c0a493d6ce` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b1876533-4ed5-4a83-90f3-b8645840a413` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b18c9d4c-fac9-4708-bd06-dd5bfacf200f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b19146a3-25d4-41b4-928b-1e2a92641b1b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b1c50487-1967-4315-a026-6491686d860e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b1cb4ab6-ac31-43f4-adf1-d9d08957419c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b1e0b3f5-b62e-41be-886a-daffde446ad4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b1e5da3b-ca8e-4adf-915c-9921f3d85481` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b1f73849-6329-4069-bc8f-78a604bb8b23` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b210394c-ba12-4f89-9117-44a2464b9511` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b222df08-0e07-11eb-adc1-0242ac120002` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b2309017-4235-44fe-b5af-b15363011957` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b2317cfa-4a47-4ead-b3ff-297438c0bc2d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b237c54b-0f15-4612-a819-44b735e0de27` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b23818c7-e575-4d13-8012-332075ec0a2b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b243b280-65fe-48df-ba07-6ddea7646427` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b27077d6-23e6-45d2-81a0-e2b356eea5fd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b2815d0d-7481-4bf0-9b6c-a4c48a94b349` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b28e58e4-2a72-4fae-bdee-0fbe904db642` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b2ddd389-f676-4ac4-845a-e00781a48e5f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b30a8bc5-e21b-4ca2-9420-0a94019ac56a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b3503044-60ce-4bf4-bbcb-e3db98788823` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b3512211-c67e-4707-bedc-66efc7848863` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b36d01a3-ddaf-4804-be18-18a6247adfcd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b37998de-a70b-4f33-b219-ec36bf433dc0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b3ad3c0f-c949-47a1-a30e-b0491ccae876` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b3d34dc5-2efd-4ae3-845f-8ec14921f449` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b3d57a5c-c92e-4b48-9a79-5f124b7cf964` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b3e6418f-7c7a-4fad-993a-93b65027a9f1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b447f7de-1e53-4cbf-bfb4-f1f6d0b04e4e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b471f462-eb0d-4832-be35-28d94bdb4780` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b4926b47-a9d7-434c-b3a0-adc3fa0bd13e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b4c8da4a-1c12-46b0-8a2b-0a8521d03442` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b4dc61f5-6cce-468e-a608-b48b469feaa2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b52e84a3-029e-4529-b09b-71d19dd27e94` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b53317a0-8acf-4fd1-8de8-a5401e776b96` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b55ca2a3-7cff-4dda-8bdd-c7bfa63bf544` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b5746143-59d6-4603-8d06-acbd60e166ee` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b57ba453-b384-4ab9-9f40-1038086b4e53` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b5b29e4e-31fa-4fdf-b058-296e7a1aa0c2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b5b78988-486d-4a80-b991-930eff3ff8bf` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b5c7395f-e501-4a08-94d4-57fe7a9da9d2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b61e87c0-50db-4b2e-8986-6a2be94b33b0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b6457d63-d2a2-4e29-859d-4e7affc153d1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b64a026b-8deb-4c1d-92fd-98893209dff1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b655a06a-31c0-477a-95c2-3726b83d649d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b66474aa-bd92-4333-a16c-298155b120df` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b6676963-0353-4f88-90f5-36c20d443c6a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b697e69c-746f-4a86-9f59-7bfff8eab881` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b6b49cd1-34d6-4ead-b1bf-176e9edba9a4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b6d235fc-1d38-4b12-adbe-325f06728f37` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b6d98a4f-cef0-4abf-bbf6-24132854a83d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b6e04788-29e1-4557-bb14-77f761848ab8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b6f91281-20aa-446a-b986-38a92813a18f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b730a276-6b63-41b8-bcf8-55930c8fc6ee` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b7916c2a-fa2f-4795-9477-32b731f70f11` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b7966f4a-b333-455b-8370-8ca53c229762` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b7b19cb6-9b32-4fc4-a108-73f19acfe262` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b7e2a8d4-74bb-4b78-adc9-3f92af2d4829` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b86852fb-4c77-48f9-8519-eb1b2c308b59` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b86f6dea-0b2f-41f5-bdcc-a057bd19cd6a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b888e3f2-224d-4435-b00b-9dd66e9ea1f1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b8b1b304-a60f-4999-9a6e-c547bde03ffd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b96b2031-7c17-4473-afe7-a30ce714db29` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b97cd4b1-30b8-4a9d-bd72-6293928d52bc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b98968aa-dbc0-4a9c-ac35-108363cbf8d5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b98a10af-1e1e-44a7-bab2-4cc026917648` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b98d0db6-511d-45de-ad02-e82a98729620` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b99a1518-1ad5-4f65-bc95-1ffff97a8fd0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b9aeac14-2ffd-4ad3-b967-1354a4e628c3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b9cbbc17-d00d-4e3d-a827-b06d03d2380d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b9d9cc83-380b-4ba3-8d8f-60c0e7e2930c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b9e8c7d6-a5f4-4e3d-8b1a-9f0c8d7e6a5b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.b9f0e6f5-09b4-4358-bae4-08408705bd5c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ba1f7802-adc7-48b4-9ecb-81e227fddfd5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ba226dcf-d390-4642-b9af-b534872f1156` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ba3874b9-0fae-465f-836c-eb5d071a1789` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ba3f5c1b-6272-4119-9dbd-0bc8d21c2702` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ba42babc-0666-4393-a4f7-ceaf5a69191e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ba4cfc11-d0fa-4d94-bf20-7c332c412e76` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bab049ca-7471-4828-9024-38279a4c04da` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bac9fb54-2da7-44e9-988f-11e9a5edbc0c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.baca5663-583c-45f9-b5dc-ea96a22ce542` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bacf58c6-e199-4040-a94f-95dea0f1e45a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.baecf8fb-edbf-429f-9ade-31fc3f22b970` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.baef1ec6-2ca9-47a3-97cc-4cf2bda10b77` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bafac3d6-7de9-4dd9-8874-4a1194b493ed` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bb09dd3e-2b78-4819-8e35-a7c1b874e449` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bb0e87ce-c89f-4857-84fa-095e4483e9cb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bb58aa4a-b80b-415a-a2c0-2f65a4c81009` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bb76d96b-821c-47cf-944b-7ce377864492` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bb780e0c-16cf-4383-8383-1e5471db6cf9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bbb7e38c-0b41-4a11-b306-d2a457b7ac2b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bbc865e4-7fcd-45a6-8ff1-95ced28ec5b2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bbf59793-6efb-4fa1-95ca-a7d288e52c88` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bc275be9-0bec-4d77-8c8f-281a2df6710f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bc2e25ed-b92b-4daa-b074-b502bdd1982b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bc92ca75-cd42-4d61-9a37-9d5aa259c88b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bd1212e5-78da-431e-95fa-c58e3237a8e6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bd1c6866-65fc-44b2-be51-5588fcff82b9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bd8b828d-0dca-48e1-8a63-8a58ecf2644f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bdd8157d-8e85-4397-bb82-f06cc9c71dbb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bdeb2cff-af74-4094-8426-724dc937f20a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bdeeabc9-ff2a-4a51-be59-bb253aac7891` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.be344333-921d-4c4d-8bb8-e584cf584780` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.be58d2e2-06c8-4f58-b666-b99f6dc3b6cd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bed2a484-9348-4143-8a8a-b801c979301c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bedfc8ad-d1c7-4e37-a20e-e2b0dbee759c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bef0bc5a-b9ae-425d-85c6-7b2d705980c6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bef37fa2-f205-4a7b-b484-0759bfd5f86f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bf344fea-d947-4ef4-9192-34d008315d3a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bf361876-6620-407a-812f-bfe11e51e924` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bf4fc428-dcc3-4bbd-99fe-2422aeee2544` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bf9e1387-b040-4393-9851-1598f8ecfae9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.bfbd3291-de87-4b7c-88a2-d6a5deb28668` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c02e96b7-c63a-4c47-bd83-4a9f74afcfb2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c048f047-7e2a-4888-b302-55f509d4a91d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c0514f28-fdae-42df-b886-06e2b2bc5b37` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c082c2b0-525b-4dbc-9a26-a57dc4692074` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c09dad97-1c78-4f71-b127-7edb2b8e491a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c0b2768a-dd06-4671-8339-b16ca8d1f27f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c0b40568-b1e9-4b03-8d6c-b096da6da9ab` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c0e0bdec-3e3d-47aa-9974-05539c999c89` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c11aecef-9c37-45a6-9c07-bc0782f963fd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c15a46a0-07d4-4c87-b4b6-89207835a83b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c17d47b7-dcd6-4109-87eb-d1817bd4cbc9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c1d867fe-8d95-4487-aab4-e53f2d339f90` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c260b6db-48ba-4b4a-a76f-2f67644e99d2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c265cf08-3f99-46c1-8d59-328247057d57` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c27515df-97a9-4162-8a60-dc0eeb51b775` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c2b86e67-b880-4eec-b045-50bc98ef4844` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c2c76b77-32be-4d1f-82c9-7e544bdfe0eb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c30fb093-1109-4dc8-88a8-b30d11c95a5d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c31364f7-8be6-4b77-8483-dd2b5a7b69a3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c363385c-f75d-4753-a108-c1a8e28bdbda` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c39f0c81-7348-4965-ab27-2fde35a1b641` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c3a99af4-35a9-4668-879e-c09aeb4f2bdf` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c3cefdf4-6703-4e1c-bad8-bf422fc5015a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c3d76afc-93df-461e-8e67-9b2bad3f2ac4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c3dbbc9f-ef1d-470a-a90a-d343448d5875` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c3e76af5-4ce0-4a14-9c9a-25ceb8fda182` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c3edc6a5-d9d4-48d8-930e-aab518390917` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c420410f-c2d8-4010-856b-dffe21866437` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c43a5405-e8e1-4221-9ac9-dbe3fa14e886` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c43c26be-2e87-46c7-8661-284588c5a53e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c443012c-7928-43bf-ac20-7eda5efe61ad` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c453ab7a-1f5c-4716-a3b4-dea8135fb43a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c484e533-ee16-4a93-b6ac-f0ea4868b2f1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c49c5062-0966-4170-9efd-9968c913a6cf` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c4e49831-1496-40cf-8ce1-b53f942b02f9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c4e92a97-a9ff-4392-9d2d-7a4c642768ca` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c4eeeeae-89f4-43a7-8b48-8d1bdfa66c78` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c4ff1eac-84ad-44dd-a6fb-d56a92fc43a9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c539afac-c12a-46ed-b1bd-5a5567c9f045` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c57872c7-614f-4d7f-a40d-b78c8df2d30d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c598cc0c-9e70-4852-b9eb-8921af79f598` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c5c00f49-b3f9-45a6-997e-cfdecc6e1967` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c5f6a85d-b647-40f7-bbad-c10b66bab038` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c615d676-f655-46b9-b913-78729021e5d7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c61daa90-3c1e-4f18-af62-8f288b5c9aaf` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c625d754-6a3d-4f65-9c9a-536aea960d37` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c633622e-cab9-4eaa-bb13-66a1d68b3e47` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c6c56ada-612b-42d1-9a29-adad3c5c2c1e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c73124a7-3e89-44a3-bdc1-25fe4df754b1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c740d4cf-a1e9-41de-bb16-8a46a4f57918` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c74c0390-3e20-41fd-a69a-128f0275a5ea` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c74d7efc-8826-45d9-b8bb-f04fac9e4eff` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c7942406-33dd-4377-a564-0f62db0593a3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c79da740-5030-45ec-a2e0-479e824a562c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c7c8aa1c-5aff-408e-828b-998e3620b341` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c7d33b50-f690-4b51-8cfb-0fb912a31e57` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c7da8edc-49ae-45a2-9e61-9fd860e4e73d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c7dcacd0-cc59-4004-b0a4-1d6cdebe6f3e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c7e91a02-d771-4a6d-a700-42587e0b1095` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c80e66d8-1780-48a9-b412-46663fd21ac0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c83bf4b5-cdf0-437c-90fa-43d734f7c476` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c86133ad-4725-4bd0-8170-210788e0a7ba` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c86500e9-a645-4680-98d7-f882c70c1ea3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c8a180d6-47a3-4345-a609-53f9c3d834fc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c8b00925-926c-47e3-beea-298fd563728e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c8da0dfd-4ed0-4b68-962d-13c9c884384e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c90362e0-2df3-4e61-94fe-b37615814cb1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c9192ad9-75e5-43eb-8647-82a0a5b493e3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c947b146-0abc-4c87-9c64-b17e9d7274a2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c9783e20-4793-4164-ba96-d9ee483992c4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c98f2a0d-e1b8-4f76-90d3-359caf88d6b9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c9eb55c3-b468-40ab-9089-db2862e42137` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.c9fbe8e9-119d-40a6-9b59-dd58a5d84429` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ca2092a1-c273-4878-9b4b-0d60115bf5ea` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ca387a8e-1c84-4da3-9993-028b45342d30` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ca5583e9-8f80-46ac-ab91-7f314d13b984` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ca621ba5-54ab-4035-9942-d378e6fcde3c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.caa06de8-fdef-4c91-826a-7f9e163eef4b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.caa9a802-8bd8-4b9e-a5cd-4d6221670219` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cad1fe90-2406-44dc-bd03-59d0b58fe722` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.caf201a9-c2ce-4a26-9c3a-2b9525413711` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cafeeba3-01da-4ab4-b6c4-a31b1d9730c7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cb0fe7c5-f3a3-484d-aa25-d350a7912729` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cb5a2333-56cf-4562-8fcb-22ba1bca728d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cb7c4a03-2871-43c0-9bbb-18bbdb079896` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cb9cc1d1-e84e-4bdc-b7ad-c31b1b7908ec` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cbb9e3d1-2386-4e59-912e-62f1484f7a89` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cbec226f-63d9-4eca-9f52-dfb6652f24df` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cc1abf27-78a3-4ac5-a51c-f3070b1d8e40` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cc268ac1-42d9-40fd-9ed3-8c4e1a5b87e6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cc368ed0-2411-45dc-a222-510ace303cb2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cc36992a-4671-4f21-a91d-6c2b72a2edf5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cc4e02ba-9c06-48e2-b09e-2500cace9ae0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cc7abbd0-762b-41e3-8a26-57ad50d2eea3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ccb5742c-c248-4982-8c5c-5571b9275ad3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cd0f7229-d16f-42de-8fe3-fba365fbcb3a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cd1f961e-0b96-436b-b7c6-38da4583ec00` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cd219ff3-fa99-45d4-8380-a7d15116c6dc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cd277474-5c52-4423-a52b-ac2d7969902f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cd3d1298-eb3b-476c-ac67-12847de55813` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cd5cfd80-aa5f-44c0-9c20-108c4ae12e3c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cd71385d-fd9b-4691-9b98-2b1f7e508714` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cd764533-2e07-40d6-a718-cfeec7f2da7f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cd8b36ac-8e4a-4c2f-a402-a29b8fbd5bca` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cd8c163e-a19b-402e-bdd5-419ff5859f12` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cd951fdc-4b2f-47f5-ba99-a33bf61e3770` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cdf05894-89e7-4ead-b2b0-0a5f97a90f2f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ce7066a6-508a-42d3-995b-2952c65dc2ce` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ce72ef99-22f1-43d4-8695-419dcb5d9330` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ce7cf472-6fcc-490a-9481-3786840b5d9b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cea2b7ea-792b-405f-95a1-b903ea06458f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cea72823-df4d-4567-950c-0b579eaf0846` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cec8e918-30f7-4e2d-9bfa-a59cc97ae60f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cf0c254b-22f1-4b2b-8221-e137b3c0af94` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cf2e938e-9a3e-4fe8-a347-411642b28a9f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cf93e05e-d798-4d9e-b522-b0248dc61eaf` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.cfeed607-6aa4-4bbd-9627-b637deb723c8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d00a9a72-2c09-4459-ad03-5e0a23351e36` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d042284c-a296-4988-9be5-f424fadcc28c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d047726b-c71c-4048-a99b-2e2f50dc107d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d04ae2b8-ad54-4de0-bd87-4bc1da66aa59` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d059842b-6b9d-4ed1-b5c3-5b89143c6ede` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d06be4b9-8045-428b-a567-740a26d9db25` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d08a2711-ee8b-4323-bdec-b7d85e892b31` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d08dd86f-681e-4a00-a92c-1db218754417` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d0dae994-26c6-4d2d-83b5-b3c8b79ae513` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d102b8f5-61dc-4e68-bd83-9a3187c67377` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d20ee2f4-822c-4827-9e15-41500b1fff10` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d21374ff-f574-44a7-9998-4a8c8bf33d7d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d223b46b-5621-4037-88fe-fda32eead684` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d22df9cd-2aee-4089-93c7-9dc4eae77f2c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d22e2925-cfd8-463f-96f6-89cec9d9bc5f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d26ce60c-2151-403c-9a42-49420d87b5e4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d2b749ee-4225-417e-b20e-a8d2193cbb84` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d2eb17db-1d39-41dc-b57f-301f6512fa75` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d353dac0-1b41-46c2-820c-d7d2561fc6ed` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d38d2fa4-98e6-4a24-aff1-410b0c9ad177` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d3abac66-f11c-4ed0-8acb-50cc29c97eed` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d3b70aad-097e-409c-9df2-450f80dc476b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d3bf399f-b0cf-4250-8bb4-dfc192ab81dc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d3c3861d-c504-4c77-ba55-224ba82d0118` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d4498716-1d52-438f-8084-4a603157d131` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d474c8fe-bb69-4ea0-b7d9-f682b56d52d3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d487ed4a-fd24-436d-a0b2-f4e95f7b2635` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d4e2745c-f0c6-4bde-a3ab-b553b3f693cc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d526c60a-e236-4011-b165-831ffa52ab70` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d557dc06-62e8-4468-a8e8-7984124908ce` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d55b793d-f847-4eea-b59a-5ab09908ac90` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d58ba5c6-0ed7-4b9d-a433-6878379efda9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d5b9ae7a-e6fc-405e-80ff-2ff9dcc64e7e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d65aee4d-2292-4cea-b832-83accd6cfa43` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d67572a0-e2ec-45d6-b8db-c100d14b8ef2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d679950c-abb7-43a6-80fb-2a480c4fc450` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d6a9b252-c666-4de6-8806-5561bbbd3bdc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d6b5520d-3934-48b4-928c-2aa3f92d6963` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d6c2ce7e-afb5-4337-9ca4-4b5254ed0565` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d6ce7ebd-260b-4323-9768-a9631c8d4db2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d75d6b6b-adb9-48f7-824b-ac2e786efe1f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d7654f02-e04b-4934-9838-65c46f187ebc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d7662ff6-9e97-4596-a61d-9839e32dee8d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d78b5d61-187d-44b6-bf02-93486a80de5a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d797268e-28a9-49a7-b9a8-2f5039011c5c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d7b50671-d1ad-4871-aa60-5aa5b331fe04` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d7b81144-b866-48a4-9bcc-275dc69d870e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d7bcd677-645d-4691-a8d4-7a5602b780d1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d7c75059-2901-4578-b209-8837fd31c6a8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d7eb979b-c2b5-4a6f-a3a7-c87ce6763819` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d80d5c81-04ba-45b4-84e4-92eba40e0ad3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d81871ef-5738-47ab-9797-7a9c90cd4bfb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d85873ef-a0f8-4c48-a53a-6b621f11729d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d87bd452-6da1-456e-8155-7dc988157b7d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d88d0ab2-e696-4d40-a2ed-9790064e66b3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d9047477-0359-48c9-b8c7-792cedcdc9c4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d9367cbb-c2e0-47ce-bdc0-128cb6da898d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d937b75f-a665-4480-88a5-2f20e9f9b22a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.d99b79d2-0a6f-4f46-ad8b-260b6e17f982` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.da2738f2-fadb-4394-afa7-0a0674885afa` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.da92713f-ca2d-4fab-8320-098013d3f43a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.dae8171c-5ec6-4396-b210-8466585b53e9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.dbbd9f66-2ed3-4ca2-98a4-6ea985dd1a1c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.dc5c24af-6995-49b2-86eb-a9ff62199e82` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.dcaa3f04-70c3-427a-80b4-b870d73c94c4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.dcdbc940-0bff-46b2-95f3-2d73f848e33b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.dcf2db1f-f091-425b-a821-c05875b8925a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.dcff7e85-d01f-4eb5-badd-84e2e6be8294` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.dd2a821e-3b07-4d3b-a9ac-929fe4c6ca0c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.dd3ee8cc-f751-41c9-ba53-5a32ed47e563` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.dd6b39d9-d9be-4a3b-8fe0-fe3c6a5c1795` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.dd80db93-6ec2-4f4c-a017-ad40da6ffe81` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.dd8756e7-a3a0-4768-b47e-8f545d1a751c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ddd171b5-2cc6-4975-9e78-f0eccd08cc76` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ddeff553-5233-4ae9-bbab-d64d2bd634be` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.de16d92c-c446-4d53-8938-10aeef41c8b6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.de46c52b-0bf8-4936-a327-aace94f94ac6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.de587dce-915e-4218-aac4-835ca6af6f70` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.de7ce410-b3fb-4e8a-b38c-3b999e2c3420` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.deb9b646-a508-44ee-b7c9-d8965921c6b6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.dee0a7a3-f200-4112-a99b-952196d81e42` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.dee4af55-1f22-4e1d-a9d2-4bdc7ecb472a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.def8b624-e08f-4ae1-8612-1ba21190da6b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.df1f26d3-bea7-4700-9ea2-ad3e990cf90e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.df4dc653-1029-47ba-8231-3c44238cc0ae` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.df55196f-f105-44d3-a675-e9dfb6cc2f2b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.df68f791-ad95-447f-a271-640a0dab9cf8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.df6ecb8b-7822-4f4b-b412-08f524b4576c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.dfa03a09-8b92-4d83-8e74-f72839b1c407` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.dfb5b4e8-91d0-4291-b40a-e3b0d3942c45` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.dfd2fcb7-8bd5-4daa-b132-5adb61d6ad45` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.dff1e1cc-d3fd-47c8-bfc2-aeb878a754c0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e01fa958-6893-41d4-ae03-182477c5e77d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e074832a-eada-4fd7-94a1-10642b130e16` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e0813366-0407-449a-9869-a2db1119dc41` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e0b06658-7d1d-4cd3-bf15-03467507ff7c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e0b0c2ab-3d52-46d9-8cb7-049dc775fbd1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e0c69ebd-b54f-4aed-8ae3-e3467843f3f0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e0d1ad53-c7eb-48ec-a87a-72393cc6cedc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e0f8ab85-0ac9-423b-a73a-81b3c7b1aa97` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e13f668e-7f95-443d-98d2-1816a7648a7b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e1561947-b4e3-4a74-9bdd-83baed21bdb5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e15b518d-b4ce-4410-a9cd-501f23ce4a18` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e1693bc8-7168-4eab-8718-cdcaa68a1738` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e173ad47-4388-4012-ae62-bd13f71c18a8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e1aa95de-610a-427d-b9e7-9b46cfafbe6a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e1e0b7d7-e10b-4ee4-ac49-a4bda05d320d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e20b5b14-ce93-4230-88af-981983ef6e74` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e212d415-0e93-435f-9e1a-f29005bb4723` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e218595b-bbe7-4ee5-8a96-f32a24ad3468` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e22a6eb2-f8a5-44b5-8b44-a2dbd47b1144` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e2482f8d-3443-4237-b906-cc145d87a076` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e290b10b-1023-4452-a4a9-eb31a9013b3a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e2e80da2-8c66-4e00-ae3c-2eebd29f6b6d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e31033fc-33f0-4020-9a16-faf9b31cbf08` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e312efd0-35a1-407f-8439-b8d434b438a6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e328cc73-f92a-42fb-b3fa-7c2cffda981a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e32d4572-9826-4738-b651-95fa63747e8a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e32f92d1-523e-49c3-9374-bdb13b46a3ba` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e36941d0-c0f0-443f-bc6f-cb2952eb69ea` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e37db05d-d1f9-49c8-b464-cee1a4b11638` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e3845023-ca9a-4024-b2b2-5422156d5527` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e3b50fa5-3c3f-444e-937b-0a99d33731cd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e3fdf743-f05b-4051-990a-b66919be1743` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e4a6b256-3e47-40fc-89d2-7a477edd6915` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e4a74e34-ecde-4aab-b2fb-9112dd01aed0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e4d22291-f3d5-4b78-9a0c-a1fbaf32a6a4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e4ed6030-ffe5-4e6a-8a8a-ab3c1ab9d94e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e52cb31c-10ed-4aea-bcb7-593c9f4a315b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e54979bd-c5f9-4d6c-967b-a04b19ac4c74` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e568650b-5dcd-4658-8f34-ded0b1e13992` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e56d3073-83ff-4021-90fe-c658e0709e72` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e5ac86dd-2da1-454b-be74-05d26c769d7d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e5d36acd-acb4-4c6f-a13f-9eb203d50099` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e61e8a88-59a9-451c-874e-70fcc9740d67` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e6313acd-208c-44fc-a0ff-db85d572e90e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e6474a1b-5390-49cd-ab41-8d88655f7394` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e66779cc-383e-4224-a3a4-267eeb585c40` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e6c54d94-498c-4562-a37c-b469d8e9a275` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e6e88853-5f20-4c4a-8d26-cd469fd8d31f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e6fe26ee-d063-4f5b-b007-39e90aaf50e3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e76ca062-4de0-4d79-8d90-160a0d335eca` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e7888eb1-13b0-4616-bd99-4bc0c2b054b9` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e78c408a-e2ea-43cd-b5ea-51975cf358c0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e7a21b5f-d8c4-4ae5-b8d9-93c5d3f28e1c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e7a2fd40-3ae1-4a85-bf80-15cf624fb1b1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e7b18879-676e-4a0e-ae18-27039185a8e7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e81528db-fc02-45e8-8e98-4e84aba1f10b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e83e8899-c9b2-483b-b355-5decc942b959` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e84d89c4-f544-41ca-a6af-4b92fd38b023` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e88a6ddc-74f7-463b-9b26-f69fc0d2ce85` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e890acee-d488-420e-8f20-d9b19b3c3d43` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e8a52bbd-bced-459f-bd93-64db45ce7657` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e8a95b5e-c891-46e2-b33a-93937d3abc31` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e8d34729-86a4-4140-adfd-0a29c2106307` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e9142d84-fbe0-401d-ac50-3e519fb00c89` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e92a4287-e072-4a40-9739-370c106bb750` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e94b9ddc-eec5-4bb8-8a58-b9dc5f4e185f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e96253b8-6b3b-4f90-9e59-3b24b99cf9b4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e97d9903-53b2-41fc-8cb9-889ed4093e80` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e9b61244-893f-427c-b287-3e708f321c6b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e9c8808f-4cfb-4ba9-97d4-e5f3beaa244d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e9d4ab66-a532-4ef7-a502-66a9e4a34f5d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e9f55347-2928-4c06-88e5-1a7f8169942e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e9f8f8cc-07cc-4e81-b724-f387db9175e4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.e9faba72-4974-4ab2-a4c5-46e25ad59e9b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ea011323-7045-460b-b2d7-0f7442ea6b38` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ea9bf0fa-edec-4fb8-8b78-b119f2528186` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.eb1c4225-1c23-4241-8dd4-051389fde4ce` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.eb2d07d4-49cb-4523-801a-da002df36602` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ebea773c-a8f1-42ad-a856-00cb221966e8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ebef4391-1a81-4761-a40a-1db446c0e625` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ebfe73c2-5bc9-4ed9-aaa8-8b54b2b4777d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ec0722a3-eb5c-4a56-8ab2-bf6f20708592` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ec1d5e28-8f3b-4188-a6f8-6e8df81dc28e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ec290c06-9b6b-4338-8b6b-095c0f284f10` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ec570e53-4c76-45a9-804d-dc3f355ff7a7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ec82e2a5-81ea-4211-a1f8-37a0286df2c2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ec88289a-7e1a-4cc3-8d18-bd1f60e4b9ba` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.eca49c87-8a75-4f13-9c73-a5a29e845f03` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.eca8ae39-5c3c-4321-b538-9e64fe25822e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.eca91c7c-9214-47b9-b4c5-cb1d7e4f2350` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ecbc5e16-58e0-4521-9c60-eb9a7ea4ad34` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ed5d72a6-f8f4-479d-ba79-02f6a80d7471` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ed74fe75-7594-4b4b-ae38-e38e3fd2eb23` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ed825c86-c009-4014-b413-b76003e33d35` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.edc2f8ae-2412-4dfd-b9d5-0c57727e70be` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.edd8a48c-1b9f-4ba1-83aa-490338cd1ccb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.edf3485d-dac4-4d50-90e4-b0e5813f7e60` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ee218c12-627a-4d27-9e30-d6fb2fe22ed2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ee37eb7c-a4e7-4cd5-8fa4-efa27f1c3f31` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ee5e119b-1f75-4b34-add8-3be976961e39` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ee63c85c-6d51-4d12-ad09-04e25877a947` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ee77a5db-b0f3-4be2-bfd4-b58be1c6b15a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ee9ca27c-9bd7-4cee-9b01-6e906be7cae3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.eeb30123-9fbd-4ee8-aaa0-2e545bbed6dc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.eee00933-a761-4cd0-be70-c42fe91731e7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ef61af62-bc74-4f58-b49b-626448227652` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ef64fc9c-a45e-43cc-8fd8-7d75d73b4c99` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ef9dcfed-690c-4c5d-a9d1-482cd422225c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.efc21479-9e83-41da-8cf1-122e06ba8db3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.efdd8dd5-cee8-4e59-9390-7d4d5e4dd6f6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.efec536f-72e8-4656-8960-5e85d091345b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f033f3f3-fd24-4995-97d8-a3bb17550a88` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f0507c0f-a3a2-40f5-acc6-7f543c334993` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f0540f7e-2db3-4432-b9e0-3965486744bc` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f0767f15-0fb3-44b9-851e-e8d9a6d0005d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f0ca6c24-3225-47d5-b1f5-352bf07ecfa7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f0cdd048-82dc-4f7a-8a7a-b87a52b6d0fd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f0d1feba-4344-4ca9-8121-a6c97bd6df52` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f0e2b768-5220-47dd-b891-d57b96fc0ec1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f0f7be61-9cf5-43be-9836-99d6ef448a18` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f1086bf7-a0c4-4a37-9102-01e573caf4a0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f10ed525-97fe-4fed-be7c-2feecca941b1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f117933c-980c-4f78-b384-e3d838111165` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f11f2808-adb4-46c0-802a-8660db50fa99` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f14719ce-d3ab-4e25-9ce6-2899092260b0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f14e169e-9978-4c69-acb3-1cff8200bc36` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f17211f1-1f24-4d0c-829f-31e28dc93cdd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f1edd233-30b5-4823-9e6a-c4171b24d316` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f1f3bf22-deb2-418d-8cce-e1a45e46a5bd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f208d6d8-d83a-4c2c-960d-877c37da84e5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f241cf1b-3a6b-4e1a-b4f9-133c00dd95ca` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f2485272-a156-4773-82d7-1d178bc4905b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f24bcaea-0cd1-11eb-adc1-0242ac120002` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f26307d8-14cd-47e3-a26b-4b4769f24af6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f26c6093-6f14-4b12-800f-0fcb46f5ffd0` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f26eb764-fd89-464b-85e2-dc4a8e6e77b8` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f2c64357-b1d2-41b7-849f-34d2682c0fad` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f331aa1f-8c53-4fc3-b083-cc159bc971cb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f356a9c4-effd-4608-bbf8-408afd5cd006` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f35c5d71-b489-4e22-a115-f003df287317` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f376c8a7-a2d0-4ddc-aa0c-16c17236d962` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f37aba28-a9e6-4045-882c-d5004043b337` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f37b4bce-49d0-4087-9f5b-58bffda77316` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f38a82d2-fba3-4781-b549-525efbec8506` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f38ce0b9-5e97-4b47-a211-7dc8d8b871da` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f3d39c45-de1a-4486-a687-ab126124f744` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f4264e47-f522-4c38-a420-04525d5b880f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f426547a-e0f7-441a-b63e-854ac5bdf54d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f44800ac-38ec-471f-936e-3fa7d9c53100` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f4a623c2-4ef5-4c33-b811-0642f702c9f1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f4ff7323-b5fc-4323-8b52-6b9408e15788` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f50f3c09-557d-492d-81db-9064a8d4e211` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f512acbf-e662-4903-843e-97ce4652b740` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f5240972-3938-4e56-8e4b-e33893176c1f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f53714ec-5077-420e-ad20-907ff9bb2958` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f548a603-c9f2-4c89-b511-b089f7e94549` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f576a613-2392-4067-9d1a-9345fb58d8d1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f57c58b3-ee69-4ef5-9041-455bf39aaa89` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f57f8d16-1f39-4dcb-a604-6c73d9b54b3d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f598ea0c-c25a-4f72-a219-50c44411c791` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f59c3faf-50f3-464b-9f4c-1b67ab512d99` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f5d19838-41b5-476c-98d8-ba8af4929ee2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f5e3b62f-e577-4e59-931e-0a15b2b94e1e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f5fe36cf-f1ec-4c23-903d-09a3110f6bbb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f63508a0-c809-4435-b3be-ed819394d612` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f63b56ee-3f79-4b8a-97fb-5c48007e8573` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f64e5c19-879c-4bae-b471-6d84c8339677` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f663a6d9-9d1b-49b8-b2b1-0637914d199a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f674e36a-4b91-431e-8aef-f8a96c2aca35` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f69a87ea-955e-4fb4-adb2-bb9fd6685632` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f6c68d5f-e101-4b86-8c84-7d96851fd65c` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f6d1dd2f-b8ce-40ca-bc23-062efb686b34` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f6de9536-0441-4b3f-a646-f4e00f300ffd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f6ecd1cf-19b8-4488-97f6-00f0924991a3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f72aa3e8-49f9-4c7d-bd74-f8ab84ff9bbb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f7375e28-5c14-432f-b8d1-1db26c832df3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f7385ee2-0e0c-11eb-adc1-0242ac120002` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f742bde7-9528-42e5-bd82-84f51a8387d2` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f7644214-0eb0-4ace-9455-331ec4c09253` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f7997770-92c3-4ec9-b112-774c4ef96f96` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f7b5f842-a6af-4da5-9e95-e32478f3cd2f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f7d7ebd5-a016-46e2-9c54-f9932f2d386d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f7f9ab88-7557-4a69-b30e-0a8f91b3a0e7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f8748f2c-89dc-4d95-afb0-5a2dfdbad332` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f89b08d0-77ad-4728-817b-9b16c5a69c7a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f8ad2e2c-40b6-4117-84d7-20b89896ab23` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f8aebc67-a56d-4ec9-9fbe-7b0e8b7b4efd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f8c1e80b-c73a-476a-ae24-6c72528b1521` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f8d6a15e-4bc8-4c27-8e5d-2b10f0b73e5b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f91ed517-a6ba-471d-9910-b3b4a398c0f3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f92a6f1e-a512-4a15-9735-da09e78d7273` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f956c7c1-0f60-4bc5-b7d7-b39ab3c08908` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f9578658-9e71-4711-b634-3f9b50cd3c06` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f9999590-1f94-4a34-a91e-951e47bedefd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f99abdf0-6283-4e71-bd2b-b5c048a94743` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.f9f62824-de4e-40ca-afe7-8358f76a876d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fa00b701-44c6-4679-994d-5a18afa8a707` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fa277e82-9b78-42dd-b05c-05555c7b6015` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fa3c117a-bc0d-416e-a31b-0c0e80653efb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fa5b1358-b040-4403-9868-15f7d9ab6329` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.faa031b5-21ed-4e02-8881-2591f98d82ed` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.faa48cae-6b25-4f00-a094-08947fef582f` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fabb0e80-030c-4e3e-a104-d09676991ac3` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fabfb3a7-3ce1-4445-9c7c-3c27f1051cdd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fad91067-08c5-4d1a-8d8c-d96a21b37814` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fadb84f0-4e84-4f6d-a1ce-9ef2bffb6ccd` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fb50eb7a-5ab1-43ae-bcc9-091818cb8424` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fb843269-508c-4b76-8b8d-88679db22ce7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fb9d3ff7-7348-46ab-af8c-b55f5fbf39b4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fbd7c32d-db2a-4418-b92c-566eb8911133` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fc014922-5def-4da9-a0fc-28c973f41bfb` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fc0e89b5-adb0-43c1-b749-c12a10ec37de` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fc4f4817-0c53-4683-a4ee-b17a64bc1039` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fca949cc-79ca-446e-8064-01aa7e52ece5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fcc6d700-68d9-4241-9a1a-06874d621b06` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fccfb43e-09a7-4bd2-8b37-a5a7df33386d` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fcddca7c-b9c0-4ddf-98da-e1e2d18b0157` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fcdf69e5-a3d3-452a-9724-26f2308bf2b1` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fd0f5778-d3cb-4c9a-9695-66759d04702a` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fd877b94-9bb5-4191-bb25-d79cbd93c167` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fdbf0b9d-0182-4c43-893b-a1eaab92d085` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fdeebdf0-9f3f-4d08-84a6-4c4d13e39fe4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fdfcbd78-48f1-4a4b-90ac-d82241e368c5` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fe20dda1-6f37-4379-bbe0-a98d400cae90` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fec96f39-988b-4586-b746-b93d59fd1922` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fecfd1a1-cc78-4313-a1ea-2ee2e8ec27a7` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.fed85bf9-e075-4280-9159-fbe8a023d6fa` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ff151c33-45fa-475d-af4f-c2f93571f4fe` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ff23ffbc-3378-435e-992f-0624dcf93ab4` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ff2fff64-4cd6-4a2b-ba7d-e28a30bbe66b` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ff3b6b39-e765-42f9-bb2c-ea6761e0e0f6` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ff992eac-6449-4c60-8c1d-91c9722a1d48` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ffa28e60-bdb1-46e0-9f82-05f7a61cc06e` | 0 | 0 | 0 | 0 | 无正样本 |
| `sigma.ffa6861c-4461-4f59-8a41-578c39f3f23e` | 0 | 0 | 0 | 0 | 无正样本 |
| `ssh.bruteforce` | 2 | 2 | 0 | 0 | 通过 |
| `ssh.bruteforce.success` | 1 | 1 | 0 | 0 | 通过 |
| `ssh.password_spray` | 1 | 1 | 0 | 0 | 通过 |
| `ssh.privileged_login` | 3 | 3 | 0 | 0 | 通过 |
| `web.404_scan` | 1 | 1 | 0 | 0 | 通过 |
| `web.5xx_burst` | 1 | 1 | 0 | 0 | 通过 |
| `web.auth_bruteforce` | 1 | 1 | 0 | 0 | 通过 |
| `web.auth_bruteforce.success` | 1 | 1 | 0 | 0 | 通过 |
| `web.cloud_metadata_access` | 1 | 1 | 0 | 0 | 通过 |
| `web.command_injection` | 1 | 1 | 0 | 0 | 通过 |
| `web.path_traversal` | 4 | 4 | 0 | 0 | 通过 |
| `web.scanner_user_agent` | 1 | 1 | 0 | 0 | 通过 |
| `web.sensitive_file_access` | 1 | 1 | 0 | 0 | 通过 |
| `web.sensitive_file_access.success` | 2 | 2 | 0 | 0 | 通过 |
| `web.sensitive_interface` | 4 | 4 | 0 | 0 | 通过 |
| `web.sensitive_path` | 2 | 2 | 0 | 0 | 通过 |
| `web.sql_injection` | 1 | 1 | 0 | 0 | 通过 |
| `web.webshell` | 1 | 1 | 0 | 0 | 通过 |
| `web.xss` | 1 | 1 | 0 | 0 | 通过 |
| `windows.account_discovery` | 1 | 1 | 0 | 0 | 通过 |
| `windows.account_lockout` | 1 | 1 | 0 | 0 | 通过 |
| `windows.account_manipulation` | 1 | 1 | 0 | 0 | 通过 |
| `windows.archive_with_password` | 2 | 2 | 0 | 0 | 通过 |
| `windows.auth_export.abnormal_time` | 1 | 1 | 0 | 0 | 通过 |
| `windows.auth_export.suspicious_ip` | 1 | 1 | 0 | 0 | 通过 |
| `windows.certutil_decode` | 1 | 1 | 0 | 0 | 通过 |
| `windows.command_shell_suspicious_parent` | 1 | 1 | 0 | 0 | 通过 |
| `windows.create_local_account` | 1 | 1 | 0 | 0 | 通过 |
| `windows.credential_file_access` | 2 | 2 | 0 | 0 | 通过 |
| `windows.credential_hunting` | 1 | 1 | 0 | 0 | 通过 |
| `windows.data_destruction` | 1 | 1 | 0 | 0 | 通过 |
| `windows.defender_exclusion_added` | 1 | 1 | 0 | 0 | 通过 |
| `windows.discovery_command` | 2 | 2 | 0 | 0 | 通过 |
| `windows.eventlog_cleared` | 1 | 1 | 0 | 0 | 通过 |
| `windows.executable_drop_in_temp` | 1 | 1 | 0 | 0 | 通过 |
| `windows.file_directory_discovery` | 1 | 1 | 0 | 0 | 通过 |
| `windows.hidden_file_attrib` | 1 | 1 | 0 | 0 | 通过 |
| `windows.inhibit_recovery` | 1 | 1 | 0 | 0 | 通过 |
| `windows.lolbin_download` | 2 | 2 | 0 | 0 | 通过 |
| `windows.lsass_memory_dump` | 1 | 1 | 0 | 0 | 通过 |
| `windows.masquerade_extension` | 2 | 2 | 0 | 0 | 通过 |
| `windows.network_connection_discovery` | 1 | 1 | 0 | 0 | 通过 |
| `windows.payload_cleanup` | 2 | 2 | 0 | 0 | 通过 |
| `windows.payload_outbound_connection` | 2 | 2 | 0 | 0 | 通过 |
| `windows.privileged_logon` | 3 | 3 | 0 | 0 | 通过 |
| `windows.protection_service_stopped` | 1 | 1 | 0 | 0 | 通过 |
| `windows.ransomware_extension` | 1 | 1 | 0 | 0 | 通过 |
| `windows.registry_bulk_write` | 2 | 2 | 0 | 0 | 通过 |
| `windows.registry_certificate_store` | 2 | 2 | 0 | 0 | 通过 |
| `windows.registry_run_key` | 1 | 1 | 0 | 0 | 通过 |
| `windows.sam_registry_dump` | 1 | 1 | 0 | 0 | 通过 |
| `windows.scheduled_task_persistence` | 1 | 1 | 0 | 0 | 通过 |
| `windows.script_interpreter_encoded` | 1 | 1 | 0 | 0 | 通过 |
| `windows.security_service_stop` | 1 | 1 | 0 | 0 | 通过 |
| `windows.service_install` | 1 | 1 | 0 | 0 | 通过 |
| `windows.suspicious_dns_query` | 2 | 2 | 0 | 0 | 通过 |
| `windows.suspicious_executable_in_temp` | 2 | 2 | 0 | 0 | 通过 |
| `windows.uac_bypass` | 1 | 1 | 0 | 0 | 通过 |

## 用例明细

| 用例 | 归属 | 期望 | 实际 | 结果 |
| --- | --- | --- | --- | --- |
| ssh-20-failures-only | 认证类（SSH / Windows / 通用结构化） | ssh.bruteforce | ssh.bruteforce | 通过 |
| ssh-20-failures-then-success | 认证类（SSH / Windows / 通用结构化） | ssh.bruteforce.success, ssh.privileged_login | ssh.bruteforce.success, ssh.privileged_login | 通过 |
| ssh-privileged-login-single | 认证类（SSH / Windows / 通用结构化） | ssh.privileged_login | ssh.privileged_login | 通过 |
| ssh-below-threshold-negative | 认证类（SSH / Windows / 通用结构化） | 无事件 | 无事件 | 通过 |
| ssh-success-outside-association-window | 认证类（SSH / Windows / 通用结构化） | ssh.bruteforce, ssh.privileged_login | ssh.bruteforce, ssh.privileged_login | 通过 |
| structured-json-auth-bruteforce-success | 认证类（SSH / Windows / 通用结构化） | auth.bruteforce.success | auth.bruteforce.success | 通过 |
| structured-csv-auth-bruteforce-only | 认证类（SSH / Windows / 通用结构化） | auth.bruteforce | auth.bruteforce | 通过 |
| ssh-password-spray | 认证类（SSH / Windows / 通用结构化） | ssh.password_spray | ssh.password_spray | 通过 |
| structured-json-auth-password-spray | 认证类（SSH / Windows / 通用结构化） | auth.password_spray | auth.password_spray | 通过 |
| ssh-repeated-single-account-negative | 认证类（SSH / Windows / 通用结构化） | 无事件 | 无事件 | 通过 |
| db-mysql-bruteforce-10-failures | 数据库（MySQL / PostgreSQL / MongoDB / Redis） | db.bruteforce | db.bruteforce | 通过 |
| db-mysql-bruteforce-then-success | 数据库（MySQL / PostgreSQL / MongoDB / Redis） | db.bruteforce.success | db.bruteforce.success | 通过 |
| db-mysql-sql-injection | 数据库（MySQL / PostgreSQL / MongoDB / Redis） | db.sql_injection | db.sql_injection | 通过 |
| db-mysql-destructive-query | 数据库（MySQL / PostgreSQL / MongoDB / Redis） | db.destructive_query | db.destructive_query | 通过 |
| db-mysql-delete-without-where | 数据库（MySQL / PostgreSQL / MongoDB / Redis） | db.destructive_query | db.destructive_query | 通过 |
| db-mysql-delete-with-where-negative | 数据库（MySQL / PostgreSQL / MongoDB / Redis） | 无事件 | 无事件 | 通过 |
| db-mysql-privilege-escalation | 数据库（MySQL / PostgreSQL / MongoDB / Redis） | db.privilege_escalation | db.privilege_escalation | 通过 |
| db-mysql-data-exfiltration | 数据库（MySQL / PostgreSQL / MongoDB / Redis） | db.data_exfiltration | db.data_exfiltration | 通过 |
| db-postgres-privileged-login | 数据库（MySQL / PostgreSQL / MongoDB / Redis） | db.privileged_login | db.privileged_login | 通过 |
| db-mongodb-bruteforce-10-failures | 数据库（MySQL / PostgreSQL / MongoDB / Redis） | db.bruteforce | db.bruteforce | 通过 |
| db-redis-bruteforce-10-failures | 数据库（MySQL / PostgreSQL / MongoDB / Redis） | db.bruteforce | db.bruteforce | 通过 |
| db-mysql-normal-query | 数据库（MySQL / PostgreSQL / MongoDB / Redis） | 无事件 | 无事件 | 通过 |
| db-mysql-bruteforce-below-threshold | 数据库（MySQL / PostgreSQL / MongoDB / Redis） | 无事件 | 无事件 | 通过 |
| db-sqlserver-bruteforce-10-failures | 数据库（MySQL / PostgreSQL / MongoDB / Redis） | db.bruteforce | db.bruteforce | 通过 |
| db-oracle-bruteforce-10-failures | 数据库（MySQL / PostgreSQL / MongoDB / Redis） | db.bruteforce | db.bruteforce | 通过 |
| domain-auth-export-suspicious-ip | 域控异常登录导出 | windows.auth_export.suspicious_ip | windows.auth_export.suspicious_ip | 通过 |
| domain-auth-export-abnormal-time | 域控异常登录导出 | windows.auth_export.abnormal_time | windows.auth_export.abnormal_time | 通过 |
| domain-auth-export-non-high-negative | 域控异常登录导出 | 无事件 | 无事件 | 通过 |
| firewall-10-distinct-ports | 网络设备（Firewall / WAF 键值 syslog） | firewall.port_scan | firewall.port_scan | 通过 |
| firewall-9-ports-negative | 网络设备（Firewall / WAF 键值 syslog） | 无事件 | 无事件 | 通过 |
| firewall-same-port-repeat-negative | 网络设备（Firewall / WAF 键值 syslog） | 无事件 | 无事件 | 通过 |
| scenario-sysmon-intrusion-chain | 攻击链场景（整份真实样本日志，回归基线） | windows.archive_with_password, windows.credential_file_access, windows.discovery_command, windows.lolbin_download, windows.masquerade_extension, windows.payload_cleanup, windows.payload_outbound_connection, windows.registry_bulk_write, windows.registry_certificate_store, windows.suspicious_dns_query, windows.suspicious_executable_in_temp | sigma.863218bd-c7d0-4c52-80cd-0a96c09f54af, sigma.9fbf5927-5261-4284-a71d-f681029ea574, sigma.c09dad97-1c78-4f71-b127-7edb2b8e491a, windows.archive_with_password, windows.credential_file_access, windows.discovery_command, windows.lolbin_download, windows.masquerade_extension, windows.payload_cleanup, windows.payload_outbound_connection, windows.registry_bulk_write, windows.registry_certificate_store, windows.suspicious_dns_query, windows.suspicious_executable_in_temp | 通过 |
| scenario-nginx-sensitive-file-probe | 攻击链场景（整份真实样本日志，回归基线） | web.path_traversal, web.sensitive_file_access.success, web.sensitive_interface | web.path_traversal, web.sensitive_file_access.success, web.sensitive_interface | 通过 |
| syslog-app-security-scenario | syslog / 容器日志（前缀剥离 + 应用层安全信号） | app.auth_threshold_block, app.restricted_resource_access, app.sensitive_path_probe, web.sensitive_interface, web.sensitive_path | app.auth_threshold_block, app.restricted_resource_access, app.sensitive_path_probe, web.sensitive_interface, web.sensitive_path | 通过 |
| syslog-normal-business-negative | syslog / 容器日志（前缀剥离 + 应用层安全信号） | 无事件 | 无事件 | 通过 |
| sysmon-lolbin-payload-download | Windows Sysmon（进程与命令行事件，XML 导出） | windows.lolbin_download | sigma.863218bd-c7d0-4c52-80cd-0a96c09f54af, windows.lolbin_download | 通过 |
| sysmon-execution-from-inetcache | Windows Sysmon（进程与命令行事件，XML 导出） | windows.masquerade_extension, windows.suspicious_executable_in_temp | sigma.c09dad97-1c78-4f71-b127-7edb2b8e491a, windows.masquerade_extension, windows.suspicious_executable_in_temp | 通过 |
| sysmon-password-protected-archive | Windows Sysmon（进程与命令行事件，XML 导出） | windows.archive_with_password | sigma.9fbf5927-5261-4284-a71d-f681029ea574, windows.archive_with_password | 通过 |
| sysmon-normal-processes-negative | Windows Sysmon（进程与命令行事件，XML 导出） | 无事件 | 无事件 | 通过 |
| sysmon-credential-file-operation | Windows Sysmon（进程与命令行事件，XML 导出） | windows.credential_file_access | windows.credential_file_access | 通过 |
| sysmon-payload-self-delete | Windows Sysmon（进程与命令行事件，XML 导出） | windows.payload_cleanup | windows.payload_cleanup | 通过 |
| sysmon-registry-certificate-store | Windows Sysmon（进程与命令行事件，XML 导出） | windows.registry_certificate_store | windows.registry_certificate_store | 通过 |
| sysmon-random-domain-dns | Windows Sysmon（进程与命令行事件，XML 导出） | windows.suspicious_dns_query | windows.suspicious_dns_query | 通过 |
| sysmon-repeated-discovery-command | Windows Sysmon（进程与命令行事件，XML 导出） | windows.discovery_command | windows.discovery_command | 通过 |
| sysmon-payload-outbound-connection | Windows Sysmon（进程与命令行事件，XML 导出） | windows.payload_outbound_connection | windows.payload_outbound_connection | 通过 |
| sysmon-executable-drop-in-temp | Windows Sysmon（进程与命令行事件，XML 导出） | windows.executable_drop_in_temp | windows.executable_drop_in_temp | 通过 |
| sysmon-registry-bulk-write | Windows Sysmon（进程与命令行事件，XML 导出） | windows.registry_bulk_write | windows.registry_bulk_write | 通过 |
| sysmon-benign-administration-negative | Windows Sysmon（进程与命令行事件，XML 导出） | 无事件 | 无事件 | 通过 |
| sysmon-encoded-command-execution | Windows Sysmon（进程与命令行事件，XML 导出） | windows.script_interpreter_encoded | sigma.438025f9-5856-4663-83f7-52f878a70a50, sigma.b9d9cc83-380b-4ba3-8d8f-60c0e7e2930c, sigma.ca2092a1-c273-4878-9b4b-0d60115bf5ea, sigma.fb843269-508c-4b76-8b8d-88679db22ce7, windows.script_interpreter_encoded | 通过 |
| sysmon-document-spawns-command-shell | Windows Sysmon（进程与命令行事件，XML 导出） | windows.command_shell_suspicious_parent | sigma.438025f9-5856-4663-83f7-52f878a70a50, windows.command_shell_suspicious_parent | 通过 |
| sysmon-normal-interpreter-usage-negative | Windows Sysmon（进程与命令行事件，XML 导出） | 无事件 | 无事件 | 通过 |
| sysmon-scheduled-task-persistence | Windows Sysmon（进程与命令行事件，XML 导出） | windows.scheduled_task_persistence | sigma.24c8392b-aa3c-46b7-a545-43f71657fe98, sigma.92626ddd-662c-49e3-ac59-f6535f12d189, windows.scheduled_task_persistence | 通过 |
| sysmon-scheduled-task-query-negative | Windows Sysmon（进程与命令行事件，XML 导出） | 无事件 | 无事件 | 通过 |
| sysmon-inhibit-recovery-vssadmin | Windows Sysmon（进程与命令行事件，XML 导出） | windows.inhibit_recovery | sigma.c947b146-0abc-4c87-9c64-b17e9d7274a2, windows.inhibit_recovery | 通过 |
| sysmon-vssadmin-list-negative | Windows Sysmon（进程与命令行事件，XML 导出） | 无事件 | 无事件 | 通过 |
| sysmon-ransomware-extension | Windows Sysmon（进程与命令行事件，XML 导出） | windows.ransomware_extension | windows.ransomware_extension | 通过 |
| sysmon-temp-file-negative | Windows Sysmon（进程与命令行事件，XML 导出） | 无事件 | 无事件 | 通过 |
| sysmon-security-service-stop | Windows Sysmon（进程与命令行事件，XML 导出） | windows.security_service_stop | sigma.ce72ef99-22f1-43d4-8695-419dcb5d9330, windows.security_service_stop | 通过 |
| sysmon-normal-service-stop-negative | Windows Sysmon（进程与命令行事件，XML 导出） | 无事件 | 无事件 | 通过 |
| sysmon-data-destruction-cipher-w | Windows Sysmon（进程与命令行事件，XML 导出） | windows.data_destruction | sigma.4b046706-5789-4673-b111-66f25fe99534, windows.data_destruction | 通过 |
| sysmon-cipher-encrypt-negative | Windows Sysmon（进程与命令行事件，XML 导出） | 无事件 | 无事件 | 通过 |
| sysmon-lsass-memory-dump | Windows Sysmon（进程与命令行事件，XML 导出） | windows.lsass_memory_dump | sigma.2e65275c-8288-4ab4-aeb7-6274f58b6b20, sigma.7cce6fc8-a07f-4d84-a53e-96e1879843c9, sigma.ffa6861c-4461-4f59-8a41-578c39f3f23e, windows.lsass_memory_dump | 通过 |
| sysmon-lsass-query-not-dump-negative | Windows Sysmon（进程与命令行事件，XML 导出） | 无事件 | 无事件 | 通过 |
| sysmon-sam-hive-export | Windows Sysmon（进程与命令行事件，XML 导出） | windows.sam_registry_dump | sigma.fd877b94-9bb5-4191-bb25-d79cbd93c167, windows.sam_registry_dump | 通过 |
| sysmon-reg-save-software-negative | Windows Sysmon（进程与命令行事件，XML 导出） | 无事件 | 无事件 | 通过 |
| sysmon-credential-hunting-findstr | Windows Sysmon（进程与命令行事件，XML 导出） | windows.credential_hunting | windows.credential_hunting | 通过 |
| sysmon-findstr-error-search-negative | Windows Sysmon（进程与命令行事件，XML 导出） | 无事件 | 无事件 | 通过 |
| sysmon-eventlog-cleared | Windows Sysmon（进程与命令行事件，XML 导出） | windows.eventlog_cleared | sigma.cc36992a-4671-4f21-a91d-6c2b72a2edf5, windows.eventlog_cleared | 通过 |
| sysmon-wevtutil-query-negative | Windows Sysmon（进程与命令行事件，XML 导出） | 无事件 | 无事件 | 通过 |
| sysmon-defender-exclusion-added | Windows Sysmon（进程与命令行事件，XML 导出） | windows.defender_exclusion_added | sigma.17769c90-230e-488b-a463-e05c08e9d48f, windows.defender_exclusion_added | 通过 |
| sysmon-defender-get-preference-negative | Windows Sysmon（进程与命令行事件，XML 导出） | 无事件 | 无事件 | 通过 |
| sysmon-certutil-decode | Windows Sysmon（进程与命令行事件，XML 导出） | windows.certutil_decode | windows.certutil_decode | 通过 |
| sysmon-certutil-hashfile-negative | Windows Sysmon（进程与命令行事件，XML 导出） | 无事件 | 无事件 | 通过 |
| sysmon-uac-bypass-registry-hijack | Windows Sysmon（进程与命令行事件，XML 导出） | windows.uac_bypass | windows.uac_bypass | 通过 |
| sysmon-normal-registry-write-negative | Windows Sysmon（进程与命令行事件，XML 导出） | 无事件 | 无事件 | 通过 |
| sysmon-hidden-file-attrib | Windows Sysmon（进程与命令行事件，XML 导出） | windows.hidden_file_attrib | windows.hidden_file_attrib | 通过 |
| sysmon-attrib-hidden-only-negative | Windows Sysmon（进程与命令行事件，XML 导出） | 无事件 | 无事件 | 通过 |
| sysmon-create-local-account | Windows Sysmon（进程与命令行事件，XML 导出） | windows.create_local_account | sigma.cd219ff3-fa99-45d4-8380-a7d15116c6dc, windows.create_local_account | 通过 |
| sysmon-net-user-query-negative | Windows Sysmon（进程与命令行事件，XML 导出） | 无事件 | 无事件 | 通过 |
| sysmon-account-added-to-admins | Windows Sysmon（进程与命令行事件，XML 导出） | windows.account_manipulation | sigma.ad720b90-25ad-43ff-9b5e-5c841facc8e5, windows.account_manipulation | 通过 |
| sysmon-localgroup-list-negative | Windows Sysmon（进程与命令行事件，XML 导出） | 无事件 | 无事件 | 通过 |
| sysmon-registry-run-key-persistence | Windows Sysmon（进程与命令行事件，XML 导出） | windows.registry_run_key | windows.registry_run_key | 通过 |
| sysmon-normal-registry-value-negative | Windows Sysmon（进程与命令行事件，XML 导出） | 无事件 | 无事件 | 通过 |
| sysmon-repeated-netstat | Windows Sysmon（进程与命令行事件，XML 导出） | windows.network_connection_discovery | windows.network_connection_discovery | 通过 |
| sysmon-single-netstat-negative | Windows Sysmon（进程与命令行事件，XML 导出） | 无事件 | 无事件 | 通过 |
| sysmon-repeated-directory-traversal | Windows Sysmon（进程与命令行事件，XML 导出） | windows.file_directory_discovery | windows.file_directory_discovery | 通过 |
| sysmon-single-directory-listing-negative | Windows Sysmon（进程与命令行事件，XML 导出） | 无事件 | 无事件 | 通过 |
| sysmon-wmic-account-enumeration | Windows Sysmon（进程与命令行事件，XML 导出） | windows.account_discovery | windows.account_discovery | 通过 |
| sysmon-wmic-process-query-negative | Windows Sysmon（进程与命令行事件，XML 导出） | 无事件 | 无事件 | 通过 |
| web-sensitive-path | Web 访问日志（Nginx / Apache / IIS 及结构化 Web 事件） | sigma.953d460b-f810-420a-97a2-cfca4c98e602, web.sensitive_path | sigma.953d460b-f810-420a-97a2-cfca4c98e602, web.sensitive_path | 通过 |
| web-path-traversal | Web 访问日志（Nginx / Apache / IIS 及结构化 Web 事件） | web.path_traversal | web.path_traversal | 通过 |
| web-404-scan | Web 访问日志（Nginx / Apache / IIS 及结构化 Web 事件） | web.404_scan | web.404_scan | 通过 |
| web-5xx-burst | Web 访问日志（Nginx / Apache / IIS 及结构化 Web 事件） | web.5xx_burst | web.5xx_burst | 通过 |
| web-sql-injection | Web 访问日志（Nginx / Apache / IIS 及结构化 Web 事件） | sigma.5513deaf-f49a-46c2-a6c8-3f111b5cb453, web.sql_injection | sigma.5513deaf-f49a-46c2-a6c8-3f111b5cb453, web.sql_injection | 通过 |
| web-xss | Web 访问日志（Nginx / Apache / IIS 及结构化 Web 事件） | sigma.65354b83-a2ea-4ea6-8414-3ab38be0d409, web.xss | sigma.65354b83-a2ea-4ea6-8414-3ab38be0d409, web.xss | 通过 |
| web-command-injection | Web 访问日志（Nginx / Apache / IIS 及结构化 Web 事件） | web.command_injection | web.command_injection | 通过 |
| web-sensitive-interface | Web 访问日志（Nginx / Apache / IIS 及结构化 Web 事件） | web.sensitive_interface | web.sensitive_interface | 通过 |
| web-webshell-upload | Web 访问日志（Nginx / Apache / IIS 及结构化 Web 事件） | web.webshell | web.webshell | 通过 |
| web-scanner-user-agent | Web 访问日志（Nginx / Apache / IIS 及结构化 Web 事件） | sigma.19aa4f58-94ca-45ff-bc34-92e533c0994a, web.scanner_user_agent | sigma.19aa4f58-94ca-45ff-bc34-92e533c0994a, web.scanner_user_agent | 通过 |
| web-auth-bruteforce-only | Web 访问日志（Nginx / Apache / IIS 及结构化 Web 事件） | web.auth_bruteforce | web.auth_bruteforce | 通过 |
| web-auth-bruteforce-success | Web 访问日志（Nginx / Apache / IIS 及结构化 Web 事件） | web.auth_bruteforce.success | web.auth_bruteforce.success | 通过 |
| web-login-failures-below-threshold-negative | Web 访问日志（Nginx / Apache / IIS 及结构化 Web 事件） | 无事件 | 无事件 | 通过 |
| web-normal-traffic-negative | Web 访问日志（Nginx / Apache / IIS 及结构化 Web 事件） | 无事件 | 无事件 | 通过 |
| web-sigma-path-traversal | Web 访问日志（Nginx / Apache / IIS 及结构化 Web 事件） | sigma.7745c2ea-24a5-4290-b680-04359cb84b35, web.path_traversal | sigma.7745c2ea-24a5-4290-b680-04359cb84b35, web.path_traversal | 通过 |
| web-sigma-java-payload | Web 访问日志（Nginx / Apache / IIS 及结构化 Web 事件） | sigma.583aa0a2-30b1-4d62-8bf3-ab73689efe6c | sigma.583aa0a2-30b1-4d62-8bf3-ab73689efe6c | 通过 |
| web-sensitive-file-read-success | Web 访问日志（Nginx / Apache / IIS 及结构化 Web 事件） | web.sensitive_file_access.success | web.sensitive_file_access.success | 通过 |
| web-sensitive-file-probe-denied | Web 访问日志（Nginx / Apache / IIS 及结构化 Web 事件） | web.sensitive_file_access | web.sensitive_file_access | 通过 |
| web-metrics-endpoint-probe | Web 访问日志（Nginx / Apache / IIS 及结构化 Web 事件） | web.sensitive_interface | web.sensitive_interface | 通过 |
| web-ipv6-client-path-traversal | Web 访问日志（Nginx / Apache / IIS 及结构化 Web 事件） | web.path_traversal | web.path_traversal | 通过 |
| web-health-check-negative | Web 访问日志（Nginx / Apache / IIS 及结构化 Web 事件） | 无事件 | 无事件 | 通过 |
| web-cloud-metadata-probe | Web 访问日志（Nginx / Apache / IIS 及结构化 Web 事件） | web.cloud_metadata_access | web.cloud_metadata_access | 通过 |
| web-normal-metadata-page-negative | Web 访问日志（Nginx / Apache / IIS 及结构化 Web 事件） | 无事件 | 无事件 | 通过 |
| rdp-10-failures-then-success | Windows Security / RDP（事件查看器文本导出的精简格式） | rdp.bruteforce.success, windows.privileged_logon | rdp.bruteforce.success, windows.privileged_logon | 通过 |
| rdp-10-failures-only | Windows Security / RDP（事件查看器文本导出的精简格式） | rdp.bruteforce | rdp.bruteforce | 通过 |
| rdp-below-threshold-negative | Windows Security / RDP（事件查看器文本导出的精简格式） | 无事件 | 无事件 | 通过 |
| windows-privileged-logon-only | Windows Security / RDP（事件查看器文本导出的精简格式） | windows.privileged_logon | windows.privileged_logon | 通过 |
| windows-non-privileged-success-negative | Windows Security / RDP（事件查看器文本导出的精简格式） | 无事件 | 无事件 | 通过 |
| windows-network-logon-type3 | Windows Security / RDP（事件查看器文本导出的精简格式） | rdp.bruteforce.success | rdp.bruteforce.success | 通过 |
| windows-sigma-denied-rdp-access | Windows Security / RDP（事件查看器文本导出的精简格式） | sigma.8e5c03fa-b7f0-11ea-b242-07e0576828d9 | sigma.8e5c03fa-b7f0-11ea-b242-07e0576828d9 | 通过 |
| windows-event-kv-credential-attack-scenario | Windows Security / RDP（事件查看器文本导出的精简格式） | windows.account_lockout, windows.privileged_logon, windows.service_install | sigma.b28e58e4-2a72-4fae-bdee-0fbe904db642, windows.account_lockout, windows.privileged_logon, windows.service_install | 通过 |
| windows-event-kv-normal-negative | Windows Security / RDP（事件查看器文本导出的精简格式） | 无事件 | 无事件 | 通过 |
| windows-protection-service-stopped-positive | Windows Security / RDP（事件查看器文本导出的精简格式） | windows.protection_service_stopped | windows.protection_service_stopped | 通过 |
| windows-protection-service-negative | Windows Security / RDP（事件查看器文本导出的精简格式） | 无事件 | 无事件 | 通过 |

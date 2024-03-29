use crate::core::{interpolate_env_vars, UserEnvVars};

pub const FOLDERID_ACCOUNT_PICTURES :&str = "{008CA0B1-55B4-4C56-B8A8-4DE4B299D3BE}";
pub const FOLDERID_ADMINTOOLS :&str = "{724EF170-A42D-4FEF-9F26-B60E846FBA4F}";
pub const FOLDERID_APPDATADESKTOP :&str = "{B2C5E279-7ADD-439F-B28C-C41FE1BBF672}";
pub const FOLDERID_APPDATADOCUMENTS :&str = "{7BE16610-1F7F-44AC-BFF0-83E15F2FFCA1}";
pub const FOLDERID_APPDATAFAVORITES :&str = "{7CFBEFBC-DE1F-45AA-B843-A542AC536CC9}";
pub const FOLDERID_APPDATAPROGRAMDATA :&str = "{559D40A3-A036-40FA-AF61-84CB430A4D34}";
pub const FOLDERID_APPLICATIONSHORTCUTS :&str = "{A3918781-E5F2-4890-B3D9-A7E54332328C}";
pub const FOLDERID_CAMERAROLL :&str = "{AB5FB87B-7CE2-4F83-915D-550846C9537B}";
pub const FOLDERID_CDBURNING :&str = "{9E52AB10-F80D-49DF-ACB8-4330F5687855}";
pub const FOLDERID_COMMONADMINTOOLS :&str = "{D0384E7D-BAC3-4797-8F14-CBA229B392B5}";
pub const FOLDERID_COMMONOEMLINKS :&str = "{C1BAE2D0-10DF-4334-BEDD-7AA20B227A9D}";
pub const FOLDERID_COMMONPROGRAMS :&str = "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}";
pub const FOLDERID_COMMONSTARTMENU :&str = "{A4115719-D62E-491D-AA7C-E74B8BE3B067}";
pub const FOLDERID_COMMONSTARTUP :&str = "{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}";
pub const FOLDERID_COMMONTEMPLATES :&str = "{B94237E7-57AC-4347-9151-B08C6C32D1F7}";
pub const FOLDERID_CONTACTS :&str = "{56784854-C6CB-462B-8169-88E350ACB882}";
pub const FOLDERID_COOKIES :&str = "{2B0F765D-C0E9-4171-908E-08A611B84FF6}";
pub const FOLDERID_DESKTOP :&str = "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}";
pub const FOLDERID_DEVICEMETADATASTORE :&str = "{5CE4A5E9-E4EB-479D-B89F-130C02886155}";
pub const FOLDERID_DOCUMENTS :&str = "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}";
pub const FOLDERID_DOCUMENTSLIBRARY :&str = "{7B0DB17D-9CD2-4A93-9733-46CC89022E7C}";
pub const FOLDERID_DOWNLOADS :&str = "{374DE290-123F-4565-9164-39C4925E467B}";
pub const FOLDERID_FAVORITES :&str = "{1777F761-68AD-4D8A-87BD-30B759FA33DD}";
pub const FOLDERID_FONTS :&str = "{FD228CB7-AE11-4AE3-864C-16F3910AB8FE}";
pub const FOLDERID_GAMETASKS :&str = "{054FAE61-4DD8-4787-80B6-090220C4B700}";
pub const FOLDERID_HISTORY :&str = "{D9DC8A3B-B784-432E-A781-5A1130A75963}";
pub const FOLDERID_IMPLICITAPPSHORTCUTS :&str = "{BCB5256F-79F6-4CEE-B725-DC34E402FD46}";
pub const FOLDERID_INTERNETCACHE :&str = "{352481E8-33BE-4251-BA85-6007CAEDCF9D}";
pub const FOLDERID_LIBRARIES :&str = "{1B3EA5DC-B587-4786-B4EF-BD1DC332AEAE}";
pub const FOLDERID_LINKS :&str = "{BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968}";
pub const FOLDERID_LOCALAPPDATA :&str = "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}";
pub const FOLDERID_LOCALAPPDATALOW :&str = "{A520A1A4-1780-4FF6-BD18-167343C5AF16}";
pub const FOLDERID_MUSIC :&str = "{4BD8D571-6D19-48D3-BE97-422220080E43}";
pub const FOLDERID_MUSICLIBRARY :&str = "{2112AB0A-C86A-4FFE-A368-0DE96E47012E}";
pub const FOLDERID_NETHOOD :&str = "{C5ABBF53-E17F-4121-8900-86626FC2C973}";
pub const FOLDERID_OBJECTS3D :&str = "{31C0DD25-9439-4F12-BF41-7FF4EDA38722}";
pub const FOLDERID_ORIGINALIMAGES :&str = "{2C36C0AA-5812-4B87-BFD0-4CD0DFB19B39}";
pub const FOLDERID_PHOTOALBUMS :&str = "{69D2CF90-FC33-4FB7-9A0C-EBB0F0FCB43C}";
pub const FOLDERID_PICTURESLIBRARY :&str = "{A990AE9F-A03B-4E80-94BC-9912D7504104}";
pub const FOLDERID_PICTURES :&str = "{33E28130-4E1E-4676-835A-98395C3BC3BB}";
pub const FOLDERID_PLAYLISTS :&str = "{DE92C1C7-837F-4F69-A3BB-86E631204A23}";
pub const FOLDERID_PRINTHOOD :&str = "{9274BD8D-CFD1-41C3-B35E-B13F55A758F4}";
pub const FOLDERID_PROFILE :&str = "{5E6C858F-0E22-4760-9AFE-EA3317B67173}";
pub const FOLDERID_PROGRAMDATA :&str = "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}";
pub const FOLDERID_PROGRAMFILES :&str = "{905E63B6-C1BF-494E-B29C-65B732D3D21A}";
pub const FOLDERID_PROGRAMFILESX64 :&str = "{6D809377-6AF0-444B-8957-A3773F02200E}";
pub const FOLDERID_PROGRAMFILESX86 :&str = "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}";
pub const FOLDERID_PROGRAMFILESCOMMON :&str = "{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}";
pub const FOLDERID_PROGRAMFILESCOMMONX64 :&str = "{6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D}";
pub const FOLDERID_PROGRAMFILESCOMMONX86 :&str = "{DE974D24-D9C6-4D3E-BF91-F4455120B917}";
pub const FOLDERID_PROGRAMS :&str = "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}";
pub const FOLDERID_PUBLIC :&str = "{DFDF76A2-C82A-4D63-906A-5644AC457385}";
pub const FOLDERID_PUBLICDESKTOP :&str = "{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}";
pub const FOLDERID_PUBLICDOCUMENTS :&str = "{ED4824AF-DCE4-45A8-81E2-FC7965083634}";
pub const FOLDERID_PUBLICDOWNLOADS :&str = "{3D644C9B-1FB8-4F30-9B45-F670235F79C0}";
pub const FOLDERID_PUBLICGAMETASKS :&str = "{DEBF2536-E1A8-4C59-B6A2-414586476AEA}";
pub const FOLDERID_PUBLICLIBRARIES :&str = "{48DAF80B-E6CF-4F4E-B800-0E69D84EE384}";
pub const FOLDERID_PUBLICMUSIC :&str = "{3214FAB5-9757-4298-BB61-92A9DEAA44FF}";
pub const FOLDERID_PUBLICPICTURES :&str = "{B6EBFB86-6907-413C-9AF7-4FC2ABF07CC5}";
pub const FOLDERID_PUBLICRINGTONES :&str = "{E555AB60-153B-4D17-9F04-A5FE99FC15EC}";
pub const FOLDERID_PUBLICUSERTILES :&str = "{0482AF6C-08F1-4C34-8C90-E17EC98B1E17}";
pub const FOLDERID_PUBLICVIDEOS :&str = "{2400183A-6185-49FB-A2D8-4A392A602BA3}";
pub const FOLDERID_QUICKLAUNCH :&str = "{52A4F021-7B75-48A9-9F6B-4B87A210BC8F}";
pub const FOLDERID_RECENT :&str = "{AE50C081-EBD2-438A-8655-8A092E34987A}";
pub const FOLDERID_RECORDEDTVLIBRARY :&str = "{1A6FDBA2-F42D-4358-A798-B74D745926C5}";
pub const FOLDERID_RESOURCEDIR :&str = "{8AD10C31-2ADB-4296-A8F7-E4701232C972}";
pub const FOLDERID_ROAMINGAPPDATA :&str = "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}";
pub const FOLDERID_ROAMEDTILEIMAGES :&str = "{AAA8D5A5-F1D6-4259-BAA8-78E7EF60835E}";
pub const FOLDERID_ROAMINGTILES :&str = "{00BCFC5A-ED94-4E48-96A1-3F6217F21990}";
pub const FOLDERID_SAMPLEMUSIC :&str = "{B250C668-F57D-4EE1-A63C-290EE7D1AA1F}";
pub const FOLDERID_SAMPLEPICTURES :&str = "{C4900540-2379-4C75-844B-64E6FAF8716B}";
pub const FOLDERID_SAMPLEPLAYLISTS :&str = "{15CA69B3-30EE-49C1-ACE1-6B5EC372AFB5}";
pub const FOLDERID_SAMPLEVIDEOS :&str = "{859EAD94-2E85-48AD-A71A-0969CB56A6CD}";
pub const FOLDERID_SAVEDGAMES :&str = "{4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4}";
pub const FOLDERID_SAVEDPICTURES :&str = "{3B193882-D3AD-4EAB-965A-69829D1FB59F}";
pub const FOLDERID_SAVEDPICTURESLIBRARY :&str = "{E25B5812-BE88-4BD9-94B0-29233477B6C3}";
pub const FOLDERID_SAVEDSEARCHES :&str = "{7D1D3A04-DEBB-4115-95CF-2F29DA2920DA}";
pub const FOLDERID_SCREENSHOTS :&str = "{B7BEDE81-DF94-4682-A7D8-57A52620B86F}";
pub const FOLDERID_SEARCHHISTORY :&str = "{0D4C3DB6-03A3-462F-A0E6-08924C41B5D4}";
pub const FOLDERID_SEARCHTEMPLATES :&str = "{7E636BFE-DFA9-4D5E-B456-D7B39851D8A9}";
pub const FOLDERID_SENDTO :&str = "{8983036C-27C0-404B-8F08-102D10DCFD74}";
pub const FOLDERID_SIDEBARDEFAULTPARTS :&str = "{7B396E54-9EC5-4300-BE0A-2482EBAE1A26}";
pub const FOLDERID_SIDEBARPARTS :&str = "{A75D362E-50FC-4FB7-AC2C-A8BEAA314493}";
pub const FOLDERID_SKYDRIVE :&str = "{A52BBA46-E9E1-435F-B3D9-28DAA648C0F6}";
pub const FOLDERID_SKYDRIVECAMERAROLL :&str = "{767E6811-49CB-4273-87C2-20F355E1085B}";
pub const FOLDERID_SKYDRIVEDOCUMENTS :&str = "{24D89E24-2F19-4534-9DDE-6A6671FBB8FE}";
pub const FOLDERID_SKYDRIVEPICTURES :&str = "{339719B5-8C47-4894-94C2-D8F77ADD44A6}";
pub const FOLDERID_STARTMENU :&str = "{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}";
pub const FOLDERID_STARTUP :&str = "{B97D20BB-F46A-4C97-BA10-5E3608430854}";
pub const FOLDERID_SYSTEM :&str = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}";
pub const FOLDERID_SYSTEMX86 :&str = "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}";
pub const FOLDERID_TEMPLATES :&str = "{A63293E8-664E-48DB-A079-DF759E0509F7}";
pub const FOLDERID_USERPINNED :&str = "{9E3995AB-1F9C-4F13-B827-48B24B6C7174}";
pub const FOLDERID_USERPROFILES :&str = "{0762D272-C50A-4BB0-A382-697DCD729B80}";
pub const FOLDERID_USERPROGRAMFILES :&str = "{5CD7AEE2-2219-4A67-B85D-6C9CE15660CB}";
pub const FOLDERID_USERPROGRAMFILESCOMMON :&str = "{BCBD3057-CA5C-4622-B42D-BC56DB0AE516}";
pub const FOLDERID_VIDEOS :&str = "{18989B1D-99B5-455B-841C-AB7C74E4DDFC}";
pub const FOLDERID_VIDEOSLIBRARY :&str = "{491E922F-5643-4AF4-A7EB-4E7A138D8174}";
pub const FOLDERID_WINDOWS :&str = "{F38BF404-1D43-42F2-9305-67DE0B28FC23}";

pub const FOLDERID_ACCOUNT_PICTURES_VALUE: &str = "%APPDATA%\\Microsoft\\Windows\\AccountPictures";
pub const FOLDERID_ADMINTOOLS_VALUE: &str ="%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools";
pub const FOLDERID_APPDATADESKTOP_VALUE: &str = "%LOCALAPPDATA%\\Desktop";
pub const FOLDERID_APPDATADOCUMENTS_VALUE: &str = "%LOCALAPPDATA%\\Documents";
pub const FOLDERID_APPDATAFAVORITES_VALUE: &str = "%LOCALAPPDATA%\\Favorites";
pub const FOLDERID_APPDATAPROGRAMDATA_VALUE: &str = "%LOCALAPPDATA%\\ProgramData";
pub const FOLDERID_APPLICATIONSHORTCUTS_VALUE: &str ="%LOCALAPPDATA%\\Microsoft\\Windows\\Application Shortcuts";
pub const FOLDERID_CAMERAROLL_VALUE: &str = "%USERPROFILE%\\Pictures\\Camera Roll";
pub const FOLDERID_CDBURNING_VALUE: &str = "%LOCALAPPDATA%\\Microsoft\\Windows\\Burn\\Burn";
pub const FOLDERID_COMMONADMINTOOLS_VALUE: &str ="%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools";
pub const FOLDERID_COMMONOEMLINKS_VALUE: &str = "%ALLUSERSPROFILE%\\OEM Links";
pub const FOLDERID_COMMONPROGRAMS_VALUE: &str ="%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs";
pub const FOLDERID_COMMONSTARTMENU_VALUE: &str ="%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu";
pub const FOLDERID_COMMONSTARTUP_VALUE: &str ="%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp";
pub const FOLDERID_COMMONTEMPLATES_VALUE: &str = "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Templates";
pub const FOLDERID_CONTACTS_VALUE: &str = "%USERPROFILE%\\Contacts";
pub const FOLDERID_COOKIES_VALUE: &str = "%APPDATA%\\Microsoft\\Windows\\Cookies";
pub const FOLDERID_DESKTOP_VALUE: &str = "%USERPROFILE%\\Desktop";
pub const FOLDERID_DEVICEMETADATASTORE_VALUE: &str ="%ALLUSERSPROFILE%\\Microsoft\\Windows\\DeviceMetadataStore";
pub const FOLDERID_DOCUMENTS_VALUE: &str = "%USERPROFILE%\\Documents";
pub const FOLDERID_DOCUMENTSLIBRARY_VALUE: &str ="%APPDATA%\\Microsoft\\Windows\\Libraries\\Documents.library-ms";
pub const FOLDERID_DOWNLOADS_VALUE: &str = "%USERPROFILE%\\Downloads";
pub const FOLDERID_FAVORITES_VALUE: &str = "%USERPROFILE%\\Favorites";
pub const FOLDERID_FONTS_VALUE: &str = "%windir%\\Fonts";
pub const FOLDERID_GAMETASKS_VALUE: &str = "%LOCALAPPDATA%\\Microsoft\\Windows\\GameExplorer";
pub const FOLDERID_HISTORY_VALUE: &str = "%LOCALAPPDATA%\\Microsoft\\Windows\\History";
pub const FOLDERID_IMPLICITAPPSHORTCUTS_VALUE: &str ="%APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\ImplicitAppShortcuts";
pub const FOLDERID_INTERNETCACHE_VALUE: &str ="%LOCALAPPDATA%\\Microsoft\\Windows\\Temporary Internet Files";
pub const FOLDERID_LIBRARIES_VALUE: &str = "%APPDATA%\\Microsoft\\Windows\\Libraries";
pub const FOLDERID_LINKS_VALUE: &str = "%USERPROFILE%\\Links";
pub const FOLDERID_LOCALAPPDATA_VALUE: &str = "%LOCALAPPDATA%";
pub const FOLDERID_LOCALAPPDATALOW_VALUE: &str = "%USERPROFILE%\\AppData\\LocalLow";
pub const FOLDERID_MUSIC_VALUE: &str = "%USERPROFILE%\\Music";
pub const FOLDERID_MUSICLIBRARY_VALUE: &str ="%APPDATA%\\Microsoft\\Windows\\Libraries\\Music.library-ms";
pub const FOLDERID_NETHOOD_VALUE: &str = "%APPDATA%\\Microsoft\\Windows\\Network Shortcuts";
pub const FOLDERID_OBJECTS3D_VALUE: &str = "%USERPROFILE%\\3D Objects";
pub const FOLDERID_ORIGINALIMAGES_VALUE: &str ="%LOCALAPPDATA%\\Microsoft\\Windows Photo Gallery\\Original Images";
pub const FOLDERID_PHOTOALBUMS_VALUE: &str = "%USERPROFILE%\\Pictures\\Slide Shows";
pub const FOLDERID_PICTURESLIBRARY_VALUE: &str ="%APPDATA%\\Microsoft\\Windows\\Libraries\\Pictures.library-ms";
pub const FOLDERID_PICTURES_VALUE: &str = "%USERPROFILE%\\Pictures";
pub const FOLDERID_PLAYLISTS_VALUE: &str = "%USERPROFILE%\\Music\\Playlists";
pub const FOLDERID_PRINTHOOD_VALUE: &str = "%APPDATA%\\Microsoft\\Windows\\Printer Shortcuts";
pub const FOLDERID_PROFILE_VALUE: &str = "%USERPROFILE%";
pub const FOLDERID_PROGRAMDATA_VALUE: &str = "%ALLUSERSPROFILE%";
pub const FOLDERID_PROGRAMFILES_VALUE: &str = "%ProgramFiles%";
pub const FOLDERID_PROGRAMFILESX64_VALUE: &str = "%ProgramFiles%";
pub const FOLDERID_PROGRAMFILESX86_VALUE: &str = "%ProgramFiles%";
pub const FOLDERID_PROGRAMFILESCOMMON_VALUE: &str = "%ProgramFiles%\\Common Files";
pub const FOLDERID_PROGRAMFILESCOMMONX64_VALUE: &str = "%ProgramFiles%\\Common Files";
pub const FOLDERID_PROGRAMFILESCOMMONX86_VALUE: &str = "%ProgramFiles%\\Common Files";
pub const FOLDERID_PROGRAMS_VALUE: &str = "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs";
pub const FOLDERID_PUBLIC_VALUE: &str = "%PUBLIC%";
pub const FOLDERID_PUBLICDESKTOP_VALUE: &str = "%PUBLIC%\\Desktop";
pub const FOLDERID_PUBLICDOCUMENTS_VALUE: &str = "%PUBLIC%\\Documents";
pub const FOLDERID_PUBLICDOWNLOADS_VALUE: &str = "%PUBLIC%\\Downloads";
pub const FOLDERID_PUBLICGAMETASKS_VALUE: &str ="%ALLUSERSPROFILE%\\Microsoft\\Windows\\GameExplorer";
pub const FOLDERID_PUBLICLIBRARIES_VALUE: &str = "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Libraries";
pub const FOLDERID_PUBLICMUSIC_VALUE: &str = "%PUBLIC%\\Music";
pub const FOLDERID_PUBLICPICTURES_VALUE: &str = "%PUBLIC%\\Pictures";
pub const FOLDERID_PUBLICRINGTONES_VALUE: &str = "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Ringtones";
pub const FOLDERID_PUBLICUSERTILES_VALUE: &str = "%PUBLIC%\\AccountPictures";
pub const FOLDERID_PUBLICVIDEOS_VALUE: &str = "%PUBLIC%\\Videos";
pub const FOLDERID_QUICKLAUNCH_VALUE: &str ="%APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch";
pub const FOLDERID_RECENT_VALUE: &str = "%APPDATA%\\Microsoft\\Windows\\Recent";
pub const FOLDERID_RECORDEDTVLIBRARY_VALUE: &str = "%PUBLIC%\\RecordedTV.library-ms";
pub const FOLDERID_RESOURCEDIR_VALUE: &str = "%windir%\\Resources";
pub const FOLDERID_ROAMINGAPPDATA_VALUE: &str = "%APPDATA%";
pub const FOLDERID_ROAMEDTILEIMAGES_VALUE: &str ="%LOCALAPPDATA%\\Microsoft\\Windows\\RoamedTileImages";
pub const FOLDERID_ROAMINGTILES_VALUE: &str = "%LOCALAPPDATA%\\Microsoft\\Windows\\RoamingTiles";
pub const FOLDERID_SAMPLEMUSIC_VALUE: &str = "%PUBLIC%\\Music\\Sample Music";
pub const FOLDERID_SAMPLEPICTURES_VALUE: &str = "%PUBLIC%\\Pictures\\Sample Pictures";
pub const FOLDERID_SAMPLEPLAYLISTS_VALUE: &str = "%PUBLIC%\\Music\\Sample Playlists";
pub const FOLDERID_SAMPLEVIDEOS_VALUE: &str = "%PUBLIC%\\Videos\\Sample Videos";
pub const FOLDERID_SAVEDGAMES_VALUE: &str = "%USERPROFILE%\\Saved Games";
pub const FOLDERID_SAVEDPICTURES_VALUE: &str = "%USERPROFILE%\\Pictures\\Saved Pictures";
pub const FOLDERID_SAVEDPICTURESLIBRARY_VALUE: &str ="%APPDATA%\\Microsoft\\Windows\\Libraries\\SavedPictures.library-ms";
pub const FOLDERID_SAVEDSEARCHES_VALUE: &str = "%USERPROFILE%\\Searches";
pub const FOLDERID_SCREENSHOTS_VALUE: &str = "%USERPROFILE%\\Pictures\\Screenshots";
pub const FOLDERID_SEARCHHISTORY_VALUE: &str ="%LOCALAPPDATA%\\Microsoft\\Windows\\ConnectedSearch\\History";
pub const FOLDERID_SEARCHTEMPLATES_VALUE: &str ="%LOCALAPPDATA%\\Microsoft\\Windows\\ConnectedSearch\\Templates";
pub const FOLDERID_SENDTO_VALUE: &str = "%APPDATA%\\Microsoft\\Windows\\SendTo";
pub const FOLDERID_SIDEBARDEFAULTPARTS_VALUE: &str = "%ProgramFiles%\\Windows Sidebar\\Gadgets";
pub const FOLDERID_SIDEBARPARTS_VALUE: &str = "%LOCALAPPDATA%\\Microsoft\\Windows Sidebar\\Gadgets";
pub const FOLDERID_SKYDRIVE_VALUE: &str = "%USERPROFILE%\\OneDrive";
pub const FOLDERID_SKYDRIVECAMERAROLL_VALUE: &str ="%USERPROFILE%\\OneDrive\\Pictures\\Camera Roll";
pub const FOLDERID_SKYDRIVEDOCUMENTS_VALUE: &str = "%USERPROFILE%\\OneDrive\\Documents";
pub const FOLDERID_SKYDRIVEPICTURES_VALUE: &str = "%USERPROFILE%\\OneDrive\\Pictures";
pub const FOLDERID_STARTMENU_VALUE: &str = "%APPDATA%\\Microsoft\\Windows\\Start Menu";
pub const FOLDERID_STARTUP_VALUE: &str ="%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp";
pub const FOLDERID_SYSTEM_VALUE: &str = "%windir%\\system32";
pub const FOLDERID_SYSTEMX86_VALUE: &str = "%windir%\\system32";
pub const FOLDERID_TEMPLATES_VALUE: &str = "%APPDATA%\\Microsoft\\Windows\\Templates";
pub const FOLDERID_USERPINNED_VALUE: &str ="%APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned";
pub const FOLDERID_USERPROFILES_VALUE: &str = "%SystemDrive%\\Users";
pub const FOLDERID_USERPROGRAMFILES_VALUE: &str = "%LOCALAPPDATA%\\Programs";
pub const FOLDERID_USERPROGRAMFILESCOMMON_VALUE: &str = "%LOCALAPPDATA%\\Programs\\Common";
pub const FOLDERID_VIDEOS_VALUE: &str = "%USERPROFILE%\\Videos";
pub const FOLDERID_VIDEOSLIBRARY_VALUE: &str ="%APPDATA%\\Microsoft\\Windows\\Libraries\\Videos.library-ms";
pub const FOLDERID_WINDOWS_VALUE: &str = "%windir%";

pub fn csidl_value(csidl: &str) -> Option<&'static str> {
    Some(match csidl {
        FOLDERID_ACCOUNT_PICTURES => FOLDERID_ACCOUNT_PICTURES_VALUE,
        FOLDERID_ADMINTOOLS => FOLDERID_ADMINTOOLS_VALUE,
        FOLDERID_APPDATADESKTOP => FOLDERID_APPDATADESKTOP_VALUE,
        FOLDERID_APPDATADOCUMENTS => FOLDERID_APPDATADOCUMENTS_VALUE,
        FOLDERID_APPDATAFAVORITES => FOLDERID_APPDATAFAVORITES_VALUE,
        FOLDERID_APPDATAPROGRAMDATA => FOLDERID_APPDATAPROGRAMDATA_VALUE,
        FOLDERID_APPLICATIONSHORTCUTS => FOLDERID_APPLICATIONSHORTCUTS_VALUE,
        FOLDERID_CAMERAROLL => FOLDERID_CAMERAROLL_VALUE,
        FOLDERID_CDBURNING => FOLDERID_CDBURNING_VALUE,
        FOLDERID_COMMONADMINTOOLS => FOLDERID_COMMONADMINTOOLS_VALUE,
        FOLDERID_COMMONOEMLINKS => FOLDERID_COMMONOEMLINKS_VALUE,
        FOLDERID_COMMONPROGRAMS => FOLDERID_COMMONPROGRAMS_VALUE,
        FOLDERID_COMMONSTARTMENU => FOLDERID_COMMONSTARTMENU_VALUE,
        FOLDERID_COMMONSTARTUP => FOLDERID_COMMONSTARTUP_VALUE,
        FOLDERID_COMMONTEMPLATES => FOLDERID_COMMONTEMPLATES_VALUE,
        FOLDERID_CONTACTS => FOLDERID_CONTACTS_VALUE,
        FOLDERID_COOKIES => FOLDERID_COOKIES_VALUE,
        FOLDERID_DESKTOP => FOLDERID_DESKTOP_VALUE,
        FOLDERID_DEVICEMETADATASTORE => FOLDERID_DEVICEMETADATASTORE_VALUE,
        FOLDERID_DOCUMENTS => FOLDERID_DOCUMENTS_VALUE,
        FOLDERID_DOCUMENTSLIBRARY => FOLDERID_DOCUMENTSLIBRARY_VALUE,
        FOLDERID_DOWNLOADS => FOLDERID_DOWNLOADS_VALUE,
        FOLDERID_FAVORITES => FOLDERID_FAVORITES_VALUE,
        FOLDERID_FONTS => FOLDERID_FONTS_VALUE,
        FOLDERID_GAMETASKS => FOLDERID_GAMETASKS_VALUE,
        FOLDERID_HISTORY => FOLDERID_HISTORY_VALUE,
        FOLDERID_IMPLICITAPPSHORTCUTS => FOLDERID_IMPLICITAPPSHORTCUTS_VALUE,
        FOLDERID_INTERNETCACHE => FOLDERID_INTERNETCACHE_VALUE,
        FOLDERID_LIBRARIES => FOLDERID_LIBRARIES_VALUE,
        FOLDERID_LINKS => FOLDERID_LINKS_VALUE,
        FOLDERID_LOCALAPPDATA => FOLDERID_LOCALAPPDATA_VALUE,
        FOLDERID_LOCALAPPDATALOW => FOLDERID_LOCALAPPDATALOW_VALUE,
        FOLDERID_MUSIC => FOLDERID_MUSIC_VALUE,
        FOLDERID_MUSICLIBRARY => FOLDERID_MUSICLIBRARY_VALUE,
        FOLDERID_NETHOOD => FOLDERID_NETHOOD_VALUE,
        FOLDERID_OBJECTS3D => FOLDERID_OBJECTS3D_VALUE,
        FOLDERID_ORIGINALIMAGES => FOLDERID_ORIGINALIMAGES_VALUE,
        FOLDERID_PHOTOALBUMS => FOLDERID_PHOTOALBUMS_VALUE,
        FOLDERID_PICTURESLIBRARY => FOLDERID_PICTURESLIBRARY_VALUE,
        FOLDERID_PICTURES => FOLDERID_PICTURES_VALUE,
        FOLDERID_PLAYLISTS => FOLDERID_PLAYLISTS_VALUE,
        FOLDERID_PRINTHOOD => FOLDERID_PRINTHOOD_VALUE,
        FOLDERID_PROFILE => FOLDERID_PROFILE_VALUE,
        FOLDERID_PROGRAMDATA => FOLDERID_PROGRAMDATA_VALUE,
        FOLDERID_PROGRAMFILES => FOLDERID_PROGRAMFILES_VALUE,
        FOLDERID_PROGRAMFILESX64 => FOLDERID_PROGRAMFILESX64_VALUE,
        FOLDERID_PROGRAMFILESX86 => FOLDERID_PROGRAMFILESX86_VALUE,
        FOLDERID_PROGRAMFILESCOMMON => FOLDERID_PROGRAMFILESCOMMON_VALUE,
        FOLDERID_PROGRAMFILESCOMMONX64 => FOLDERID_PROGRAMFILESCOMMONX64_VALUE,
        FOLDERID_PROGRAMFILESCOMMONX86 => FOLDERID_PROGRAMFILESCOMMONX86_VALUE,
        FOLDERID_PROGRAMS => FOLDERID_PROGRAMS_VALUE,
        FOLDERID_PUBLIC => FOLDERID_PUBLIC_VALUE,
        FOLDERID_PUBLICDESKTOP => FOLDERID_PUBLICDESKTOP_VALUE,
        FOLDERID_PUBLICDOCUMENTS => FOLDERID_PUBLICDOCUMENTS_VALUE,
        FOLDERID_PUBLICDOWNLOADS => FOLDERID_PUBLICDOWNLOADS_VALUE,
        FOLDERID_PUBLICGAMETASKS => FOLDERID_PUBLICGAMETASKS_VALUE,
        FOLDERID_PUBLICLIBRARIES => FOLDERID_PUBLICLIBRARIES_VALUE,
        FOLDERID_PUBLICMUSIC => FOLDERID_PUBLICMUSIC_VALUE,
        FOLDERID_PUBLICPICTURES => FOLDERID_PUBLICPICTURES_VALUE,
        FOLDERID_PUBLICRINGTONES => FOLDERID_PUBLICRINGTONES_VALUE,
        FOLDERID_PUBLICUSERTILES => FOLDERID_PUBLICUSERTILES_VALUE,
        FOLDERID_PUBLICVIDEOS => FOLDERID_PUBLICVIDEOS_VALUE,
        FOLDERID_QUICKLAUNCH => FOLDERID_QUICKLAUNCH_VALUE,
        FOLDERID_RECENT => FOLDERID_RECENT_VALUE,
        FOLDERID_RECORDEDTVLIBRARY => FOLDERID_RECORDEDTVLIBRARY_VALUE,
        FOLDERID_RESOURCEDIR => FOLDERID_RESOURCEDIR_VALUE,
        FOLDERID_ROAMINGAPPDATA => FOLDERID_ROAMINGAPPDATA_VALUE,
        FOLDERID_ROAMEDTILEIMAGES => FOLDERID_ROAMEDTILEIMAGES_VALUE,
        FOLDERID_ROAMINGTILES => FOLDERID_ROAMINGTILES_VALUE,
        FOLDERID_SAMPLEMUSIC => FOLDERID_SAMPLEMUSIC_VALUE,
        FOLDERID_SAMPLEPICTURES => FOLDERID_SAMPLEPICTURES_VALUE,
        FOLDERID_SAMPLEPLAYLISTS => FOLDERID_SAMPLEPLAYLISTS_VALUE,
        FOLDERID_SAMPLEVIDEOS => FOLDERID_SAMPLEVIDEOS_VALUE,
        FOLDERID_SAVEDGAMES => FOLDERID_SAVEDGAMES_VALUE,
        FOLDERID_SAVEDPICTURES => FOLDERID_SAVEDPICTURES_VALUE,
        FOLDERID_SAVEDPICTURESLIBRARY => FOLDERID_SAVEDPICTURESLIBRARY_VALUE,
        FOLDERID_SAVEDSEARCHES => FOLDERID_SAVEDSEARCHES_VALUE,
        FOLDERID_SCREENSHOTS => FOLDERID_SCREENSHOTS_VALUE,
        FOLDERID_SEARCHHISTORY => FOLDERID_SEARCHHISTORY_VALUE,
        FOLDERID_SEARCHTEMPLATES => FOLDERID_SEARCHTEMPLATES_VALUE,
        FOLDERID_SENDTO => FOLDERID_SENDTO_VALUE,
        FOLDERID_SIDEBARDEFAULTPARTS => FOLDERID_SIDEBARDEFAULTPARTS_VALUE,
        FOLDERID_SIDEBARPARTS => FOLDERID_SIDEBARPARTS_VALUE,
        FOLDERID_SKYDRIVE => FOLDERID_SKYDRIVE_VALUE,
        FOLDERID_SKYDRIVECAMERAROLL => FOLDERID_SKYDRIVECAMERAROLL_VALUE,
        FOLDERID_SKYDRIVEDOCUMENTS => FOLDERID_SKYDRIVEDOCUMENTS_VALUE,
        FOLDERID_SKYDRIVEPICTURES => FOLDERID_SKYDRIVEPICTURES_VALUE,
        FOLDERID_STARTMENU => FOLDERID_STARTMENU_VALUE,
        FOLDERID_STARTUP => FOLDERID_STARTUP_VALUE,
        FOLDERID_SYSTEM => FOLDERID_SYSTEM_VALUE,
        FOLDERID_SYSTEMX86 => FOLDERID_SYSTEMX86_VALUE,
        FOLDERID_TEMPLATES => FOLDERID_TEMPLATES_VALUE,
        FOLDERID_USERPINNED => FOLDERID_USERPINNED_VALUE,
        FOLDERID_USERPROFILES => FOLDERID_USERPROFILES_VALUE,
        FOLDERID_USERPROGRAMFILES => FOLDERID_USERPROGRAMFILES_VALUE,
        FOLDERID_USERPROGRAMFILESCOMMON => FOLDERID_USERPROGRAMFILESCOMMON_VALUE,
        FOLDERID_VIDEOS => FOLDERID_VIDEOS_VALUE,
        FOLDERID_VIDEOSLIBRARY => FOLDERID_VIDEOSLIBRARY_VALUE,
        FOLDERID_WINDOWS => FOLDERID_WINDOWS_VALUE,
        _ => return None,
    })
}

/// Interpolates paths that contains a CSIDL
/// 
/// ```rust
/// use forensic_rs::core::UserEnvVars;
/// use forensic_rs::utils::win::csidl::interpolate_csidl_path;
/// let env_vars = {
/// let mut map = UserEnvVars::new();
/// map.insert("APPDATA".into(), "C:\\ProgramData".into());
/// map.insert("LOCALAPPDATA".into(), "%USERPROFILE%\\AppData\\Local".into());
/// map.insert("ProgramFiles".into(), "C:\\Program Files".into());
/// map.insert("USERPROFILE".into(), "C:\\Users\\tester".into());
/// map
/// };
/// // CSIDL {B2C5E279-7ADD-439F-B28C-C41FE1BBF672} = %LOCALAPPDATA%\Desktop = %USERPROFILE%\\AppData\\Local\Desktop = C:\Users\tester\AppData\Local\Desktop
/// let mut pth = r"{B2C5E279-7ADD-439F-B28C-C41FE1BBF672}\Electronic Arts\EA Desktop\EA Desktop\EADesktop.exe".to_string();
/// let interpolated = interpolate_csidl_path(&mut pth, &env_vars).unwrap();
/// assert_eq!(r"C:\Users\tester\AppData\Local\Desktop\Electronic Arts\EA Desktop\EA Desktop\EADesktop.exe", interpolated);
/// ```
pub fn interpolate_csidl_path(pth : &mut str, env_vars : &UserEnvVars) -> Option<String> {
    if !pth.starts_with('{') {
        return Some(pth.to_string())
    }
    let pos = pth.as_bytes().iter().position(|&v| v == b'}')?;
    (&mut pth[0..pos + 1]).make_ascii_uppercase();
    let csidl = &pth[0..pos + 1];
    let rest = &pth[pos + 1..];
    let csidl_value = csidl_value(csidl)?;
    let mut ret = String::with_capacity(256);
    interpolate_env_vars(csidl_value, env_vars, &mut ret)?;
    ret.push_str(rest);
    Some(ret)
}

#[test]
fn should_interpolate_complex_env_vars_with_csidl() {
    let env_vars = {
        let mut map = UserEnvVars::new();
        map.insert("APPDATA".into(), "C:\\ProgramData".into());
        map.insert("LOCALAPPDATA".into(), "%USERPROFILE%\\AppData\\Local".into());
        map.insert("ProgramFiles".into(), "C:\\Program Files".into());
        map.insert("USERPROFILE".into(), "C:\\Users\\tester".into());
        map
    };
    let mut pth = r"{6D809377-6AF0-444B-8957-A3773F02200E}\Electronic Arts\EA Desktop\EA Desktop\EADesktop.exe".to_string();
    let interpolated = interpolate_csidl_path(&mut pth, &env_vars).unwrap();
    assert_eq!(r"C:\Program Files\Electronic Arts\EA Desktop\EA Desktop\EADesktop.exe", interpolated);
    let mut pth = r"{B2C5E279-7ADD-439F-B28C-C41FE1BBF672}\Electronic Arts\EA Desktop\EA Desktop\EADesktop.exe".to_string();
    let interpolated = interpolate_csidl_path(&mut pth, &env_vars).unwrap();
    assert_eq!(r"C:\Users\tester\AppData\Local\Desktop\Electronic Arts\EA Desktop\EA Desktop\EADesktop.exe", interpolated);
}
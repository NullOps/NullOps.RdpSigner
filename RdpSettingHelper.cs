using System;
using System.Collections.Generic;

namespace NullOps.RdpSigner
{
	/// <summary>
	/// A static class full of helpful values!
	/// </summary>
	internal static class RdpSettingHelper
	{
		public const string AlternateFullAddressSettingName = "alternate full address";
		public const string FullAddressSettingName = "full address";
		public const string SignatureSettingName = "signature";
		public const string SignScopeSettingName = "signscope";

		public const char SignScopeSettingType = StringSettingType;
		public const char SignatureSettingType = StringSettingType;

		public const char StringSettingType = 's';
		public const char IntSettingType = 'i';
		public const char BinarySettingType = 'b';

		/// <summary>
		/// A string containing all valid setting values
		/// </summary>
		public static readonly string ValidSettingTypes = string.Concat(StringSettingType + IntSettingType + BinarySettingType);

		/// <summary>
		/// A collection of all setting names (keys) that should be signed, and their associated scopes (values)
		/// </summary>
		public static readonly IReadOnlyDictionary<string, string> SecureSettingScopes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
		{
			{FullAddressSettingName, "Full Address"},
			{AlternateFullAddressSettingName,"Alternate Full Address"},
			{"pcb","PCB"},
			{"use redirection server name","Use Redirection Server Name"},
			{"server port","Server Port"},
			{"negotiate security layer","Negotiate Security Layer"},
			{"enablecredsspsupport","EnableCredSspSupport"},
			{"disableconnectionsharing","DisableConnectionSharing"},
			{"autoreconnection enabled","AutoReconnection Enabled"},
			{"gatewayhostname","GatewayHostname"},
			{"gatewayusagemethod","GatewayUsageMethod"},
			{"gatewayprofileusagemethod","GatewayProfileUsageMethod"},
			{"gatewaycredentialssource","GatewayCredentialsSource"},
			{"support url","Support URL"},
			{"promptcredentialonce","PromptCredentialOnce"},
			{"require pre-authentication","Require pre-authentication"},
			{"pre-authentication server address","Pre-authentication server address"},
			{"alternate shell","Alternate Shell"},
			{"shell working directory","Shell Working Directory"},
			{"remoteapplicationprogram","RemoteApplicationProgram"},
			{"remoteapplicationexpandworkingdir","RemoteApplicationExpandWorkingdir"},
			{"remoteapplicationmode","RemoteApplicationMode"},
			{"remoteapplicationguid","RemoteApplicationGuid"},
			{"remoteapplicationname","RemoteApplicationName"},
			{"remoteapplicationicon","RemoteApplicationIcon"},
			{"remoteapplicationfile","RemoteApplicationFile"},
			{"remoteapplicationfileextensions","RemoteApplicationFileExtensions"},
			{"remoteapplicationcmdline","RemoteApplicationCmdLine"},
			{"remoteapplicationexpandcmdline","RemoteApplicationExpandCmdLine"},
			{"prompt for credentials","Prompt For Credentials"},
			{"authentication level","Authentication Level"},
			{"audiomode","AudioMode"},
			{"redirectdrives","RedirectDrives"},
			{"redirectprinters","RedirectPrinters"},
			{"redirectcomports","RedirectCOMPorts"},
			{"redirectsmartcards","RedirectSmartCards"},
			{"redirectposdevices","RedirectPOSDevices"},
			{"redirectclipboard","RedirectClipboard"},
			{"devicestoredirect","DevicesToRedirect"},
			{"drivestoredirect","DrivesToRedirect"},
			{"loadbalanceinfo","LoadBalanceInfo"},
			{"redirectdirectx","RedirectDirectX"},
			{"rdgiskdcproxy","RDGIsKDCProxy"},
			{"kdcproxyname","KDCProxyName"},
			{"eventloguploadaddress","EventLogUploadAddress"}
		};
	}
}
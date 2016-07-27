using System;
using System.Text;
using System.Text.RegularExpressions;

namespace NullOps.RdpSigner
{
	/// <summary>
	/// An individual Rdp setting.
	/// A complete list of valid settings can be found at:
	///  https://technet.microsoft.com/en-us/library/ff393699(WS.10).aspx
	///
	/// </summary>
	internal class RdpSetting
	{
		/// <summary>
		/// Name of the capture group containing the Setting Name within the SettingRegex
		/// </summary>
		private const string SettingNameGroupName = "SettingName";

		/// <summary>
		/// Name of the capture group containing the Setting Type within the SettingRegex
		/// </summary>
		private const string SettingTypeGroupName = "SettingType";

		/// <summary>
		/// Name of the capture group containing the Setting Value within the SettingRegex
		/// </summary>
		private const string SettingValueGroupName = "SettingValue";

		/// <summary>
		/// Regex to match Rdp settings against
		/// </summary>
		private static readonly Regex SettingRegex = new Regex($"^(?<{SettingNameGroupName}>[^:]+):(?<{SettingTypeGroupName}>[{RdpSettingHelper.ValidSettingTypes}]):(?<{SettingValueGroupName}>.*)$");

		/// <summary>
		/// An individual Rdp setting.
		/// </summary>
		/// <param name="settingName">The Rdp setting name</param>
		/// <param name="settingType">The Rdp setting type</param>
		/// <param name="settingValue">The Rdp setting value</param>
		public RdpSetting(string settingName, char settingType, string settingValue)
		{
			if (string.IsNullOrWhiteSpace(settingName))
			{
				throw new ArgumentException(nameof(settingName) + " is required.");
			}

			if (RdpSettingHelper.ValidSettingTypes.IndexOf(settingType) < 0)
			{
				throw new ArgumentException(nameof(settingType) + $" is not a valid setting type. (Valid values are '{RdpSettingHelper.ValidSettingTypes}')");
			}

			SettingName = settingName;
			SettingType = settingType;
			SettingValue = settingValue;
		}

		/// <summary>
		/// The Rdp setting name
		/// </summary>
		public string SettingName { get; }

		/// <summary>
		/// The Rdp setting type
		/// </summary>
		public char SettingType { get; }

		/// <summary>
		/// The Rdp setting value
		/// </summary>
		public string SettingValue { get; }

		/// <summary>
		/// If this setting should be signed
		/// </summary>
		public bool IsSignableSetting
		{
			get { return RdpSettingHelper.SecureSettingScopes.ContainsKey(this.SettingName); }
		}

		/// <summary>
		/// Attempts to parse a string as an Rdp setting
		/// </summary>
		/// <param name="rdpSettingString">The Rdp setting in string format</param>
		/// <param name="setting">The parsed RdpSetting</param>
		/// <returns>If parse was successful. There will be no cake.</returns>
		public static bool TryParse(string rdpSettingString, out RdpSetting setting)
		{
			setting = null;

			if (string.IsNullOrWhiteSpace(rdpSettingString))
			{
				return false;
			}

			Match regexMatch = SettingRegex.Match(rdpSettingString);

			if (!regexMatch.Success)
			{
				return false;
			}

			string settingName = regexMatch.Groups[SettingNameGroupName].Value;
			char settingType = regexMatch.Groups[SettingTypeGroupName].Value[0];
			string settingValue = regexMatch.Groups[SettingValueGroupName].Value;

			try
			{
				setting = new RdpSetting(settingName, settingType, settingValue);
			}
			catch (ArgumentException)
			{
				return false;
			}

			return true;
		}

		/// <summary>
		/// Converts this RdpSetting to string format
		/// </summary>
		/// <returns>The Rdp setting as a string</returns>
		public override string ToString()
		{
			StringBuilder builder = new StringBuilder();

			builder.Append(SettingName).Append(':').Append(SettingType).Append(':').Append(SettingValue);

			return builder.ToString();
		}
	}
}
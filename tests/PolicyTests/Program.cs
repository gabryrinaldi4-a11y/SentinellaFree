using System.Text.Json;
using Sentinella.App;
int checks=0;
void Check(bool ok,string message){if(!ok)throw new Exception(message);checks++;Console.WriteLine("PASS "+message);}
foreach(var action in new[]{"ransomware-on","ransomware-audit","pua-on","network-audit","firewall-on"})
{ ProtectionTools.ValidateAction(action); Check(true,"Closed-list accepts "+action+" without executing"); }
foreach(var action in new[]{"", "RANSOMWARE-ON", "pua-on; Set-MpPreference -DisableRealtimeMonitoring 1", "firewall-off", "network-on", " ransomware-on"})
{
 bool rejected=false;try{ProtectionTools.ValidateAction(action);}catch(ArgumentException){rejected=true;}
 Check(rejected,"Closed-list rejects unsupported/injected action");
}
using(var canceled=new CancellationTokenSource())
{
 canceled.Cancel();bool stopped=false;try{await ProtectionTools.ApplyPolicyAsync("firewall-on",canceled.Token);}catch(OperationCanceledException){stopped=true;}
 Check(stopped,"Pre-cancelled mutation never launches elevation");
}
bool invalidStopped=false;try{await ProtectionTools.ApplyPolicyAsync("arbitrary-script");}catch(ArgumentException){invalidStopped=true;}
Check(invalidStopped,"Unsupported action rejected before elevation");
var audit=await ProtectionTools.GetAuditAsync();
Check(audit.GetProperty("ObservedAt").GetString() is not null,"Audit has observation timestamp");
foreach(var section in new[]{"Defender","Providers","Firewall","Startup","Connections"})
{
 var value=audit.GetProperty(section); Check(value.GetProperty("Available").ValueKind is JsonValueKind.True or JsonValueKind.False,"Audit availability explicit: "+section);
 if(!value.GetProperty("Available").GetBoolean()) Check(!string.IsNullOrWhiteSpace(value.GetProperty("Error").GetString()),"Unavailable section includes reason: "+section);
}
if(audit.GetProperty("Firewall").GetProperty("Available").GetBoolean())
 foreach(var item in audit.GetProperty("Firewall").GetProperty("Items").EnumerateArray())
 Check(item.GetProperty("Enabled").ValueKind is JsonValueKind.True or JsonValueKind.False,"Firewall enabled is observed Boolean");
if(audit.GetProperty("Connections").GetProperty("Available").GetBoolean())
 Check(audit.GetProperty("Connections").GetProperty("Items").GetArrayLength()<=500,"TCP inventory bounded to 500 rows");
File.WriteAllText(Path.Combine(AppContext.BaseDirectory,"audit-observed.json"),JsonSerializer.Serialize(audit,new JsonSerializerOptions{WriteIndented=true}));
Console.WriteLine($"RESULT {checks} passed; no settings changed and no elevation requested.");

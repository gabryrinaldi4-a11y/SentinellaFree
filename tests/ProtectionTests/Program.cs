using System.Security.Cryptography;
using System.Text.Json;
using Sentinella.Core;
int passed=0;
void Check(bool condition,string name){if(!condition)throw new Exception("FAIL: "+name);Console.WriteLine("PASS: "+name);passed++;}
void Reject(Action action,string name){try{action();}catch(Exception ex)when(ex is ArgumentException or IOException or CryptographicException or InvalidDataException){Check(true,name);return;}throw new Exception("FAIL: "+name);}
var now=DateTimeOffset.UtcNow;var queue=new DebouncedChanges(2);
Check(queue.Add("A",now)&&queue.Add("B",now),"bounded queue accepts capacity");
Check(!queue.Add("C",now),"queue overflow is explicit");
Check(queue.Add("a",now.AddSeconds(1)),"duplicate path does not consume capacity");
Check(queue.Take(now.AddSeconds(1)) is null,"debounce waits for stable interval");
Check(queue.Take(now.AddSeconds(3)) is not null,"settled change becomes available");
Check(BehavioralSignals.Process(@"C:\Windows\powershell.exe","Get-Date","explorer.exe",now) is null,"normal shell invocation not treated as a detection");
var signal=BehavioralSignals.Process(@"C:\Windows\powershell.exe","secret-value","WINWORD.EXE",now);
Check(signal?.Severity=="Warning"&&!JsonSerializer.Serialize(signal).Contains("secret-value"),"Office shell warning redacts command arguments");
Check(BehavioralSignals.Process(@"C:\Windows\mshta.exe","https://test.invalid/secret","explorer.exe",now)?.Kind=="ProcessBehavior","remote interpreter signal is reported without execution");
var bursts=new FileBurstDetector();ProtectionAlert? warning=null;
for(int i=0;i<150;i++)warning=bursts.Observe(@"C:\fixture\file"+i,now);
Check(warning?.Severity=="Warning","file burst is an uncertain warning, not a malware verdict");
Check(bursts.Observe(@"C:\fixture\another",now.AddSeconds(1)) is null,"burst warnings are throttled");
var repeated=new FileBurstDetector();for(int i=0;i<200;i++)CheckBurst();
void CheckBurst(){if(repeated.Observe(@"C:\fixture\same",now) is not null)throw new Exception("Duplicate event counted as separate file");}
Check(true,"duplicate write notifications do not create a burst");
string temp=Path.Combine(Path.GetTempPath(),"Sentinella-ProtectionTests-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(temp);
try
{
    string root=Path.Combine(temp,"watched"),state=Path.Combine(temp,"state"),runtime=Path.Combine(temp,"runtime");Directory.CreateDirectory(root);Directory.CreateDirectory(state);Directory.CreateDirectory(runtime);
    var config=new ContinuousSettings(true,[root]);ContinuousConfiguration.Save(Path.Combine(state,"settings.json"),config);
    Check(ContinuousConfiguration.Load(Path.Combine(state,"settings.json")).Folders.Single()==root,"configuration survives restart");
    Reject(()=>ContinuousConfiguration.Validate(config with{Folders=[]}),"enabled monitor requires a selected scope");
    Reject(()=>ContinuousConfiguration.Validate(config with{Folders=[Path.GetPathRoot(root)!]}),"whole-drive watchers refused");
    string path=Path.Combine(root,"harmless.txt");await File.WriteAllTextAsync(path,"ordinary text");
    var fake=new FakeEngine();using var monitor=new ContinuousProtection(config,fake,state,runtime);
    Check(!monitor.Queue(Path.Combine(temp,"outside.txt"),now),"events outside configured folders rejected");
    using(var flood=new ContinuousProtection(config,new FakeEngine(),state,runtime))
    {for(int i=0;i<2001;i++)flood.Queue(Path.Combine(root,"queued-"+i),now);Check(flood.Snapshot().Pending==2000&&flood.Snapshot().Incomplete==1,"dropped watcher events increment incomplete coverage");}
    Check(monitor.Queue(path,now),"changed file queued");await monitor.ProcessNextAsync(now.AddSeconds(3),default);
    Check(monitor.Snapshot().Scanned==1&&monitor.Snapshot().Detections==0,"complete benign scan recorded");
    fake.Incomplete=true;monitor.Queue(path,now);await monitor.ProcessNextAsync(now.AddSeconds(3),default);
    Check(monitor.Snapshot().Incomplete==1&&monitor.Snapshot().Alerts.Any(a=>a.Kind=="IncompleteScan"),"partial scan never represented as full coverage");
    fake.Incomplete=false;fake.Detected=true;monitor.Queue(path,now);await monitor.ProcessNextAsync(now.AddSeconds(3),default);
    Check(monitor.Snapshot().Detections==1&&File.Exists(path),"confirmed marker alert never deletes the source automatically");
    fake.Detected=false;fake.Mutate=true;monitor.Queue(path,now);long before=monitor.Snapshot().Scanned;await monitor.ProcessNextAsync(now.AddSeconds(3),default);
    Check(monitor.Snapshot().Scanned==before&&monitor.Snapshot().Pending==1,"content race triggers retry, not a clean result");
    fake.Mutate=false;using(var cancelled=new CancellationTokenSource()){cancelled.Cancel();try{await monitor.ProcessNextAsync(now.AddSeconds(7),cancelled.Token);throw new Exception("Cancellation ignored");}catch(OperationCanceledException){Check(true,"cancellation propagates");}}
    fake.UpdateFails=true;await monitor.UpdateAsync(default);Check(monitor.Snapshot().Error is not null&&monitor.Snapshot().SignaturesUpdated is null,"failed signature update is visible");
    fake.UpdateFails=false;await monitor.UpdateAsync(default);Check(monitor.Snapshot().SignaturesUpdated is not null&&monitor.Snapshot().Error is null,"signature success clears the update error");
    using(var token=new CancellationTokenSource())
    using(var watching=new ContinuousProtection(config,new FakeEngine(),state,runtime))
    {
        var task=watching.RunAsync(token.Token);string fresh=Path.Combine(root,"live-watch.txt");await File.WriteAllTextAsync(fresh,"harmless filesystem fixture");
        for(int i=0;i<60&&watching.Snapshot().Scanned==0;i++)await Task.Delay(100);
        Check(watching.Snapshot().Scanned>0,"real filesystem notification reaches the scan pipeline");token.Cancel();try{await task;}catch(OperationCanceledException){}
        Check(watching.Snapshot().State=="Stopped","watchers stop and report their stopped state");
    }
    using var rsa=RSA.Create(3072);string pub=rsa.ExportSubjectPublicKeyInfoPem();
    var release=new ReleaseManifest("0.5.0","SentinellaFree-0.5.0.zip",4,Convert.ToHexString(SHA256.HashData([1,2,3,4])),"https://github.com/gabryrinaldi4-a11y/SentinellaFree/releases/download/v0.5.0/SentinellaFree-0.5.0.zip",now.AddDays(2));
    byte[] manifest=JsonSerializer.SerializeToUtf8Bytes(release),signature=rsa.SignData(manifest,HashAlgorithmName.SHA256,RSASignaturePadding.Pss);
    Check(ReleaseVerification.Verify(manifest,signature,pub,new Version(0,4,0),now).Version=="0.5.0","pinned RSA-PSS release manifest accepted");
    byte[] changed=manifest.ToArray();changed[5]^=1;Reject(()=>ReleaseVerification.Verify(changed,signature,pub,new Version(0,4,0),now),"changed release manifest rejected");
    Reject(()=>ReleaseVerification.Verify(manifest,signature,pub,new Version(0,5,0),now),"release replay or downgrade rejected");
    Reject(()=>ReleaseVerification.Verify(manifest,signature,pub,new Version(0,4,0),now.AddDays(3)),"expired manifest rejected");
    Reject(()=>ReleaseVerification.Verify(manifest,signature,"",new Version(0,4,0),now),"missing trusted key fails closed");
    var foreign=release with{Url="https://example.invalid/update.zip"};byte[] foreignJson=JsonSerializer.SerializeToUtf8Bytes(foreign);
    Reject(()=>ReleaseVerification.Verify(foreignJson,rsa.SignData(foreignJson,HashAlgorithmName.SHA256,RSASignaturePadding.Pss),pub,new Version(0,4,0),now),"even a signed manifest cannot change the allowed repository");
    string archive=Path.Combine(temp,"archive.zip");await File.WriteAllBytesAsync(archive,[1,2,3,4]);await ReleaseVerification.VerifyArchiveAsync(archive,release);Check(true,"release archive size and hash checked");
    await File.WriteAllBytesAsync(archive,[4,3,2,1]);try{await ReleaseVerification.VerifyArchiveAsync(archive,release);throw new Exception("Bad archive accepted");}catch(CryptographicException){Check(true,"changed release archive rejected");}
    Console.WriteLine($"RESULT: {passed} protection checks passed. Harmless fixtures only; no policy, process termination, persistence or network changes.");
}
finally{string full=Path.GetFullPath(temp);if(Path.GetDirectoryName(full)!=Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar)||!Path.GetFileName(full).StartsWith("Sentinella-ProtectionTests-",StringComparison.Ordinal))throw new Exception("Unsafe test cleanup path");Directory.Delete(full,true);}
sealed class FakeEngine:IContinuousEngine
{
    public bool Incomplete,Detected,Mutate,UpdateFails;
    public async Task<ClamScanReport> ScanAsync(string path,CancellationToken token)
    {token.ThrowIfCancellationRequested();if(Mutate)await File.AppendAllTextAsync(path,"changed",token);return new(DateTimeOffset.UtcNow,DateTimeOffset.UtcNow,"fixture",path,Detected?1:Incomplete?2:0,"test",!Incomplete,1,Detected?[new(path,"Harmless.Custom.Marker",false)]:[],Incomplete?["fixture limitation"]:[],"","");}
    public Task UpdateAsync(CancellationToken token)=>UpdateFails?Task.FromException(new IOException("fixture update failure")):Task.CompletedTask;
}

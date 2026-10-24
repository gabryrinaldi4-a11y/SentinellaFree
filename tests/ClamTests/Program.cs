using System.IO.Compression;
using System.Text;
using Sentinella.Core;

int passed = 0;
void Assert(bool ok, string message) { if(!ok) throw new Exception(message); passed++; Console.WriteLine("PASS " + message); }
async Task Reject(Func<Task> work, string message) { bool rejected=false; try {await work();} catch(Exception e) when(e is IOException or InvalidOperationException or System.ComponentModel.Win32Exception) {rejected=true;} Assert(rejected,message); }
string root=Path.GetFullPath(args.Length > 1 ? args[1] : Path.Combine("work","clam-test-data"));
Directory.CreateDirectory(root);
string engine=Path.GetFullPath(args[0]);
string database=Path.Combine(root,"db"); Directory.CreateDirectory(database);
const string marker="SENTINELLA_HARMLESS_CUSTOM_TEST_SIGNATURE_20261024";
string signature="Sentinella.HarmlessFixture:0:*:" + Convert.ToHexString(Encoding.ASCII.GetBytes(marker));
File.WriteAllText(Path.Combine(database,"test.ndb"),signature+"\n",new UTF8Encoding(false));
var clam=new ClamEngine(engine,database);
var status=await clam.GetStatusAsync();
Console.WriteLine("STATUS " + System.Text.Json.JsonSerializer.Serialize(status));
Assert(status.EngineAvailable,"Official ClamAV binary starts without Defender");
Assert(status.DatabaseAvailable && !status.OfficialDatabasesPresent && status.SignatureCount==1,"Custom test database identified as partial, never official full coverage");
string clean=Path.Combine(root,"benign & spaces.txt"); File.WriteAllText(clean,"This text is an independent benign control.");
string marked=Path.Combine(root,"innocuo-matched.txt"); File.WriteAllText(marked,"Harmless test data. " + marker);
var cleanReport=await clam.ScanAsync(clean);
Console.WriteLine("CLEAN " + System.Text.Json.JsonSerializer.Serialize(cleanReport));
Assert(cleanReport.ExitCode==0 && cleanReport.Verdict=="NoDetectionsWithinScope" && cleanReport.Detections.Count==0,"Benign control returns scoped no-detections, not universal clean");
Assert(cleanReport.ScannedFiles==1 && cleanReport.Warnings.Any(x=>x.Contains("parziale")),"Report retains scanned count and partial-signatures warning");
var matchReport=await clam.ScanAsync(marked);
Console.WriteLine("MATCH " + System.Text.Json.JsonSerializer.Serialize(matchReport));
Assert(matchReport.ExitCode==1 && matchReport.Verdict=="ThreatsDetected","Harmless custom signature exercises real engine detection exit1");
Assert(matchReport.Detections.Any(x=>x.Path==marked && x.Signature.StartsWith("Sentinella.HarmlessFixture")),"Windows path and exact signature parsed from actual engine output");
string inner=Path.Combine(root,"inner.zip"),outer=Path.Combine(root,"outer.zip");
if(File.Exists(inner)) File.Delete(inner); if(File.Exists(outer)) File.Delete(outer);
using(var zip=ZipFile.Open(inner,ZipArchiveMode.Create)) zip.CreateEntryFromFile(marked,"data.txt");
using(var zip=ZipFile.Open(outer,ZipArchiveMode.Create)) zip.CreateEntryFromFile(inner,"inner.zip");
var archiveReport=await clam.ScanAsync(outer);
Console.WriteLine("ARCHIVE " + System.Text.Json.JsonSerializer.Serialize(archiveReport));
Assert(archiveReport.ExitCode==1 && archiveReport.Detections.Count>0,"Real engine inspects nested ZIP without app extracting executable content");
Assert(File.Exists(marked) && File.Exists(outer),"Scanning never deletes or quarantines source files automatically");
var missingDb=new ClamEngine(engine,Path.Combine(root,"missing-db"));
Assert(!(await missingDb.GetStatusAsync()).DatabaseAvailable,"Missing database is unavailable status");
await Reject(()=>missingDb.ScanAsync(clean),"Missing database cannot yield no-detections verdict");
await Reject(()=>clam.ScanAsync(Path.Combine(root,"missing.txt")),"Missing target rejected before engine launch");
using(var cts=new CancellationTokenSource()){cts.Cancel(); bool canceled=false; try{await clam.ScanAsync(clean,cts.Token);}catch(OperationCanceledException){canceled=true;} Assert(canceled,"Cancellation is honored");}
string badDb=Path.Combine(root,"invalid-db"); Directory.CreateDirectory(badDb); File.WriteAllText(Path.Combine(badDb,"bad.ndb"),"This is not a ClamAV signature.\n");
var invalid=new ClamEngine(engine,badDb); var badReport=await invalid.ScanAsync(clean);
Console.WriteLine("BADDB " + System.Text.Json.JsonSerializer.Serialize(badReport));
Assert(badReport.ExitCode==2 && !badReport.IsComplete && badReport.Verdict=="Incomplete","Real database parse failure returns error2 and incomplete, never clean");
Assert(badReport.Warnings.Count>0,"Engine failure is preserved in diagnostics");
string unicode=Path.Combine(root,"caffè-漢字-innocuo.txt"); File.WriteAllText(unicode, marker);
var unicodeReport=await clam.ScanAsync(unicode); Console.WriteLine("UNICODE " + System.Text.Json.JsonSerializer.Serialize(unicodeReport));
Assert(unicodeReport.ExitCode==1 && unicodeReport.Detections.Count>0,"Real engine accepts Unicode target path");
Assert(unicodeReport.Detections[0].Path==unicode,"Detected Unicode path preserved exactly");
string large=Path.Combine(root,"large-benign.dat"); using(var stream=new FileStream(large,FileMode.Create,FileAccess.Write)) stream.SetLength(257L*1024*1024);
var limitReport=await clam.ScanAsync(large); Console.WriteLine("LIMIT " + System.Text.Json.JsonSerializer.Serialize(limitReport));
Assert(!limitReport.IsComplete && limitReport.Verdict=="Incomplete","Oversize file yields incomplete instead of clean");
Assert(limitReport.Detections.All(x=>x.IsHeuristicWarning),"Limit warnings never presented as confirmed malware");
File.Delete(large);
string staging=Path.Combine(root,"staging"); Directory.CreateDirectory(staging);
var store=new QuarantineStore(Path.Combine(root,"quarantine-"+Guid.NewGuid().ToString("N")));
string isolationSource=Path.Combine(root,"quarantine-source.txt"); File.WriteAllText(isolationSource,marker);
var isolated=await ClamQuarantine.IsolateAsync(clam,store,isolationSource,staging);
Assert(!File.Exists(isolationSource) && store.List().Any(x=>x.Id==isolated.Id),"Clam snapshot rescan confirms detection before encrypted quarantine removes original");
string recovered=Path.Combine(root,"quarantine-restored-"+Guid.NewGuid().ToString("N")+".txt"); await store.RestoreAsync(isolated.Id,recovered);
Assert(File.ReadAllText(recovered)==marker,"Clam quarantine roundtrip preserves exact benign fixture bytes");
Assert(!Directory.EnumerateFiles(staging).Any(),"Clam quarantine removes only its GUID snapshot after completion");
await Reject(()=>ClamQuarantine.IsolateAsync(clam,store,clean,staging),"Clam quarantine refuses benign nondetection");
Assert(File.Exists(clean) && !Directory.EnumerateFiles(staging).Any(),"Benign refusal preserves original and cleans staging");
using(var locked=new FileStream(clean,FileMode.Open,FileAccess.ReadWrite,FileShare.None))
    await Reject(()=>ClamQuarantine.IsolateAsync(clam,store,clean,staging),"Clam quarantine rejects locked original");
await Reject(()=>ClamQuarantine.IsolateAsync(clam,store,clean,@"\\server\share"),"Clam quarantine rejects network staging path");
string changing=Path.Combine(root,"changing-source.txt"); File.WriteAllText(changing,marker);
using(var watcher=new FileSystemWatcher(staging,"*.bin"))
{
    var created=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    watcher.Created+=(_,_)=>created.TrySetResult(); watcher.EnableRaisingEvents=true;
    var change=Task.Run(async()=>
    {
        await created.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var deadline=DateTimeOffset.UtcNow.AddSeconds(5);
        while(true)
        {
            try { File.AppendAllText(changing," changed after snapshot"); return; }
            catch(IOException) when(DateTimeOffset.UtcNow<deadline) { await Task.Delay(1); }
        }
    });
    await Reject(()=>ClamQuarantine.IsolateAsync(clam,store,changing,staging),"Original changed after capture cannot be quarantined from stale snapshot");
    await change;
}
Assert(File.Exists(changing) && File.ReadAllText(changing).Contains("changed after snapshot"),"Concurrent source change is preserved");
Assert(!Directory.EnumerateFiles(staging).Any(),"Rejected stale snapshot is cleaned up");
Console.WriteLine($"RESULT {passed} passed; real ClamAV process, only harmless custom signature and benign ZIP fixtures.");



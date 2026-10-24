using Sentinella.Core;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
int passed=0,skipped=0;
string root=Path.Combine(Path.GetTempPath(),"SentinellaSnapshotTests-"+Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
void Check(bool ok,string message){if(!ok)throw new Exception(message);passed++;Console.WriteLine("PASS "+message);}
async Task Reject(Func<Task> action,string message){bool rejected=false;try{await action();}catch(Exception e)when(e is IOException or InvalidDataException or ArgumentException or System.ComponentModel.Win32Exception){rejected=true;}Check(rejected,message);}
try
{
 string source=Path.Combine(root,"source"), vaultPath=Path.Combine(root,"vault");Directory.CreateDirectory(source);
 Directory.CreateDirectory(Path.Combine(source,"empty"));Directory.CreateDirectory(Path.Combine(source,"nested"));
 byte[] original="Snapshot benign bytes, nessun malware."u8.ToArray();
 File.WriteAllBytes(Path.Combine(source,"original.txt"),original);File.WriteAllText(Path.Combine(source,"nested","file with spaces & literal.txt"),"second benign file");
 var vault=new SnapshotVault(vaultPath);var first=await vault.CreateAsync(source);
 Check(first.Complete&&first.FileCount==2&&first.Errors.Count==0,"Complete snapshot captures benign files");
 Check(File.ReadAllBytes(Path.Combine(source,"original.txt")).SequenceEqual(original),"Snapshot never changes source bytes");
 Check(Directory.EnumerateDirectories(vaultPath).All(p=>!Path.GetFileName(p).StartsWith(".staging-")),"Successful snapshot committed atomically, no staging remains");
 File.WriteAllText(Path.Combine(source,"original.txt"),"new original version");
 var second=await vault.CreateAsync(source);Check(first.Id!=second.Id&&vault.List().Count==2,"Different versions retained");
 string restore=Path.Combine(root,"restore-first");await vault.RestoreAsync(first.Id,restore);
 Check(File.ReadAllBytes(Path.Combine(restore,"original.txt")).SequenceEqual(original),"Old version restores exact original bytes after source changes");
 Check(Directory.Exists(Path.Combine(restore,"empty")),"Empty directories preserved");
 Check(File.ReadAllText(Path.Combine(source,"original.txt"))=="new original version","Restore leaves current original unchanged");
 await Reject(()=>vault.RestoreAsync(first.Id,restore),"Existing destination rejected, no overwrite");
 Check(File.ReadAllBytes(Path.Combine(restore,"original.txt")).SequenceEqual(original),"Overwrite rejection preserves destination bytes");
 await Reject(()=>vault.RestoreAsync("../outside",Path.Combine(root,"badid")),"Traversal snapshot ID rejected");
 await Reject(()=>vault.CreateAsync(Path.Combine(root,"missing")),"Missing source rejected");
 await Reject(()=>vault.CreateAsync(root),"Vault inside source rejected");
 await Reject(()=>vault.CreateAsync(vaultPath),"Vault equal source rejected");
 await Reject(()=>vault.CreateAsync(Path.GetPathRoot(root)!),"Root source containing vault rejected");
 await Reject(()=>vault.RestoreAsync(first.Id,Path.Combine(vaultPath,"restored")),"Restore inside vault rejected");
 string manifestPath=Path.Combine(vaultPath,first.Id,"manifest.json");string manifestText=File.ReadAllText(manifestPath);
 var manifest=JsonNode.Parse(manifestText)!.AsObject();manifest["Files"]![0]!["Path"]="..\\escape.txt";
 File.WriteAllText(manifestPath,manifest.ToJsonString());
 await Reject(()=>vault.RestoreAsync(first.Id,Path.Combine(root,"badpath")),"Manifest relative traversal rejected before copying");
 Check(!Directory.Exists(Path.Combine(root,"badpath"))&&!File.Exists(Path.Combine(root,"escape.txt")),"Traversal produces no destination or escaped file");
 File.WriteAllText(manifestPath,manifestText);
 string stored=Path.Combine(vaultPath,first.Id,"data","original.txt");File.WriteAllText(stored,"tampered");
 string corruptedTarget=Path.Combine(root,"corrupted");
 await Reject(()=>vault.RestoreAsync(first.Id,corruptedTarget),"Tampered snapshot content rejected");
 Check(!Directory.Exists(corruptedTarget),"Integrity verified before creating restore destination");
 File.WriteAllBytes(stored,original);
 string locked=Path.Combine(source,"locked.txt");File.WriteAllText(locked,"locked benign file");
 using(var handle=new FileStream(locked,FileMode.Open,FileAccess.ReadWrite,FileShare.None))
 { var incomplete=await vault.CreateAsync(source);Check(!incomplete.Complete&&incomplete.Errors.Count>0&&incomplete.FileCount==2,"Inaccessible file explicitly marks snapshot incomplete"); }
 string oversized=Path.Combine(source,"oversized.bin");using(var handle=new FileStream(oversized,FileMode.CreateNew,FileAccess.Write)){handle.SetLength(SnapshotVault.MaxFileBytes+1);}
 var over=await vault.CreateAsync(source);Check(!over.Complete&&over.Errors.Any(x=>x.Contains("dimensione")),"Oversized file skipped and snapshot incomplete");File.Delete(oversized);
 using(var cancel=new CancellationTokenSource()){cancel.Cancel();bool stopped=false;try{await vault.CreateAsync(source,cancel.Token);}catch(OperationCanceledException){stopped=true;}Check(stopped,"Cancellation honored before capture");}
 try
 {
  string link=Path.Combine(source,"link");Directory.CreateSymbolicLink(link,Path.Combine(source,"nested"));
  var withLink=await vault.CreateAsync(source);Check(!withLink.Complete&&withLink.Errors.Any(x=>x.Contains("Collegamento")),"Symbolic link skipped and capture incomplete");
 }
 catch(Exception e)when(e is UnauthorizedAccessException or IOException){skipped++;Console.WriteLine("SKIP symlink test: privilege unavailable");}
 File.WriteAllText(Path.Combine(vaultPath,".staging-uncommitted.txt"),"not a committed snapshot");
 Directory.CreateDirectory(Path.Combine(vaultPath,".staging-uncommitted"));
 Check(vault.List().All(x=>Guid.TryParseExact(x.Id,"N",out _)),"Incomplete staging never listed as committed");
 Console.WriteLine($"RESULT {passed} passed, {skipped} skipped, 0 failed; harmless fixtures only.");
}
finally
{
 // Only this test-owned randomly named root. Reparse links are not recursively followed by Directory.Delete.
 if(root.StartsWith(Path.Combine(Path.GetTempPath(),"SentinellaSnapshotTests-"),StringComparison.OrdinalIgnoreCase)&&Directory.Exists(root)) Directory.Delete(root,true);
}

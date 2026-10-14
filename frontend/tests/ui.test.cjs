const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),ts=require('typescript');
for(const extension of ['.ts','.tsx'])require.extensions[extension]=(module,file)=>{const source=fs.readFileSync(file,'utf8');module._compile(ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.CommonJS,jsx:ts.JsxEmit.ReactJSX,target:ts.ScriptTarget.ES2022}}).outputText,file);};
require.extensions['.css']=()=>{};
const model=require('../src/overviewModel.ts');
test('unknown coverage or clock cannot be labelled clean',()=>{const topology={stall_ms:200,min_eligible_ratio:.9},segment={reason:null,max_ms:.4,p95_ms:.01,loss_percent:0,eligible_ratio:1,classes:{},latency_uncertainty_ms:.01};assert.equal(model.segmentHealth(segment,topology),'clean');assert.equal(model.segmentHealth({...segment,reason:'Clock unknown'},topology),'unknown');assert.equal(model.segmentHealth({...segment,loss_percent:null},topology),'unknown');assert.equal(model.segmentHealth({...segment,eligible_ratio:.2},topology),'unknown');assert.equal(model.segmentHealth({...segment,latency_uncertainty_ms:300},topology),'unknown');assert.equal(model.segmentHealth({...segment,classes:{recovered_loss:1}},topology),'clean');});
test('client port comes from earliest forward evidence, never a hash or service port',()=>{const refs=[{point:'nat',content_filter:'tcp.srcport == 50000'},{point:'client',content_filter:'tcp.srcport == 41049 && tcp.dstport == 8080'}];assert.equal(model.portFromEvidence(refs,['client','nat']),41049);assert.equal(model.portFromEvidence([{point:'x'}]),null);const bar={time:1700000020,parts:[{component:'RX',evidence:refs}]};assert.match(model.cycleLabel(bar,['client','nat']),/:41049/);});
test('p99 uses the available sample population and retains an extreme value outside the cap',()=>{const samples=Array(1000).fill(1300).concat(16000);assert.equal(model.quantile(samples,.99),1300);assert.equal(model.quantile([], .99),null);assert.equal(model.quantile([NaN,Infinity,2,4],.5),3);});
test('identical hold trains form one selector group without losing occurrences',()=>{const item={hop:'forward:wire:host',metrics:{wire_spacing_ms:[200.1,400.1],receive_spacing_ms:[1.1,1]},evidence:[]};const rows=Array.from({length:30},(_,i)=>({...item,id:String(i)}));const groups=model.groupHolds(rows);assert.equal(groups.length,1);assert.equal(groups[0].length,30);assert.deepEqual(groups[0].map(r=>r.id),rows.map(r=>r.id));assert.equal(model.groupHolds(rows.concat({...item,id:'different',metrics:{wire_spacing_ms:[100,200],receive_spacing_ms:[1,1]}})).length,2);});
test('all metric labels include readable units',()=>{for(const label of Object.values(model.metricLabels))assert.match(label,/\((ms|count|%)\)/);});
test('every frontend source file remains at most 400 lines',()=>{function walk(dir){for(const n of fs.readdirSync(dir)){const file=path.join(dir,n);if(fs.statSync(file).isDirectory())walk(file);else if(/\.(ts|tsx|css)$/.test(file)){const count=fs.readFileSync(file,'utf8').trimEnd().split('\n').length;assert.ok(count<=400,`${file}: ${count}`);}}}walk(path.join(__dirname,'../src'));});
const stateFile=process.env.PACKETBREAKER_UI_STATE;
if(stateFile){const React=require('react'),{renderToStaticMarkup}=require('react-dom/server'),state=JSON.parse(fs.readFileSync(stateFile,'utf8'));const {WorkspaceContext}=require('../src/WorkspaceContext.tsx');const value={state,report:state.report,topology:state.topology,range:null,rangeQuery:'',visibleFindings:state.report.findings,ready:6,kinds:{},job:{state:'idle',busy:false},busy:false,flows:{total:50,items:[]},flowOffset:0,search:'',filter:'',sort:'bytes',selectedFlow:null,ladder:null,ladderOffset:0,events:null,fieldDiff:null,inspection:null,overlay:null,tab:'Overview',path:'',projectPath:state.project,tsharkPath:'',prefix:64,parallelIngest:false,memoryLimit:'',checkpointUuid:false,f5Trailer:false,assistantEnabled:false,fortiPath:'',fortiStart:'',fortiDevice:'FortiGate',uploadPercent:null,error:'',notice:'',selectRange:()=>{},setEvidence:()=>{},setTab:()=>{}};
function render(name){const Component=require('../src/'+name+'.tsx')[name];return renderToStaticMarkup(React.createElement(WorkspaceContext.Provider,{value},React.createElement(Component)));}
test('50-flow aggregate card has six evidence-linked lines and avoids raw verdict/key text',()=>{const html=render('ResultCard');for(const label of ['Where','When','How much','Not the cause','Server-local p95','Clock confidence'])assert.ok(html.includes(label));assert.equal((html.match(/Evidence ↗/g)||[]).length,6);assert.ok(!html.includes('rx_max_ms'));assert.ok(html.includes('100/0'));});
test('outlier has a readable client-port label',()=>{const bar=state.report.incident.cycle_bars.find(b=>b.total_ms>16000);assert.ok(bar);assert.match(model.cycleLabel(bar,state.topology.forward),/:41049/);});
test('100 real hold findings render exactly one chart',()=>{assert.equal(state.report.flow_count,50);assert.equal(state.report.incident.hold_release.length,100);const html=render('HoldReleaseView');assert.equal((html.match(/role="img"/g)||[]).length,1);assert.ok(html.includes('100 trains'));});
test('all non-Overview views still render their existing controls',()=>{for(const [name,label] of [['CapturesView','Choose capture files'],['PathView','Save topology'],['FlowsView','Search conversations'],['SettingsView','Project directory']])assert.ok(render(name).includes(label),name);});}

const cycles=require('../src/cycleDisplay.ts');
test('materiality keeps tiny recovered loss clean, distinguishes event impact and outside-event minor',()=>{
 const topology={min_eligible_ratio:.9}, segment={id:'fw',reason:null,max_ms:.1,p95_ms:.01,loss_percent:.01,eligible_ratio:1,classes:{recovered_loss:2},latency_uncertainty_ms:.01};
 const report={incident:{window:{start:20,end:45}},findings:[]};
 assert.equal(model.segmentHealth(segment,topology,report),'clean');
 assert.equal(model.segmentHealth({...segment,reason:'Clock unknown'},topology,report),'unknown');
 assert.equal(model.segmentHealth({...segment,loss_percent:.1},topology,report),'degraded');
 const loss={hop:'fw',type:'impactful_loss',time_range:[25,26]};
 assert.equal(model.segmentHealth({...segment,classes:{impactful_loss:1}},topology,{...report,findings:[loss]}),'degraded');
 assert.equal(model.segmentHealth({...segment,classes:{impactful_loss:1}},topology,{...report,findings:[{...loss,time_range:[1,2]}]}),'minor');
 assert.equal(model.segmentHealth({...segment,max_ms:11},topology,report),'degraded');
});
test('cycle stacks omit local service/client wait and retain missing components as unknown',()=>{
 const bar={parts:[{component:'RX',ms:100},{component:'TX',ms:1123},{component:'local',ms:4000},{component:'wait',ms:2000}]};
 assert.equal(cycles.addedTotal(bar),1223);assert.equal(cycles.addedParts(bar).length,2);
 assert.equal(cycles.addedTotal({parts:[...bar.parts,{component:'RX',ms:null}]}),null);
});
test('path labels truncate with a tooltip instead of wrapping inside words',()=>{
 const css=fs.readFileSync(path.join(__dirname,'../src/styles/overview.css'),'utf8');
 assert.match(css,/text-overflow: ellipsis/);assert.match(css,/white-space: nowrap/);assert.ok(!css.includes('overflow-wrap: anywhere'));
 const source=fs.readFileSync(path.join(__dirname,'../src/PathHealth.tsx'),'utf8');assert.ok(source.includes('point?.label || id} —'));
});
if(stateFile)test('50-flow replica maximum added stack agrees with event aggregate within 1 ms rounding',()=>{
 const state=JSON.parse(fs.readFileSync(stateFile,'utf8')), r=state.report,window=r.incident.window;
 const bars=cycles.displayCycles(r,true).filter(b=>b.time>=window.start && b.time<window.end);
 const maximum=Math.max(...bars.map(b=>cycles.addedTotal(b)).filter(n=>n!=null));
 assert.ok(Math.abs(maximum-r.cycles.event.max_added_ms)<1,`${maximum} vs ${r.cycles.event.max_added_ms}`);
 const degraded=r.segments.find(s=>s.classes && Object.values(s.classes).some(n=>n>0));
 assert.equal(model.segmentHealth({...degraded,reason:null,max_ms:.1,p95_ms:.01,loss_percent:.01,eligible_ratio:1,classes:{recovered_loss:2},latency_uncertainty_ms:.01},state.topology,{...r,findings:[]}),'clean');
 const source=fs.readFileSync(path.join(__dirname,'../src/CycleAddedChart.tsx'),'utf8');assert.match(source,/type: "plain"/);assert.ok(!source.includes('Server-local (ms)'));
});

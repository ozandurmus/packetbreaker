import { ResultCard } from "./ResultCard";
import { PathHealth } from "./PathHealth";
import { CycleAddedChart } from "./CycleAddedChart";
import { HoldReleaseView } from "./HoldReleaseView";
import { FindingDetails } from "./FindingDetails";
import { CoverageDetails } from "./CoverageDetails";
import { ProtocolDiagnostics } from "./ProtocolDiagnostics";
import { CaptureQualityCards } from "./CaptureQualityCards";
import { CaptureNotes } from "./CaptureNotes";
export function OverviewView() { return <><ResultCard /><PathHealth /><CycleAddedChart /><HoldReleaseView /><FindingDetails /><CoverageDetails /><ProtocolDiagnostics /><CaptureQualityCards /><CaptureNotes /></>; }

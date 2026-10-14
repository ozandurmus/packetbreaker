import { FindingDetails } from "./FindingDetails";
import { CoverageDetails } from "./CoverageDetails";
import { ProtocolDiagnostics } from "./ProtocolDiagnostics";
import { CaptureQualityCards } from "./CaptureQualityCards";
import { CaptureNotes } from "./CaptureNotes";
export function OverviewView() { return <><FindingDetails /><CoverageDetails /><ProtocolDiagnostics /><CaptureQualityCards /><CaptureNotes /></>; }

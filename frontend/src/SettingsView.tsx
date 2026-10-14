import {ProjectSettings} from "./ProjectSettings";
import {AnalysisSettings} from "./AnalysisSettings";
import {ClockSettings} from "./ClockSettings";
export function SettingsView() {
  return (
    <>
      <ProjectSettings />
      <AnalysisSettings />
      <ClockSettings />
    </>
  );
}

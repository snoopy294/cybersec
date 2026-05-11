import ReportView from "../../../_components/ReportView";

export default function ReportPage({ params }) {
  return <ReportView reportHash={params.hash} />;
}

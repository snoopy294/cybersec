import ReportView from "../../../_components/ReportView";

export default async function ReportPage({ params }) {
  const { hash } = await params;
  return <ReportView reportHash={hash} />;
}

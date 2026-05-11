import AnalyzeClient from "../../_components/AnalyzeClient";

export default function AnalyzePage({ searchParams }) {
  return <AnalyzeClient initialJobId={searchParams?.job || null} />;
}

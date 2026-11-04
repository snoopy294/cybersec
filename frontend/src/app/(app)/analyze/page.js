import AnalyzeClient from "../../_components/AnalyzeClient";

export default async function AnalyzePage({ searchParams }) {
  const { job } = (await searchParams) || {};
  return <AnalyzeClient initialJobId={typeof job === "string" ? job : null} />;
}

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

type SummaryCardProps = {
  title: string;
  value: string;
  detail?: string;
  accent?: "critical" | "high" | "medium" | "info";
  icon?: React.ReactNode;
};

const accentStyles: Record<NonNullable<SummaryCardProps["accent"]>, { bg: string; border: string; text: string; icon: string }> = {
  critical: {
    bg: "bg-gradient-to-br from-red-500/10 to-red-600/5",
    border: "border-red-500/30",
    text: "text-red-400",
    icon: "text-red-500"
  },
  high: {
    bg: "bg-gradient-to-br from-orange-500/10 to-orange-600/5",
    border: "border-orange-500/30",
    text: "text-orange-400",
    icon: "text-orange-500"
  },
  medium: {
    bg: "bg-gradient-to-br from-yellow-500/10 to-yellow-600/5",
    border: "border-yellow-500/30",
    text: "text-yellow-400",
    icon: "text-yellow-500"
  },
  info: {
    bg: "bg-gradient-to-br from-blue-500/10 to-blue-600/5",
    border: "border-blue-500/30",
    text: "text-blue-400",
    icon: "text-blue-500"
  }
};

export function SummaryCard({
  title,
  value,
  detail,
  accent = "info",
  icon
}: SummaryCardProps) {
  const styles = accentStyles[accent];
  
  return (
    <Card className={cn("border backdrop-blur-sm transition-all hover:shadow-lg hover:shadow-slate-900/50", styles.bg, styles.border)}>
      <CardHeader>
        <div className="flex items-start justify-between">
          <CardTitle className="text-sm uppercase tracking-[0.15em] text-slate-400 font-medium">
            {title}
          </CardTitle>
          {icon && <div className={cn("text-2xl", styles.icon)}>{icon}</div>}
        </div>
      </CardHeader>
      <CardContent>
        <div className={cn("text-4xl font-bold", styles.text)}>
          {value}
        </div>
        {detail ? <p className="mt-3 text-xs text-slate-400">{detail}</p> : null}
      </CardContent>
    </Card>
  );
}

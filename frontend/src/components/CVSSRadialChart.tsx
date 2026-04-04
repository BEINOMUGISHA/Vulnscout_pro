import React from "react";

interface CVSSData {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

interface Props {
  data: CVSSData;
  total: number;
  averageScore?: number;
}

const CVSSRadialChart: React.FC<Props> = ({ data, total, averageScore = 0 }) => {
  const categories = [
    { label: "Critical", count: data.critical, color: "rgb(239, 68, 68)", glow: "0 0 20px rgba(239, 68, 68, 0.5)", range: "9.0 - 10.0" },
    { label: "High", count: data.high, color: "rgb(249, 115, 22)", glow: "0 0 20px rgba(249, 115, 22, 0.4)", range: "7.0 - 8.9" },
    { label: "Medium", count: data.medium, color: "rgb(234, 179, 8)", glow: "0 0 20px rgba(234, 179, 8, 0.3)", range: "4.0 - 6.9" },
    { label: "Low", count: data.low, color: "rgb(34, 197, 94)", glow: "0 0 20px rgba(34, 197, 94, 0.2)", range: "0.1 - 3.9" },
  ];

  const size = 280;
  const strokeWidth = 14;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;

  // Calculate cumulative offsets for segments
  let currentOffset = 0;

  return (
    <div className="flex flex-col items-center justify-center p-8 glass rounded-3xl relative overflow-hidden transition-all hover:shadow-[0_0_40px_rgba(59,130,246,0.1)] group">
      {/* Background Decorative Glow */}
      <div className="absolute top-0 right-0 w-64 h-64 bg-primary/10 blur-[100px] -mr-32 -mt-32 rounded-full pointer-events-none"></div>
      <div className="absolute bottom-0 left-0 w-64 h-64 bg-accent/10 blur-[100px] -ml-32 -mb-32 rounded-full pointer-events-none"></div>

      <h3 className="text-xl font-bold tracking-tight text-foreground/90 mb-8 flex items-center gap-2 self-start">
        <span className="w-2 h-6 bg-primary rounded-full"></span>
        CVSS DISTRIBUTION
      </h3>

      <div className="flex flex-col lg:flex-row items-center gap-12 w-full justify-around">
        {/* Radial Component */}
        <div className="relative" style={{ width: size, height: size }}>
          <svg
            width={size}
            height={size}
            viewBox={`0 0 ${size} ${size}`}
            className="transform -rotate-90 filter drop-shadow-lg"
          >
            {/* Background Track */}
            <circle
              cx={size / 2}
              cy={size / 2}
              r={radius}
              fill="transparent"
              stroke="rgba(255,255,255,0.05)"
              strokeWidth={strokeWidth}
            />

            {/* Severity Segments */}
            {categories.map((cat, i) => {
              const percentage = total > 0 ? (cat.count / total) * 100 : 0;
              const strokeLength = (percentage / 100) * circumference;
              const offset = currentOffset;
              currentOffset += strokeLength;

              return (
                <circle
                  key={cat.label}
                  cx={size / 2}
                  cy={size / 2}
                  r={radius}
                  fill="transparent"
                  stroke={cat.color}
                  strokeWidth={strokeWidth}
                  strokeDasharray={`${strokeLength} ${circumference}`}
                  strokeDashoffset={-offset}
                  strokeLinecap={strokeLength > 1 ? "round" : "butt"}
                  className="transition-all duration-1000 ease-out"
                  style={{ 
                    filter: `drop-shadow(${cat.glow})`,
                    opacity: cat.count > 0 ? 1 : 0.1 
                  }}
                />
              );
            })}
          </svg>

          {/* Center Info */}
          <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
            <span className="text-sm font-medium text-muted-foreground uppercase tracking-widest mb-1">Impact Avg</span>
            <span className={`text-6xl font-black tracking-tighter transition-all duration-300 ${
              averageScore >= 9 ? 'text-red-500 drop-shadow-[0_0_12px_rgba(239,68,68,0.5)]' :
              averageScore >= 7 ? 'text-orange-500' :
              averageScore >= 4 ? 'text-yellow-500' :
              'text-green-500'
            }`}>
              {averageScore.toFixed(1)}
            </span>
            <div className="mt-2 px-3 py-1 bg-white/5 border border-white/10 rounded-full text-[10px] font-bold text-foreground/70 uppercase tracking-widest">
              Risk Matrix Alpha
            </div>
          </div>
        </div>

        {/* Legend / Stats */}
        <div className="grid grid-cols-1 gap-4 w-full max-w-xs">
          {categories.map((cat) => (
            <div 
              key={cat.label} 
              className="flex items-center justify-between p-3 rounded-xl hover:bg-white/[0.03] transition-colors border border-transparent hover:border-white/5 group/item"
            >
              <div className="flex items-center gap-3">
                <div 
                  className="w-3 h-3 rounded-full animate-pulse" 
                  style={{ 
                    backgroundColor: cat.color,
                    boxShadow: cat.glow 
                  }}
                />
                <div className="flex flex-col">
                  <span className="text-sm font-bold text-foreground/80 group-hover/item:text-foreground transition-colors uppercase tracking-wide">
                    {cat.label}
                  </span>
                  <span className="text-[10px] text-muted-foreground font-mono">
                    {cat.range}
                  </span>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xl font-black font-mono text-foreground/90">{cat.count}</span>
                <div className="w-12 h-1 bg-white/5 rounded-full overflow-hidden">
                  <div 
                    className="h-full transition-all duration-1000" 
                    style={{ 
                      width: `${total > 0 ? (cat.count / total) * 100 : 0}%`,
                      backgroundColor: cat.color 
                    }}
                  />
                </div>
              </div>
            </div>
          ))}
          
          <div className="mt-4 pt-4 border-t border-white/5 flex items-center justify-between">
            <span className="text-xs font-bold text-muted-foreground uppercase tracking-widest">Global Findings</span>
            <span className="text-2xl font-black text-primary drop-shadow-[0_0_10px_rgba(59,130,246,0.3)]">{total}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CVSSRadialChart;

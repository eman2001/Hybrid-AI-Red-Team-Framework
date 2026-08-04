import {
  Minus,
  TrendingDown,
  TrendingUp
} from "lucide-react";


function StatCard({
  title,
  value,
  icon,
  trend,
  trendDirection = "neutral",
  hint,
  variant = "default"
}) {
  const TrendIcon =
    trendDirection === "up"
      ? TrendingUp
      : trendDirection === "down"
        ? TrendingDown
        : Minus;

  return (
    <article
      className={
        `stat-card stat-card-${variant}`
      }
    >

      <div className="stat-card-top">

        <div className="stat-icon">
          {icon}
        </div>


        <span className="stat-card-status-dot" />

      </div>


      <div className="stat-content">

        <span className="stat-title">
          {title}
        </span>

        <strong className="stat-value">
          {value}
        </strong>


        {
          (trend || hint) && (

            <div className="stat-footer">

              {
                trend && (

                  <span
                    className={
                      `stat-trend ${
                        trendDirection
                      }`
                    }
                  >

                    <TrendIcon size={13} />

                    {trend}

                  </span>

                )
              }


              {
                hint && (
                  <span className="stat-hint">
                    {hint}
                  </span>
                )
              }

            </div>

          )
        }

      </div>


      <svg
        className="stat-card-graph"
        viewBox="0 0 150 55"
        preserveAspectRatio="none"
        aria-hidden="true"
      >

        <path
          d="
            M0 46
            C15 42, 22 49, 34 35
            S55 40, 67 25
            S86 41, 100 18
            S123 31, 150 8
          "
        />

      </svg>

    </article>
  );
}


export default StatCard;

import { useEffect, useState } from "react";
import {
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

import "./App.css";

const API = "http://127.0.0.1:8000";

function App() {
  const [stats, setStats] = useState(null);
  const [decisions, setDecisions] = useState([]);
  const [reviews, setReviews] = useState([]);
  const [selectedDecision, setSelectedDecision] = useState(null);
  const [error, setError] = useState("");
  const [integrity, setIntegrity] = useState(null)
  const [search, setSearch] = useState("");
  const [outcomeFilter, setOutcomeFilter] = useState("ALL");

  useEffect(() => {
    async function loadDashboard() {
      try {
          const [
            statsResponse,
            decisionsResponse,
            reviewsResponse,
            integrityResponse,
          ] = await Promise.all([
            fetch(`${API}/api/stats`),
            fetch(`${API}/api/decisions`),
            fetch(`${API}/api/reviews`),
            fetch(`${API}/api/integrity`),
          ]);

        if (
          !statsResponse.ok ||
          !decisionsResponse.ok ||
          !reviewsResponse.ok ||
          !integrityResponse.ok
        ) {
          throw new Error("API request failed");
        }

        const statsData = await statsResponse.json();
        const decisionsData = await decisionsResponse.json();
        const reviewsData = await reviewsResponse.json();
        const integrityData = await integrityResponse.json();
        setStats(statsData);
        setDecisions(decisionsData);
        setReviews(reviewsData);
        setIntegrity(integrityData);
        setError("");
      } catch (err) {
        setError(err.message);
      }
    }

    // chargement immédiat
    loadDashboard();

    // rafraîchissement automatique toutes les 3 secondes
    const interval = setInterval(() => {
      loadDashboard();
    }, 3000);
    
    // nettoyage quand la page est fermée
    return () => clearInterval(interval);
  }, []);

  async function handleReview(actionId, decision) {
    try {
      const response = await fetch(
        `${API}/api/reviews/${actionId}/${decision}`,
        {
          method: "POST",
        }
      );

      if (!response.ok) {
        throw new Error("Human review failed");
      }

      await response.json();

      // Recharger les données après APPROVE / DENY
      const [
        reviewsResponse,
        decisionsResponse,
        statsResponse,
      ] = await Promise.all([
        fetch(`${API}/api/reviews`),
        fetch(`${API}/api/decisions`),
        fetch(`${API}/api/stats`),
      ]);

      if (
        !reviewsResponse.ok ||
        !decisionsResponse.ok ||
        !statsResponse.ok
      ) {
        throw new Error("Dashboard refresh failed");
      }

      const reviewsData = await reviewsResponse.json();
      const decisionsData = await decisionsResponse.json();
      const statsData = await statsResponse.json();

      setReviews(reviewsData);
      setDecisions(decisionsData);
      setStats(statsData);

      setSelectedDecision(null);
      setError("");
    } catch (err) {
      setError(err.message);
    }
  }

  if (error) {
    return (
      <div className="page">
        <h1>SENTINEL</h1>
        <p className="error">
          Backend error: {error}
        </p>
      </div>
    );
  }

  if (!stats) {
    return (
      <div className="page">
        <h1>SENTINEL</h1>
        <p>Loading dashboard...</p>
      </div>
    );
  }

  const chartData = [
    {
      name: "Allow",
      value: stats.allow,
    },
    {
      name: "Rewrite",
      value: stats.rewrite,
    },
    {
      name: "Escalate",
      value: stats.escalate,
    },
    {
      name: "Block",
      value: stats.block,
    },
  ];
  const timelineData = [...decisions]
    .reverse()
    .map((decision) => ({
      name: decision.action_id,
      risk: decision.risk_score,
      outcome: decision.outcome,
    }));

  function getRiskLevel(score) {
    if (score >= 75) return "critical";
    if (score >= 50) return "high";
    if (score >= 25) return "medium";
    return "low";
  }
  function getSystemStatus(decisions, reviews) {
    const recentDecisions = decisions.slice(0, 5);

    const hasCritical = recentDecisions.some(
      (decision) =>
        decision.risk_score >= 75 ||
        decision.outcome === "BLOCK"
    );

    if (hasCritical) {
      return {
        label: "CRITICAL ACTIVITY",
        className: "system-critical",
        symbol: "●",
      };
    }

    const hasAttention =
      reviews.length > 0 ||
      recentDecisions.some(
        (decision) => decision.risk_score >= 25
      );

    if (hasAttention) {
      return {
        label: "ATTENTION",
        className: "system-attention",
        symbol: "⚠",
      };
    }

    return {
      label: "SYSTEM SAFE",
      className: "system-safe",
      symbol: "●",
    };
  } 
  const systemStatus = getSystemStatus(
    decisions,
    reviews
  );
  const filteredDecisions = decisions.filter((decision) => {
    const matchesSearch =
      decision.action_id
        ?.toLowerCase()
        .includes(search.toLowerCase());

    const matchesOutcome =
      outcomeFilter === "ALL" ||
      decision.outcome === outcomeFilter;

    return matchesSearch && matchesOutcome;
  });
  return (
    <div className="page">

      {/* HEADER */}

      <header className="header">
        <div>
          <h1>SENTINEL</h1>
          <p>AI Agent Security Dashboard</p>
        </div>

        <div className="system-status-container">

          <div className="status">
            ● API Online
          </div>

          <div
            className={`system-safety ${systemStatus.className}`}
          >
            {systemStatus.symbol} {systemStatus.label}
          </div>
          <div
            className={`integrity-badge ${
              integrity?.valid
                ? "integrity-valid"
                : "integrity-invalid"
            }`}
          >
            {integrity?.valid ? "✓" : "✕"} Audit Log{" "}
            {integrity?.status || "CHECKING"}
          </div>
          
        </div>
      </header>


      {/* STATISTICS */}

      <section className="cards">

        <div className="card">
          <span>Total Actions</span>
          <strong>{stats.total}</strong>
        </div>

        <div className="card allow">
          <span>Allowed</span>
          <strong>{stats.allow}</strong>
        </div>

        <div className="card escalate">
          <span>Escalated</span>
          <strong>{stats.escalate}</strong>
        </div>

        <div className="card block">
          <span>Blocked</span>
          <strong>{stats.block}</strong>
        </div>

        <div className="card">
          <span>Average Risk</span>
          <strong>{stats.average_risk}</strong>
        </div>

      </section>


      {/* DECISION DISTRIBUTION */}

      <section className="panel">

        <h2>Decision Distribution</h2>

        <div className="chart">
          <ResponsiveContainer
            width="100%"
            height={280}
          >
            <BarChart data={chartData}>

              <XAxis dataKey="name" />

              <YAxis allowDecimals={false} />

              <Tooltip />

              <Bar
                dataKey="value"
                radius={[6, 6, 0, 0]}
              />

            </BarChart>
          </ResponsiveContainer>
        </div>

      </section>
      {/* RISK TIMELINE */}

      <section className="panel">

        <h2>Risk Timeline</h2>

        <p className="review-subtitle">
          Evolution of risk scores across SENTINEL decisions
        </p>

        <div className="chart">

          <ResponsiveContainer
            width="100%"
            height={280}
          >

            <LineChart data={timelineData}>

              <XAxis
                dataKey="name"
                tick={{ fontSize: 12 }}
              />

              <YAxis
                domain={[0, 100]}
              />

              <Tooltip
                formatter={(value) => [
                  `${value}/100`,
                  "Risk Score",
                ]}
              />

              <Line
                type="monotone"
                dataKey="risk"
                strokeWidth={3}
              />

            </LineChart>

          </ResponsiveContainer>

        </div>

      </section>

      {/* HUMAN REVIEW */}

      <section className="panel">

        <div className="review-title">

          <div>
            <h2>Human Review</h2>

            <p className="review-subtitle">
              Actions waiting for human validation
            </p>
          </div>

          <span className="pending-count">
            {reviews.length} Pending
          </span>

        </div>


        {reviews.length === 0 ? (

          <div className="empty-review">
            No actions waiting for review.
          </div>

        ) : (

          <div className="review-list">

            {reviews.map((review) => {
              const verdict = review.verdict || {};

              return (
                <div
                  className="review-card"
                  key={review.action_id}
                >

                  <div className="review-card-header">

                    <div>

                      <h3>
                        {review.action_id}
                      </h3>

                      <span className="review-escalate">
                        ESCALATE
                      </span>

                    </div>


                    <div className="risk-number">

                      {verdict.risk_score}/100

                      <span>
                        Risk
                      </span>

                    </div>

                  </div>


                  <div className="review-info">

                    <div>

                      <span>
                        ML Confidence
                      </span>

                      <strong>
                        {review.proposal?.ml_confidence ??
                          review.proposal?.part2?.ml_confidence ??
                          "-"}
                      </strong>

                    </div>


                    <div>

                      <span>
                        Semantic Similarity
                      </span>

                      <strong>
                        {review.proposal?.semantic_similarity ??
                          review.proposal?.part2?.semantic_similarity ??
                          "-"}
                      </strong>

                    </div>

                  </div>


                  <div className="review-reasons">

                    <strong>
                      Reason Codes
                    </strong>

                    <div className="flags">

                      {verdict.reason_codes?.length ? (
                        verdict.reason_codes.map(
                          (reason) => (
                            <span
                              className="flag"
                              key={reason}
                            >
                              {reason}
                            </span>
                          )
                        )
                      ) : (
                        <span>None</span>
                      )}

                    </div>

                  </div>


                  <p className="review-explanation">
                    {verdict.explanation}
                  </p>


                  <div className="review-actions">

                    <button
                      className="approve-button"
                      onClick={() =>
                        handleReview(
                          review.action_id,
                          "approve"
                        )
                      }
                    >
                      ✓ APPROVE
                    </button>


                    <button
                      className="deny-button"
                      onClick={() =>
                        handleReview(
                          review.action_id,
                          "deny"
                        )
                      }
                    >
                      ✕ DENY
                    </button>

                  </div>

                </div>
              );
            })}

          </div>
        )}

      </section>


      {/* RECENT DECISIONS */}

      <section className="panel">

        <h2>Recent Decisions</h2>
          <div className="decision-filters">
            <input
              type="text"
              placeholder="Search action..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />

            <select
              value={outcomeFilter}
              onChange={(e) => setOutcomeFilter(e.target.value)}
            >
              <option value="ALL">All outcomes</option>
              <option value="ALLOW">ALLOW</option>
              <option value="REWRITE">REWRITE</option>
              <option value="ESCALATE">ESCALATE</option>
              <option value="BLOCK">BLOCK</option>
            </select>
          </div>
        <div className="table-wrapper">

          <table>

            <thead>

              <tr>
                <th>Action</th>
                <th>Risk</th>
                <th>Outcome</th>
                <th>Trust</th>
                <th>ML Confidence</th>
                <th>Similarity</th>
                <th>Human</th>
              </tr>

            </thead>


            <tbody>

              {filteredDecisions.map((decision) => (

                <tr
                  key={`${decision.seq}-${decision.action_id}`}
                  onClick={() =>
                    setSelectedDecision(decision)
                  }
                  className="clickable-row"
                >

                  <td>
                    {decision.action_id}
                  </td>


                  <td>
                    <span
                      className={`risk-badge ${getRiskLevel(
                        decision.risk_score
                      )}`}
                    >
                      {decision.risk_score}/100
                    </span>
                  </td>


                  <td>

                    <span
                      className={`badge ${
                        decision.outcome?.toLowerCase() ||
                        ""
                      }`}
                    >
                      {decision.outcome}
                    </span>

                  </td>


                  <td>
                    {decision.trust_level || "-"}
                  </td>


                  <td>
                    {decision.ml_confidence ?? "-"}
                  </td>


                  <td>
                    {decision.semantic_similarity ?? "-"}
                  </td>


                  <td>
                    {decision.human_response || "-"}
                  </td>

                </tr>
              ))}

            </tbody>

          </table>

        </div>

      </section>


      {/* DECISION DETAILS */}

      {selectedDecision && (

        <section className="panel details-panel">

          <div className="details-header">

            <h2>
              Decision Details
            </h2>

            <button
              onClick={() =>
                setSelectedDecision(null)
              }
            >
              Close
            </button>

          </div>


          <div className="details-grid">

            <div>

              <span>
                Action ID
              </span>

              <strong>
                {selectedDecision.action_id}
              </strong>

            </div>


            <div>

              <span>
                Risk Score
              </span>

              <span
                className={`risk-badge ${getRiskLevel(
                  selectedDecision.risk_score
                )}`}
              >
                {selectedDecision.risk_score}/100
              </span>

            </div>


            <div>

              <span>
                Outcome
              </span>

              <strong>
                {selectedDecision.outcome}
              </strong>

            </div>


            <div>

              <span>
                Trust Level
              </span>

              <strong>
                {selectedDecision.trust_level ||
                  "-"}
              </strong>

            </div>


            <div>

              <span>
                Permission
              </span>

              <strong>
                {selectedDecision.permission_ok === true
                  ? "ALLOWED"
                  : selectedDecision.permission_ok === false
                    ? "DENIED"
                    : "-"}
              </strong>

            </div>


            <div>

              <span>
                ML Confidence
              </span>

              <strong>
                {selectedDecision.ml_confidence ??
                  "-"}
              </strong>

            </div>


            <div>

              <span>
                Semantic Similarity
              </span>

              <strong>
                {selectedDecision.semantic_similarity ??
                  "-"}
              </strong>

            </div>


            <div>

              <span>
                Human Response
              </span>

              <strong>
                {selectedDecision.human_response ||
                  "-"}
              </strong>

            </div>

          </div>


          <h3>
            Structural Flags
          </h3>

          <div className="flags">

            {selectedDecision.structural_flags?.length
              ? selectedDecision.structural_flags.map(
                  (flag) => (
                    <span
                      className="flag"
                      key={flag}
                    >
                      {flag}
                    </span>
                  )
                )
              : "None"}

          </div>


          <h3>
            ML Content Flags
          </h3>

          <div className="flags">

            {selectedDecision.content_flags?.length
              ? selectedDecision.content_flags.map(
                  (flag) => (
                    <span
                      className="flag"
                      key={flag}
                    >
                      {flag}
                    </span>
                  )
                )
              : "None"}

          </div>


          <h3>
            Reason Codes
          </h3>

          <div className="flags">

            {selectedDecision.reason_codes?.length
              ? selectedDecision.reason_codes.map(
                  (reason) => (
                    <span
                      className="flag"
                      key={reason}
                    >
                      {reason}
                    </span>
                  )
                )
              : "None"}

          </div>


          <h3>
            Explanation
          </h3>

          <p className="explanation">
            {selectedDecision.explanation ||
              "No explanation available."}
          </p>

        </section>
      )}

    </div>
  );
}

export default App;
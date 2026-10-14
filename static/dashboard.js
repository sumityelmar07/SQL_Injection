/**
 * Renders two Chart.js charts on the admin dashboard.
 * Called with the stats JSON object passed from the template.
 */
function initCharts(stats) {
  // --- Bar chart: events per endpoint ---
  const epLabels = stats.by_endpoint.map(function(x){ return x.endpoint || "(none)"; });
  const epCounts = stats.by_endpoint.map(function(x){ return x.cnt; });

  new Chart(document.getElementById("endpointChart"), {
    type: "bar",
    data: {
      labels: epLabels,
      datasets: [{
        label: "Events",
        data: epCounts,
        backgroundColor: "#3b5bdb",
        borderRadius: 4,
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } }
    }
  });

  // --- Pie chart: decision breakdown ---
  var decisionColorMap = {
    "SAFE":            "#2f9e44",
    "SUSPICIOUS":      "#f59f00",
    "LIKELY_ATTACK":   "#e8590c",
    "DEFINITE_ATTACK": "#e03131",
  };

  var decLabels = stats.by_decision.map(function(x){ return x.decision; });
  var decCounts = stats.by_decision.map(function(x){ return x.cnt; });
  var decColors = decLabels.map(function(l){ return decisionColorMap[l] || "#aaa"; });

  new Chart(document.getElementById("decisionChart"), {
    type: "pie",
    data: {
      labels: decLabels,
      datasets: [{
        data: decCounts,
        backgroundColor: decColors,
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: { position: "bottom", labels: { font: { size: 11 } } }
      }
    }
  });
}

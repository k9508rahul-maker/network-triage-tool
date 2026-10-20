const themeToggle = document.getElementById("themeToggle");

const savedTheme = localStorage.getItem("netguard-theme");

if (savedTheme === "light") {
    document.body.classList.add("light-mode");
}

function updateThemeButton() {
    if (!themeToggle) return;

    themeToggle.textContent =
        document.body.classList.contains("light-mode")
            ? "☾ Dark Mode"
            : "☼ Light Mode";
}

updateThemeButton();

if (themeToggle) {
    themeToggle.addEventListener("click", () => {
        document.body.classList.toggle("light-mode");

        const theme = document.body.classList.contains("light-mode")
            ? "light"
            : "dark";

        localStorage.setItem("netguard-theme", theme);

        updateThemeButton();
    });
}

const protocolDataElement = document.getElementById("protocol-data");
const protocolCanvas = document.getElementById("protocolChart");

if (protocolDataElement && protocolCanvas && window.Chart) {
    const protocolData = JSON.parse(protocolDataElement.textContent);

    const labels = Object.keys(protocolData);
    const values = Object.values(protocolData);

    if (labels.length > 0) {
        new Chart(protocolCanvas, {
            type: "doughnut",

            data: {
                labels: labels,
                datasets: [{
                    label: "Packets",
                    data: values,
                    borderWidth: 2,
                    hoverOffset: 6
                }]
            },

            options: {
                responsive: true,
                maintainAspectRatio: false,

                plugins: {
                    legend: {
                        position: "bottom",
                        labels: {
                            color: getComputedStyle(document.body)
                                .getPropertyValue("--text").trim()
                        }
                    },

                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return `${context.label}: ${context.raw} packets`;
                            }
                        }
                    }
                }
            }
        });
    }
}

document.addEventListener("DOMContentLoaded", () => {
    if (typeof Chart === "undefined") return;

    const trafficElement = document.getElementById("traffic-chart-data");
    const trafficCanvas = document.getElementById("trafficTrendChart");

    if (trafficElement && trafficCanvas) {
        const traffic = JSON.parse(trafficElement.textContent);

        new Chart(trafficCanvas, {
            type: "line",
            data: {
                labels: traffic.map(item => item.label),
                datasets: [{
                    label: "Packets",
                    data: traffic.map(item => item.packets),
                    tension: 0.3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true
            }
        });
    }

    const severityElement = document.getElementById("severity-chart-data");
    const severityCanvas = document.getElementById("severityChart");

    if (severityElement && severityCanvas) {
        const severity = JSON.parse(severityElement.textContent);

        new Chart(severityCanvas, {
            type: "doughnut",
            data: {
                labels: Object.keys(severity),
                datasets: [{
                    data: Object.values(severity)
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true
            }
        });
    }
});

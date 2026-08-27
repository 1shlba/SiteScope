/* Lightweight inline-SVG charts.
   Written by hand rather than pulled from a library so the packaged
   application has no external dependencies and works entirely offline. */

const Charts = (() => {
  "use strict";

  const NS = "http://www.w3.org/2000/svg";

  function svgEl(tag, attrs = {}) {
    const node = document.createElementNS(NS, tag);
    for (const [key, value] of Object.entries(attrs)) {
      node.setAttribute(key, value);
    }
    return node;
  }

  /** Nice round upper bound for an axis, so gridlines land on readable values. */
  function niceMax(value) {
    if (value <= 5) return 5;
    const magnitude = Math.pow(10, Math.floor(Math.log10(value)));
    const normalised = value / magnitude;
    const step = normalised <= 1 ? 1 : normalised <= 2 ? 2 : normalised <= 5 ? 5 : 10;
    return step * magnitude;
  }

  /** Catmull-Rom to cubic Bezier, giving a smooth curve through every point. */
  function smoothPath(points) {
    if (points.length < 2) return "";
    if (points.length === 2) {
      return `M${points[0][0]},${points[0][1]} L${points[1][0]},${points[1][1]}`;
    }

    let d = `M${points[0][0]},${points[0][1]}`;
    for (let i = 0; i < points.length - 1; i++) {
      const p0 = points[i - 1] || points[i];
      const p1 = points[i];
      const p2 = points[i + 1];
      const p3 = points[i + 2] || p2;

      const cp1x = p1[0] + (p2[0] - p0[0]) / 6;
      const cp1y = p1[1] + (p2[1] - p0[1]) / 6;
      const cp2x = p2[0] - (p3[0] - p1[0]) / 6;
      const cp2y = p2[1] - (p3[1] - p1[1]) / 6;

      d += ` C${cp1x},${cp1y} ${cp2x},${cp2y} ${p2[0]},${p2[1]}`;
    }
    return d;
  }

  /**
   * Line chart with horizontal gridlines and month labels.
   * series: [{ values: number[], colour, smooth, endDot }]
   */
  function lineChart(container, { labels, series, height = 240, yTicks = 5, smooth = false }) {
    container.innerHTML = "";

    const width = 640;
    const pad = { top: 14, right: 16, bottom: 26, left: 42 };
    const plotW = width - pad.left - pad.right;
    const plotH = height - pad.top - pad.bottom;

    const allValues = series.flatMap((s) => s.values);
    const max = niceMax(Math.max(1, ...allValues));

    const svg = svgEl("svg", {
      viewBox: `0 0 ${width} ${height}`,
      preserveAspectRatio: "none",
      role: "img",
    });
    svg.style.width = "100%";
    svg.style.height = height + "px";

    // Gridlines and y-axis labels
    for (let i = 0; i <= yTicks; i++) {
      const value = (max / yTicks) * i;
      const y = pad.top + plotH - (plotH * i) / yTicks;

      svg.appendChild(svgEl("line", {
        x1: pad.left, y1: y, x2: width - pad.right, y2: y,
        stroke: "#222a38", "stroke-width": 1,
      }));

      const label = svgEl("text", {
        x: pad.left - 9, y: y + 3.5,
        "text-anchor": "end", fill: "#6b7488", "font-size": 10,
        "font-family": "inherit",
      });
      label.textContent = Math.round(value);
      svg.appendChild(label);
    }

    const stepX = labels.length > 1 ? plotW / (labels.length - 1) : 0;
    const pointAt = (index, value) => [
      pad.left + stepX * index,
      pad.top + plotH - (value / max) * plotH,
    ];

    // X labels
    labels.forEach((text, index) => {
      const label = svgEl("text", {
        x: pad.left + stepX * index, y: height - 8,
        "text-anchor": "middle", fill: "#6b7488", "font-size": 10,
        "font-family": "inherit",
      });
      label.textContent = text;
      svg.appendChild(label);
    });

    // Series
    series.forEach((line) => {
      const points = line.values.map((value, index) => pointAt(index, value));
      if (!points.length) return;

      const useSmooth = line.smooth !== undefined ? line.smooth : smooth;
      const d = useSmooth ? smoothPath(points)
                          : "M" + points.map((p) => `${p[0]},${p[1]}`).join(" L");

      if (line.fill) {
        const area = svgEl("path", {
          d: `${d} L${points[points.length - 1][0]},${pad.top + plotH} L${points[0][0]},${pad.top + plotH} Z`,
          fill: line.fill, stroke: "none",
        });
        svg.appendChild(area);
      }

      svg.appendChild(svgEl("path", {
        d, fill: "none", stroke: line.colour || "#fff",
        "stroke-width": line.width || 2,
        "stroke-linecap": "round", "stroke-linejoin": "round",
      }));

      if (line.endDot && points.length) {
        const [cx, cy] = points[points.length - 1];
        svg.appendChild(svgEl("circle", {
          cx, cy, r: 11, fill: line.colour || "#fff", opacity: 0.16,
        }));
        svg.appendChild(svgEl("circle", {
          cx, cy, r: 4.5, fill: line.colour || "#fff",
        }));
      }
    });

    container.appendChild(svg);
  }

  /** Circular score gauge used on the scan results screen. */
  function scoreRing(container, { score, max, colour }) {
    container.innerHTML = "";

    const size = 116;
    const stroke = 9;
    const radius = (size - stroke) / 2;
    const circumference = 2 * Math.PI * radius;
    const fraction = Math.max(0, Math.min(1, score / max));

    const svg = svgEl("svg", { viewBox: `0 0 ${size} ${size}`, width: size, height: size });

    svg.appendChild(svgEl("circle", {
      cx: size / 2, cy: size / 2, r: radius,
      fill: "none", stroke: "#222a38", "stroke-width": stroke,
    }));

    const arc = svgEl("circle", {
      cx: size / 2, cy: size / 2, r: radius,
      fill: "none", stroke: colour, "stroke-width": stroke,
      "stroke-linecap": "round",
      "stroke-dasharray": circumference,
      "stroke-dashoffset": circumference,
    });
    arc.style.transition = "stroke-dashoffset 0.9s cubic-bezier(.4,0,.2,1)";
    svg.appendChild(arc);
    container.appendChild(svg);

    // Animate on the next frame so the transition is visible.
    requestAnimationFrame(() => {
      arc.setAttribute("stroke-dashoffset", String(circumference * (1 - fraction)));
    });
  }

  return { lineChart, scoreRing };
})();

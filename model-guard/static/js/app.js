(function () {
  "use strict";

  function initTheme() {
    var stored = localStorage.getItem("mg-theme");
    if (stored) document.documentElement.setAttribute("data-theme", stored);
    var toggle = document.getElementById("theme-toggle");
    if (!toggle) return;
    toggle.addEventListener("click", function () {
      var next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("mg-theme", next);
    });
  }

  function initMenu() {
    var toggle = document.getElementById("menu-toggle");
    var sidebar = document.getElementById("sidebar");
    if (!toggle || !sidebar) return;
    toggle.addEventListener("click", function () { sidebar.classList.toggle("open"); });
  }

  function initAnimations() {
    if (!window.gsap) return;
    gsap.from(".panel, .card", { opacity: 0, y: 16, duration: 0.45, stagger: 0.05, ease: "power2.out" });
  }

  function readData(element, key, fallback) {
    try {
      var raw = element.getAttribute("data-" + key);
      return raw ? JSON.parse(raw) : fallback;
    } catch (error) {
      return fallback;
    }
  }

  function initCharts() {
    if (!window.Chart) return;
    Chart.defaults.color = getComputedStyle(document.body).getPropertyValue("--muted");
    Chart.defaults.font.family = "Inter, Segoe UI, sans-serif";

    var severity = document.getElementById("severity-chart");
    var timeline = document.getElementById("risk-chart");
    if (!severity && !timeline) return;

    fetch("/dashboard/api/chart-data/")
      .then(function (response) { return response.json(); })
      .then(function (data) {
        if (severity && data.severity) {
          var labels = data.severity.map(function (item) { return item.severity; });
          var values = data.severity.map(function (item) { return item.total; });
          new Chart(severity, {
            type: "doughnut",
            data: { labels: labels, datasets: [{ data: values, backgroundColor: ["#d4af37", "#ff6b6b", "#ffb84d", "#6aa9ff", "#55d6a4"], borderWidth: 0 }] },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: "bottom" } } }
          });
        }
        if (timeline && data.timeline) {
          new Chart(timeline, {
            type: "line",
            data: {
              labels: data.timeline.map(function (item) { return item.created_at.slice(0, 10); }),
              datasets: [{ label: "Risk score", data: data.timeline.map(function (item) { return item.risk_score; }), borderColor: "#d4af37", backgroundColor: "rgba(212,175,55,0.14)", fill: true, tension: 0.35 }]
            },
            options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, max: 100 } } }
          });
        }
      })
      .catch(function () {});
  }

  function makeNetwork(scene, features, mode) {
    var group = new THREE.Group();
    var nodeGeometry = new THREE.SphereGeometry(mode === "background" ? 0.06 : 0.11, 12, 12);
    var nodeMaterial = new THREE.MeshBasicMaterial({ color: 0xd4af37 });
    var nodes = [];
    var layers = mode === "background" ? 5 : 3;
    var perLayer = mode === "background" ? 7 : Math.min(8, Math.max(3, features.length));

    for (var layer = 0; layer < layers; layer++) {
      for (var index = 0; index < perLayer; index++) {
        var x = (layer - (layers - 1) / 2) * (mode === "background" ? 1.7 : 2.4);
        var y = (index - (perLayer - 1) / 2) * (mode === "background" ? 0.9 : 0.68);
        var z = mode === "background" ? Math.sin(layer * 1.3 + index) * 0.7 : Math.cos(index * 0.8) * 0.4;
        var mesh = new THREE.Mesh(nodeGeometry, nodeMaterial.clone());
        mesh.position.set(x, y, z);
        if (mode === "viz") {
          var importance = features[index % features.length] || 0;
          mesh.material.color.setHSL(0.13 - Math.min(importance, 1) * 0.1, 0.75, 0.45 + Math.min(importance, 1) * 0.25);
        }
        group.add(mesh);
        nodes.push(mesh);
      }
    }

    var lineMaterial = new THREE.LineBasicMaterial({ color: 0x6aa9ff, transparent: true, opacity: 0.22 });
    for (var n = 0; n < nodes.length - perLayer; n++) {
      if ((n + 1) % perLayer === 0) continue;
      var geometry = new THREE.BufferGeometry().setFromPoints([nodes[n].position, nodes[n + perLayer].position]);
      group.add(new THREE.Line(geometry, lineMaterial));
    }
    scene.add(group);
    return group;
  }

  function initThree(canvas, mode, features) {
    if (!window.THREE || !canvas || !canvas.getContext) return;
    try {
      var renderer = new THREE.WebGLRenderer({ canvas: canvas, antialias: true, alpha: true });
      renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5));
      var width = mode === "background" ? window.innerWidth : canvas.clientWidth || 800;
      var height = mode === "background" ? window.innerHeight : canvas.clientHeight || 300;
      renderer.setSize(width, height, false);
      var scene = new THREE.Scene();
      var camera = new THREE.PerspectiveCamera(50, width / height, 0.1, 100);
      camera.position.z = mode === "background" ? 9 : 8;
      var group = makeNetwork(scene, features, mode);
      var start = Date.now();
      function animate() {
        var elapsed = (Date.now() - start) / 1000;
        group.rotation.y = Math.sin(elapsed * 0.12) * 0.28;
        group.rotation.x = Math.cos(elapsed * 0.09) * 0.08;
        renderer.render(scene, camera);
        if (mode === "background") requestAnimationFrame(animate);
      }
      if (mode === "background") animate(); else setTimeout(animate, 60);
    } catch (error) {
      canvas.style.display = "none";
    }
  }

  function initVisualizations() {
    var background = document.getElementById("neural-bg");
    initThree(background, "background", [0.2, 0.5, 0.3, 0.7]);

    var viz = document.getElementById("neural-viz");
    if (!viz) return;
    var features = readData(viz, "features", []).map(function (item) { return Number(item.value) || 0; });
    if (!features.length) features = [0.2, 0.4, 0.6];
    initThree(viz, "viz", features);
    viz.addEventListener("mousemove", function (event) {
      var rect = viz.getBoundingClientRect();
      viz.style.transform = "perspective(900px) rotateY(" + ((event.clientX - rect.left) / rect.width - 0.5) * 4 + "deg)";
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    initTheme();
    initMenu();
    initAnimations();
    initCharts();
    initVisualizations();
  });
})();

(() => {
  const root = document.documentElement;
  const tabButtons = Array.from(document.querySelectorAll(".auth-tab"));
  const forms = {
    login: document.getElementById("login-form"),
    register: document.getElementById("register-form"),
  };
  const feedback = document.getElementById("auth-feedback");
  const themeToggle = document.getElementById("auth-theme-toggle");

  function setTheme(theme) {
    root.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
    themeToggle.textContent = theme === "dark" ? "Light Mode" : "Dark Mode";
  }

  function setMode(mode) {
    tabButtons.forEach((btn) => btn.classList.toggle("active", btn.dataset.mode === mode));
    Object.entries(forms).forEach(([name, form]) => {
      form.classList.toggle("active", name === mode);
    });
    feedback.textContent = "";
    feedback.className = "feedback";
  }

  function showFeedback(message, isError = true) {
    feedback.textContent = message;
    feedback.className = `feedback ${isError ? "error" : "success"}`;
  }

  async function requestJson(url, payload) {
    const params = new URLSearchParams(payload);
    const response = await fetch(url + "?" + params.toString(), {
      method: "GET",
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok || data.ok === false) {
      throw new Error(data.error || "Something went wrong.");
    }

    return data;
  }

  async function handleLogin(event) {
    event.preventDefault();
    const username = document.getElementById("login-username").value.trim();
    const password = document.getElementById("login-password").value;

    try {
      const data = await requestJson("/api/login", { username, password });
      localStorage.setItem("user_session", JSON.stringify({
        username: username,
        loginTime: new Date().toISOString(),
        sessionToken: data.token || null
      }));
      window.location.href = data.redirect || "/main";
    } catch (error) {
      showFeedback(error.message, true);
    }
  }

  async function handleRegister(event) {
    event.preventDefault();
    const displayName = document.getElementById("register-display-name").value.trim();
    const username = document.getElementById("register-username").value.trim();
    const password = document.getElementById("register-password").value;
    const confirmPassword = document.getElementById("register-confirm-password").value;

    if (password !== confirmPassword) {
      showFeedback("Passwords do not match.", true);
      return;
    }

    try {
      const data = await requestJson("/api/register", {
        display_name: displayName,
        username,
        password,
      });
      localStorage.setItem("user_session", JSON.stringify({
        username: username,
        displayName: displayName,
        registrationTime: new Date().toISOString(),
        sessionToken: data.token || null
      }));
      window.location.href = data.redirect || "/main";
    } catch (error) {
      showFeedback(error.message, true);
    }
  }

  tabButtons.forEach((button) => {
    button.addEventListener("click", () => setMode(button.dataset.mode));
  });

  forms.login.addEventListener("submit", handleLogin);
  forms.register.addEventListener("submit", handleRegister);

  themeToggle.addEventListener("click", () => {
    const nextTheme = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
    setTheme(nextTheme);
  });

  const savedTheme = localStorage.getItem("theme") || "dark";
  setTheme(savedTheme);
  setMode("login");

  // Silently restore user session and pre-fill username
  const savedSession = localStorage.getItem("user_session");
  if (savedSession) {
    try {
      const session = JSON.parse(savedSession);
      if (session.username) {
        document.getElementById("login-username").value = session.username;
      }
    } catch (e) {
      // Silently ignore parse errors
    }
  }
})();

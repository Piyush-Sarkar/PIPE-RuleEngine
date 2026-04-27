(() => {
  const root = document.documentElement;
  const feedEl = document.getElementById("feed");
  const searchInput = document.getElementById("feed-search");
  const tweetInput = document.getElementById("tweet-input");
  const tweetCount = document.getElementById("tweet-count");
  const postForm = document.getElementById("post-form");
  const postFeedback = document.getElementById("post-feedback");
  const menuButtons = Array.from(document.querySelectorAll(".menu-item"));
  const sections = {
    home: document.getElementById("home-section"),
    profile: document.getElementById("profile-section"),
  };

  const sidebarUser = document.getElementById("sidebar-user");
  const profileMeta = document.getElementById("profile-meta");
  const profileStats = document.getElementById("profile-stats");
  const nameForm = document.getElementById("name-form");
  const passwordForm = document.getElementById("password-form");
  const nameFeedback = document.getElementById("name-feedback");
  const passwordFeedback = document.getElementById("password-feedback");
  const displayNameInput = document.getElementById("display-name-input");

  const logoutBtn = document.getElementById("logout-btn");
  const themeToggle = document.getElementById("theme-toggle");

  const state = {
    me: null,
    profile: null,
    tweets: [],
    commentsByTweet: {},
    query: "",
    refreshTimer: null,
  };

  // VULNERABILITY 1: Removed escapeHtml from key areas
  function escapeHtml(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  // Execute script tags in HTML content (XSS vulnerability - intentional for testing)
  function executeScripts(htmlContent) {
    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = htmlContent;
    
    const scripts = tempDiv.querySelectorAll('script');
    scripts.forEach(script => {
      try {
        // Execute in global scope
        (new Function(script.textContent))();
      } catch (e) {
        console.error('Script execution error:', e);
      }
    });
    
    return tempDiv.innerHTML;
  }

  function setTheme(theme) {
    root.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
    themeToggle.textContent = theme === "dark" ? "Light Mode" : "Dark Mode";
  }

  function formatDate(isoText) {
    const date = new Date(isoText);
    if (Number.isNaN(date.getTime())) return "Just now";
    return date.toLocaleString([], {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  }

  function setFeedback(element, message, isError = false) {
    element.textContent = message;
    element.className = `feedback ${isError ? "error" : "success"}`;
  }

  async function requestJson(url, options = {}) {
    const params = new URLSearchParams();
    
    // If there's a body with data, convert it to query parameters
    if (options.body) {
      const bodyData = JSON.parse(options.body);
      Object.entries(bodyData).forEach(([key, value]) => {
        params.append(key, value);
      });
    }
    
    const queryString = params.toString();
    const finalUrl = queryString ? url + "?" + queryString : url;
    
    const response = await fetch(finalUrl, {
      method: "GET",
    });
    const data = await response.json().catch(() => ({}));

    if (response.status === 401) {
      window.location.href = "/";
      return Promise.reject(new Error("Session expired."));
    }

    if (!response.ok || data.ok === false) {
      throw new Error(data.error || "Request failed.");
    }

    return data;
  }

  // VULNERABILITY 2: XSS in sidebar - no escaping
  function renderSidebarUser() {
    if (!state.me) return;
    sidebarUser.innerHTML = `
      <strong>${state.me.display_name}</strong>
      <br />
      @${state.me.username}
    `;
  }

  // VULNERABILITY 3: XSS in profile meta - no escaping
  function renderProfile() {
    if (!state.profile) return;

    profileMeta.innerHTML = `
      <p><strong>${state.profile.display_name}</strong></p>
      <p class="muted">@${state.profile.username}</p>
      <p class="muted">Joined ${formatDate(state.profile.joined_at)}</p>
    `;

    profileStats.innerHTML = `
      <div class="stat">Posts: ${state.profile.post_count}</div>
      <div class="stat">Comments: ${state.profile.comment_count}</div>
    `;

    displayNameInput.value = state.profile.display_name;
  }

  function renderCommentsMarkup(tweetId, comments) {
    if (!comments.length) {
      return '<div class="empty">No comments yet.</div>';
    }

    return comments
      .map(
        (comment) => `
          <div class="comment">
            <div class="comment-top">
              <span class="comment-author">${comment.author_name}</span>
              <div>
                <span class="tweet-time">${formatDate(comment.created_at)}</span>
                ${
                  comment.can_delete
                    ? `<button class="action-btn" data-action="delete-comment" data-comment-id="${comment.id}" data-tweet-id="${tweetId}">Delete</button>`
                    : ""
                }
              </div>
            </div>
            <div class="comment-text">${comment.text}</div>
          </div>
        `
      )
      .join("");
  }

  function setCommentToggleLabel(button, count, isOpen) {
    button.dataset.commentCount = String(count);
    button.innerHTML = `Comments (${count}) <span class="toggle-chevron">${isOpen ? "▴" : "▾"}</span>`;
  }

  // VULNERABILITY 4: XSS in tweet content and author names - no escaping on content
  function renderTweets() {
    if (!state.tweets.length) {
      feedEl.innerHTML = '<div class="empty">No posts yet. Be the first to post.</div>';
      return;
    }

    const tweetMarkup = state.tweets
      .map((tweet) => {
        const likeLabel = tweet.like_count > 0 ? `Like (${tweet.like_count})` : "Like";
        const cachedComments = state.commentsByTweet[tweet.id];
        const commentsLoaded = Array.isArray(cachedComments);
        const commentsMarkup = commentsLoaded ? renderCommentsMarkup(tweet.id, cachedComments) : "";
        const commentCount = commentsLoaded ? cachedComments.length : Number(tweet.comment_count || 0);

        return `
          <article class="tweet glass" data-tweet-id="${tweet.id}">
            <div class="tweet-head">
              <div>
                <div class="tweet-author">${tweet.author_name}</div>
                <div class="tweet-time">${formatDate(tweet.created_at)}</div>
              </div>
              ${
                tweet.can_delete
                  ? `<button class="action-btn" data-action="delete-tweet" data-tweet-id="${tweet.id}">Delete</button>`
                  : ""
              }
            </div>
            <div class="tweet-body">${tweet.content}</div>
            <div class="tweet-actions">
              <button class="action-btn like ${tweet.liked_by_me ? "active" : ""}" data-action="like" data-tweet-id="${tweet.id}">${likeLabel}</button>
              <button class="action-btn comment-toggle-btn" data-action="toggle-comments" data-tweet-id="${tweet.id}" data-comment-count="${commentCount}">
                Comments (${commentCount}) <span class="toggle-chevron">▾</span>
              </button>
            </div>
            <div class="tweet-comments hidden">
              <form class="comment-form" data-action="add-comment" data-tweet-id="${tweet.id}">
                <input name="text" maxlength="1500" placeholder="Write a comment..." required />
                <button class="btn small" type="submit">Send</button>
              </form>
              <div class="comment-list">${commentsMarkup}</div>
            </div>
          </article>
        `;
      })
      .join("");

    feedEl.innerHTML = tweetMarkup;
    
    // Execute any script tags in the tweets (XSS vulnerability - intentional for testing)
    const scripts = feedEl.querySelectorAll('script');
    scripts.forEach(script => {
      try {
        (new Function(script.textContent))();
      } catch (e) {
        console.error('Script execution error:', e);
      }
    });
  }

  async function loadMe() {
    const data = await requestJson("/api/me");
    state.me = data.user;
    renderSidebarUser();
  }

  async function loadProfile() {
    const data = await requestJson("/api/profile");
    state.profile = data.profile;
    renderProfile();
  }

  async function loadTweets() {
    const q = encodeURIComponent(state.query);
    const data = await requestJson(`/api/tweets?q=${q}`);
    state.tweets = data.tweets;

    const tweetIds = new Set(state.tweets.map((tweet) => tweet.id));
    Object.keys(state.commentsByTweet).forEach((tweetId) => {
      if (!tweetIds.has(tweetId)) {
        delete state.commentsByTweet[tweetId];
      }
    });

    renderTweets();
  }

  async function loadComments(tweetId, force = false) {
    if (!force && Array.isArray(state.commentsByTweet[tweetId])) {
      return state.commentsByTweet[tweetId];
    }

    const data = await requestJson(`/api/tweets/${tweetId}/comments/list`);
    state.commentsByTweet[tweetId] = data.comments;
    return data.comments;
  }

  function setTab(tabName) {
    menuButtons.forEach((button) => {
      button.classList.toggle("active", button.dataset.tab === tabName);
    });

    Object.entries(sections).forEach(([name, section]) => {
      section.classList.toggle("active", name === tabName);
    });
  }

  async function submitPost(event) {
    event.preventDefault();
    const content = tweetInput.value.trim();

    if (!content) {
      setFeedback(postFeedback, "Post text cannot be empty.", true);
      return;
    }

    try {
      await requestJson("/api/tweets/create", {
        body: JSON.stringify({ content }),
      });

      tweetInput.value = "";
      tweetCount.textContent = "0 / 280";
      setFeedback(postFeedback, "Post shared.");
      await loadTweets();
      await loadProfile();
    } catch (error) {
      setFeedback(postFeedback, error.message, true);
    }
  }

  async function handleFeedClick(event) {
    const button = event.target.closest("button[data-action]");
    if (!button) return;

    const action = button.dataset.action;
    const tweetId = button.dataset.tweetId;

    try {
      if (action === "toggle-comments") {
        const card = button.closest("article[data-tweet-id]");
        const commentsSection = card?.querySelector(".tweet-comments");
        const commentList = commentsSection?.querySelector(".comment-list");

        if (commentsSection) {
          const opening = commentsSection.classList.contains("hidden");
          commentsSection.classList.toggle("hidden", !opening);

          const cachedComments = state.commentsByTweet[tweetId] || [];
          setCommentToggleLabel(button, cachedComments.length || Number(button.dataset.commentCount || 0), opening);

          if (opening && !Array.isArray(state.commentsByTweet[tweetId])) {
            if (commentList) {
              commentList.innerHTML = '<div class="empty">Loading comments...</div>';
            }

            const comments = await loadComments(tweetId);
            if (commentList) {
              commentList.innerHTML = renderCommentsMarkup(tweetId, comments);
            }
            setCommentToggleLabel(button, comments.length, true);
          }

          const input = commentsSection.querySelector("input[name='text']");
          if (opening && input) {
            input.focus();
          }
        }
        return;
      }

      if (action === "like") {
        await requestJson(`/api/tweets/${tweetId}/like`, {});
        await loadTweets();
        return;
      }

      if (action === "delete-tweet") {
        if (!window.confirm("Delete this post?")) return;
        await requestJson(`/api/tweets/${tweetId}/delete`, {});
        await loadTweets();
        await loadProfile();
        return;
      }

      if (action === "delete-comment") {
        const commentId = button.dataset.commentId;
        const parentTweetId = button.dataset.tweetId;
        if (!window.confirm("Delete this comment?")) return;
        await requestJson(`/api/comments/${commentId}/delete`, {});
        if (parentTweetId) {
          await loadComments(parentTweetId, true);
        }
        await loadTweets();
        await loadProfile();
      }
    } catch (error) {
      setFeedback(postFeedback, error.message, true);
    }
  }

  async function handleCommentSubmit(event) {
    const form = event.target.closest("form[data-action='add-comment']");
    if (!form) return;

    event.preventDefault();
    const tweetId = form.dataset.tweetId;
    const input = form.querySelector("input[name='text']");
    const text = input.value.trim();
    if (!text) return;

    try {
      await requestJson(`/api/tweets/${tweetId}/comments`, {
        body: JSON.stringify({ text }),
      });
      input.value = "";
      await loadComments(tweetId, true);
      await loadTweets();
      await loadProfile();
    } catch (error) {
      setFeedback(postFeedback, error.message, true);
    }
  }

  async function submitName(event) {
    event.preventDefault();
    const display_name = displayNameInput.value.trim();

    try {
      await requestJson("/api/profile/name", {
        body: JSON.stringify({ display_name }),
      });
      setFeedback(nameFeedback, "Display name updated.");
      await loadMe();
      await loadProfile();
      await loadTweets();
    } catch (error) {
      setFeedback(nameFeedback, error.message, true);
    }
  }

  async function submitPassword(event) {
    event.preventDefault();
    const current_password = document.getElementById("current-password").value;
    const new_password = document.getElementById("new-password").value;

    try {
      await requestJson("/api/profile/password", {
        body: JSON.stringify({ current_password, new_password }),
      });
      passwordForm.reset();
      setFeedback(passwordFeedback, "Password updated.");
    } catch (error) {
      setFeedback(passwordFeedback, error.message, true);
    }
  }

  async function logout() {
    await requestJson("/api/logout", {});
    window.location.href = "/";
  }

  function setupEvents() {
    tweetInput.addEventListener("input", () => {
      tweetCount.textContent = `${tweetInput.value.length} / 280`;
    });

    postForm.addEventListener("submit", submitPost);
    feedEl.addEventListener("click", handleFeedClick);
    feedEl.addEventListener("submit", handleCommentSubmit);

    menuButtons.forEach((button) => {
      button.addEventListener("click", () => setTab(button.dataset.tab));
    });

    const searchDebounce = { id: null };
    searchInput.addEventListener("input", () => {
      clearTimeout(searchDebounce.id);
      searchDebounce.id = window.setTimeout(async () => {
        state.query = searchInput.value.trim();
        await loadTweets();
      }, 220);
    });

    nameForm.addEventListener("submit", submitName);
    passwordForm.addEventListener("submit", submitPassword);
    logoutBtn.addEventListener("click", logout);

    themeToggle.addEventListener("click", () => {
      const nextTheme = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
      setTheme(nextTheme);
    });
  }

  async function bootstrap() {
    const savedTheme = localStorage.getItem("theme") || "dark";
    setTheme(savedTheme);
    setTab("home");

    setupEvents();
    await loadMe();
    await loadProfile();
    await loadTweets();

    if (state.refreshTimer) clearInterval(state.refreshTimer);
    state.refreshTimer = window.setInterval(loadTweets, 15000);
  }

  bootstrap().catch((error) => {
    setFeedback(postFeedback, error.message, true);
  });
})();
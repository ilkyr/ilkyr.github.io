---
layout: home
title: Home
---

<section class="hero">
  <div class="container hero-intro">
    <div class="avatar-wrap reveal">
      <img class="avatar" src="{{ site.avatar | relative_url }}" alt="Ilias">
    </div>
    <div class="hero-copy reveal delay-1">
      <h1>Ilias</h1>
      <p class="hero-role">Penetration Tester - United Kingdom</p>
      <p class="lead">
        I work in offensive security, focused on infrastructure penetration testing and red team
        operations. This is where I publish research notes and tooling.
      </p>
      <div class="hero-social">
        <a href="{{ site.social.github }}">GitHub</a>
        <a href="{{ site.social.linkedin }}">LinkedIn</a>
        <a href="{{ site.social.x }}">X</a>
      </div>
    </div>
  </div>
</section>

<section class="section">
  <div class="container">
    <h2 class="section-label">Latest posts</h2>
    {% if site.posts.size > 0 %}
      <div class="post-list">
        {% for post in site.posts limit:5 %}
        <a class="post-row reveal" href="{{ post.url | relative_url }}">
          <span class="post-date">{{ post.date | date: "%b %d, %Y" }}</span>
          <span class="post-title">{{ post.title }}</span>
        </a>
        {% endfor %}
      </div>
      <a class="all-posts-link" href="{{ '/blog/' | relative_url }}">All posts &rarr;</a>
    {% else %}
      <p class="muted">No posts yet. First write-up coming soon.</p>
    {% endif %}
  </div>
</section>

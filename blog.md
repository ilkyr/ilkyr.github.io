---
layout: default
title: All Posts
permalink: /blog/
---

<section class="page-hero">
  <p class="eyebrow">Blog</p>
  <h1>Write-ups, tooling, and research notes.</h1>
</section>

{% if site.posts.size > 0 %}
  <div class="post-grid">
    {% for post in site.posts %}
    <a class="post-card reveal" href="{{ post.url | relative_url }}">
      <span class="post-date">{{ post.date | date: "%b %d, %Y" }}</span>
      <h3>{{ post.title }}</h3>
      <p>{{ post.excerpt | strip_html | truncate: 160 }}</p>
    </a>
    {% endfor %}
  </div>
{% else %}
  <div class="empty-state">
    No posts yet. The first series will cover lab setup, credential access drills, and detection validation.
  </div>
{% endif %}

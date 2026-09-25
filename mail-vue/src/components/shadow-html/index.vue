<template>
  <div class="content-box" ref="contentBox">
    <div ref="container" class="content-html"></div>
  </div>
</template>

<script setup>
import { ref, onMounted, watch } from 'vue'
import DOMPurify from 'dompurify'

const props = defineProps({
  html: {
    type: String,
    required: true
  }
})

const container = ref(null)
const contentBox = ref(null)
let shadowRoot = null

// Sanitize untrusted email HTML before it touches the DOM.
//
// A shadow root is NOT a security boundary: <script> tags inserted via
// innerHTML don't run, but event-handler attributes (<img onerror=...>,
// <svg onload=...>, ...) and javascript: URLs execute normally inside it.
// Without sanitization, one malicious email could run JS in the app's
// origin and steal the auth token from localStorage.
function sanitizeEmailHtml(dirty) {
  return DOMPurify.sanitize(dirty || '', {
    WHOLE_DOCUMENT: true,
    // Email essentials: keep formatting, allow inline data: images.
    ADD_DATA_URI_TAGS: ['img'],
    // Mail content must never submit forms or embed browsing contexts.
    FORBID_TAGS: ['form', 'input', 'button', 'select', 'textarea', 'iframe', 'frame', 'object', 'embed', 'base', 'meta', 'link', 'script', 'noscript'],
    FORBID_ATTR: ['formaction'],
  })
}

function updateContent() {
  if (!shadowRoot) return;

  // DOMPurify parses with the real HTML parser, so the serialized output
  // below cannot contain a literal "</style>" breakout sequence.
  const clean = sanitizeEmailHtml(props.html)

  // 1. Extract <body style="..."> (common in marketing mail). Applied via
  // the DOM API below — the old code interpolated the raw style string
  // into the <style> block, where a crafted value like
  // `x</style><img src=x onerror=...>` broke out into arbitrary markup.
  let bodyStyle = ''
  const bodyOpen = clean.match(/<body[^>]*>/i)
  const styleMatch = bodyOpen && bodyOpen[0].match(/\sstyle=(["'])([\s\S]*?)\1/i)
  if (styleMatch) bodyStyle = styleMatch[2]

  // 2. Keep the mail's own <style> blocks for rendering fidelity
  // (already sanitized above).
  const emailStyles = [...clean.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/gi)]
    .map(m => m[1]).join('\n')

  // 3. Drop document wrappers, keep the content.
  const content = clean
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<title>[\s\S]*?<\/title>/gi, '')
    .replace(/<\/?(?:html|head|body)[^>]*>/gi, '')

  shadowRoot.innerHTML = `
    <style>
      :host {
        all: initial;
        width: 100%;
        height: 100%;
        font-family: Inter, 'Helvetica Neue', Helvetica, 'PingFang SC',
                    'Hiragino Sans GB', 'Microsoft YaHei', '微软雅黑', Arial, sans-serif;
        font-size: 14px;
        line-height: 1.5;
        color: #13181D;
        word-break: break-word;
      }

      h1, h2, h3, h4 {
          font-size: 18px;
          font-weight: 700;
      }

      p {
        margin: 0;
      }

      a {
        text-decoration: none;
        color: #0E70DF;
      }

      .shadow-content {
        background: #FFFFFF;
        width: fit-content;
        height: fit-content;
        min-width: 100%;
      }

      img:not(table img) {
        max-width: 100%;
        height: auto !important;
      }

      ${emailStyles}
    </style>
    <div class="shadow-content"></div>
  `;

  // setAttribute() never parses HTML, so a hostile style value can't
  // escape into markup here.
  const contentDiv = shadowRoot.querySelector('.shadow-content')
  if (bodyStyle) contentDiv.setAttribute('style', bodyStyle)
  contentDiv.innerHTML = content
}

function autoScale() {
  if (!shadowRoot || !contentBox.value) return

  const parent = contentBox.value
  const shadowContent = shadowRoot.querySelector('.shadow-content')

  if (!shadowContent) return

  const parentWidth = parent.offsetWidth
  const childWidth = shadowContent.scrollWidth

  if (childWidth === 0) return

  const scale = parentWidth / childWidth

  const hostElement = shadowRoot.host
  hostElement.style.zoom = scale
}

onMounted(() => {
  shadowRoot = container.value.attachShadow({ mode: 'open' })
  updateContent()
  autoScale()
})

watch(() => props.html, () => {
  updateContent()
  autoScale()
})
</script>

<style scoped>
.content-box {
  width: 100%;
  height: 100%;
  overflow: hidden;
  font-family: Inter, "Helvetica Neue", Helvetica, "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", "微软雅黑", Arial, sans-serif;
}

.content-html {
  width: 100%;
  height: 100%;
}
</style>

// Copyright 2026 John "topjohnwu" Wu
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Light / dark / system theme selection, persisted in localStorage.
//
// The choice is applied as data-theme on <html>, which styles.css maps to
// color-scheme. "system" removes the attribute so the OS preference applies.
// An inline script in index.html applies the stored theme before first paint;
// keep its storage key and values in sync with this module.

const STORAGE_KEY = "theme";
const THEMES = ["light", "dark", "system"];

function readStoredTheme() {
  try {
    const value = localStorage.getItem(STORAGE_KEY);
    return THEMES.includes(value) ? value : "system";
  } catch {
    // Storage can be unavailable (e.g. blocked by privacy settings)
    return "system";
  }
}

function applyTheme(theme) {
  if (theme === "system") {
    document.documentElement.removeAttribute("data-theme");
  } else {
    document.documentElement.dataset.theme = theme;
  }
}

function syncRadios(theme) {
  const radio = document.querySelector(`input[name="theme"][value="${theme}"]`);
  if (radio) radio.checked = true;
}

export function setupThemeToggle() {
  const theme = readStoredTheme();
  applyTheme(theme);
  syncRadios(theme);

  for (const radio of document.querySelectorAll('input[name="theme"]')) {
    radio.addEventListener("change", (e) => {
      const selected = e.target.value;
      applyTheme(selected);
      try {
        if (selected === "system") {
          localStorage.removeItem(STORAGE_KEY);
        } else {
          localStorage.setItem(STORAGE_KEY, selected);
        }
      } catch {
        // Not persisted, but still applied for this page
      }
    });
  }

  // Follow theme changes made in other tabs
  window.addEventListener("storage", (e) => {
    if (e.key !== STORAGE_KEY && e.key !== null) return;
    const updated = readStoredTheme();
    applyTheme(updated);
    syncRadios(updated);
  });
}

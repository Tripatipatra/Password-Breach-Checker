
const form = document.getElementById("passwordForm");
const passwordInput = document.getElementById("password");
const togglePassword = document.getElementById("togglePassword");
const checkBtn = document.getElementById("checkBtn");
const loading = document.getElementById("loading");
const result = document.getElementById("result");

// Show / Hide Password
togglePassword.addEventListener("click", () => {
    if (passwordInput.type === "password") {
        passwordInput.type = "text";
        togglePassword.textContent = "Hide";
    } else {
        passwordInput.type = "password";
        togglePassword.textContent = "Show";
    }
});

// Generate SHA-1 Hash
async function generateSHA1(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);

    const hashBuffer = await crypto.subtle.digest("SHA-1", data);

    const hashArray = Array.from(new Uint8Array(hashBuffer));

    return hashArray
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("")
        .toUpperCase();
}

// Check Password using HIBP API
async function checkPassword(password) {

    // Generate password hash
    const hash = await generateSHA1(password);

    // Split hash into prefix and suffix
    const prefix = hash.substring(0, 5);
    const suffix = hash.substring(5);

    // Send only first 5 characters to HIBP
    const response = await fetch(
        `https://api.pwnedpasswords.com/range/${prefix}`,
        {
            headers: {
                "Add-Padding": "true"
            }
        }
    );

    if (!response.ok) {
        throw new Error("API request failed. Please try again.");
    }

    const data = await response.text();

    // Search for matching hash suffix
    const lines = data.split(/\r?\n/);

    for (const line of lines) {
        const [hashSuffix, count] = line.split(":");

        if (hashSuffix === suffix) {
            return Number(count);
        }
    }

    return 0;
}

// Form Submission
form.addEventListener("submit", async (event) => {

    event.preventDefault();

    const password = passwordInput.value;

    if (!password) {
        showResult("Please enter a password.", "error");
        return;
    }

    // Show loading
    result.classList.add("hidden");
    loading.classList.remove("hidden");
    checkBtn.disabled = true;

    try {

        const count = await checkPassword(password);

        if (count > 0) {

            showResult(
                `⚠️ Warning! This password has appeared
                ${count.toLocaleString()} times in known data breaches.
                Please choose a different password.`,
                "danger"
            );

        } else {

            showResult(
    `✅ Good news! This password was not found
    in the HIBP Pwned Passwords dataset.`,
    "safe"
);
        }

    } catch (error) {

        showResult(
            "❌ Unable to check your password. " + error.message,
            "error"
        );

    } finally {

        loading.classList.add("hidden");
        checkBtn.disabled = false;

    }
});

// Display Result
function showResult(message, type) {

    result.textContent = message;
    result.className = "result " + type;

}

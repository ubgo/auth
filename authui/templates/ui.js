// Show-password toggles, added only when scripts run: without them the form
// still works, the field just stays hidden.
document.querySelectorAll("input[data-reveal]").forEach(function (input) {
  var b = document.createElement("button");
  b.type = "button";
  b.className = "reveal";
  b.textContent = "Show";
  b.addEventListener("click", function () {
    var show = input.type === "password";
    input.type = show ? "text" : "password";
    b.textContent = show ? "Hide" : "Show";
  });
  input.insertAdjacentElement("afterend", b);
});

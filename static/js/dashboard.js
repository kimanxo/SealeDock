document
  .querySelector("#user-menu-button")
  .addEventListener("click", function () {
    document.querySelector("#user-menu").classList.toggle("hidden");
  });

document
  .querySelector("#mobile-menu-button")
  .addEventListener("click", function () {
    document.querySelector("#mobile-menu").classList.toggle("hidden");
    console.log('hey');
    
  });

document
  .getElementById("closeFileModal")
  .addEventListener("click", function () {
    const uploadOverlay = document.getElementById("upload_overlay");
    uploadOverlay.removeChild(uploadOverlay.firstChild);
  });


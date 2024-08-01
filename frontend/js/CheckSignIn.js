document.getElementById("main-form").addEventListener("submit", checkForm);

async function checkForm(event) {
    event.preventDefault();

    var form = document.getElementById("main-form");
    console.log(form);

    try {
        let response = await fetch("http://localhost:8000/sign_in", {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: `username=${form.username.value}&password=${form.password.value}`,
        });

        console.log(response);
  
        if (!response.ok) {
          alert(`Произошла ошибка: ${response.status}`);
          return;
        }
  
        let responseText = await response.text();
      }
    catch (err) {
        alert(`Ошибка: ${err}`);
    }
    return false;
}
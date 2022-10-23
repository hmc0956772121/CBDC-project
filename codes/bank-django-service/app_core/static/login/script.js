import Cookies from '/static/login/js.cookie.min.mjs'
import CheckLoginStatus from '/static/login/CheckLoginStatus.js'

// 送出函數
function sendMessage(account_input, password_input) {
    // Fetch Get 函數
    // 不過由於 Get 參數要加在URL裏頭，所以要加問候並且使用URLSearchParams()來轉換。
    fetch("/api/login?" + new URLSearchParams({
        account: account_input,
        password: password_input,
    }),
        {
            // Get方法
            method: "get",
            // Header 一定要加入，否則在Laravel一類的框架可能會接收不到
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Requested-With": "XMLHttpRequest",
            }
        }).then((response) => {
            // 將收到的回應轉換成JSON物件
            return response.json();
        }).then((jsonObj) => {
            // 若登入成功
            if (jsonObj['code'] == 1){
                Cookies.set('token', jsonObj['token'])
                LoginFail.innerHTML = " "
                window.location.replace("/");
            }else{
                LoginFail.innerHTML = "登入失敗，請重新登入"
            }
        });
}

// 將帳號密碼送出
function submit() {
    sendMessage(account.value, password.value)
}

// 主函數
async function main() {
    // 假如已經登入了就跳轉到主頁面
    let token = Cookies.get('token')
    let loginCheck = await CheckLoginStatus(token)
    if (loginCheck) {
        window.location.replace("/");
    }

    document.getElementById("submit").onclick = submit;
}

// 當頁面完全載入後啟動主函數
window.onload = function () {
    main()
}
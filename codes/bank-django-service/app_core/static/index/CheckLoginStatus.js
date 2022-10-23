// 送出函數
async function CheckLoginStatus(token_input) {
    // Fetch Get 函數
    // 不過由於 Get 參數要加在URL裏頭，所以要加問候並且使用URLSearchParams()來轉換。
    let result = await  fetch("/api/check_login?" + new URLSearchParams({
        token: token_input,
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
                return true
            }else{
                return false
            }
        });

    return result
}

export default CheckLoginStatus
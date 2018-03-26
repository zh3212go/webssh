function getCookie(name){
    var x = document.cookie.match("\\b" + name + "=([^;]*)\\b");
    return x ? x[1]:undefined;
}
$(document).ready(function(){
    $("#loginBtn").click(function(){
        var user = $("#username").val();
        var pwd = $("#password").val();
        var pd = {"username":user, "password":pwd, "_xsrf":getCookie("_xsrf")};
        if (user.length === 0) {
            $("#username").parent().addClass("has-error");
            return false;
        }
        if (pwd.length === 0) {
            $("#username_tip").text('') ;
            $("#password_tip").text('密码不能为空') ;
            $("#password").focus();
            return false;
        }
        $.ajax({
            type:"post",
            url:"/login",
            data:pd,
            cache:false,
            success:function(data){
                if (data === "1") {
                    window.location.href = "/";
                }
                if (data === "-1") {
                    $("#username_tip").text('用户不存在') ;
                    $("#password_tip").text('') ;
                    $("#username").focus();
                }
                if (data === "-2") {
                    $("#username_tip").text('') ;
                    $("#password_tip").text('密码错误') ;
                    $("#password").focus();
                }
            },
            error:function(){
                alert("error!");
            }
        });
        return false;
    });
});